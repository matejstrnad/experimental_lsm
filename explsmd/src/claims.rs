//! Writing answers into the policy: grants and claims go to
//! `claims.d/<user>.explsm`, which the daemon reads after the policy
//! directory; declined claims go to a state file so they are not asked
//! again.
//!
//! ```text
//! # allowed by alice through a prompt
//! app rg { exe "/usr/bin/rg" }
//! grant rg read, list to ssh
//!
//! # claimed by alice through a prompt
//! claim claude "/home/alice/.claude-cache"
//! ```

use std::{
    collections::HashSet,
    fs::{self, OpenOptions},
    io::{self, Write as _},
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _},
    path::{Path, PathBuf},
};

use explsm_common::perm;
use explsm_policy::{EXTENSION, compile::RESERVED_NAMES, users::parse_passwd};

/// Names that look like an app but run any script given to them, so
/// allowing one always allows every script.
const INTERPRETERS: &[&str] = &[
    "sh", "bash", "dash", "zsh", "fish", "ksh", "csh", "tcsh", "python", "perl", "ruby", "node",
    "deno", "bun", "lua", "php", "env", "busybox", "sudo", "doas", "xargs", "find",
];

/// A string of the policy language.
pub fn quote(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

/// Whether `path` can be written into the policy and the declined file.
pub fn writable_path(path: &Path) -> bool {
    path.to_str()
        .is_some_and(|s| s.starts_with('/') && !s.chars().any(char::is_control))
}

pub fn perm_list(bits: u32) -> String {
    if bits & perm::ALL == perm::ALL {
        return "all".into();
    }
    let names: Vec<_> = perm::NAMES
        .iter()
        .filter(|(b, _)| bits & b != 0)
        .map(|(_, n)| *n)
        .collect();
    names.join(", ")
}

/// An app name for `exe`: its file name, made a valid name, with a number
/// added if `taken`.
pub fn app_name(exe: &Path, taken: impl Fn(&str) -> bool) -> String {
    let file = exe.file_name().map(|n| n.to_string_lossy()).unwrap_or_default();
    let mut base: String = file
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || "_-.".contains(c) {
                c
            } else {
                '_'
            }
        })
        .collect();
    if base.is_empty() || !base.starts_with(|c: char| c.is_ascii_alphanumeric()) {
        base = format!("exe-{base}");
    }
    let free = |n: &str| !taken(n) && !RESERVED_NAMES.contains(&n);
    if free(&base) {
        return base;
    }
    (2..)
        .map(|i| format!("{base}-{i}"))
        .find(|n| free(n))
        .expect("unbounded")
}

/// What "allow always" writes for an unconfined exe: a new app and its grant.
pub fn exe_grant(user: &str, name: &str, exe: &Path, perms: u32, owner: &str) -> String {
    format!(
        "\n# allowed by {user} through a prompt\napp {name} {{ exe {} }}\ngrant {name} {} to {owner}\n",
        quote(&exe.to_string_lossy()),
        perm_list(perms)
    )
}

/// What "allow always" writes for an app.
pub fn app_grant(user: &str, subject: &str, perms: u32, owner: &str) -> String {
    format!(
        "\n# allowed by {user} through a prompt\ngrant {subject} {} to {owner}\n",
        perm_list(perms)
    )
}

pub fn claim(user: &str, app: &str, path: &Path) -> String {
    format!(
        "\n# claimed by {user} through a prompt\nclaim {app} {}\n",
        quote(&path.to_string_lossy())
    )
}

/// Something worth knowing before allowing `exe` for good.
pub fn exe_warning(exe: &Path, uid: u32) -> String {
    let name = exe.file_name().map(|n| n.to_string_lossy()).unwrap_or_default();
    let stem = name.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    if INTERPRETERS.contains(&stem) {
        return format!("{name} runs other programs and scripts: allowing it allows all of them");
    }
    let writable = |p: &Path| {
        fs::metadata(p).is_ok_and(|m| m.uid() == uid || m.mode() & 0o002 != 0)
    };
    if writable(exe) || exe.parent().is_some_and(writable) {
        return format!(
            "{} can be changed by this user, so any program could take its place",
            exe.display()
        );
    }
    String::new()
}

/// Why an exe with `nlink` hard links can't be allowed for good.
pub fn linked_warning(exe: &Path, nlink: u64) -> String {
    format!(
        "{} is the same file as {} other programs (e.g. coreutils): allowing it allows all of them",
        exe.display(),
        nlink - 1
    )
}

/// The login name of `uid`, for comments and file names.
pub fn user_name(uid: u32) -> String {
    fs::read_to_string("/etc/passwd")
        .ok()
        .and_then(|t| parse_passwd(&t).into_iter().find(|u| u.uid == uid))
        .map(|u| u.name)
        .filter(|n| n.chars().all(|c| c.is_ascii_alphanumeric() || "_-.".contains(c)))
        .unwrap_or_else(|| format!("uid-{uid}"))
}

/// Text appended to a claims file, so it can be taken back if the policy
/// does not load with it.
pub struct Appended {
    path: PathBuf,
    old_len: u64,
}

impl Appended {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn undo(self) -> io::Result<()> {
        if self.old_len == 0 {
            return fs::remove_file(&self.path);
        }
        OpenOptions::new()
            .write(true)
            .open(&self.path)?
            .set_len(self.old_len)
    }
}

/// Append `text` to `<dir>/<user>.explsm`.
pub fn append(dir: &Path, user: &str, text: &str) -> io::Result<Appended> {
    fs::create_dir_all(dir)?;
    let path = dir.join(format!("{user}.{EXTENSION}"));
    let old_len = fs::metadata(&path).map_or(0, |m| m.len());
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o644)
        .open(&path)?;
    if old_len == 0 {
        file.write_all(b"# Written by explsmd for answers to prompts. Edit freely.\n")?;
    }
    file.write_all(text.as_bytes())?;
    Ok(Appended { path, old_len })
}

/// Declined claims, one `app<TAB>path` per line.
pub fn load_declined(file: &Path) -> HashSet<(String, PathBuf)> {
    fs::read_to_string(file)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.split_once('\t'))
        .map(|(app, path)| (app.to_string(), PathBuf::from(path)))
        .collect()
}

pub fn add_declined(file: &Path, app: &str, path: &Path) -> io::Result<()> {
    if let Some(dir) = file.parent() {
        fs::create_dir_all(dir)?;
    }
    let mut f = OpenOptions::new().create(true).append(true).mode(0o644).open(file)?;
    writeln!(f, "{app}\t{}", path.display())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_apps_after_their_exe() {
        let taken = |n: &str| ["rg", "rg-2"].contains(&n);
        assert_eq!(app_name(Path::new("/usr/bin/rg"), taken), "rg-3");
        assert_eq!(app_name(Path::new("/usr/bin/fd"), taken), "fd");
        assert_eq!(app_name(Path::new("/opt/My App"), taken), "My_App");
        assert_eq!(app_name(Path::new("/opt/.hidden"), taken), "exe-.hidden");
        assert_eq!(app_name(Path::new("/opt/terminal"), taken), "terminal-2");
        assert_eq!(app_name(Path::new("/opt/explsmd"), taken), "explsmd-2");
    }

    #[test]
    fn writes_policy_text() {
        assert_eq!(
            exe_grant("me", "rg", Path::new("/usr/bin/r\"g"), perm::READ | perm::LIST, "ssh"),
            "\n# allowed by me through a prompt\napp rg { exe \"/usr/bin/r\\\"g\" }\n\
             grant rg read, list to ssh\n"
        );
        assert_eq!(
            app_grant("me", "backup", perm::ALL, "ssh"),
            "\n# allowed by me through a prompt\ngrant backup all to ssh\n"
        );
        assert_eq!(
            claim("me", "claude", Path::new("/home/me/.claude")),
            "\n# claimed by me through a prompt\nclaim claude \"/home/me/.claude\"\n"
        );
        assert!(!writable_path(Path::new("/a\nb")));
        assert!(!writable_path(Path::new("rel")));
    }

    #[test]
    fn the_text_compiles() {
        use explsm_policy::{IdTable, Sources, check};
        let text = format!(
            "app ssh {{ exe \"/usr/bin/ssh\" }}\napp claude {{ exe \"/c\" }}{}{}{}",
            exe_grant("me", "rg", Path::new("/usr/bin/rg"), perm::READ, "ssh"),
            app_grant("me", "claude", perm::WRITE, "ssh"),
            claim("me", "claude", Path::new("/home/me/.c\\x"))
        );
        let c = check(&Sources::single("t", &text), &IdTable::default()).unwrap();
        assert_eq!(c.grants.len(), 2);
        assert_eq!(c.apps[1].roots[0].path, Path::new("/home/me/.c\\x"));
    }

    #[test]
    fn warns_about_interpreters() {
        assert!(exe_warning(Path::new("/usr/bin/python3.12"), 1).contains("runs other programs"));
        assert!(exe_warning(Path::new("/usr/bin/bash"), 1).contains("runs other programs"));
        assert_eq!(exe_warning(Path::new("/nonexistent/rg"), 1), "");
    }

    #[test]
    fn appends_and_undoes() {
        let dir = std::env::temp_dir().join(format!("explsm-claims-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let first = append(&dir, "me", "a\n").unwrap();
        let second = append(&dir, "me", "b\n").unwrap();
        let text = fs::read_to_string(first.path()).unwrap();
        assert!(text.ends_with("a\nb\n"), "{text}");
        second.undo().unwrap();
        assert!(fs::read_to_string(first.path()).unwrap().ends_with("a\n"));
        first.undo().unwrap();
        assert!(!dir.join("me.explsm").exists());

        let declined = dir.join("declined");
        add_declined(&declined, "claude", Path::new("/h/.x")).unwrap();
        assert!(load_declined(&declined).contains(&("claude".into(), "/h/.x".into())));
        fs::remove_dir_all(&dir).unwrap();
    }
}
