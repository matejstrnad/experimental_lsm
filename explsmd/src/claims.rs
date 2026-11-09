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
use explsm_ipc::{SavedClaim, SavedGrant};
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
    let file = exe
        .file_name()
        .map(|n| n.to_string_lossy())
        .unwrap_or_default();
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
    let name = exe
        .file_name()
        .map(|n| n.to_string_lossy())
        .unwrap_or_default();
    let stem = name.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    if INTERPRETERS.contains(&stem) {
        return format!("{name} runs other programs and scripts: allowing it allows all of them");
    }
    let writable =
        |p: &Path| fs::metadata(p).is_ok_and(|m| m.uid() == uid || m.mode() & 0o002 != 0);
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
        .filter(|n| {
            n.chars()
                .all(|c| c.is_ascii_alphanumeric() || "_-.".contains(c))
        })
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
    let path = file_of(dir, user);
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

/// The path of `user`'s claims file.
pub fn file_of(dir: &Path, user: &str) -> PathBuf {
    dir.join(format!("{user}.{EXTENSION}"))
}

/// A line without its comment and surrounding blanks. Only the forms
/// explsmd writes are understood; a `#` in a string ends nothing here
/// because they are only looked at in `grant` and `app` lines, which
/// explsmd writes without one.
fn code(line: &str) -> &str {
    line.split_once('#').map_or(line, |(c, _)| c).trim()
}

/// `grant SUBJECT PERMS to OWNER`, with one subject and one owner.
fn grant_line(line: &str) -> Option<(&str, Vec<String>, &str)> {
    let rest = code(line).strip_prefix("grant ")?;
    let (subject, rest) = rest.trim_start().split_once(char::is_whitespace)?;
    let (perms, owner) = rest.rsplit_once(" to ")?;
    let owner = owner.trim();
    if subject.contains(',') || owner.contains([',', ' ']) || owner.is_empty() {
        return None;
    }
    let perms = perms
        .split(',')
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .collect();
    Some((subject, perms, owner))
}

/// `app NAME { exe "PATH" }` on one line, as [`exe_grant`] writes it.
fn exe_app_line(line: &str) -> Option<(&str, String)> {
    let rest = code(line).strip_prefix("app ")?;
    let (name, rest) = rest.trim_start().split_once(char::is_whitespace)?;
    let inner = rest
        .trim()
        .strip_prefix('{')?
        .strip_suffix('}')?
        .trim()
        .strip_prefix("exe ")?
        .trim();
    let quoted = inner.strip_prefix('"')?.strip_suffix('"')?;
    let path = quoted.replace("\\\"", "\"").replace("\\\\", "\\");
    Some((name, path))
}

/// `claim APP "PATH"`, as [`claim`] writes it.
fn claim_line(line: &str) -> Option<SavedClaim> {
    let rest = code(line).strip_prefix("claim ")?;
    let (app, rest) = rest.trim_start().split_once(char::is_whitespace)?;
    let path = rest.trim().strip_prefix('"')?.strip_suffix('"')?;
    Some(SavedClaim {
        app: app.into(),
        path: path.replace("\\\"", "\"").replace("\\\\", "\\"),
    })
}

/// The grants and claims of a claims file.
pub fn saved(text: &str) -> (Vec<SavedGrant>, Vec<SavedClaim>) {
    let exes: Vec<(&str, String)> = text.lines().filter_map(exe_app_line).collect();
    let grants = text
        .lines()
        .filter_map(grant_line)
        .map(|(subject, perms, owner)| SavedGrant {
            subject: subject.into(),
            exe: exes
                .iter()
                .find(|(n, _)| *n == subject)
                .map(|(_, p)| p.clone())
                .unwrap_or_default(),
            owner: owner.into(),
            perms,
        })
        .collect();
    (grants, text.lines().filter_map(claim_line).collect())
}

/// `text` without the grants of `subject` to `owner`; without the app
/// line that made `subject` too if nothing else in it names the app, and
/// without the comments left heading nothing. `None` if there is no such
/// grant.
pub fn remove_grant(text: &str, subject: &str, owner: &str) -> Option<String> {
    let lines: Vec<&str> = text.lines().collect();
    let is_target = |l: &str| grant_line(l).is_some_and(|(s, _, o)| s == subject && o == owner);
    if !lines.iter().any(|l| is_target(l)) {
        return None;
    }
    let mut keep: Vec<&str> = lines.iter().copied().filter(|l| !is_target(l)).collect();
    // The app made for an exe goes when no grant of it is left.
    let still_named = keep.iter().any(|l| {
        grant_line(l).is_some_and(|(s, _, o)| s == subject || o == subject)
            || claim_line(l).is_some_and(|c| c.app == subject)
    });
    if !still_named {
        keep.retain(|l| exe_app_line(l).is_none_or(|(n, _)| n != subject));
    }
    // A prompt comment followed by nothing but blanks or another comment
    // headed what was removed.
    let mut out: Vec<&str> = Vec::new();
    for (i, l) in keep.iter().enumerate() {
        let prompt_comment = l.trim_start().starts_with("# allowed by ")
            && l.trim_end().ends_with("through a prompt");
        if prompt_comment {
            let next = keep[i + 1..].iter().find(|n| !n.trim().is_empty());
            if next.is_none_or(|n| n.trim_start().starts_with('#')) {
                // Drop it, and the blank line before it.
                if out.last().is_some_and(|p| p.trim().is_empty()) {
                    out.pop();
                }
                continue;
            }
        }
        out.push(l);
    }
    let mut s = out.join("\n");
    if text.ends_with('\n') && !s.is_empty() {
        s.push('\n');
    }
    Some(s)
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
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o644)
        .open(file)?;
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
            exe_grant(
                "me",
                "rg",
                Path::new("/usr/bin/r\"g"),
                perm::READ | perm::LIST,
                "ssh"
            ),
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
    fn reads_and_removes_saved_grants() {
        let text = format!(
            "# Written by explsmd for answers to prompts. Edit freely.\n{}{}{}{}",
            exe_grant(
                "me",
                "rg",
                Path::new("/usr/bin/r\"g"),
                perm::READ | perm::LIST,
                "ssh"
            ),
            app_grant("me", "backup", perm::ALL, "ssh"),
            claim("me", "claude", Path::new("/home/me/.claude")),
            app_grant("me", "backup", perm::READ, "claude"),
        );
        let (grants, claims) = saved(&text);
        assert_eq!(grants.len(), 3);
        assert_eq!(grants[0].subject, "rg");
        assert_eq!(grants[0].exe, "/usr/bin/r\"g");
        assert_eq!(grants[0].perms, ["read", "list"]);
        assert_eq!(grants[1].perms, ["all"]);
        assert_eq!(grants[1].exe, "");
        assert_eq!(claims[0].path, "/home/me/.claude");

        // The app made for rg goes with its only grant, and the comment.
        let t = remove_grant(&text, "rg", "ssh").unwrap();
        assert!(!t.contains("rg"), "{t}");
        assert_eq!(saved(&t).0.len(), 2);
        // backup's other grant stays.
        let t = remove_grant(&t, "backup", "ssh").unwrap();
        assert_eq!(saved(&t).0.len(), 1);
        assert!(t.contains("grant backup read to claude"));
        assert!(t.contains("claim claude"));
        assert_eq!(t.matches("# allowed by").count(), 1, "{t}");
        assert!(remove_grant(&t, "backup", "ssh").is_none());

        use explsm_policy::{IdTable, Sources, check};
        let full = format!(
            "app ssh {{ exe \"/usr/bin/ssh\" }}\napp claude {{ exe \"/c\" }}\napp backup {{ exe \"/b\" }}\n{t}"
        );
        check(&Sources::single("t", &full), &IdTable::default()).unwrap();
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
