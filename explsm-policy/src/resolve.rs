//! Turning the paths of a compiled policy into inodes, and finding the
//! directories to watch so the daemon can resolve them again when they
//! change (package updates, folders created later).

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fs::{self, Metadata},
    io,
    os::unix::fs::MetadataExt as _,
    path::{Path, PathBuf},
};

use explsm_common::{APP_UNCONFINED, AppId, FileKey, OWNER_LAUNCH, term};

use sha2::{Digest as _, Sha256};

use crate::{Compiled, PathPat, compile::Pin, env_paths, parse_sha256, users::User};

/// The SHA-256 of a file's contents.
pub fn sha256_file(path: &Path) -> io::Result<[u8; 32]> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    io::copy(&mut file, &mut hasher)?;
    Ok(hasher.finalize().into())
}

/// Whether the file at `path` has one of the hashes `pin` allows. A hash
/// list that can't be read allows nothing.
fn pinned_ok(pin: &Pin, path: &Path) -> bool {
    let Ok(hash) = sha256_file(path) else {
        return false;
    };
    if pin.sha256.contains(&hash) {
        return true;
    }
    pin.lists.iter().any(|list| {
        fs::read_to_string(list).is_ok_and(|text| {
            text.lines()
                .filter_map(|l| l.split_whitespace().next())
                .any(|h| parse_sha256(h) == Some(hash))
        })
    })
}

/// `(s_dev, i_ino)` as the kernel sees it. Userspace `st_dev` uses a
/// different encoding than the kernel's internal `MKDEV` (major << 20).
pub fn key_of(md: &Metadata) -> FileKey {
    let dev = md.dev();
    let (major, minor) = (libc::major(dev), libc::minor(dev));
    FileKey {
        dev: (major << 20) | minor,
        _pad: 0,
        ino: md.ino(),
    }
}

/// [`key_of`] a path, following symlinks.
pub fn file_key(path: &Path) -> io::Result<FileKey> {
    Ok(key_of(&fs::metadata(path)?))
}

pub fn show_key(key: &FileKey) -> String {
    format!("{}:{}/{}", key.dev >> 20, key.dev & 0xfffff, key.ino)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Exe,
    Root,
    /// A terminal entry exe (`terminal …`), shell (`shell …`) or desktop
    /// shell (`desktop …`); its `app` is unconfined.
    Terminal,
}

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Exe => "exe",
            Self::Root => "root",
            Self::Terminal => "terminal",
        }
    }
}

/// A path of the policy that exists.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Found {
    pub path: PathBuf,
    pub key: FileKey,
    pub app: AppId,
    /// [`PathPat::text`] it came from.
    pub pattern: String,
    /// Of a [`Kind::Terminal`]: the [`term`] bits (terminal, shell,
    /// desktop), the value of the `TERMINALS` map. 0 otherwise.
    pub term: u32,
}

/// A path (or glob) of the policy that matches nothing yet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Missing {
    pub path: PathBuf,
    pub app: AppId,
    pub kind: Kind,
}

#[derive(Debug, Default)]
pub struct Resolved {
    pub exes: Vec<Found>,
    pub roots: Vec<Found>,
    pub terminals: Vec<Found>,
    pub missing: Vec<Missing>,
    /// Files an exe path of a pinned exe matches that have none of its
    /// hashes: they don't get the app's identity.
    pub rejected: Vec<Missing>,
    /// Directory → glob patterns of entry names in it that matter. A change
    /// to a matching entry means the policy has to be resolved again.
    pub watches: BTreeMap<PathBuf, BTreeSet<String>>,
}

impl Resolved {
    pub fn exe_map(&self) -> HashMap<FileKey, AppId> {
        self.exes.iter().map(|f| (f.key, f.app)).collect()
    }
}

/// Resolve every exe, root and terminal of `policy` for `users`. Missing
/// paths are not errors; one inode claimed by two apps is, and so is an app
/// exe that is also a terminal, and an `env` path a user could replace.
pub fn resolve(policy: &Compiled, users: &[User]) -> Result<Resolved, Vec<String>> {
    let mut out = Resolved::default();
    let mut errors = Vec::new();
    for app in &policy.apps {
        for var in &app.env {
            for path in env_paths(var) {
                if let Some(bad) = replaceable(Path::new(path)) {
                    errors.push(format!(
                        "`env \"{var}\"` of {}: a user could replace {}, and the loader \
                         would run what they put there as the app",
                        app.name,
                        bad.display()
                    ));
                }
            }
        }
        for pin in app.pins.values() {
            for list in &pin.lists {
                if let Some(bad) = replaceable(list) {
                    errors.push(format!(
                        "hash list {} of {}: a user could replace {}, and with it what \
                         gets the identity",
                        list.display(),
                        app.name,
                        bad.display()
                    ));
                }
            }
        }
        for (kind, pats) in [(Kind::Exe, &app.exes), (Kind::Root, &app.roots)] {
            for pat in pats {
                for path in pat.expand(users) {
                    resolve_one(policy, (app.id, 0), kind, pat, &path, &mut out, &mut errors);
                }
            }
        }
    }
    for pat in &policy.launch_paths() {
        for path in pat.expand(users) {
            resolve_one(
                policy,
                (OWNER_LAUNCH, 0),
                Kind::Root,
                pat,
                &path,
                &mut out,
                &mut errors,
            );
        }
    }
    for (bit, pats) in [
        (term::TERMINAL, &policy.terminals),
        (term::SHELL, &policy.shells),
        (term::DESKTOP, &policy.desktops),
    ] {
        for pat in pats {
            for path in pat.expand(users) {
                resolve_one(
                    policy,
                    (APP_UNCONFINED, bit),
                    Kind::Terminal,
                    pat,
                    &path,
                    &mut out,
                    &mut errors,
                );
            }
        }
    }
    for t in &out.terminals {
        if let Some(exe) = out.exes.iter().find(|e| e.key == t.key) {
            errors.push(format!(
                "{} is both a terminal, shell or desktop exe and an exe of {}",
                t.path.display(),
                policy.name(exe.app)
            ));
        }
    }
    if errors.is_empty() {
        Ok(out)
    } else {
        Err(errors)
    }
}

/// The first of `path` (or what it links to) and the directories above it
/// that a user other than root could change, or create where it is missing.
fn replaceable(path: &Path) -> Option<PathBuf> {
    let mut chains = vec![path.to_path_buf()];
    if let Ok(real) = fs::canonicalize(path)
        && real != path
    {
        chains.push(real);
    }
    for chain in chains {
        // Of the entry below p: in a sticky directory (`/tmp`, `/var/tmp`)
        // only its owner and the directory's may rename or remove it.
        let mut below_is_roots = false;
        for p in chain.ancestors() {
            let Ok(md) = fs::symlink_metadata(p) else {
                below_is_roots = false;
                continue;
            };
            let sticky = md.is_dir() && md.mode() & 0o1000 != 0;
            let mode_writable = !md.file_type().is_symlink()
                && md.mode() & 0o022 != 0
                && !(sticky && below_is_roots);
            if md.uid() != 0 || mode_writable {
                return Some(p.to_path_buf());
            }
            below_is_roots = true;
        }
    }
    None
}

fn resolve_one(
    policy: &Compiled,
    (app, term): (AppId, u32),
    kind: Kind,
    pat: &PathPat,
    path: &Path,
    out: &mut Resolved,
    errors: &mut Vec<String>,
) {
    let (Some(parent), Some(leaf)) = (path.parent(), path.file_name()) else {
        return;
    };
    let leaf = leaf.to_string_lossy();
    let leaf_pattern = if pat.glob {
        leaf.to_string()
    } else {
        glob::Pattern::escape(&leaf)
    };
    watch(out, parent, leaf_pattern);

    let candidates: Vec<PathBuf> = if pat.glob {
        let pattern = glob::Pattern::new(&leaf).expect("checked when compiling");
        let mut found: Vec<_> = fs::read_dir(parent)
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| pattern.matches(&e.file_name().to_string_lossy()))
            .map(|e| e.path())
            .collect();
        found.sort();
        found
    } else {
        vec![path.to_path_buf()]
    };

    let mut any = false;
    for candidate in candidates {
        let Ok(md) = fs::metadata(&candidate) else {
            continue;
        };
        if kind != Kind::Root && !md.is_file() {
            continue;
        }
        // A symlink's target can change without the link changing.
        if fs::symlink_metadata(&candidate).is_ok_and(|m| m.file_type().is_symlink())
            && let Ok(target) = fs::canonicalize(&candidate)
            && let (Some(dir), Some(name)) = (target.parent(), target.file_name())
        {
            watch(out, dir, glob::Pattern::escape(&name.to_string_lossy()));
        }
        if kind == Kind::Exe
            && let Some(pin) = policy.app(app).and_then(|a| a.pins.get(&pat.text))
            && !pinned_ok(pin, &candidate)
        {
            out.rejected.push(Missing {
                path: candidate,
                app,
                kind,
            });
            any = true;
            continue;
        }
        any = true;
        let key = key_of(&md);
        let list = match kind {
            Kind::Exe => &mut out.exes,
            Kind::Root => &mut out.roots,
            Kind::Terminal => &mut out.terminals,
        };
        if let Some(other) = list.iter_mut().find(|f| f.key == key) {
            other.term |= term;
            if other.app != app {
                errors.push(format!(
                    "{} is {} {} of both {} and {}",
                    candidate.display(),
                    if kind == Kind::Root { "a" } else { "an" },
                    kind.name(),
                    policy.name(other.app),
                    policy.name(app)
                ));
            }
            continue;
        }
        list.push(Found {
            path: candidate,
            key,
            app,
            pattern: pat.text.clone(),
            term,
        });
    }
    if !any {
        out.missing.push(Missing {
            path: path.to_path_buf(),
            app,
            kind,
        });
    }
}

/// Watch `dir` for entries matching `pattern`. If `dir` does not exist,
/// watch its closest existing ancestor for the next component instead.
fn watch(out: &mut Resolved, dir: &Path, pattern: String) {
    let mut dir = dir;
    let mut pattern = pattern;
    while !dir.is_dir() {
        let (Some(parent), Some(name)) = (dir.parent(), dir.file_name()) else {
            return;
        };
        pattern = glob::Pattern::escape(&name.to_string_lossy());
        dir = parent;
    }
    out.watches
        .entry(dir.to_path_buf())
        .or_default()
        .insert(pattern);
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    use super::*;
    use crate::{IdTable, Sources, check};

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("explsm-resolve-{name}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn policy(text: &str) -> Compiled {
        check(&Sources::single("t", text), &IdTable::default()).unwrap()
    }

    fn user(home: &Path) -> User {
        User {
            name: "u".into(),
            uid: 1000,
            home: home.into(),
        }
    }

    #[test]
    fn env_paths_a_user_could_replace() {
        let t = TempDir::new("env");
        let d = &t.0;
        // Writable by others (and not sticky): its entries are replaceable.
        fs::set_permissions(d, fs::Permissions::from_mode(0o777)).unwrap();
        fs::write(d.join("lib.so"), "").unwrap();
        let p = policy(&format!(
            r#"app a {{ exe "/a" env "LD_PRELOAD=/usr", "LD_LIBRARY_PATH=/usr/lib:{d}/lib.so" }}"#,
            d = d.display()
        ));
        let errors = resolve(&p, &[]).unwrap_err();
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(errors[0].contains("LD_LIBRARY_PATH"), "{errors:?}");
        let p = policy(r#"app a { exe "/a" env "LD_PRELOAD=/usr/bin/env" }"#);
        assert!(resolve(&p, &[]).is_ok());
    }

    #[test]
    fn root_entries_in_sticky_directories() {
        let t = TempDir::new("sticky");
        let d = &t.0;
        fs::create_dir(d.join("sticky")).unwrap();
        fs::set_permissions(d.join("sticky"), fs::Permissions::from_mode(0o1777)).unwrap();
        fs::create_dir(d.join("sticky/mine")).unwrap();
        fs::set_permissions(d.join("sticky/mine"), fs::Permissions::from_mode(0o755)).unwrap();
        fs::create_dir(d.join("open")).unwrap();
        fs::set_permissions(d.join("open"), fs::Permissions::from_mode(0o777)).unwrap();
        // The temp dir itself is under /tmp: start below it.
        let below = |p: &Path| replaceable(p).filter(|bad| bad.starts_with(d));
        if fs::metadata(d).unwrap().uid() == 0 {
            assert_eq!(below(&d.join("sticky/mine")), None);
            assert_eq!(below(&d.join("open/x")), Some(d.join("open")));
        }
    }

    #[test]
    fn pinned_exes() {
        let t = TempDir::new("pins");
        let d = &t.0;
        fs::set_permissions(d, fs::Permissions::from_mode(0o777)).unwrap();
        fs::write(d.join("v1"), "good").unwrap();
        fs::write(d.join("v2"), "evil").unwrap();
        let good = sha256_file(&d.join("v1")).unwrap();
        let hex: String = good.iter().map(|b| format!("{b:02x}")).collect();
        let p = policy(&format!(
            r#"app a {{ exe "{d}/v*" sha256 "{hex}" }}"#,
            d = d.display()
        ));
        let r = resolve(&p, &[]).unwrap();
        assert_eq!(r.exes.len(), 1);
        assert_eq!(r.exes[0].path, d.join("v1"));
        assert_eq!(r.rejected.len(), 1);
        assert_eq!(r.rejected[0].path, d.join("v2"));
        assert!(r.missing.is_empty());
        // A list a user could replace.
        fs::write(d.join("list"), format!("{hex}  v1\n")).unwrap();
        let p = policy(&format!(
            r#"app a {{ exe "{d}/v*" hashes "{d}/list" }}"#,
            d = d.display()
        ));
        let errors = resolve(&p, &[]).unwrap_err();
        assert!(errors[0].contains("could replace"), "{errors:?}");
    }

    #[test]
    fn globs_homes_and_missing_paths() {
        let t = TempDir::new("globs");
        let d = &t.0;
        let home = d.join("home");
        fs::create_dir_all(home.join(".a")).unwrap();
        fs::create_dir_all(d.join("versions")).unwrap();
        for v in ["1.0", "2.0", "notes.txt"] {
            fs::write(d.join("versions").join(v), "").unwrap();
        }
        fs::create_dir(d.join("versions/3.0")).unwrap(); // not a file
        symlink(d.join("versions/2.0"), d.join("current")).unwrap();
        let p = policy(&format!(
            r#"launch_files off
               app a {{
                exe "{d}/versions/[0-9]*", "{d}/current", "{d}/none"
                owns "~/.a", "~/.b/deep"
            }}"#,
            d = d.display()
        ));
        let r = resolve(&p, &[user(&home)]).unwrap();
        let exes: Vec<_> = r.exes.iter().map(|f| f.path.clone()).collect();
        // `current` points at 2.0, which is already there.
        assert_eq!(exes, [d.join("versions/1.0"), d.join("versions/2.0")]);
        assert_eq!(r.roots.len(), 1);
        assert_eq!(r.roots[0].path, home.join(".a"));
        assert_eq!(r.roots[0].pattern, "~/.a");
        let missing: Vec<_> = r.missing.iter().map(|m| (m.path.clone(), m.kind)).collect();
        assert_eq!(
            missing,
            [
                (d.join("none"), Kind::Exe),
                (home.join(".b/deep"), Kind::Root)
            ]
        );
        let set = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<BTreeSet<_>>();
        assert_eq!(r.watches[&d.join("versions")], set(&["2.0", "[0-9]*"]));
        assert_eq!(r.watches[d], set(&["current", "none"]));
        // ~/.b does not exist: watch home for it.
        assert_eq!(r.watches[&home], set(&[".a", ".b"]));
    }

    #[test]
    fn conflicts() {
        let t = TempDir::new("conflicts");
        let d = t.0.display();
        fs::write(t.0.join("x"), "").unwrap();
        let p = policy(&format!(
            r#"app a {{ exe "{d}/x" owns "{d}" }}
               app b {{ exe "{d}/x" owns "{d}/" }}"#
        ));
        assert_eq!(
            resolve(&p, &[]).unwrap_err(),
            [
                format!("{d}/x is an exe of both a and b"),
                format!("{d} is a root of both a and b"),
            ]
        );
        let p = policy(&format!("terminal \"{d}/x\"\napp a {{ exe \"{d}/x\" }}"));
        assert_eq!(
            resolve(&p, &[]).unwrap_err(),
            [format!(
                "{d}/x is both a terminal, shell or desktop exe and an exe of a"
            )]
        );
        let p = policy(&format!("terminal \"{d}/x\""));
        assert_eq!(resolve(&p, &[]).unwrap().terminals[0].path, t.0.join("x"));
    }
}
