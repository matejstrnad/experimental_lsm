//! Watching the directories that hold the policy's paths, so they are
//! resolved again when a package update replaces an exe or a protected folder
//! is created later.
//!
//! Each watched directory comes with glob patterns of the entry names that
//! matter, so the many other changes in a home directory are ignored.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    ffi::OsString,
    io,
    path::{Path, PathBuf},
};

use futures_util::StreamExt as _;
use inotify::{EventMask, EventStream, Inotify, WatchDescriptor, WatchMask};

/// Why a directory is watched.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Purpose {
    /// Exes, roots, `/etc/passwd`: resolve the policy again.
    Resolve,
    /// The policy directory: only tell the admin to reload.
    Policy,
}

/// What a batch of inotify events asks for.
#[derive(Default, Debug)]
pub struct Changes {
    pub resolve: bool,
    pub policy: Vec<OsString>,
}

/// Directory → (name pattern, purpose).
pub type Wanted = BTreeMap<PathBuf, BTreeSet<(String, Purpose)>>;

struct Dir {
    path: PathBuf,
    patterns: Vec<(glob::Pattern, Purpose)>,
}

pub struct Watcher {
    stream: EventStream<Vec<u8>>,
    by_path: HashMap<PathBuf, WatchDescriptor>,
    dirs: HashMap<WatchDescriptor, Dir>,
}

const RESOLVE_MASK: WatchMask = WatchMask::CREATE
    .union(WatchMask::DELETE)
    .union(WatchMask::MOVED_FROM)
    .union(WatchMask::MOVED_TO)
    .union(WatchMask::DELETE_SELF)
    .union(WatchMask::MOVE_SELF)
    .union(WatchMask::ONLYDIR);

impl Watcher {
    pub fn new() -> io::Result<Self> {
        Ok(Self {
            stream: Inotify::init()?.into_event_stream(vec![0; 64 * 1024])?,
            by_path: HashMap::new(),
            dirs: HashMap::new(),
        })
    }

    /// Watch exactly the directories of `wanted`. Returns warnings for
    /// directories that could not be watched.
    ///
    /// Two paths can be one directory (`/bin` and `/usr/bin` on merged-usr
    /// systems), and inotify then returns the same watch for both, so the
    /// patterns are kept per watch. Masks only grow (`MASK_ADD`): adding one
    /// path must not take away events another path of the same directory
    /// asked for.
    pub fn sync(&mut self, wanted: &Wanted) -> Vec<String> {
        let mut warnings = Vec::new();
        let mut by_path = HashMap::new();
        let mut dirs: HashMap<WatchDescriptor, Dir> = HashMap::new();
        for (path, patterns) in wanted {
            let mut mask = RESOLVE_MASK | WatchMask::MASK_ADD;
            if patterns.iter().any(|(_, p)| *p == Purpose::Policy) {
                mask |= WatchMask::CLOSE_WRITE;
            }
            let wd = match self.stream.watches().add(path, mask) {
                Ok(wd) => wd,
                Err(e) => {
                    warnings.push(format!("watching {}: {e}", path.display()));
                    continue;
                }
            };
            by_path.insert(path.clone(), wd.clone());
            dirs.entry(wd)
                .or_insert_with(|| Dir {
                    path: path.clone(),
                    patterns: Vec::new(),
                })
                .patterns
                .extend(
                    patterns
                        .iter()
                        .filter_map(|(p, purpose)| Some((glob::Pattern::new(p).ok()?, *purpose))),
                );
        }
        for (path, wd) in self.by_path.drain() {
            if !by_path.contains_key(&path) && !dirs.contains_key(&wd) {
                // Fails if the directory is gone, which removed the watch.
                let _ = self.stream.watches().remove(wd);
            }
        }
        self.by_path = by_path;
        self.dirs = dirs;
        warnings
    }

    /// Wait for events and return what they ask for. Events nobody cares
    /// about are skipped without returning.
    pub async fn next(&mut self) -> io::Result<Changes> {
        loop {
            let Some(event) = self.stream.next().await else {
                return Err(io::Error::other("inotify stream ended"));
            };
            let event = event?;
            let mut changes = Changes::default();
            if event.mask.contains(EventMask::Q_OVERFLOW) {
                changes.resolve = true;
                return Ok(changes);
            }
            let Some(dir) = self.dirs.get(&event.wd) else {
                continue;
            };
            let gone = event
                .mask
                .intersects(EventMask::DELETE_SELF | EventMask::MOVE_SELF | EventMask::IGNORED);
            if gone {
                // The directory itself went away: its ancestors are watched
                // instead after the next resolution.
                changes.resolve = true;
                return Ok(changes);
            }
            let Some(name) = &event.name else { continue };
            let name_str = name.to_string_lossy();
            for (pattern, purpose) in &dir.patterns {
                if pattern.matches(&name_str) {
                    match purpose {
                        Purpose::Resolve => changes.resolve = true,
                        Purpose::Policy => changes.policy.push(dir.path.join(name).into()),
                    }
                }
            }
            if changes.resolve || !changes.policy.is_empty() {
                return Ok(changes);
            }
        }
    }
}

/// The directories to watch for the policy (a directory or one file) and
/// `/etc/passwd`, on
/// top of those of the resolved paths.
pub fn wanted(resolved: &BTreeMap<PathBuf, BTreeSet<String>>, policy_dir: &Path) -> Wanted {
    let mut out = Wanted::new();
    for (dir, patterns) in resolved {
        out.entry(dir.clone())
            .or_default()
            .extend(patterns.iter().map(|p| (p.clone(), Purpose::Resolve)));
    }
    out.entry("/etc".into())
        .or_default()
        .insert(("passwd".into(), Purpose::Resolve));
    let (dir, pattern) = match (policy_dir.is_dir(), policy_dir.parent(), policy_dir.file_name()) {
        (false, Some(parent), Some(name)) => (
            parent.to_path_buf(),
            glob::Pattern::escape(&name.to_string_lossy()),
        ),
        _ => (
            policy_dir.to_path_buf(),
            format!("*.{}", explsm_policy::EXTENSION),
        ),
    };
    out.entry(dir).or_default().insert((pattern, Purpose::Policy));
    out
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::symlink, time::Duration};

    use super::*;

    async fn next(w: &mut Watcher) -> Option<Changes> {
        tokio::time::timeout(Duration::from_millis(500), w.next())
            .await
            .ok()
            .map(Result::unwrap)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn reports_only_matching_entries() {
        let dir = std::env::temp_dir().join(format!("explsm-watch-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("real")).unwrap();
        // Two paths for one directory, as /bin and /usr/bin.
        symlink(dir.join("real"), dir.join("alias")).unwrap();
        let mut wanted = Wanted::new();
        let set = |p: &str, purpose| BTreeSet::from([(p.to_string(), purpose)]);
        wanted.insert(dir.join("real"), set("app-*", Purpose::Resolve));
        wanted.insert(dir.join("alias"), set("*.explsm", Purpose::Policy));
        let mut w = Watcher::new().unwrap();
        assert!(w.sync(&wanted).is_empty());

        fs::write(dir.join("real/unrelated"), "").unwrap();
        assert!(next(&mut w).await.is_none());

        fs::write(dir.join("real/app-2"), "").unwrap();
        let c = next(&mut w).await.unwrap();
        assert!(c.resolve && c.policy.is_empty());
        while next(&mut w).await.is_some() {} // CLOSE_WRITE, wanted by the alias

        fs::write(dir.join("real/x.explsm"), "").unwrap();
        let c = next(&mut w).await.unwrap();
        assert!(!c.resolve && c.policy.len() == 1);
        while next(&mut w).await.is_some() {}

        // Dropping one of the two paths keeps the other's watch.
        wanted.remove(&dir.join("alias"));
        w.sync(&wanted);
        fs::write(dir.join("real/app-3"), "").unwrap();
        assert!(next(&mut w).await.unwrap().resolve);
        fs::remove_dir_all(&dir).unwrap();
    }
}
