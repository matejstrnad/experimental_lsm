//! Open prompts: which denials and new folders are put to the user, and
//! which are not because they are already asked, were just denied, or were
//! declined before.
//!
//! Denials of one subject on one owner's data, for one user, are one prompt:
//! perms of later denials are added to it while it is open. After "Deny" the
//! same question is not asked again for [`QUIET`]. A prompt nobody answered
//! for [`STALE`] is replaced by the next denial. Pure bookkeeping; the
//! daemon does the sending and granting (`desk.rs`).

use std::{
    collections::{HashMap, HashSet},
    os::fd::OwnedFd,
    path::PathBuf,
    time::{Duration, Instant},
};

use explsm_common::{AppId, FileKey};

/// How long "Deny" silences the same question.
pub const QUIET: Duration = Duration::from_secs(10 * 60);
/// How long an unanswered prompt keeps later denials from asking again.
pub const STALE: Duration = Duration::from_secs(2 * 60);

/// Who is asking for access.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Subject {
    App(AppId),
    /// Unconfined processes of an exe.
    Exe(FileKey),
}

#[derive(Debug)]
pub enum Kind {
    Access {
        subject: Subject,
        owner: AppId,
        perms: u32,
        /// The process that was denied first, and a pidfd pinning it, for
        /// "allow this process".
        pid: u32,
        pidfd: Option<OwnedFd>,
        /// Path of the exe, if it could be read and is still the exe the
        /// kernel saw.
        exe: Option<PathBuf>,
    },
    Claim {
        app: AppId,
        path: PathBuf,
    },
}

#[derive(Debug)]
pub struct Prompt {
    pub id: u64,
    pub uid: u32,
    pub kind: Kind,
    pub asked: Instant,
    /// The answers the user was offered; only these are taken.
    pub choices: Vec<String>,
}

/// What [`Prompts::access`] decided.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Ask: a new prompt with this id. The stale prompt it replaces, if any,
    /// should be cancelled.
    Ask { id: u64, replaces: Option<u64> },
    /// Added to an open prompt.
    Merged,
    /// Denied recently, or declined: don't ask.
    Quiet,
}

type AccessKey = (u32, Subject, AppId);

#[derive(Default)]
pub struct Prompts {
    next_id: u64,
    open: HashMap<u64, Prompt>,
    quiet: HashMap<AccessKey, Instant>,
    /// Declined claims: (app name, path).
    declined: HashSet<(String, PathBuf)>,
}

impl Prompts {
    pub fn new(declined: HashSet<(String, PathBuf)>) -> Self {
        Self {
            declined,
            ..Self::default()
        }
    }

    fn add(&mut self, uid: u32, kind: Kind, now: Instant) -> u64 {
        self.next_id += 1;
        let id = self.next_id;
        self.open.insert(
            id,
            Prompt {
                id,
                uid,
                kind,
                asked: now,
                choices: Vec::new(),
            },
        );
        id
    }

    fn open_access(&mut self, key: AccessKey) -> Option<&mut Prompt> {
        self.open.values_mut().find(|p| match p.kind {
            Kind::Access { subject, owner, .. } => (p.uid, subject, owner) == key,
            Kind::Claim { .. } => false,
        })
    }

    /// A denial of `perms` on data of `owner`.
    #[allow(clippy::too_many_arguments)]
    pub fn access(
        &mut self,
        now: Instant,
        uid: u32,
        subject: Subject,
        owner: AppId,
        perms: u32,
        pid: u32,
        pidfd: Option<OwnedFd>,
        exe: Option<PathBuf>,
    ) -> Outcome {
        let key = (uid, subject, owner);
        if self.quiet.get(&key).is_some_and(|until| *until > now) {
            return Outcome::Quiet;
        }
        self.quiet.remove(&key);
        let mut replaces = None;
        if let Some(p) = self.open_access(key) {
            if now.duration_since(p.asked) < STALE {
                if let Kind::Access { perms: open, .. } = &mut p.kind {
                    *open |= perms;
                }
                return Outcome::Merged;
            }
            replaces = Some(p.id);
        }
        if let Some(old) = replaces {
            self.open.remove(&old);
        }
        let kind = Kind::Access {
            subject,
            owner,
            perms,
            pid,
            pidfd,
            exe,
        };
        Outcome::Ask {
            id: self.add(uid, kind, now),
            replaces,
        }
    }

    /// App `app` (named `name`) created the folder `path`. `known` says
    /// whether the policy already names it.
    pub fn claim(
        &mut self,
        now: Instant,
        uid: u32,
        app: AppId,
        name: &str,
        path: PathBuf,
        known: bool,
    ) -> Option<u64> {
        if known || self.declined.contains(&(name.to_string(), path.clone())) {
            return None;
        }
        let asked = self.open.values().any(|p| {
            matches!(&p.kind, Kind::Claim { app: a, path: q } if *a == app && *q == path)
        });
        if asked {
            return None;
        }
        Some(self.add(uid, Kind::Claim { app, path }, now))
    }

    pub fn get(&self, id: u64) -> Option<&Prompt> {
        self.open.get(&id)
    }

    pub fn get_mut(&mut self, id: u64) -> Option<&mut Prompt> {
        self.open.get_mut(&id)
    }

    /// Close a prompt to act on its answer.
    pub fn take(&mut self, id: u64) -> Option<Prompt> {
        self.open.remove(&id)
    }

    /// The user said "Deny" to `prompt`.
    pub fn denied(&mut self, prompt: &Prompt, now: Instant) {
        if let Kind::Access { subject, owner, .. } = prompt.kind {
            self.quiet.insert((prompt.uid, subject, owner), now + QUIET);
        }
    }

    pub fn declined(&mut self, name: &str, path: PathBuf) {
        self.declined.insert((name.to_string(), path));
    }

    /// Close every prompt of `uid` (its agent went away). Returns their ids.
    pub fn drop_uid(&mut self, uid: u32) -> Vec<u64> {
        let ids: Vec<u64> = self
            .open
            .values()
            .filter(|p| p.uid == uid)
            .map(|p| p.id)
            .collect();
        for id in &ids {
            self.open.remove(id);
        }
        ids
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const READ: u32 = 1;
    const WRITE: u32 = 2;

    fn exe(ino: u64) -> Subject {
        Subject::Exe(FileKey { dev: 1, _pad: 0, ino })
    }

    #[test]
    fn merges_and_quiets() {
        let mut p = Prompts::default();
        let t = Instant::now();
        let ask = p.access(t, 1000, exe(5), 1, READ, 42, None, None);
        assert_eq!(ask, Outcome::Ask { id: 1, replaces: None });
        // Same subject and owner: merged, perms added.
        assert_eq!(p.access(t, 1000, exe(5), 1, WRITE, 43, None, None), Outcome::Merged);
        let Kind::Access { perms, pid, .. } = p.get(1).unwrap().kind else {
            panic!()
        };
        assert_eq!((perms, pid), (READ | WRITE, 42));
        // Another user, owner or exe: separate prompts.
        assert!(matches!(p.access(t, 1001, exe(5), 1, READ, 1, None, None), Outcome::Ask { .. }));
        assert!(matches!(p.access(t, 1000, exe(5), 2, READ, 1, None, None), Outcome::Ask { .. }));
        assert!(matches!(p.access(t, 1000, exe(6), 1, READ, 1, None, None), Outcome::Ask { .. }));

        let prompt = p.take(1).unwrap();
        p.denied(&prompt, t);
        assert_eq!(p.access(t + Duration::from_secs(60), 1000, exe(5), 1, READ, 42, None, None), Outcome::Quiet);
        let later = t + QUIET + Duration::from_secs(1);
        assert!(matches!(p.access(later, 1000, exe(5), 1, READ, 42, None, None), Outcome::Ask { .. }));
    }

    #[test]
    fn replaces_stale_prompts() {
        let mut p = Prompts::default();
        let t = Instant::now();
        p.access(t, 1000, Subject::App(3), 1, READ, 42, None, None);
        let later = t + STALE + Duration::from_secs(1);
        assert_eq!(
            p.access(later, 1000, Subject::App(3), 1, READ, 44, None, None),
            Outcome::Ask { id: 2, replaces: Some(1) }
        );
        assert!(p.get(1).is_none());
    }

    #[test]
    fn claims() {
        let mut declined = HashSet::new();
        declined.insert(("claude".to_string(), PathBuf::from("/h/.no")));
        let mut p = Prompts::new(declined);
        let t = Instant::now();
        assert_eq!(p.claim(t, 1000, 1, "claude", "/h/.claude".into(), false), Some(1));
        assert_eq!(p.claim(t, 1000, 1, "claude", "/h/.claude".into(), false), None);
        assert_eq!(p.claim(t, 1000, 1, "claude", "/h/.known".into(), true), None);
        assert_eq!(p.claim(t, 1000, 1, "claude", "/h/.no".into(), false), None);
        p.declined("claude", "/h/.other".into());
        assert_eq!(p.claim(t, 1000, 1, "claude", "/h/.other".into(), false), None);
        assert_eq!(p.drop_uid(1000), [1]);
        assert!(p.get(1).is_none());
    }
}
