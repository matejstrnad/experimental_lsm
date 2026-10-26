//! Grants given through prompts (`TEMP_GRANTS`): to one process until it
//! exits, or to an app (or the exe of unconfined processes) until the
//! user's agent goes away. None of them survive the daemon: nothing is
//! pinned.

use std::{collections::HashMap, os::fd::OwnedFd};

use anyhow::{Context as _, Result};
use aya::{Ebpf, maps::HashMap as BpfHashMap};
use explsm_common::{TempKey, perm, temp_kind};
use explsm_ipc::TempGrantStatus;
use explsm_policy::IdTable;
use tokio::{
    io::{Interest, unix::AsyncFd},
    sync::mpsc,
};

#[derive(Default)]
pub struct TempGrants {
    /// What is in the map, and how to show the subject.
    entries: HashMap<TempKey, (u32, String)>,
}

impl TempGrants {
    fn map(ebpf: &mut Ebpf) -> Result<BpfHashMap<&mut aya::maps::MapData, TempKey, u32>> {
        Ok(BpfHashMap::try_from(
            ebpf.map_mut("TEMP_GRANTS").context("TEMP_GRANTS missing")?,
        )?)
    }

    /// Add `perms` to what `key` has. `subject` is shown in the status.
    pub fn add(&mut self, ebpf: &mut Ebpf, key: TempKey, perms: u32, subject: String) -> Result<()> {
        let bits = self.entries.get(&key).map_or(0, |(b, _)| *b) | perms;
        Self::map(ebpf)?
            .insert(key, bits, 0)
            .context("updating TEMP_GRANTS (full?)")?;
        self.entries.insert(key, (bits, subject));
        Ok(())
    }

    fn remove_where(&mut self, ebpf: &mut Ebpf, gone: impl Fn(&TempKey) -> bool) -> Result<usize> {
        let keys: Vec<TempKey> = self.entries.keys().filter(|k| gone(k)).copied().collect();
        let mut map = Self::map(ebpf)?;
        for k in &keys {
            map.remove(k).context("removing from TEMP_GRANTS")?;
            self.entries.remove(k);
        }
        Ok(keys.len())
    }

    /// The process `tgid` exited.
    pub fn process_exited(&mut self, ebpf: &mut Ebpf, tgid: u32) -> Result<usize> {
        self.remove_where(ebpf, |k| k.kind == temp_kind::PROC && k.a == u64::from(tgid))
    }

    /// The session of `uid` ended.
    pub fn session_ended(&mut self, ebpf: &mut Ebpf, uid: u32) -> Result<usize> {
        self.remove_where(ebpf, |k| k.kind != temp_kind::PROC && k.uid == uid)
    }

    pub fn status(&self, ids: &IdTable) -> Vec<TempGrantStatus> {
        let mut out: Vec<_> = self
            .entries
            .iter()
            .map(|(k, (bits, subject))| TempGrantStatus {
                lifetime: if k.kind == temp_kind::PROC {
                    "process".into()
                } else {
                    "session".into()
                },
                subject: subject.clone(),
                owner: ids.name(k.owner).into(),
                uid: k.uid,
                perms: perm::NAMES
                    .iter()
                    .filter(|(b, _)| bits & b != 0)
                    .map(|(_, n)| n.to_string())
                    .collect(),
            })
            .collect();
        out.sort_by(|a, b| (a.uid, &a.subject, &a.owner).cmp(&(b.uid, &b.subject, &b.owner)));
        out
    }
}

/// Send `pid` on `tx` once the process behind `pidfd` has exited (a pidfd
/// becomes readable then), with the pidfd: it keeps the pid from being
/// reused until the grant keyed by it is removed.
pub fn watch_exit(pidfd: OwnedFd, pid: u32, tx: mpsc::UnboundedSender<(u32, OwnedFd)>) {
    tokio::spawn(async move {
        // SAFETY: the AsyncFd owns the pidfd and keeps it open.
        let pidfd = match unsafe { AsyncFd::register_with_interest(pidfd, Interest::READABLE) } {
            Ok(fd) => {
                let _ = fd.readable().await;
                fd.into_inner()
            }
            Err(e) => {
                let (pidfd, e) = e.into_parts();
                eprintln!("explsmd: warning: watching pid {pid}: {e}; its grant ends now");
                pidfd
            }
        };
        let _ = tx.send((pid, pidfd));
    });
}
