//! Give processes that were already running their identity: at startup, and
//! when a reload or rescan adds exes.
//!
//! The exec hook only sees execs that happen after it is attached, and only
//! for exes that are in `EXES` at the time. For everything older, scan `/proc` for tasks whose exe is an app exe and write
//! their task storage directly: a task storage map is keyed by a pidfd from
//! userspace. Each thread has its own storage, so every thread gets a
//! `PIDFD_THREAD` pidfd.
//!
//! Two races are closed here:
//! - A task forked by an app process after `task_alloc` was attached but
//!   before its parent was seeded inherits nothing. The scan is repeated
//!   until a pass finds no app thread without storage: once every app task
//!   has storage, `task_alloc` covers every later fork.
//! - A task that execs another binary between the scan and the seeding would
//!   keep the app identity. After seeding, its exe is checked again and the
//!   identity dropped if it changed.
//!
//! [`terminals`] does the same for the terminal flag: a process gets it when
//! its exe is a terminal, or when its parent has it and its own exe is no
//! app's.

use std::{
    collections::{HashMap, HashSet},
    fs, io,
    os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, FromRawFd as _, OwnedFd},
    ptr,
};

use anyhow::Result;
use aya::maps::MapData;
use explsm_common::{APP_UNCONFINED, AppId, FileKey, TF_TAINTED, TF_TERMINAL, TaskInfo};

use crate::procs;

/// `PIDFD_THREAD` (Linux 6.9+): a pidfd for one thread, not its group.
const PIDFD_THREAD: libc::c_uint = libc::O_EXCL as libc::c_uint;
const BPF_MAP_LOOKUP_ELEM: libc::c_long = 1;
const BPF_MAP_UPDATE_ELEM: libc::c_long = 2;
const BPF_ANY: u64 = 0;
/// Passes before giving up on a process that keeps forking.
const MAX_PASSES: usize = 8;

#[derive(Default)]
pub struct Seeded {
    pub processes: usize,
    pub threads: usize,
    pub passes: usize,
    /// Threads that exec'd another binary while being seeded.
    pub reverted: usize,
    /// App processes left unconfined: started with `LD_PRELOAD` and the
    /// like or in a user namespace, before or after explsm was loaded.
    pub tainted: HashSet<u32>,
    pub failures: Vec<(u32, io::Error)>,
}

pub fn running_apps(tasks: &MapData, exes: &HashMap<FileKey, AppId>) -> Result<Seeded> {
    let map = tasks.fd().as_fd();
    let mut out = Seeded::default();
    let mut seen_processes = HashSet::new();
    for _ in 0..MAX_PASSES {
        out.passes += 1;
        let before = out.threads + out.failures.len();
        seed_pass(map, exes, &mut out, &mut seen_processes)?;
        if out.threads + out.failures.len() == before {
            break;
        }
    }
    out.processes = seen_processes.len();
    Ok(out)
}

fn seed_pass(
    map: BorrowedFd<'_>,
    exes: &HashMap<FileKey, AppId>,
    out: &mut Seeded,
    seen: &mut HashSet<u32>,
) -> Result<()> {
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let Some(pid) = entry.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        // Kernel threads have no exe, and a process may exit mid-scan.
        let Ok(key) = procs::exe(pid).map(|e| e.key) else {
            continue;
        };
        let Some(&app_id) = exes.get(&key) else {
            continue;
        };
        // Started before explsm could look at its exec: its environment
        // block still shows what the loader saw, and its user namespace
        // whether its user could have mounted its own libraries.
        if procs::tainted_env(pid) || procs::foreign_userns(pid) {
            out.tainted.insert(pid);
            continue;
        }
        seen.insert(pid);
        let Ok(threads) = fs::read_dir(entry.path().join("task")) else {
            continue;
        };
        for thread in threads.flatten() {
            let Some(tid) = thread.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else {
                continue;
            };
            match seed_thread(map, tid, app_id, pid, key) {
                Ok(Outcome::Seeded) => out.threads += 1,
                Ok(Outcome::Reverted) => out.reverted += 1,
                Ok(Outcome::Present) => {}
                // Exited since the directory was read.
                Err(e) if e.raw_os_error() == Some(libc::ESRCH) => {}
                Err(e) => out.failures.push((tid, e)),
            }
        }
    }
    Ok(())
}

enum Outcome {
    Seeded,
    /// Already had this identity: seeded earlier, or inherited it on fork.
    Present,
    /// Exec'd another binary while being seeded.
    Reverted,
}

fn seed_thread(
    map: BorrowedFd<'_>,
    tid: u32,
    app_id: AppId,
    pid: u32,
    key: FileKey,
) -> io::Result<Outcome> {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, tid as libc::pid_t, PIDFD_THREAD) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let pidfd = unsafe { OwnedFd::from_raw_fd(fd as i32) };
    let fd: i32 = pidfd.as_raw_fd();
    let mut current = TaskInfo::default();
    // Storage with another id is from before the exe became the app's
    // (a reload), or was dropped by an exec of an unknown exe back then.
    let found = map_cmd(BPF_MAP_LOOKUP_ELEM, map, &fd, &mut current, 0).is_ok();
    if found && (current.app_id == app_id || current.flags & TF_TAINTED != 0) {
        return Ok(Outcome::Present);
    }
    map_cmd(
        BPF_MAP_UPDATE_ELEM,
        map,
        &fd,
        &mut TaskInfo { app_id, flags: 0 },
        BPF_ANY,
    )?;
    if procs::exe(pid).ok().map(|e| e.key) == Some(key) {
        return Ok(Outcome::Seeded);
    }
    map_cmd(
        BPF_MAP_UPDATE_ELEM,
        map,
        &fd,
        &mut TaskInfo {
            app_id: APP_UNCONFINED,
            flags: 0,
        },
        BPF_ANY,
    )?;
    Ok(Outcome::Reverted)
}

/// Flag every thread of the processes below a terminal exe with no app exe
/// in between. Two passes, so children forked during the first are found.
pub fn terminals(
    tasks: &MapData,
    terminals: &HashSet<FileKey>,
    exes: &HashMap<FileKey, AppId>,
) -> Result<Seeded> {
    let map = tasks.fd().as_fd();
    let mut out = Seeded::default();
    let mut seen = HashSet::new();
    for _ in 0..2 {
        out.passes += 1;
        let procs = processes()?;
        for pid in below_terminals(&procs, terminals, exes) {
            seen.insert(pid);
            let Ok(threads) = fs::read_dir(format!("/proc/{pid}/task")) else {
                continue;
            };
            for thread in threads.flatten() {
                let Some(tid) = thread.file_name().to_str().and_then(|s| s.parse::<u32>().ok())
                else {
                    continue;
                };
                match flag_thread(map, tid) {
                    Ok(true) => out.threads += 1,
                    Ok(false) => {}
                    Err(e) if e.raw_os_error() == Some(libc::ESRCH) => {}
                    Err(e) => out.failures.push((tid, e)),
                }
            }
        }
    }
    out.processes = seen.len();
    Ok(out)
}

/// pid → (parent pid, exe). Kernel threads have no exe.
fn processes() -> Result<HashMap<u32, (u32, Option<FileKey>)>> {
    let mut out = HashMap::new();
    for entry in fs::read_dir("/proc")?.flatten() {
        let Some(pid) = entry.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        let Ok(stat) = fs::read_to_string(entry.path().join("stat")) else {
            continue;
        };
        let Some(ppid) = parent_of(&stat) else {
            continue;
        };
        out.insert(pid, (ppid, procs::exe(pid).ok().map(|e| e.key)));
    }
    Ok(out)
}

/// The parent pid from `/proc/<pid>/stat`. The name in parentheses may
/// contain anything, so fields are counted from its last `)`.
fn parent_of(stat: &str) -> Option<u32> {
    let rest = &stat[stat.rfind(')')? + 1..];
    rest.split_whitespace().nth(1)?.parse().ok()
}

/// The pids whose exe is a terminal, or whose parent is in the result while
/// their own exe is no app's.
fn below_terminals(
    procs: &HashMap<u32, (u32, Option<FileKey>)>,
    terminals: &HashSet<FileKey>,
    exes: &HashMap<FileKey, AppId>,
) -> Vec<u32> {
    fn flagged(
        pid: u32,
        procs: &HashMap<u32, (u32, Option<FileKey>)>,
        terminals: &HashSet<FileKey>,
        exes: &HashMap<FileKey, AppId>,
        memo: &mut HashMap<u32, bool>,
        depth: usize,
    ) -> bool {
        if let Some(v) = memo.get(&pid) {
            return *v;
        }
        let Some(&(ppid, exe)) = procs.get(&pid) else {
            return false;
        };
        let v = match exe {
            Some(k) if terminals.contains(&k) => true,
            Some(k) if exes.contains_key(&k) => false,
            None => false,
            _ => ppid != 0 && ppid != pid && depth < 256 && {
                flagged(ppid, procs, terminals, exes, memo, depth + 1)
            },
        };
        memo.insert(pid, v);
        v
    }
    let mut memo = HashMap::new();
    let mut out: Vec<u32> = procs
        .keys()
        .copied()
        .filter(|pid| flagged(*pid, procs, terminals, exes, &mut memo, 0))
        .collect();
    out.sort_unstable();
    out
}

/// Set the terminal flag on an unconfined thread. Returns whether it
/// changed anything.
fn flag_thread(map: BorrowedFd<'_>, tid: u32) -> io::Result<bool> {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, tid as libc::pid_t, PIDFD_THREAD) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let pidfd = unsafe { OwnedFd::from_raw_fd(fd as i32) };
    let fd: i32 = pidfd.as_raw_fd();
    let mut current = TaskInfo::default();
    let found = map_cmd(BPF_MAP_LOOKUP_ELEM, map, &fd, &mut current, 0).is_ok();
    if found && (current.app_id != APP_UNCONFINED || current.flags & TF_TERMINAL != 0) {
        return Ok(false);
    }
    map_cmd(
        BPF_MAP_UPDATE_ELEM,
        map,
        &fd,
        &mut TaskInfo {
            app_id: APP_UNCONFINED,
            flags: current.flags | TF_TERMINAL,
        },
        BPF_ANY,
    )?;
    Ok(true)
}

/// A pidfd for the process `pid`.
pub fn pidfd_open(pid: u32) -> io::Result<OwnedFd> {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
}

/// When process `pid` started, in nanoseconds since boot, at the
/// resolution `/proc/<pid>/stat` has (clock ticks).
fn start_time(pid: u32) -> Option<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // Field 22; fields are counted from the last `)` of the name (field 2).
    let rest = &stat[stat.rfind(')')? + 1..];
    let ticks: u64 = rest.split_whitespace().nth(19)?.parse().ok()?;
    let hz = u64::try_from(unsafe { libc::sysconf(libc::_SC_CLK_TCK) }).ok()?;
    Some(ticks * (1_000_000_000 / hz))
}

/// Whether the process that `pidfd` (opened for `pid`) pins is the one that
/// started at `start` (from an event): the pid may have been reused before
/// the pidfd was opened.
pub fn same_process(pid: u32, start: u64) -> bool {
    let Ok(hz) = u64::try_from(unsafe { libc::sysconf(libc::_SC_CLK_TCK) }) else {
        return false;
    };
    let tick = 1_000_000_000 / hz;
    start_time(pid).is_some_and(|t| t == start / tick * tick)
}

/// The app identity of a process, read from task storage through a pidfd
/// (of its thread group leader). Unconfined if it has none.
pub fn app_of(tasks: &MapData, pidfd: BorrowedFd<'_>) -> io::Result<AppId> {
    let fd: i32 = pidfd.as_raw_fd();
    let mut info = TaskInfo::default();
    match map_cmd(BPF_MAP_LOOKUP_ELEM, tasks.fd().as_fd(), &fd, &mut info, 0) {
        Ok(()) => Ok(info.app_id),
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => Ok(APP_UNCONFINED),
        Err(e) => Err(e),
    }
}

/// Map element commands by hand: Aya has no userspace type for task
/// storage.
fn map_cmd<K, V>(
    cmd: libc::c_long,
    map: BorrowedFd<'_>,
    key: &K,
    value: &mut V,
    flags: u64,
) -> io::Result<()> {
    // The prefix of `union bpf_attr` used by the map element commands.
    #[repr(C)]
    struct Attr {
        map_fd: u32,
        _pad: u32,
        key: u64,
        value: u64,
        flags: u64,
    }
    let attr = Attr {
        map_fd: map.as_raw_fd() as u32,
        _pad: 0,
        key: ptr::from_ref(key) as u64,
        value: ptr::from_mut(value) as u64,
        flags,
    };
    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            cmd,
            ptr::from_ref(&attr),
            size_of::<Attr>(),
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(ino: u64) -> FileKey {
        FileKey { dev: 1, _pad: 0, ino }
    }

    #[test]
    fn parses_parent_pids() {
        assert_eq!(parent_of("42 (bash) S 7 42 42 0"), Some(7));
        assert_eq!(parent_of("42 (we ird) x) S 9 1"), Some(9));
        assert_eq!(parent_of("garbage"), None);
    }

    #[test]
    fn finds_processes_below_terminals() {
        // 1 init, 10 konsole (terminal), 11 bash, 12 cat, 13 ssh (app),
        // 14 bash below ssh, 20 unrelated bash.
        let procs: HashMap<u32, (u32, Option<FileKey>)> = [
            (1, (0, Some(key(1)))),
            (10, (1, Some(key(10)))),
            (11, (10, Some(key(2)))),
            (12, (11, Some(key(3)))),
            (13, (11, Some(key(13)))),
            (14, (13, Some(key(2)))),
            (20, (1, Some(key(2)))),
        ]
        .into();
        let terminals = [key(10)].into();
        let exes = [(key(13), 1)].into();
        assert_eq!(below_terminals(&procs, &terminals, &exes), [10, 11, 12]);
    }
}
