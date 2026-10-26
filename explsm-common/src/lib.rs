//! Types shared between the eBPF programs and userspace.
//!
//! Everything here is `#[repr(C)]` plain data so it has the same layout on
//! both sides of a map or ring buffer.

#![no_std]

/// Application id. `0` means unconfined (no identity).
pub type AppId = u32;

pub const APP_UNCONFINED: AppId = 0;

/// Owner wildcard in a [`GrantKey`]: the grant applies to every owner.
pub const OWNER_ANY: AppId = u32::MAX;

/// App ids are indexes into `MODES`, so they stay below this.
pub const MAX_APPS: u32 = 256;

/// Identity of `explsm-agent`, outside the ids the policy assigns. The
/// daemon only takes prompt answers from a process with this identity.
pub const APP_AGENT: AppId = MAX_APPS - 1;

/// Identity of `explsmd` itself. It owns explsm's own files (policy, state,
/// binaries) and is the only process that may use explsm's BPF objects.
pub const APP_DAEMON: AppId = MAX_APPS - 2;

/// Owner of the pin directory (`/sys/fs/bpf/explsm`). Only [`APP_DAEMON`]
/// may change it; the `@root` bypass does not apply.
pub const OWNER_PINS: AppId = MAX_APPS - 3;

/// Set in a `ROOTS` value: the entry is a user-writable app exe. Anyone may
/// read (and so run) it, only its app may change it.
pub const OWNER_EXE: u32 = 1 << 31;

/// Subject of `@terminal` grants in a [`GrantKey`].
pub const SUBJECT_TERMINAL: AppId = u32::MAX - 1;

/// [`TaskInfo::flags`]: the task descends from a terminal entry exe with no
/// app exec in between. With a controlling tty it gets `@terminal` grants.
pub const TF_TERMINAL: u32 = 1;

/// [`TaskInfo::flags`]: the task (or an ancestor without an exec of an app
/// since) was exec'd as an app with loader variables such as `LD_PRELOAD`,
/// and runs unconfined. Seeding never gives it an identity.
pub const TF_TAINTED: u32 = 2;

/// Bounded number of `d_parent` steps when looking for a protected root.
/// Data more than this many levels below its root is not protected.
pub const MAX_WALK: u32 = 64;

/// Bytes reserved for a path in an [`Event`], including the trailing NUL.
pub const PATH_LEN: usize = 512;

/// Most path components collected for a [`PathKind::Chain`].
pub const MAX_CHAIN: u32 = 16;

/// Name of the label the daemon writes on every protected root. Nobody but
/// the daemon may set or remove it.
pub const LABEL_XATTR: &str = "security.bpf.explsm";

/// Identity of a file: `(s_dev, i_ino)`.
///
/// `dev` uses the kernel's internal `MKDEV` encoding (`major << 20 | minor`),
/// not userspace `st_dev`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FileKey {
    pub dev: u32,
    pub _pad: u32,
    pub ino: u64,
}

/// Per-task subject state, kept in task local storage.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct TaskInfo {
    pub app_id: AppId,
    pub flags: u32,
}

/// Cached ownership of an inode, kept in inode local storage.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct InodeCache {
    pub owner: AppId,
    /// Policy generation the entry was computed for; stale when it differs
    /// from `CONFIG[CFG_GENERATION]`.
    pub generation: u32,
}

/// Key of the `GRANTS` map: `subject` may access data of `owner` with the
/// perms in the value. `owner` may be [`OWNER_ANY`].
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct GrantKey {
    pub subject: AppId,
    pub owner: AppId,
}

/// Key of the `TEMP_GRANTS` map: grants the user gave through a prompt,
/// for one process or one session. The daemon removes them when they end.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TempKey {
    /// One of [`temp_kind`].
    pub kind: u32,
    /// Real uid of the accessing task.
    pub uid: u32,
    pub owner: AppId,
    pub _pad: u32,
    pub a: u64,
    pub b: u64,
}

/// [`TempKey::kind`] and what `a` and `b` hold.
pub mod temp_kind {
    /// One process: `a` is its tgid.
    pub const PROC: u32 = 1;
    /// An app: `a` is its id.
    pub const APP: u32 = 2;
    /// Unconfined processes of one exe: `a` is its dev, `b` its inode.
    pub const EXE: u32 = 3;
}

/// Permission bits, used in `GRANTS` values and [`Event::perms`].
pub mod perm {
    pub const READ: u32 = 1 << 0;
    pub const WRITE: u32 = 1 << 1;
    pub const CREATE: u32 = 1 << 2;
    pub const DELETE: u32 = 1 << 3;
    pub const RENAME: u32 = 1 << 4;
    pub const LIST: u32 = 1 << 5;
    pub const SETATTR: u32 = 1 << 6;
    pub const ALL: u32 = (1 << 7) - 1;

    pub const NAMES: [(u32, &str); 7] = [
        (READ, "read"),
        (WRITE, "write"),
        (CREATE, "create"),
        (DELETE, "delete"),
        (RENAME, "rename"),
        (LIST, "list"),
        (SETATTR, "setattr"),
    ];
}

/// Values of the per-owner `MODES` array.
pub const MODE_AUDIT: u32 = 0;
pub const MODE_ENFORCE: u32 = 1;

/// Indexes into the `CONFIG` array map.
pub const CFG_GENERATION: u32 = 0;
/// Non-zero: tasks with fsuid 0 bypass every check except the label.
pub const CFG_ROOT_BYPASS: u32 = 1;
/// Thread group id of the daemon, the only process that may write the label.
pub const CFG_DAEMON_TGID: u32 = 2;
/// Layout version of the pinned maps, so a daemon of another build refuses
/// to reuse them.
pub const CFG_LAYOUT: u32 = 3;
/// Non-zero: every exec that gives a task an app identity is reported
/// (`explsmd --log-execs`). Off by default; they are many.
pub const CFG_LOG_EXECS: u32 = 4;
pub const CONFIG_LEN: u32 = 5;

/// Value of `CONFIG[CFG_LAYOUT]` this build writes and expects. Bump it when
/// a map's key, value or meaning changes.
pub const LAYOUT_VERSION: u32 = 7;

/// Index into the per-CPU `STATS` array map.
#[repr(u32)]
#[derive(Clone, Copy, Debug)]
pub enum Stat {
    /// Operations that were looked at (opens and inode operations).
    Checks = 0,
    /// Owner found in the inode cache without walking.
    CacheHits = 1,
    /// Cache misses that needed a `d_parent` walk.
    CacheMisses = 2,
    /// Walks that hit `MAX_WALK` without an answer. Treated (and cached) as
    /// unprotected.
    WalkExhausted = 3,
    /// Operations on protected data by a subject other than the owner.
    Foreign = 4,
    /// Operations that would have been denied in an audit-mode owner.
    Audited = 5,
    /// Operations denied.
    Denied = 6,
    /// Execs that gave a task an app identity.
    Execs = 7,
    /// Forks where the parent's identity was copied to the child.
    Forks = 8,
    /// Events lost because the ring buffer was full.
    Dropped = 9,
    /// App execs that ran unconfined because of `LD_PRELOAD` and the like.
    EnvDropped = 10,
    /// ptrace-like accesses to an app process, core-dumping signals and
    /// resource limit changes from other subjects (denied in enforce mode).
    Tamper = 11,
}

pub const STATS_LEN: u32 = 12;

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventKind {
    /// A task got an app identity on exec. `path` is the filename passed to
    /// `execve`, `file` the exe.
    Exec = 1,
    /// An operation on protected data that the policy does not allow, or a
    /// rename/link across owners. See [`Event::action`].
    Access = 2,
    /// An app created a folder directly in one of the auto-claim parents
    /// (`~`, `~/.config`, …). `file` is the parent, `path` the new name.
    Claim = 3,
}

/// Operation of an [`EventKind::Access`] event.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    Open = 1,
    Create = 2,
    Mkdir = 3,
    Mknod = 4,
    Symlink = 5,
    Link = 6,
    Unlink = 7,
    Rmdir = 8,
    Rename = 9,
    Setattr = 10,
    Setxattr = 11,
    Removexattr = 12,
    SetAcl = 13,
    RemoveAcl = 14,
    /// ptrace, `/proc/<pid>/mem` and the like on a process of `owner`;
    /// `flags` is the `PTRACE_MODE_*` mask, `owner2` the target's tgid.
    Ptrace = 15,
    /// `PTRACE_TRACEME` under a tracer that is not the same app; `owner2` is
    /// the tracer's tgid.
    Traceme = 16,
    /// Creating an entry in the directory of a user-writable app exe, or
    /// renaming or removing a directory on the way to it.
    ExeDir = 17,
    /// Getting a file descriptor for one of explsm's own BPF objects;
    /// `flags` is the kind ([`own_kind`]), `owner2` its id.
    Bpf = 18,
    /// A signal that dumps core sent to a process of `owner`: the dump
    /// would hold its memory. `flags` is the signal, `owner2` the target's
    /// tgid.
    Signal = 19,
    /// Changing a resource limit of a process of `owner` (`prlimit`), which
    /// can make it dump core. `flags` is the resource, `owner2` the target's
    /// tgid.
    Rlimit = 20,
}

impl Op {
    pub fn from_u32(v: u32) -> Option<Self> {
        Some(match v {
            1 => Self::Open,
            2 => Self::Create,
            3 => Self::Mkdir,
            4 => Self::Mknod,
            5 => Self::Symlink,
            6 => Self::Link,
            7 => Self::Unlink,
            8 => Self::Rmdir,
            9 => Self::Rename,
            10 => Self::Setattr,
            11 => Self::Setxattr,
            12 => Self::Removexattr,
            13 => Self::SetAcl,
            14 => Self::RemoveAcl,
            15 => Self::Ptrace,
            16 => Self::Traceme,
            17 => Self::ExeDir,
            18 => Self::Bpf,
            19 => Self::Signal,
            20 => Self::Rlimit,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Create => "create",
            Self::Mkdir => "mkdir",
            Self::Mknod => "mknod",
            Self::Symlink => "symlink",
            Self::Link => "link",
            Self::Unlink => "unlink",
            Self::Rmdir => "rmdir",
            Self::Rename => "rename",
            Self::Setattr => "setattr",
            Self::Setxattr => "setxattr",
            Self::Removexattr => "removexattr",
            Self::SetAcl => "set_acl",
            Self::RemoveAcl => "remove_acl",
            Self::Ptrace => "ptrace",
            Self::Traceme => "traceme",
            Self::ExeDir => "exe_dir",
            Self::Bpf => "bpf",
            Self::Signal => "signal",
            Self::Rlimit => "rlimit",
        }
    }
}

/// [`Event::action`]: what happened to the operation.
pub const ACTION_AUDIT: u32 = 0;
pub const ACTION_DENY: u32 = 1;

/// [`Event::reason`]: why the operation was reported.
/// The subject lacks `perms` on data of `owner`.
pub const REASON_PERMS: u32 = 0;
/// A rename or link would move data from `owner` to `owner2` in place.
/// Denied with `EXDEV`, so `mv` falls back to copy and unlink.
pub const REASON_CROSS: u32 = 1;
/// Someone other than the daemon tried to change the label xattr.
pub const REASON_LABEL: u32 = 2;
/// Tampering with an app: ptrace and the like, or planting a file next to
/// a user-writable app exe. Denied if the app is in enforce mode (explsm's
/// own agent and daemon always are).
pub const REASON_TAMPER: u32 = 3;
/// An [`EventKind::Exec`] of an app exe that ran unconfined because of its
/// environment or namespace; `flags` holds the [`env_var`] bits found.
pub const REASON_ENV: u32 = 4;
/// Someone other than the daemon reached for explsm's own BPF objects.
pub const REASON_SELF: u32 = 5;

/// Environment variables that make the dynamic loader run foreign code in a
/// process. An app exec'd with one of them (non-empty) gets no identity.
pub mod env_var {
    pub const LD_PRELOAD: u32 = 1 << 0;
    pub const LD_LIBRARY_PATH: u32 = 1 << 1;
    pub const LD_AUDIT: u32 = 1 << 2;
    /// The environment could not be read in full; treated as tainted.
    pub const UNREADABLE: u32 = 1 << 3;
    /// Exec'd in a user namespace other than the initial one, where its
    /// user may have mounted its own libraries or `/etc/ld.so.preload`.
    pub const USERNS: u32 = 1 << 4;

    pub const NAMES: [(u32, &str); 5] = [
        (LD_PRELOAD, "LD_PRELOAD"),
        (LD_LIBRARY_PATH, "LD_LIBRARY_PATH"),
        (LD_AUDIT, "LD_AUDIT"),
        (UNREADABLE, "unreadable environment"),
        (USERNS, "userns"),
    ];
}

/// Kind of a key of the `OWN_IDS` map: explsm's own BPF objects by id.
pub mod own_kind {
    pub const MAP: u32 = 1;
    pub const PROG: u32 = 2;
    pub const LINK: u32 = 3;
}

/// Value of the `DAEMON_PATH` map: the path explsmd is installed at,
/// NUL-terminated.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DaemonPath {
    pub path: [u8; DAEMON_PATH_LEN],
}

pub const DAEMON_PATH_LEN: usize = 256;

/// Key of the `OWN_IDS` map.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct OwnKey {
    pub kind: u32,
    pub id: u32,
}

/// How [`EvPath::buf`] is to be read.
pub mod path_kind {
    /// Nothing was filled in.
    pub const NONE: u32 = 0;
    /// A complete NUL-terminated path (`bpf_d_path`, exec filename).
    pub const FULL: u32 = 1;
    /// NUL-separated names from the leaf upwards, relative to the root of
    /// the file's filesystem. Inode hooks have no `struct path` to resolve.
    pub const CHAIN: u32 = 2;
    /// Like `CHAIN`, and the walk reached the filesystem root.
    pub const CHAIN_COMPLETE: u32 = 3;
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct EvPath {
    pub kind: u32,
    /// Bytes used in `buf`, or a negative errno if it could not be filled.
    pub len: i32,
    pub buf: [u8; PATH_LEN],
}

/// Ring buffer event.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Event {
    pub kind: u32,
    /// Thread group id (what userspace calls the pid).
    pub pid: u32,
    /// Thread id.
    pub tid: u32,
    /// Real uid of the task.
    pub uid: u32,
    pub subject: AppId,
    pub owner: AppId,
    /// Destination owner of a cross-owner rename or link.
    pub owner2: AppId,
    /// [`Op`] of an access event.
    pub op: u32,
    /// Perms the subject lacks (`REASON_PERMS`).
    pub perms: u32,
    pub action: u32,
    pub reason: u32,
    /// Op specific: `f_flags` for open, `ia_valid` for setattr.
    pub flags: u32,
    pub file: FileKey,
    /// Name of the thread (`/proc/<pid>/task/<tid>/comm`).
    pub comm: [u8; 16],
    /// Name of the process, i.e. of its thread group leader
    /// (`/proc/<pid>/comm`). Thread pools name their threads `pool-N` and
    /// the like, so this is what identifies the accessor.
    pub proc_comm: [u8; 16],
    pub path: EvPath,
    /// Destination of a rename or link.
    pub path2: EvPath,
    /// Exe of the task (zero for exec events and kernel threads).
    pub exe: FileKey,
    /// [`TaskInfo::flags`] of the task.
    pub task_flags: u32,
    pub _pad: u32,
    /// Start of the process (its thread group leader) in nanoseconds since
    /// boot, which tells it from a later process with the same pid.
    pub start_time: u64,
}

// The C side (explsmd/bpf/explsm.h) asserts the same layout.
const _: () = {
    use core::mem::{offset_of, size_of};
    assert!(size_of::<FileKey>() == 16);
    assert!(size_of::<EvPath>() == 520);
    assert!(offset_of!(Event, file) == 48);
    assert!(offset_of!(Event, path) == 96);
    assert!(offset_of!(Event, path2) == 616);
    assert!(offset_of!(Event, exe) == 1136);
    assert!(offset_of!(Event, start_time) == 1160);
    assert!(size_of::<Event>() == 1168);
    assert!(size_of::<TempKey>() == 32);
};

#[cfg(feature = "user")]
mod user {
    use super::*;

    // SAFETY: plain `#[repr(C)]` data with explicit padding.
    unsafe impl aya::Pod for FileKey {}
    unsafe impl aya::Pod for TaskInfo {}
    unsafe impl aya::Pod for InodeCache {}
    unsafe impl aya::Pod for GrantKey {}
    unsafe impl aya::Pod for TempKey {}
    unsafe impl aya::Pod for OwnKey {}
    unsafe impl aya::Pod for DaemonPath {}
}
