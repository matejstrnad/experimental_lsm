//! What the daemon reads about other processes: their exe, the loader
//! variables set in their environment, and their user namespace.
//!
//! All three are ptrace-mode reads of `/proc/<pid>`, and the Landlock
//! domain the daemon puts itself in (`sandbox.rs`) refuses those for every
//! process outside it. So before restricting itself the daemon forks a
//! helper that stays outside the domain and answers just these questions
//! for a pid, over a socket pair. The helper keeps only `CAP_SYS_PTRACE`
//! and `CAP_DAC_READ_SEARCH`, holds no other file descriptor, and dies with
//! the daemon. It can't be started again once the daemon is restricted: if
//! it is gone, the reads fail and the callers take the cautious answer.
//!
//! Until the helper runs (at startup), the daemon reads `/proc` itself.

use std::{
    fs::{self, File},
    io::{self, Read as _, Write as _},
    os::{
        fd::{AsRawFd as _, FromRawFd as _, IntoRawFd as _, OwnedFd},
        unix::{ffi::OsStrExt as _, fs::MetadataExt as _},
    },
    path::PathBuf,
    sync::{Mutex, PoisonError},
    time::Duration,
};

use explsm_common::{ENV_CHUNK, FileKey};
use explsm_policy::resolve::file_key;

const OP_EXE: u8 = 1;
const OP_TAINTED: u8 = 2;
const OP_FOREIGN_USERNS: u8 = 3;

/// How long one answer may take. `/proc/<pid>/environ` can block on a
/// process stuck in the kernel; the daemon must not.
const TIMEOUT: Duration = Duration::from_secs(2);

/// Sequence number, then the exe's errno (0 if found), dev, ino and path.
const REPLY_MAX: usize = 4 + 4 + 4 + 8 + libc::PATH_MAX as usize;

/// `CAP_DAC_READ_SEARCH`, `CAP_SYS_PTRACE` (linux/capability.h).
const KEEP_CAPS: u64 = 1 << 2 | 1 << 19;

struct Helper {
    sock: File,
    seq: u32,
}

static HELPER: Mutex<Option<Helper>> = Mutex::new(None);

pub struct Exe {
    pub key: FileKey,
    pub path: PathBuf,
}

/// The exe of process (or thread) `pid`.
pub fn exe(pid: u32) -> io::Result<Exe> {
    let Some(reply) = ask(OP_EXE, pid) else {
        return local_exe(pid);
    };
    let reply = reply?;
    if reply.len() < 16 {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    let errno = i32::from_le_bytes(reply[0..4].try_into().unwrap());
    if errno != 0 {
        return Err(io::Error::from_raw_os_error(errno));
    }
    Ok(Exe {
        key: FileKey {
            dev: u32::from_le_bytes(reply[4..8].try_into().unwrap()),
            _pad: 0,
            ino: u64::from_le_bytes(reply[8..16].try_into().unwrap()),
        },
        path: PathBuf::from(std::ffi::OsStr::from_bytes(&reply[16..])),
    })
}

/// Whether process `pid` was started with a loader variable set (non-empty)
/// that `allowed` does not take, or that can't be told.
pub fn tainted_env(pid: u32, allowed: impl Fn(&[u8]) -> bool) -> bool {
    let reply = match ask(OP_TAINTED, pid) {
        Some(Ok(r)) => r,
        // No answer is the cautious one.
        Some(Err(_)) => return true,
        None => encode_loader_vars(local_loader_vars(pid)),
    };
    match reply.split_first() {
        Some((0, vars)) => vars
            .split(|b| *b == 0)
            .filter(|v| !v.is_empty())
            .any(|v| !allowed(v)),
        _ => true,
    }
}

/// Whether process `pid` runs in a user namespace other than the initial
/// one (that of pid 1), or that can't be told.
pub fn foreign_userns(pid: u32) -> bool {
    ask_bool(OP_FOREIGN_USERNS, pid).unwrap_or_else(|| local_foreign_userns(pid))
}

fn ask_bool(op: u8, pid: u32) -> Option<bool> {
    // No answer is the cautious one: tainted, foreign.
    ask(op, pid).map(|r| r.map_or(true, |r| r.first() != Some(&0)))
}

/// The helper's answer, or `None` if there is no helper.
fn ask(op: u8, pid: u32) -> Option<io::Result<Vec<u8>>> {
    let mut helper = HELPER.lock().unwrap_or_else(PoisonError::into_inner);
    let reply = helper.as_mut()?.ask(op, pid);
    if let Err(e) = &reply
        && e.kind() != io::ErrorKind::WouldBlock
    {
        eprintln!(
            "explsmd: warning: the /proc helper is gone ({e}); processes found from now on \
             can't be seeded"
        );
        // Asking again would only fail again.
        *helper = None;
    }
    Some(reply)
}

impl Helper {
    fn ask(&mut self, op: u8, pid: u32) -> io::Result<Vec<u8>> {
        self.seq = self.seq.wrapping_add(1);
        let mut req = [0; 9];
        req[0..4].copy_from_slice(&self.seq.to_le_bytes());
        req[4] = op;
        req[5..9].copy_from_slice(&pid.to_le_bytes());
        self.sock.write_all(&req)?;
        let mut buf = vec![0; REPLY_MAX];
        loop {
            let n = self.sock.read(&mut buf)?;
            if n == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            // Else a late answer to a question that timed out.
            if n >= 4 && buf[0..4] == self.seq.to_le_bytes() {
                buf.truncate(n);
                buf.drain(0..4);
                return Ok(buf);
            }
        }
    }
}

/// Fork the helper. Must be called while the daemon is single-threaded and
/// before it installs signal handlers. Returns the helper's pid.
pub fn start() -> io::Result<u32> {
    let mut fds = [0; 2];
    let flags = libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC;
    if unsafe { libc::socketpair(libc::AF_UNIX, flags, 0, fds.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let (ours, theirs) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    let parent = unsafe { libc::getpid() };
    match unsafe { libc::fork() } {
        -1 => Err(io::Error::last_os_error()),
        0 => {
            drop(ours);
            serve(theirs, parent)
        }
        pid => {
            drop(theirs);
            let sock = File::from(ours);
            set_timeout(&sock, libc::SO_RCVTIMEO)?;
            set_timeout(&sock, libc::SO_SNDTIMEO)?;
            *HELPER.lock().unwrap_or_else(PoisonError::into_inner) = Some(Helper { sock, seq: 0 });
            Ok(pid as u32)
        }
    }
}

fn set_timeout(sock: &File, opt: libc::c_int) -> io::Result<()> {
    let tv = libc::timeval {
        tv_sec: TIMEOUT.as_secs() as libc::time_t,
        tv_usec: TIMEOUT.subsec_micros() as libc::suseconds_t,
    };
    let ret = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            opt,
            (&raw const tv).cast(),
            size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// The helper: answer until the daemon closes its end.
fn serve(sock: OwnedFd, parent: libc::pid_t) -> ! {
    // Only the socket (as fd 3) and stdin, stdout, stderr stay open: not the
    // daemon's maps, links or bus connection.
    let raw = sock.into_raw_fd();
    unsafe {
        libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
        if libc::getppid() != parent {
            libc::_exit(0);
        }
        libc::prctl(libc::PR_SET_NAME, c"explsmd-proc".as_ptr());
        for sig in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
            libc::signal(sig, libc::SIG_DFL);
        }
        if raw != 3 && libc::dup2(raw, 3) < 0 {
            libc::_exit(1);
        }
        libc::syscall(libc::SYS_close_range, 4u32, u32::MAX, 0u32);
    }
    if let Err(e) = drop_privileges() {
        eprintln!("explsmd: warning: /proc helper: dropping privileges: {e}");
        unsafe { libc::_exit(1) };
    }
    let mut sock = unsafe { File::from_raw_fd(3) };
    let mut req = [0; 16];
    loop {
        let n = match sock.read(&mut req) {
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => 0,
        };
        if n == 0 {
            unsafe { libc::_exit(0) };
        }
        if n != 9 {
            continue;
        }
        let pid = u32::from_le_bytes(req[5..9].try_into().unwrap());
        let mut reply = req[0..4].to_vec();
        match req[4] {
            OP_EXE => match local_exe(pid) {
                Ok(exe) => {
                    reply.extend_from_slice(&0i32.to_le_bytes());
                    reply.extend_from_slice(&exe.key.dev.to_le_bytes());
                    reply.extend_from_slice(&exe.key.ino.to_le_bytes());
                    reply.extend_from_slice(exe.path.as_os_str().as_bytes());
                }
                Err(e) => {
                    reply.extend_from_slice(&e.raw_os_error().unwrap_or(libc::EIO).to_le_bytes());
                    reply.extend_from_slice(&[0; 12]);
                }
            },
            OP_TAINTED => reply.extend(encode_loader_vars(local_loader_vars(pid))),
            OP_FOREIGN_USERNS => reply.push(local_foreign_userns(pid).into()),
            _ => continue,
        }
        if sock.write_all(&reply).is_err() {
            unsafe { libc::_exit(0) };
        }
    }
}

/// Keep only the capabilities the reads need, for good.
fn drop_privileges() -> io::Result<()> {
    let check = |ret: libc::c_long| {
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    };
    unsafe {
        check(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0).into())?;
        check(
            libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_CLEAR_ALL,
                0,
                0,
                0,
            )
            .into(),
        )?;
        for cap in 0..64 {
            if KEEP_CAPS & 1 << cap == 0
                && libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) < 0
                && io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL)
            {
                // Past the last capability this kernel has.
                break;
            }
        }
        #[repr(C)]
        struct Header {
            version: u32,
            pid: i32,
        }
        #[repr(C)]
        #[derive(Clone, Copy, Default)]
        struct Data {
            effective: u32,
            permitted: u32,
            inheritable: u32,
        }
        // _LINUX_CAPABILITY_VERSION_3: two 32-bit halves.
        let header = Header {
            version: 0x2008_0522,
            pid: 0,
        };
        let mut have = [Data::default(); 2];
        check(libc::syscall(
            libc::SYS_capget,
            &raw const header,
            have.as_mut_ptr(),
        ))?;
        let keep = KEEP_CAPS & (u64::from(have[0].permitted) | u64::from(have[1].permitted) << 32);
        let half = |shift: u32| {
            let bits = (keep >> shift) as u32;
            Data {
                effective: bits,
                permitted: bits,
                inheritable: 0,
            }
        };
        let data = [half(0), half(32)];
        check(libc::syscall(
            libc::SYS_capset,
            &raw const header,
            data.as_ptr(),
        ))?;
    }
    Ok(())
}

fn local_exe(pid: u32) -> io::Result<Exe> {
    let link = PathBuf::from(format!("/proc/{pid}/exe"));
    let path = fs::read_link(&link)?;
    let key = file_key(&link)?;
    Ok(Exe { key, path })
}

/// Loader variables that make a process run foreign code; see
/// `explsm_common::env_var`.
const LOADER_VARS: [&[u8]; 3] = [b"LD_PRELOAD=", b"LD_LIBRARY_PATH=", b"LD_AUDIT="];

/// The loader variables (non-empty) in the environment of `pid`, or `None`
/// if it can't be read.
fn local_loader_vars(pid: u32) -> Option<Vec<Vec<u8>>> {
    match fs::read(format!("/proc/{pid}/environ")) {
        Ok(env) => Some(
            env.split(|b| *b == 0)
                .filter(|var| {
                    LOADER_VARS
                        .iter()
                        .any(|p| var.len() > p.len() && var.starts_with(p))
                })
                .map(<[u8]>::to_vec)
                .collect(),
        ),
        // Gone: nothing to seed anyway.
        Err(e) if e.kind() == io::ErrorKind::NotFound || e.raw_os_error() == Some(libc::ESRCH) => {
            Some(Vec::new())
        }
        Err(_) => None,
    }
}

/// The answer to `OP_TAINTED`: `0` and the variables, each followed by a
/// NUL, or `1` if the process counts as tainted whatever is allowed:
/// unreadable, or a variable too long to be allowed (or to fit the reply).
fn encode_loader_vars(vars: Option<Vec<Vec<u8>>>) -> Vec<u8> {
    let Some(vars) = vars else {
        return vec![1];
    };
    let mut out = vec![0];
    for var in vars {
        if var.len() + 1 >= ENV_CHUNK || out.len() + var.len() + 1 > REPLY_MAX - 4 {
            return vec![1];
        }
        out.extend(var);
        out.push(0);
    }
    out
}

fn local_foreign_userns(pid: u32) -> bool {
    let ns = |p: &str| fs::metadata(p).map(|m| (m.dev(), m.ino()));
    match (ns("/proc/1/ns/user"), ns(&format!("/proc/{pid}/ns/user"))) {
        (Ok(init), Ok(its)) => init != its,
        // Gone: nothing to seed anyway.
        (Ok(_), Err(e)) if e.kind() == io::ErrorKind::NotFound => false,
        _ => true,
    }
}
