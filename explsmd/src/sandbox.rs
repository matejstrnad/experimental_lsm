//! Landlock for the daemon itself, once it is set up.
//!
//! From then on explsmd works on input from outside: events of every
//! process, D-Bus calls from agents, changes in directories users write to.
//! A bug in handling it must not get to users' files or the rest of the
//! system. What stays allowed:
//!
//! - listing any directory and looking at any file's metadata, which
//!   resolving the policy, finding new folders and scanning roots for hard
//!   links need. Labelling roots (xattrs) and opening them `O_PATH` are not
//!   covered by Landlock at all;
//! - reading the policy, the claims, the state directory, `/etc/passwd`,
//!   `/etc/login.defs`, the CPU lists in `/sys` and `/proc` (other
//!   processes' `exe`, `environ` and
//!   `ns` only through `procs.rs`);
//! - writing claims and state, and removing the pins (unload).
//!
//! Everything else is refused: reading other files, writing anywhere else,
//! exec, mounts, TCP, connecting to UNIX sockets (the bus and the journal
//! are connected before), signals and abstract sockets out of the domain,
//! ioctls on devices opened later.
//!
//! The daemon keeps `CAP_BPF` and `CAP_SYS_ADMIN` for the maps, so this
//! contains bugs; it does not stop code running in the daemon, which could
//! load BPF programs of its own.

use std::{fs, io, path::Path};

use anyhow::{Context as _, Result};
use landlock::{
    ABI, Access as _, AccessFs, AccessNet, BitFlags, PathBeneath, PathFd, RestrictSelfAttr as _,
    Ruleset, RulesetAttr as _, RulesetCreatedAttr as _, RulesetStatus, Scope,
};

/// The Landlock version the rules were written for. Newer kernels enforce
/// what it has; older ones what they have of it.
const ABI: ABI = ABI::V9;

pub struct Paths<'a> {
    pub policy: &'a Path,
    pub claims: &'a Path,
    pub state_dir: &'a Path,
    pub pin_dir: &'a Path,
}

/// Restrict the daemon, all of its threads. Returns how much of it the
/// kernel enforces.
pub fn restrict(paths: &Paths) -> Result<String> {
    let read = AccessFs::ReadFile | AccessFs::ReadDir;
    let write =
        read | AccessFs::WriteFile | AccessFs::MakeReg | AccessFs::RemoveFile | AccessFs::Truncate;
    let mut rules: Vec<(&Path, BitFlags<AccessFs>)> = vec![
        (Path::new("/"), AccessFs::ReadDir.into()),
        (Path::new("/proc"), read),
        // aya counts the CPUs on every read of a per-CPU map (`STATS`).
        (
            Path::new("/sys/devices/system/cpu/possible"),
            AccessFs::ReadFile.into(),
        ),
        (
            Path::new("/sys/devices/system/cpu/online"),
            AccessFs::ReadFile.into(),
        ),
        (Path::new("/etc/passwd"), AccessFs::ReadFile.into()),
        (Path::new("/etc/login.defs"), AccessFs::ReadFile.into()),
        (paths.policy, read),
        (paths.claims, write),
        (paths.state_dir, write),
        (paths.pin_dir, AccessFs::RemoveFile.into()),
    ];
    // Unloading removes the pin directory itself.
    if let Some(parent) = paths.pin_dir.parent() {
        rules.push((parent, AccessFs::RemoveDir.into()));
    }

    let mut ruleset = Ruleset::default()
        .handle_access(AccessFs::from_all(ABI))?
        .handle_access(AccessNet::from_all(ABI))?
        .scope(Scope::from_all(ABI))?
        .create()?;
    for (path, access) in rules {
        let md = match fs::metadata(path) {
            Ok(md) => md,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e).with_context(|| format!("{}", path.display())),
        };
        let access = if md.is_dir() {
            access
        } else {
            access & AccessFs::from_file(ABI)
        };
        let fd = PathFd::new(path).with_context(|| format!("{}", path.display()))?;
        ruleset = ruleset.add_rule(PathBeneath::new(fd, access))?;
    }
    let status = ruleset.all_threads(true)?.restrict_self()?;
    let threads = threads();
    if !status.all_threads && threads != Some(1) {
        eprintln!(
            "explsmd: warning: Landlock restricts only the main thread of {}",
            threads.map_or("?".into(), |n| n.to_string())
        );
    }
    Ok(match status.ruleset {
        RulesetStatus::FullyEnforced => "sandboxed (Landlock)".into(),
        RulesetStatus::PartiallyEnforced => {
            "partly sandboxed (Landlock: this kernel has only some of its rights)".into()
        }
        RulesetStatus::NotEnforced => "not sandboxed (this kernel has no Landlock)".into(),
    })
}

fn threads() -> Option<usize> {
    fs::read_to_string("/proc/self/status")
        .ok()?
        .lines()
        .find_map(|l| l.strip_prefix("Threads:"))?
        .trim()
        .parse()
        .ok()
}

#[cfg(test)]
mod tests {
    use std::{
        ffi::CString,
        io,
        net::TcpStream,
        os::unix::{ffi::OsStrExt as _, net::UnixDatagram},
        path::PathBuf,
        process::Command,
    };

    use super::*;
    use crate::{claims, pin, procs};

    const CHILD: &str = "EXPLSM_SANDBOX_TEST_DIR";

    /// Landlock can't be undone, so the checks run in a process of their own.
    #[test]
    fn restricts_the_daemon() {
        let dir = std::env::temp_dir().join(format!("explsm-sandbox-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        for d in ["policy.d", "claims.d", "state", "pins", "other"] {
            fs::create_dir_all(dir.join(d)).unwrap();
        }
        fs::write(dir.join("policy.d/a.explsm"), "").unwrap();
        fs::write(dir.join("other/secret"), "s").unwrap();
        fs::write(dir.join("pins/CONFIG"), "").unwrap();
        let out = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "sandbox::tests::child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD, &dir)
            .output()
            .unwrap();
        let _ = fs::remove_dir_all(&dir);
        let text = String::from_utf8_lossy(&out.stdout) + String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "{text}");
        assert!(text.contains("1 passed"), "{text}");
    }

    #[test]
    fn child() {
        let Some(dir) = std::env::var_os(CHILD).map(PathBuf::from) else {
            return;
        };
        let parent = std::os::unix::process::parent_id();
        let parent_exe = fs::read_link(format!("/proc/{parent}/exe")).unwrap();
        // Connected before, like the journal.
        let server = UnixDatagram::bind(dir.join("other/sock")).unwrap();
        let client = UnixDatagram::unbound().unwrap();
        client.connect(dir.join("other/sock")).unwrap();
        procs::start().unwrap();
        let status = restrict(&Paths {
            policy: &dir.join("policy.d"),
            claims: &dir.join("claims.d"),
            state_dir: &dir.join("state"),
            pin_dir: &dir.join("pins"),
        })
        .unwrap();
        if status.starts_with("not") {
            eprintln!("skipped: {status}");
            return;
        }
        let denied =
            |r: io::Result<()>| r.is_err_and(|e| e.kind() == io::ErrorKind::PermissionDenied);

        // Metadata and listings anywhere, reading only explsm's files.
        assert!(fs::read_dir(dir.join("other")).is_ok());
        assert!(fs::metadata(dir.join("other/secret")).is_ok());
        assert!(denied(fs::read(dir.join("other/secret")).map(drop)));
        assert!(fs::read(dir.join("policy.d/a.explsm")).is_ok());
        assert!(fs::read("/etc/passwd").is_ok());
        assert!(fs::read("/sys/devices/system/cpu/possible").is_ok());
        assert!(denied(fs::read("/sys/kernel/security/lsm").map(drop)));

        // Labels, watches and the journal still work.
        let secret = CString::new(dir.join("other/secret").as_os_str().as_bytes()).unwrap();
        let ret = unsafe {
            libc::setxattr(
                secret.as_ptr(),
                c"user.explsm".as_ptr(),
                b"x".as_ptr().cast(),
                1,
                0,
            )
        };
        let e = io::Error::last_os_error();
        assert!(
            ret == 0 || e.raw_os_error() == Some(libc::EOPNOTSUPP),
            "setxattr: {e}"
        );
        let ino = unsafe { libc::inotify_init1(libc::IN_CLOEXEC) };
        assert!(ino >= 0);
        let other = CString::new(dir.join("other").as_os_str().as_bytes()).unwrap();
        assert!(unsafe { libc::inotify_add_watch(ino, other.as_ptr(), libc::IN_CREATE) } >= 0);
        client.send(b"line").unwrap();
        let mut buf = [0; 8];
        assert_eq!(server.recv(&mut buf).unwrap(), 4);
        assert!(denied(
            UnixDatagram::unbound()
                .unwrap()
                .connect(dir.join("other/sock"))
        ));

        // Writing claims and state, nothing else.
        let appended = claims::append(&dir.join("claims.d"), "me", "a\n").unwrap();
        let again = claims::append(&dir.join("claims.d"), "me", "b\n").unwrap();
        again.undo().unwrap();
        appended.undo().unwrap();
        let ids = dir.join("state/ids");
        fs::write(ids.with_extension("new"), "a\n").unwrap();
        fs::rename(ids.with_extension("new"), &ids).unwrap();
        assert!(denied(fs::write(dir.join("other/new"), "")));
        assert!(denied(fs::remove_file(dir.join("other/secret"))));
        assert!(denied(fs::write(dir.join("policy.d/b.explsm"), "")));

        // Unloading removes the pins and their directory.
        assert!(pin::unload(&dir.join("pins")).unwrap());

        // No programs, no TCP.
        assert!(denied(Command::new("/bin/true").status().map(drop)));
        assert!(denied(TcpStream::connect("127.0.0.1:9").map(drop)));

        // Other processes' exe only through the helper.
        assert!(fs::read_link(format!("/proc/{parent}/exe")).is_err());
        assert_eq!(procs::exe(parent).unwrap().path, parent_exe);
    }
}
