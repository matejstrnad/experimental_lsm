//! Turning ring buffer events into log lines.
//!
//! ```text
//! exec   pid=… tid=… uid=… proc=ssh comm=ssh app=ssh exe=/usr/bin/ssh
//! deny   pid=… … subject=unconfined owner=ssh open(r) need=read /home/me/.ssh/id_ed25519
//! audit  pid=… … subject=unconfined owner=ssh unlink need=delete /home/me/.ssh/known_hosts
//! deny   pid=… … subject=ssh owner=ssh->unconfined rename need=xdev /home/me/.ssh/a -> /tmp/a
//! deny   pid=… … subject=unconfined owner=ssh removexattr need=label /home/me/.ssh
//! deny   pid=… … subject=unconfined(terminal) owner=ssh open(r) need=read /home/me/.ssh/config
//! claim  pid=… … app=claude path=/home/me/.claude
//! deny   pid=… … app=claude exe=/usr/bin/claude dropped=LD_PRELOAD
//! deny   pid=… … app=claude exe=/usr/bin/claude dropped=userns
//! deny   pid=… … subject=unconfined owner=claude ptrace(attach) need=tamper target=4242
//! deny   pid=… … subject=unconfined owner=claude signal(SIGSEGV) need=tamper target=4242
//! deny   pid=… … subject=unconfined owner=claude rlimit(RLIMIT_CPU) need=tamper target=4242
//! deny   pid=… … subject=unconfined owner=claude exe_dir need=tamper /home/me/.local/share/claude/versions/x
//! deny   pid=… … subject=unconfined owner=explsmd bpf(map) need=self id=17
//! ```
//!
//! `exec` lines are only written with `explsmd --log-execs`. `deny` lines
//! were refused, `audit` lines would have been in enforce mode.
//! Under systemd the same information also goes to the journal as `EXPLSM_*`
//! fields (see `journal.rs`), which `explsmctl log` and `learn` query.

use std::{collections::HashMap, fs, path::PathBuf};

use explsm_common::{
    ACTION_DENY, APP_UNCONFINED, EvPath, Event, EventKind, FileKey, Op, REASON_CROSS, REASON_ENV,
    REASON_LABEL, REASON_SELF, REASON_TAMPER, TF_TERMINAL, env_var, own_kind, path_kind, perm,
};
use explsm_policy::{IdTable, resolve::show_key};

/// Kernel device number → where its filesystem root is mounted, to turn the
/// name chains of inode hooks into full paths.
pub struct Mounts(HashMap<u32, String>);

impl Mounts {
    pub fn read() -> Self {
        let mut map = HashMap::new();
        let Ok(info) = fs::read_to_string("/proc/self/mountinfo") else {
            return Self(map);
        };
        for line in info.lines() {
            let f: Vec<_> = line.split(' ').collect();
            if f.len() < 5 || f[3] != "/" {
                continue;
            }
            let Some((major, minor)) = f[2].split_once(':') else {
                continue;
            };
            let (Ok(major), Ok(minor)) = (major.parse::<u32>(), minor.parse::<u32>()) else {
                continue;
            };
            map.entry((major << 20) | minor)
                .or_insert_with(|| unescape(f[4]));
        }
        Self(map)
    }

    /// Whether `dev` has a known mount; `0` (exec events) needs none.
    pub fn knows(&self, dev: u32) -> bool {
        dev == 0 || self.0.contains_key(&dev)
    }
}

/// mountinfo escapes space, tab, newline and backslash as `\ooo`.
fn unescape(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\'
            && i + 4 <= b.len()
            && b[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c))
            && let Ok(v) = u8::from_str_radix(&s[i + 1..i + 4], 8)
        {
            out.push(v);
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn cstr_field(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn render_path(p: &EvPath, file: &FileKey, mounts: &Mounts) -> String {
    if p.len < 0 {
        return format!(
            "<{} unresolved: {}>",
            show_key(file),
            std::io::Error::from_raw_os_error(-p.len)
        );
    }
    let len = (p.len as usize).min(p.buf.len());
    match p.kind {
        path_kind::FULL => cstr_field(&p.buf[..len]),
        path_kind::CHAIN | path_kind::CHAIN_COMPLETE => {
            let names: Vec<_> = p.buf[..len]
                .split(|b| *b == 0)
                .filter(|n| !n.is_empty())
                .map(String::from_utf8_lossy)
                .collect();
            let rel = names.into_iter().rev().collect::<Vec<_>>().join("/");
            if p.kind == path_kind::CHAIN {
                format!("…/{rel}")
            } else {
                match mounts.0.get(&file.dev).map(String::as_str) {
                    Some("/") => format!("/{rel}"),
                    Some(mnt) => format!("{mnt}/{rel}"),
                    None => format!("<dev {}>/{rel}", show_key(file)),
                }
            }
        }
        _ => "<no path>".into(),
    }
}

fn perm_names(bits: u32) -> String {
    let names: Vec<_> = perm::NAMES
        .iter()
        .filter(|(bit, _)| bits & bit != 0)
        .map(|(_, n)| *n)
        .collect();
    names.join(",")
}

fn access_mode(flags: u32) -> &'static str {
    match flags as i32 & libc::O_ACCMODE {
        libc::O_RDONLY => "(r)",
        libc::O_WRONLY => "(w)",
        _ => "(rw)",
    }
}

/// An event, rendered.
#[derive(Clone)]
pub struct Line {
    /// The log line.
    pub text: String,
    /// syslog priority: warning for denials, notice for audits, info else.
    pub priority: u8,
    /// Structured journal fields (`EXPLSM_*`), with names instead of ids:
    /// ids are not stable across daemon restarts.
    pub fields: Vec<(&'static str, String)>,
}

/// The folder a claim event's new folder was created in, and its name.
pub fn claim_path(ev: &Event, parents: &HashMap<FileKey, (u32, PathBuf)>) -> Option<PathBuf> {
    let name = render_path(&ev.path, &ev.file, &Mounts(HashMap::new()));
    if name.is_empty() || name.contains('/') || name == "." || name == ".." {
        return None;
    }
    parents.get(&ev.file).map(|(_, dir)| dir.join(name))
}

/// The signals the BPF side reports: those that dump core.
fn signal_name(sig: u32) -> &'static str {
    match sig {
        3 => "(SIGQUIT)",
        4 => "(SIGILL)",
        5 => "(SIGTRAP)",
        6 => "(SIGABRT)",
        7 => "(SIGBUS)",
        8 => "(SIGFPE)",
        11 => "(SIGSEGV)",
        24 => "(SIGXCPU)",
        25 => "(SIGXFSZ)",
        31 => "(SIGSYS)",
        _ => "",
    }
}

fn rlimit_name(resource: u32) -> &'static str {
    const NAMES: [&str; 16] = [
        "(RLIMIT_CPU)",
        "(RLIMIT_FSIZE)",
        "(RLIMIT_DATA)",
        "(RLIMIT_STACK)",
        "(RLIMIT_CORE)",
        "(RLIMIT_RSS)",
        "(RLIMIT_NPROC)",
        "(RLIMIT_NOFILE)",
        "(RLIMIT_MEMLOCK)",
        "(RLIMIT_AS)",
        "(RLIMIT_LOCKS)",
        "(RLIMIT_SIGPENDING)",
        "(RLIMIT_MSGQUEUE)",
        "(RLIMIT_NICE)",
        "(RLIMIT_RTPRIO)",
        "(RLIMIT_RTTIME)",
    ];
    NAMES.get(resource as usize).copied().unwrap_or("")
}

/// The subject's name; unconfined tasks below a terminal are marked.
fn subject_name(ev: &Event, names: &IdTable) -> String {
    let name = names.name(ev.subject);
    if ev.subject == APP_UNCONFINED && ev.task_flags & TF_TERMINAL != 0 {
        format!("{name}(terminal)")
    } else {
        name.to_string()
    }
}

pub fn render(
    ev: &Event,
    names: &IdTable,
    mounts: &Mounts,
    parents: &HashMap<FileKey, (u32, PathBuf)>,
) -> Line {
    let proc = cstr_field(&ev.proc_comm);
    let common = format!(
        "pid={} tid={} uid={} proc={proc} comm={}",
        ev.pid,
        ev.tid,
        ev.uid,
        cstr_field(&ev.comm)
    );
    let path = render_path(&ev.path, &ev.file, mounts);
    let mut fields = vec![
        ("EXPLSM_PID", ev.pid.to_string()),
        ("EXPLSM_UID", ev.uid.to_string()),
        ("EXPLSM_PROC", proc),
        ("EXPLSM_SUBJECT", names.name(ev.subject).to_string()),
    ];
    if ev.task_flags & TF_TERMINAL != 0 {
        fields.push(("EXPLSM_TERMINAL", "1".into()));
    }
    if ev.kind == EventKind::Exec as u32 && ev.reason == REASON_ENV {
        let vars: Vec<_> = env_var::NAMES
            .iter()
            .filter(|(bit, _)| ev.flags & bit != 0)
            .map(|(_, n)| n.replace(' ', "_"))
            .collect();
        let vars = vars.join(",");
        fields.push(("EXPLSM_KIND", "exec".into()));
        fields.push(("EXPLSM_PATH", path.clone()));
        fields.push(("EXPLSM_DROPPED", vars.clone()));
        return Line {
            text: format!(
                "deny   {common} app={} exe={path} dropped={vars}",
                names.name(ev.subject)
            ),
            priority: 4,
            fields,
        };
    }
    if ev.kind == EventKind::Exec as u32 {
        fields.push(("EXPLSM_KIND", "exec".into()));
        fields.push(("EXPLSM_PATH", path.clone()));
        return Line {
            text: format!("exec   {common} app={} exe={path}", names.name(ev.subject)),
            priority: 6,
            fields,
        };
    }
    if ev.kind == EventKind::Claim as u32 {
        let path = claim_path(ev, parents)
            .map_or_else(|| format!("<{}>/{path}", show_key(&ev.file)), |p| p.display().to_string());
        fields.push(("EXPLSM_KIND", "claim".into()));
        fields.push(("EXPLSM_PATH", path.clone()));
        return Line {
            text: format!("claim  {common} app={} path={path}", names.name(ev.subject)),
            priority: 5,
            fields,
        };
    }
    if ev.kind != EventKind::Access as u32 {
        return Line {
            text: format!("?      unknown event kind {}", ev.kind),
            priority: 4,
            fields: Vec::new(),
        };
    }

    let deny = ev.action == ACTION_DENY;
    let verb = if deny { "deny  " } else { "audit " };
    let op = Op::from_u32(ev.op);
    let op_name = op.map_or("?", Op::name);
    let mode = match op {
        Some(Op::Open) => access_mode(ev.flags),
        // PTRACE_MODE_ATTACH
        Some(Op::Ptrace) if ev.flags & 2 != 0 => "(attach)",
        Some(Op::Ptrace) => "(read)",
        Some(Op::Bpf) => match ev.flags {
            own_kind::MAP => "(map)",
            own_kind::PROG => "(prog)",
            own_kind::LINK => "(link)",
            _ => "",
        },
        Some(Op::Signal) => signal_name(ev.flags),
        Some(Op::Rlimit) => rlimit_name(ev.flags),
        _ => "",
    };
    let (owner, need) = match ev.reason {
        REASON_CROSS => (
            format!("{}->{}", names.name(ev.owner), names.name(ev.owner2)),
            "xdev".to_string(),
        ),
        REASON_LABEL => (names.name(ev.owner).to_string(), "label".to_string()),
        REASON_TAMPER => (names.name(ev.owner).to_string(), "tamper".to_string()),
        REASON_SELF => (names.name(ev.owner).to_string(), "self".to_string()),
        _ => (names.name(ev.owner).to_string(), perm_names(ev.perms)),
    };
    // A process, not a path: the target's pid, or the object's id.
    let path = match op {
        Some(Op::Ptrace | Op::Traceme | Op::Signal | Op::Rlimit) => format!("target={}", ev.owner2),
        Some(Op::Bpf) => format!("id={}", ev.owner2),
        _ => path,
    };
    let mut text = format!(
        "{verb} {common} subject={} owner={owner} {op_name}{mode} need={need} {path}",
        subject_name(ev, names)
    );
    fields.extend([
        ("EXPLSM_KIND", "access".to_string()),
        ("EXPLSM_ACTION", verb.trim_end().to_string()),
        ("EXPLSM_OWNER", names.name(ev.owner).to_string()),
        ("EXPLSM_OP", op_name.to_string()),
        ("EXPLSM_NEED", need),
        ("EXPLSM_PATH", path),
    ]);
    if ev.reason == REASON_CROSS {
        fields.push(("EXPLSM_OWNER2", names.name(ev.owner2).to_string()));
    }
    if matches!(op, Some(Op::Ptrace | Op::Traceme | Op::Signal | Op::Rlimit)) {
        fields.push(("EXPLSM_TARGET", ev.owner2.to_string()));
    }
    if ev.path2.kind != path_kind::NONE {
        let path2 = render_path(&ev.path2, &ev.file, mounts);
        text.push_str(" -> ");
        text.push_str(&path2);
        fields.push(("EXPLSM_PATH2", path2));
    }
    Line {
        text,
        priority: if deny { 4 } else { 5 },
        fields,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unescapes_mountinfo() {
        assert_eq!(unescape(r"/mnt/a\040b"), "/mnt/a b");
        assert_eq!(unescape(r"/plain"), "/plain");
        assert_eq!(unescape(r"/end\04"), r"/end\04");
    }

    #[test]
    fn renders_chains() {
        let mut mounts = Mounts(HashMap::new());
        mounts.0.insert(1 << 20, "/".into());
        mounts.0.insert(2 << 20, "/home".into());
        let mut p = EvPath {
            kind: path_kind::CHAIN_COMPLETE,
            len: 0,
            buf: [0; explsm_common::PATH_LEN],
        };
        let chain = b"c\0b\0a\0";
        p.buf[..chain.len()].copy_from_slice(chain);
        p.len = chain.len() as i32;
        let key = |major: u32| FileKey {
            dev: major << 20,
            _pad: 0,
            ino: 1,
        };
        assert_eq!(render_path(&p, &key(1), &mounts), "/a/b/c");
        assert_eq!(render_path(&p, &key(2), &mounts), "/home/a/b/c");
        p.kind = path_kind::CHAIN;
        assert_eq!(render_path(&p, &key(1), &mounts), "…/a/b/c");
    }

    #[test]
    fn renders_access_events_with_fields() {
        use explsm_common::{ACTION_AUDIT, REASON_PERMS};
        use explsm_policy::{IdTable, Sources, check};

        let ids = check(
            &Sources::single("t", "app ssh { exe \"/s\" }\napp backup { exe \"/b\" }"),
            &IdTable::default(),
        )
        .unwrap()
        .ids;
        let mut ev: Event = unsafe { std::mem::zeroed() };
        ev.kind = EventKind::Access as u32;
        ev.pid = 7;
        ev.tid = 7;
        ev.uid = 1000;
        ev.subject = 2;
        ev.owner = 1;
        ev.op = Op::Unlink as u32;
        ev.perms = perm::DELETE;
        ev.action = ACTION_AUDIT;
        ev.reason = REASON_PERMS;
        ev.proc_comm[..2].copy_from_slice(b"rm");
        ev.comm[..2].copy_from_slice(b"rm");
        ev.path.kind = path_kind::FULL;
        let p = b"/home/me/.ssh/known_hosts";
        ev.path.buf[..p.len()].copy_from_slice(p);
        ev.path.len = p.len() as i32;
        let line = render(&ev, &ids, &Mounts(HashMap::new()), &HashMap::new());
        assert_eq!(
            line.text,
            "audit  pid=7 tid=7 uid=1000 proc=rm comm=rm subject=backup owner=ssh \
             unlink need=delete /home/me/.ssh/known_hosts"
        );
        assert_eq!(line.priority, 5);
        let field = |k: &str| {
            line.fields
                .iter()
                .find(|(key, _)| *key == k)
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(field("EXPLSM_KIND"), Some("access"));
        assert_eq!(field("EXPLSM_ACTION"), Some("audit"));
        assert_eq!(field("EXPLSM_SUBJECT"), Some("backup"));
        assert_eq!(field("EXPLSM_OWNER"), Some("ssh"));
        assert_eq!(field("EXPLSM_NEED"), Some("delete"));
        assert_eq!(field("EXPLSM_PATH2"), None);

        ev.subject = APP_UNCONFINED;
        ev.task_flags = TF_TERMINAL;
        let line = render(&ev, &ids, &Mounts(HashMap::new()), &HashMap::new());
        assert!(line.text.contains(" subject=unconfined(terminal) "), "{}", line.text);
        assert!(line.fields.contains(&("EXPLSM_TERMINAL", "1".into())));
    }

    #[test]
    fn renders_claims() {
        use explsm_policy::{IdTable, Sources, check};

        let ids = check(&Sources::single("t", "app claude { exe \"/c\" }"), &IdTable::default())
            .unwrap()
            .ids;
        let mut ev: Event = unsafe { std::mem::zeroed() };
        ev.kind = EventKind::Claim as u32;
        ev.pid = 7;
        ev.tid = 7;
        ev.uid = 1000;
        ev.subject = 1;
        ev.file = FileKey { dev: 1, _pad: 0, ino: 5 };
        ev.path.kind = path_kind::FULL;
        ev.path.buf[..7].copy_from_slice(b".claude");
        ev.path.len = 8;
        let parents = [(ev.file, (1000, PathBuf::from("/home/me")))].into();
        let line = render(&ev, &ids, &Mounts(HashMap::new()), &parents);
        assert_eq!(
            line.text,
            "claim  pid=7 tid=7 uid=1000 proc= comm= app=claude path=/home/me/.claude"
        );
        assert_eq!(claim_path(&ev, &parents), Some(PathBuf::from("/home/me/.claude")));
    }
}
