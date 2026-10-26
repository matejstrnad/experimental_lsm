//! explsmd: the enforcement engine, configured by the policy language and
//! run as a system service, with prompts through each user's explsm-agent.
//!
//! The policy (`/etc/explsm/policy.d/*.explsm`, see `docs/dsl.md`) is
//! compiled and written into the BPF maps (`state.rs`). It is reloaded on
//! SIGHUP or D-Bus `Reload` (`dbus.rs`), and its paths are resolved again
//! when the directories holding them change (`watch.rs`). Every operation on
//! protected data that the policy does not allow is logged, one line each
//! (`events.rs`), to stdout or the journal (`journal.rs`), and denied for
//! owners in enforce mode. Denials and folders apps create are put to the
//! user's agent, whose answers become grants and claims (`desk.rs`).
//! Repeated read-only ptrace probes (process monitors) are merged
//! (`quiet.rs`).
//! Diagnostics go to stderr. Must run as root.
//!
//! Programs and maps are pinned (`pin.rs`): explsm keeps enforcing when the
//! daemon exits, and the next daemon takes over. `explsmctl unload` (D-Bus
//! `Unload`, or `explsmd --unload` when no daemon runs) removes them; nothing
//! else can, root included.
//!
//! Once set up, the daemon puts itself in a Landlock sandbox (`sandbox.rs`)
//! and reads other processes' `/proc` entries through a helper outside it
//! (`procs.rs`).

mod claims;
mod dbus;
mod desk;
mod events;
mod grants;
mod journal;
mod labels;
mod pin;
mod procs;
mod prompts;
mod quiet;
mod sandbox;
mod seed;
mod state;
mod watch;

use std::{collections::HashMap, fs, path::PathBuf, pin::pin, ptr, time::Duration};

use anyhow::{Context as _, Result, bail};
use aya::{
    Btf, Ebpf, EbpfLoader,
    maps::{Array, RingBuf},
    programs::{Lsm, ProgramError, links::FdLink},
};
use clap::Parser;
use explsm_common::{CFG_LAYOUT, Event, LAYOUT_VERSION, OwnKey, own_kind};
use futures_util::StreamExt as _;
use tokio::{
    io::{Interest, unix::AsyncFd},
    signal::unix::{SignalKind, signal},
    sync::mpsc,
    time::{Instant, sleep_until},
};

use crate::{
    dbus::Request,
    desk::{Answered, Desk},
    events::Mounts,
    state::{Options, STAT_NAMES, State},
    watch::Watcher,
};

static EXPLSM: &[u8] = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/explsm"));

/// Programs that check accesses. Attached after seeding, so running apps
/// have their identity before anything they do is looked at.
const ACCESS_HOOKS: &[&str] = &[
    "file_open",
    "inode_create",
    "inode_mkdir",
    "inode_mknod",
    "inode_symlink",
    "inode_link",
    "inode_unlink",
    "inode_rmdir",
    "inode_rename",
    "inode_setattr",
    "inode_setxattr",
    "inode_removexattr",
    "inode_set_acl",
    "inode_remove_acl",
    "ptrace_access_check",
    "ptrace_traceme",
    "task_kill",
    "task_setrlimit",
    "bpf_map",
    "bpf_prog",
    "bpf",
];

/// Quiet time after a change in a watched directory before resolving again,
/// so a package update that touches many files causes one rescan.
const SETTLE: Duration = Duration::from_millis(500);

#[derive(Parser)]
#[command(about = "explsm daemon")]
struct Cli {
    /// Policy directory (`*.explsm` files), or a single policy file.
    #[arg(long, default_value = explsm_policy::POLICY_DIR)]
    policy: PathBuf,
    /// Directory the answers to prompts are written to, read after the
    /// policy.
    #[arg(long, default_value = explsm_policy::CLAIMS_DIR)]
    claims: PathBuf,
    /// The explsm-agent executable. Only processes running it may answer
    /// prompts.
    #[arg(long, default_value = "/usr/libexec/explsm-agent")]
    agent: PathBuf,
    /// Where the daemon keeps what it must remember, e.g. declined claims.
    #[arg(long, default_value = "/var/lib/explsm")]
    state_dir: PathBuf,
    /// Log every exec that gives a process an app identity (`exec` lines).
    #[arg(long)]
    log_execs: bool,
    /// Don't give already running processes of the apps their identity.
    #[arg(long, hide = true)]
    no_seed: bool,
    /// Turn off the @root bypass even if the policy enables it.
    #[arg(long)]
    no_root_bypass: bool,
    /// Don't serve the D-Bus API.
    #[arg(long)]
    no_dbus: bool,
    // For tests and development; hidden from --help.
    /// Where the programs and maps are pinned.
    #[arg(long, default_value = pin::PIN_DIR, hide = true)]
    pin_dir: PathBuf,
    /// Don't keep explsm loaded after the daemon exits: pin the maps in a
    /// directory of this run only and detach everything on exit.
    #[arg(long, hide = true)]
    no_pin: bool,
    /// Don't protect explsm's own files and pins (for development builds).
    #[arg(long, hide = true)]
    no_self_protect: bool,
    /// Don't sandbox the daemon with Landlock once it is set up.
    #[arg(long, hide = true)]
    no_landlock: bool,
    /// Where explsmd is installed: given the daemon identity and protected.
    /// Defaults to the running executable.
    #[arg(long, hide = true)]
    daemon: Option<PathBuf>,
    /// Seconds over which repeated read-only ptrace reports of one program
    /// on one app are merged; 0 logs each.
    #[arg(long, default_value_t = quiet::WINDOW.as_secs(), hide = true)]
    quiet_window: u64,
    /// Remove the labels and the pins and exit, for when no daemon runs.
    /// `explsmctl unload` asks a running daemon instead.
    #[arg(long)]
    unload: bool,
}

/// Keep the useful end of a verifier log instead of thousands of lines.
fn verifier_tail(e: ProgramError) -> anyhow::Error {
    match e {
        ProgramError::LoadError {
            io_error,
            verifier_log,
        } => {
            let log = verifier_log.to_string();
            let lines: Vec<_> = log.lines().collect();
            let tail = lines[lines.len().saturating_sub(25)..].join("\n    ");
            anyhow::anyhow!("{io_error}\n    verifier log tail:\n    {tail}")
        }
        other => other.into(),
    }
}

/// Load and attach `prog`, keep its link, and note the ids of both.
fn attach(
    ebpf: &mut Ebpf,
    btf: &Btf,
    pins: &mut pin::Pins,
    own: &mut HashMap<OwnKey, u32>,
    prog: &str,
) -> Result<()> {
    let p: &mut Lsm = ebpf
        .program_mut(prog)
        .with_context(|| format!("program {prog} missing"))?
        .try_into()?;
    p.load(prog, btf)
        .map_err(verifier_tail)
        .with_context(|| format!("loading {prog}"))?;
    let link = p.attach().with_context(|| format!("attaching {prog}"))?;
    let id = p.info()?.id();
    own.insert(OwnKey { kind: own_kind::PROG, id }, 1);
    let link = FdLink::from(p.take_link(link)?);
    let id = pins.link(prog, link)?;
    own.insert(OwnKey { kind: own_kind::LINK, id }, 1);
    Ok(())
}

/// Refuse maps pinned by a build of another layout.
fn check_layout(ebpf: &mut Ebpf, dir: &std::path::Path) -> Result<()> {
    let mut config: Array<_, u32> = Array::try_from(ebpf.map_mut("CONFIG").context("CONFIG")?)?;
    match config.get(&CFG_LAYOUT, 0)? {
        0 => config.set(CFG_LAYOUT, LAYOUT_VERSION, 0)?,
        LAYOUT_VERSION => {}
        other => bail!(
            "the maps pinned in {} are of another explsm version (layout {other}, this is \
             {LAYOUT_VERSION}); run `explsmctl unload` or reboot first",
            dir.display()
        ),
    }
    Ok(())
}

/// `--unload` with no daemon running: take the labels off the policy's
/// roots, then remove the pins. Only allowed to the installed explsmd.
fn unload_standalone(cli: &Cli) -> Result<()> {
    let sources = explsm_policy::Sources::load_with_claims(&cli.policy, Some(&cli.claims))
        .with_context(|| format!("reading {}", cli.policy.display()));
    let roots = sources.ok().and_then(|sources| {
        let policy = explsm_policy::check(&sources, &Default::default()).ok()?;
        let (users, _) = explsm_policy::users::system(policy.users.as_deref()).ok()?;
        explsm_policy::resolve::resolve(&policy, &users).ok()
    });
    match roots {
        Some(resolved) => {
            for root in &resolved.roots {
                if let Err(e) = labels::remove_label(&root.path) {
                    eprintln!("explsmd: warning: unlabelling {}: {e}", root.path.display());
                }
            }
        }
        None => eprintln!("explsmd: warning: the policy does not load; labels are left"),
    }
    match pin::unload(&cli.pin_dir) {
        Ok(true) => {
            eprintln!("explsmd: unloaded: removed {}", cli.pin_dir.display());
            Ok(())
        }
        Ok(false) => {
            eprintln!("explsmd: nothing pinned in {}", cli.pin_dir.display());
            Ok(())
        }
        Err(e) if e.raw_os_error() == Some(libc::EACCES) => Err(anyhow::anyhow!(
            "removing {}: {e}; only the installed explsmd may (is this it?)",
            cli.pin_dir.display()
        )),
        Err(e) => Err(e).with_context(|| format!("removing {}", cli.pin_dir.display())),
    }
}

fn reload(state: &mut State) -> explsm_ipc::ReloadReply {
    let reply = state.reload();
    if reply.ok {
        eprintln!("explsmd: policy reloaded: {}", reply.summary);
    } else {
        eprintln!("explsmd: reload failed: {}\n{}", reply.summary, reply.diagnostics);
    }
    reply
}

fn sync_watches(watcher: &mut Watcher, state: &State) {
    let mut wanted = watch::wanted(state.watches(), state.policy_path());
    // The agent's exe is resolved again like the policy's.
    if let (Some(dir), Some(name)) = (state.agent_path().parent(), state.agent_path().file_name()) {
        wanted
            .entry(dir.to_path_buf())
            .or_default()
            .insert((glob::Pattern::escape(&name.to_string_lossy()), watch::Purpose::Resolve));
    }
    for w in watcher.sync(&wanted) {
        eprintln!("explsmd: warning: {w}");
    }
}

/// `NameOwnerChanged` of the bus.
async fn fdo_names(conn: &zbus::Connection) -> zbus::Result<zbus::fdo::NameOwnerChangedStream> {
    zbus::fdo::DBusProxy::new(conn)
        .await?
        .receive_name_owner_changed()
        .await
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    if unsafe { libc::geteuid() } != 0 {
        bail!("must run as root (BPF LSM programs need CAP_BPF + CAP_MAC_ADMIN)");
    }
    if cli.unload {
        return unload_standalone(&cli);
    }
    let lsms = fs::read_to_string("/sys/kernel/security/lsm")?;
    if !lsms.split(',').any(|s| s.trim() == "bpf") {
        bail!("the bpf LSM is not active (lsm list: {})", lsms.trim());
    }
    // Both exist from the start, so the sandbox can let the daemon write
    // into them.
    for dir in [&cli.state_dir, &cli.claims] {
        fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let daemon = match &cli.daemon {
        Some(p) => p.clone(),
        None => std::env::current_exe().context("finding the explsmd executable")?,
    };

    // Without pinning, the maps still go to bpffs (their definitions ask
    // for it), in a directory of this run that is removed on exit.
    let pin_dir = if cli.no_pin {
        PathBuf::from(format!("{}-run{}", cli.pin_dir.display(), std::process::id()))
    } else {
        cli.pin_dir.clone()
    };
    let mut pins = pin::Pins::new(pin_dir, !cli.no_pin)?;
    let reused = pins.reused();
    // TASK_STORAGE has no Aya userspace type yet; it still loads as an
    // "unsupported" map, which is all the programs need.
    let mut ebpf = EbpfLoader::new()
        .allow_unsupported_maps()
        .default_map_pin_directory(&pins.dir)
        .load(EXPLSM)
        .with_context(|| {
            format!(
                "loading explsm object{}",
                if reused {
                    " (into the pinned maps; if access is denied, this explsmd is not the \
                     installed one: `explsmctl unload` or reboot)"
                } else {
                    ""
                }
            )
        })?;
    check_layout(&mut ebpf, &pins.dir)?;
    let mut own = HashMap::new();
    for id in pins.map_ids()? {
        own.insert(OwnKey { kind: own_kind::MAP, id }, 1);
    }
    // Fills the maps and labels the roots, before the xattr hooks are
    // attached (they would let the daemon through anyway).
    let mut state = State::new(
        ebpf,
        Options {
            policy: cli.policy.clone(),
            claims: Some(cli.claims.clone()),
            agent: cli.agent.clone(),
            no_root_bypass: cli.no_root_bypass,
            daemon,
            state_dir: cli.state_dir.clone(),
            pin_dir: pins.dir.clone(),
            self_protect: !cli.no_self_protect,
            reused,
            log_execs: cli.log_execs,
        },
    )?;
    eprintln!("explsmd: policy loaded: {}", state.summary());

    let btf = Btf::from_sys_fs()?;
    attach(&mut state.ebpf, &btf, &mut pins, &mut own, "task_alloc")?;
    attach(&mut state.ebpf, &btf, &mut pins, &mut own, "bprm_committed_creds")?;
    if cli.no_seed {
        // The daemon itself needs its identity for its own files.
        let me: HashMap<_, _> = state
            .exes()
            .into_iter()
            .filter(|(_, app)| *app == explsm_common::APP_DAEMON)
            .collect();
        state.seed(&me)?;
    } else {
        state.seed(&state.exes())?;
        state.seed_terminals()?;
        state.seeding = true;
    }
    for prog in ACCESS_HOOKS {
        attach(&mut state.ebpf, &btf, &mut pins, &mut own, prog)?;
    }
    state.set_own_ids(&own)?;
    // Forked while there is one thread and no signal handler yet.
    if !cli.no_landlock
        && let Err(e) = procs::start()
    {
        eprintln!("explsmd: warning: /proc helper: {e}; processes found from now on can't be seeded");
    }

    let ring = RingBuf::try_from(state.ebpf.take_map("EVENTS").context("EVENTS")?)?;
    // SAFETY: the ring buffer owns its map fd and keeps it open while the
    // AsyncFd owns it.
    let mut ring = unsafe { AsyncFd::register_with_interest(ring, Interest::READABLE) }
        .map_err(|e| e.into_parts().1)?;
    let mut term = signal(SignalKind::terminate())?;
    let mut int = signal(SignalKind::interrupt())?;
    let mut hup = signal(SignalKind::hangup())?;
    let mut mounts = Mounts::read();
    let sink = journal::Sink::from_env();
    let mut watcher = Watcher::new().context("inotify")?;
    sync_watches(&mut watcher, &state);

    let (tx, mut requests) = mpsc::channel(8);
    let bus = if cli.no_dbus {
        None
    } else {
        match dbus::serve(tx).await {
            Ok(conn) => Some(conn),
            Err(e) => {
                eprintln!("explsmd: warning: D-Bus API not available: {e}");
                None
            }
        }
    };
    // Agents leaving the bus end their user's session grants.
    let mut owner_changes = match &bus {
        Some(conn) => match fdo_names(conn).await {
            Ok(s) => Some(s),
            Err(e) => {
                eprintln!("explsmd: warning: not watching for agents leaving: {e}");
                None
            }
        },
        None => None,
    };
    let (exit_tx, mut exits) = mpsc::unbounded_channel();
    let mut desk = Desk::new(bus.clone(), exit_tx, cli.state_dir.join("declined-claims"));
    let mut quiet = quiet::Quiet::new(Duration::from_secs(cli.quiet_window));
    eprintln!(
        "explsmd: attached{}",
        if pins.keep {
            format!("; pinned in {}", pins.dir.display())
        } else {
            " (Ctrl-C to stop)".into()
        }
    );
    // Connected to the bus and the journal, and nothing else to set up.
    if !cli.no_landlock {
        let paths = sandbox::Paths {
            policy: &cli.policy,
            claims: &cli.claims,
            state_dir: &cli.state_dir,
            pin_dir: &pins.dir,
        };
        match sandbox::restrict(&paths) {
            Ok(status) => eprintln!("explsmd: {status}"),
            Err(e) => eprintln!("explsmd: warning: not sandboxed: {e:#}"),
        }
    }

    let mut rescan_at: Option<Instant> = None;
    let mut unloaded = false;
    loop {
        let rescan = async {
            match rescan_at {
                Some(t) => sleep_until(t).await,
                None => std::future::pending().await,
            }
        };
        let folders_due = desk.new_folders_due();
        let new_folders = async {
            match folders_due {
                Some(t) => sleep_until(t.into()).await,
                None => std::future::pending().await,
            }
        };
        let quiet_due = quiet.due();
        let quiet_ends = async {
            match quiet_due {
                Some(t) => sleep_until(t.into()).await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            guard = ring.readable_mut() => {
                let mut guard = guard?;
                let rb = guard.get_inner_mut();
                while let Some(item) = rb.next() {
                    if item.len() >= size_of::<Event>() {
                        let ev = unsafe { ptr::read_unaligned(item.as_ptr().cast::<Event>()) };
                        if !mounts.knows(ev.file.dev) {
                            mounts = Mounts::read();
                        }
                        let line = events::render(
                            &ev,
                            &state.policy.ids,
                            &mounts,
                            state.claim_parents(),
                        );
                        if quiet.admit(&ev, &line, std::time::Instant::now()) {
                            sink.emit(&line);
                        }
                        desk.event(&state, &ev, &line);
                    }
                }
                guard.clear_ready();
            }
            changes = watcher.next() => {
                let changes = changes.context("inotify")?;
                for path in &changes.policy {
                    eprintln!(
                        "explsmd: {} changed; `explsmctl load` (or SIGHUP) applies it",
                        PathBuf::from(path).display()
                    );
                }
                if changes.resolve {
                    rescan_at = Some(Instant::now() + SETTLE);
                }
            }
            () = pin!(rescan) => {
                rescan_at = None;
                if let Err(e) = state.rescan() {
                    eprintln!("explsmd: warning: rescan failed, keeping the old inodes: {e:#}");
                }
                sync_watches(&mut watcher, &state);
            }
            Some(req) = requests.recv() => match req {
                Request::Status(reply) => {
                    let mut status = state.status();
                    status.temp_grants = desk.temp.status(&state.policy.ids);
                    status.agents = desk.agents();
                    let _ = reply.send(status);
                }
                Request::Reload(reply) => {
                    let _ = reply.send(reload(&mut state));
                    sync_watches(&mut watcher, &state);
                }
                Request::Unload(reply) => {
                    let mut notes = state.unlabel_all();
                    match pin::unload(&pins.dir) {
                        Ok(_) => notes.insert(0, format!("removed {}", pins.dir.display())),
                        Err(e) => notes.insert(0, format!("removing {}: {e}", pins.dir.display())),
                    }
                    eprintln!("explsmd: unloaded: {}", notes.join("; "));
                    let _ = reply.send(notes.join("\n"));
                    unloaded = true;
                    break;
                }
                Request::Register { connection, uid, pid, pidfd, reply } => {
                    let _ = reply.send(desk.register(&state, connection, uid, pid, pidfd));
                }
                Request::Answer { connection, uid, id, choice, reply } => {
                    let answered = desk.answer(&mut state, &connection, uid, id, &choice);
                    if matches!(answered, Ok(Answered { reloaded: true })) {
                        sync_watches(&mut watcher, &state);
                    }
                    let _ = reply.send(answered.map(|_| ()));
                }
            },
            // The pidfd goes only after the grant: until then the pid can't
            // be reused by another process.
            Some((pid, _pidfd)) = exits.recv() => desk.process_exited(&mut state, pid),
            () = pin!(new_folders) => desk.new_folders(&state),
            () = pin!(quiet_ends) => {
                for line in quiet.close(std::time::Instant::now()) {
                    sink.emit(&line);
                }
            }
            Some(change) = async {
                match owner_changes.as_mut() {
                    Some(s) => s.next().await,
                    None => std::future::pending().await,
                }
            } => {
                if let Ok(args) = change.args()
                    && args.new_owner().is_none()
                {
                    desk.connection_gone(&mut state, args.name().as_str());
                }
            }
            _ = hup.recv() => {
                reload(&mut state);
                sync_watches(&mut watcher, &state);
            }
            _ = term.recv() => break,
            _ = int.recv() => break,
        }
    }

    for line in quiet.close_all() {
        sink.emit(&line);
    }
    let s = state.stats()?;
    let counters: Vec<_> = STAT_NAMES
        .iter()
        .zip(s)
        .map(|(n, v)| format!("{n}={v}"))
        .collect();
    eprintln!("explsmd: stopping. {}", counters.join(" "));
    if !pins.keep && !unloaded {
        // Dropping the links detaches the programs; the maps go with the pins.
        if let Err(e) = pin::unload(&pins.dir) {
            eprintln!("explsmd: warning: removing {}: {e}", pins.dir.display());
        }
    } else if !unloaded {
        if let Err(e) = state.release_tgid() {
            eprintln!("explsmd: warning: {e:#}");
        }
        eprintln!(
            "explsmd: explsm stays loaded (pinned in {}); `explsmctl unload` removes it",
            pins.dir.display()
        );
    }
    // Let the D-Bus reply of an unload go out before the connection closes.
    // That waits for every clone of the connection to go, the desk's too.
    drop(desk);
    if unloaded && let Some(conn) = bus {
        let _ = tokio::time::timeout(Duration::from_secs(2), conn.graceful_shutdown()).await;
    }
    Ok(())
}
