//! The policy in force, what it resolved to, and what of it is in the BPF
//! maps.
//!
//! A load or reload parses and compiles the policy; a rescan only resolves
//! its paths again (an exe was replaced, a folder appeared). Both end in
//! [`State::apply`], which writes the differences into the maps, so a reload
//! never leaves the maps empty in between.
//!
//! Roots are held open (`O_PATH`). A root that moves away from its path stays
//! protected under its inode, as in Phase 2, as long as it exists and the
//! policy still names the path it came from. The fd also keeps its inode
//! number from being reused while it is in `ROOTS`.
//!
//! `ROOTS` also holds, as owned data: app exes a user could change
//! (readable by all, see `OWNER_EXE`), explsm's own files (owner
//! `APP_DAEMON`) and the pin directory (`OWNER_PINS`).
//!
//! The maps are pinned and outlive a daemon run. A daemon that finds them
//! reads back what is in them, and keeps app ids stable across runs through
//! `<state dir>/ids`, because running tasks keep their id in `TASKS`.

use std::{
    collections::{HashMap, HashSet},
    fs::{self, File},
    hash::Hash,
    io::IsTerminal as _,
    os::{fd::OwnedFd, unix::fs::MetadataExt as _, unix::fs::OpenOptionsExt as _},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context as _, Result, anyhow};
use aya::{
    Ebpf, Pod,
    maps::{Array, HashMap as BpfHashMap, Map, PerCpuArray},
};
use explsm_common::{
    APP_AGENT, APP_DAEMON, AppId, CFG_DAEMON_TGID, CFG_GENERATION, CFG_LOG_EXECS, CFG_ROOT_BYPASS,
    DAEMON_PATH_LEN, DaemonPath, EnvKey, FileKey, GrantKey, MODE_ENFORCE, OWNER_EXE, OWNER_PINS, OwnKey,
    STATS_LEN, TempKey, perm,
};
use explsm_ipc::{AppStatus, FileStatus, GrantStatus, ReloadReply, Status};
use explsm_policy::{
    Compiled, IdTable, Sources, diag,
    resolve::{self, Found, Resolved, key_of, show_key},
    users::{self, User},
};

use crate::{labels, seed};

/// Names of the `STATS` counters, in index order.
pub const STAT_NAMES: [&str; STATS_LEN as usize] = [
    "checks",
    "cache_hits",
    "cache_misses",
    "walk_exhausted",
    "foreign",
    "audited",
    "denied",
    "execs",
    "forks",
    "dropped",
    "env_dropped",
    "tamper",
];

pub struct Options {
    /// Policy directory, or a single policy file.
    pub policy: PathBuf,
    /// Directory of the policy written for answered prompts.
    pub claims: Option<PathBuf>,
    /// The `explsm-agent` executable, given the agent identity.
    pub agent: PathBuf,
    pub no_root_bypass: bool,
    /// Where explsmd is installed: given the daemon identity (also by path,
    /// see `DAEMON_PATH`) and protected.
    pub daemon: PathBuf,
    /// Where state is kept: declined claims and the app ids.
    pub state_dir: PathBuf,
    /// The pin directory.
    pub pin_dir: PathBuf,
    /// Protect explsm's own files and the pins.
    pub self_protect: bool,
    /// The maps are from an earlier run.
    pub reused: bool,
    /// Report every exec that gives a task an app identity.
    pub log_execs: bool,
}

/// Unit files and bus policy of explsm, protected where they are installed.
const OWN_FILES: [&str; 9] = [
    "/etc/systemd/system/explsmd.service",
    "/usr/lib/systemd/system/explsmd.service",
    "/lib/systemd/system/explsmd.service",
    "/etc/systemd/user/explsm-agent.service",
    "/usr/lib/systemd/user/explsm-agent.service",
    "/etc/dbus-1/system.d/org.explsm.Daemon1.conf",
    "/usr/share/dbus-1/system.d/org.explsm.Daemon1.conf",
    "/usr/local/bin/explsmctl",
    "/usr/bin/explsmctl",
];

/// Folders below each home in which a new folder of an app is offered for
/// auto-claim.
pub const CLAIM_PARENTS: [&str; 4] = ["", ".config", ".local/share", ".cache"];

struct Root {
    path: PathBuf,
    app: AppId,
    /// The policy path it was resolved from.
    pattern: String,
    fd: OwnedFd,
    /// No longer found at its path, kept by inode.
    moved: bool,
    /// Value of the label as last written.
    label: Option<String>,
}

/// What is in the maps.
#[derive(Default)]
struct Applied {
    exes: HashMap<FileKey, AppId>,
    roots: HashMap<FileKey, AppId>,
    grants: HashMap<GrantKey, u32>,
    modes: HashMap<AppId, u32>,
    app_flags: HashMap<AppId, u32>,
    allowed_env: HashMap<EnvKey, u32>,
    terminals: HashMap<FileKey, u32>,
    claim_parents: HashMap<FileKey, u32>,
    exe_dirs: HashMap<FileKey, AppId>,
    exe_paths: HashMap<FileKey, AppId>,
    own_ids: HashMap<OwnKey, u32>,
}

pub struct State {
    pub ebpf: Ebpf,
    opts: Options,
    pub policy: Compiled,
    users: Vec<User>,
    resolved: Resolved,
    roots: HashMap<FileKey, Root>,
    /// Multiply linked files inside each root, found when it was added.
    linked: HashMap<FileKey, Vec<FileKey>>,
    applied: Applied,
    /// Auto-claim parents: key → (uid, path).
    claim_parents: HashMap<FileKey, (u32, PathBuf)>,
    /// Warnings of the last policy load, rendered.
    policy_warnings: Vec<String>,
    /// Those plus the warnings of the last resolution.
    warnings: Vec<String>,
    loaded_at: SystemTime,
    resolved_at: SystemTime,
    /// Set once running processes were seeded at startup: from then on,
    /// processes of newly added exes are seeded when they are applied.
    pub seeding: bool,
    /// App exes a user could replace: key → path.
    writable_exes: HashMap<FileKey, PathBuf>,
}

/// The compiled policy and its warnings, rendered.
fn load_policy(opts: &Options, ids: &IdTable, color: bool) -> Result<(Compiled, Vec<String>), String> {
    let sources = Sources::load_with_claims(&opts.policy, opts.claims.as_deref())
        .map_err(|e| format!("reading {}: {e}", opts.policy.display()))?;
    let policy =
        explsm_policy::check(&sources, ids).map_err(|d| diag::render(&d, &sources, color))?;
    let warnings = policy
        .warnings
        .iter()
        .map(|d| diag::render(std::slice::from_ref(d), &sources, color).trim_end().to_string())
        .collect();
    Ok((policy, warnings))
}

fn resolve_all(policy: &Compiled) -> Result<(Vec<User>, Resolved, Vec<String>), String> {
    let (users, warnings) =
        users::system(policy.users.as_deref()).map_err(|e| format!("reading users: {e}"))?;
    let resolved = resolve::resolve(policy, &users).map_err(|e| e.join("\n"))?;
    Ok((users, resolved, warnings))
}

fn open_root(path: &Path) -> std::io::Result<(OwnedFd, FileKey)> {
    // Follows symlinks, like the resolution.
    let file = File::options()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
        .open(path)?;
    let key = key_of(&file.metadata()?);
    Ok((file.into(), key))
}

/// Whether a user other than root could change a file or directory with
/// this metadata.
fn writable(md: &fs::Metadata) -> bool {
    md.uid() != 0 || md.mode() & 0o022 != 0
}

/// Whether a user other than root could change the file at `path`: its
/// owner, its mode, or the directory it is in. The second value is whether
/// the directory is one only its owner may add to and that is safe to
/// lock: not a shared sticky one like `/tmp`.
fn user_writable(path: &Path) -> (bool, bool) {
    let Ok(md) = fs::metadata(path) else {
        return (false, false);
    };
    let dir = path.parent().and_then(|d| fs::metadata(d).ok());
    let dir_writable = dir.as_ref().is_some_and(writable);
    let shared = dir.as_ref().is_some_and(|d| d.mode() & 0o1002 == 0o1002);
    (writable(&md) || dir_writable, dir_writable && !shared)
}

/// `dir` and its ancestors that a user other than root could rename or
/// remove, because their parent is writable: moving one aside and creating
/// it anew would put a new exe at the path the policy names.
fn renameable(dir: &Path) -> Vec<FileKey> {
    let mut out = Vec::new();
    let mut cur = dir;
    while let Some(parent) = cur.parent() {
        let (Ok(md), Ok(parent_md)) = (fs::metadata(cur), fs::metadata(parent)) else {
            break;
        };
        if !writable(&parent_md) {
            break;
        }
        out.push(key_of(&md));
        cur = parent;
    }
    out
}

/// Read a BPF hash map into a `HashMap`.
fn read_map<K: Pod + Eq + Hash, V: Pod>(ebpf: &Ebpf, name: &str) -> Result<HashMap<K, V>> {
    let map: BpfHashMap<_, K, V> =
        BpfHashMap::try_from(ebpf.map(name).with_context(|| format!("{name} missing"))?)?;
    map.iter()
        .collect::<Result<_, _>>()
        .with_context(|| format!("reading {name}"))
}

fn ids_file(state_dir: &Path) -> PathBuf {
    state_dir.join("ids")
}

/// The app ids an earlier run used, one name per line in id order.
fn saved_ids(state_dir: &Path) -> IdTable {
    let names = fs::read_to_string(ids_file(state_dir))
        .map(|t| t.lines().map(str::to_string).collect())
        .unwrap_or_default();
    IdTable::from_names(names)
}

fn unix_time(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// Bring a BPF hash map from `have` to `want`. Returns whether anything
/// changed.
fn sync_map<K: Pod + Eq + Hash, V: Pod + PartialEq>(
    ebpf: &mut Ebpf,
    name: &str,
    want: &HashMap<K, V>,
    have: &mut HashMap<K, V>,
) -> Result<bool> {
    let mut map: BpfHashMap<_, K, V> =
        BpfHashMap::try_from(ebpf.map_mut(name).with_context(|| format!("{name} missing"))?)?;
    let mut changed = false;
    // Inserts first: a replaced exe stays known throughout.
    for (k, v) in want {
        if have.get(k) != Some(v) {
            map.insert(k, v, 0).with_context(|| format!("updating {name} (full?)"))?;
            have.insert(*k, *v);
            changed = true;
        }
    }
    let stale: Vec<K> = have.keys().filter(|k| !want.contains_key(*k)).copied().collect();
    for k in stale {
        map.remove(&k).with_context(|| format!("removing from {name}"))?;
        have.remove(&k);
        changed = true;
    }
    Ok(changed)
}

impl State {
    /// Load the policy and fill the maps. Nothing is attached yet.
    pub fn new(ebpf: Ebpf, opts: Options) -> Result<Self> {
        let color = std::io::stderr().is_terminal();
        // Running tasks keep the ids of the run that gave them.
        let ids = if opts.reused {
            saved_ids(&opts.state_dir)
        } else {
            IdTable::default()
        };
        let (policy, policy_warnings) = load_policy(&opts, &ids, color)
            .map_err(|d| anyhow!("the policy has errors:\n{d}"))?;
        let (users, resolved, warnings) = resolve_all(&policy).map_err(|e| anyhow!(e))?;
        let now = SystemTime::now();
        let mut state = Self {
            ebpf,
            opts,
            policy: policy.clone(),
            users: Vec::new(),
            resolved: Resolved::default(),
            roots: HashMap::new(),
            linked: HashMap::new(),
            applied: Applied::default(),
            claim_parents: HashMap::new(),
            policy_warnings,
            warnings: Vec::new(),
            loaded_at: now,
            resolved_at: now,
            seeding: false,
            writable_exes: HashMap::new(),
        };
        if state.opts.reused {
            state.read_back()?;
        }
        state.commit(policy, users, resolved, warnings)?;
        Ok(state)
    }

    /// Take over the maps of an earlier run: what is in them is what is
    /// applied, so the first apply removes what the policy no longer has.
    /// Prompt grants ended with the daemon that kept track of them.
    fn read_back(&mut self) -> Result<()> {
        self.applied.exes = read_map(&self.ebpf, "EXES")?;
        self.applied.roots = read_map(&self.ebpf, "ROOTS")?;
        self.applied.grants = read_map(&self.ebpf, "GRANTS")?;
        self.applied.terminals = read_map(&self.ebpf, "TERMINALS")?;
        self.applied.claim_parents = read_map(&self.ebpf, "CLAIM_PARENTS")?;
        self.applied.exe_dirs = read_map(&self.ebpf, "EXE_DIRS")?;
        self.applied.exe_paths = read_map(&self.ebpf, "EXE_PATHS")?;
        self.applied.own_ids = read_map(&self.ebpf, "OWN_IDS")?;
        self.applied.allowed_env = read_map(&self.ebpf, "ALLOWED_ENV")?;
        let temp: HashMap<TempKey, u32> = read_map(&self.ebpf, "TEMP_GRANTS")?;
        let mut map: BpfHashMap<_, TempKey, u32> =
            BpfHashMap::try_from(self.ebpf.map_mut("TEMP_GRANTS").context("TEMP_GRANTS")?)?;
        for key in temp.keys() {
            let _ = map.remove(key);
        }
        // Whatever was cached may predate a change made while no daemon ran.
        let mut config: Array<_, u32> =
            Array::try_from(self.ebpf.map_mut("CONFIG").context("CONFIG")?)?;
        let generation = config.get(&CFG_GENERATION, 0)?;
        config.set(CFG_GENERATION, generation.wrapping_add(1), 0)?;
        eprintln!(
            "explsmd: took over the pinned state: {} exes, {} roots, {} grants, {} prompt grants dropped",
            self.applied.exes.len(),
            self.applied.roots.len(),
            self.applied.grants.len(),
            temp.len()
        );
        Ok(())
    }

    /// Remember the app ids for the next run.
    fn save_ids(&self) {
        let path = ids_file(&self.opts.state_dir);
        let mut text = self.policy.ids.names().join("\n");
        text.push('\n');
        if fs::read_to_string(&path).ok().as_deref() == Some(text.as_str()) {
            return;
        }
        let tmp = path.with_extension("new");
        if let Err(e) = fs::write(&tmp, &text).and_then(|()| fs::rename(&tmp, &path)) {
            eprintln!("explsmd: warning: saving app ids to {}: {e}", path.display());
        }
    }

    /// Read the policy again and apply it. On errors the old policy stays.
    pub fn reload(&mut self) -> ReloadReply {
        let fail = |summary: &str, diagnostics: String| ReloadReply {
            ok: false,
            summary: summary.into(),
            diagnostics,
        };
        let (policy, policy_warnings) = match load_policy(&self.opts, &self.policy.ids, false) {
            Ok(p) => p,
            Err(d) => return fail("the policy has errors; the old policy stays in force", d),
        };
        let (users, resolved, warnings) = match resolve_all(&policy) {
            Ok(r) => r,
            Err(e) => return fail("the policy does not resolve; the old policy stays in force", e),
        };
        self.loaded_at = SystemTime::now();
        self.policy_warnings = policy_warnings;
        if let Err(e) = self.commit(policy, users, resolved, warnings) {
            return fail("applying the policy failed", format!("{e:#}"));
        }
        ReloadReply {
            ok: true,
            summary: self.summary(),
            diagnostics: self.warnings.join("\n"),
        }
    }

    /// Resolve the paths of the current policy again.
    pub fn rescan(&mut self) -> Result<()> {
        let (users, resolved, warnings) = resolve_all(&self.policy).map_err(|e| anyhow!(e))?;
        self.commit(self.policy.clone(), users, resolved, warnings)
    }

    fn commit(
        &mut self,
        policy: Compiled,
        users: Vec<User>,
        resolved: Resolved,
        mut warnings: Vec<String>,
    ) -> Result<()> {
        self.policy = policy;
        self.log_changes(&resolved);
        warnings.splice(0..0, self.policy_warnings.iter().cloned());
        for w in warnings.iter().filter(|w| !self.warnings.contains(w)) {
            eprintln!("explsmd: warning: {w}");
        }
        self.users = users;
        self.warnings = warnings;
        self.update_roots(&resolved);
        self.resolved = resolved;
        self.resolved_at = SystemTime::now();
        self.save_ids();
        self.apply()
    }

    fn log_changes(&self, new: &Resolved) {
        let name = |app| self.policy.name(app);
        let show = |sign: &str, kind: &str, f: &Found| {
            eprintln!(
                "explsmd: {sign} {kind} {} ({}) of {}",
                f.path.display(),
                show_key(&f.key),
                name(f.app)
            );
        };
        let old = &self.resolved;
        for f in new.exes.iter().filter(|f| !old.exes.contains(f)) {
            show("+", "exe ", f);
        }
        for f in old.exes.iter().filter(|f| !new.exes.contains(f)) {
            show("-", "exe ", f);
        }
        for f in new.terminals.iter().filter(|f| !old.terminals.contains(f)) {
            eprintln!("explsmd: + terminal {} ({})", f.path.display(), show_key(&f.key));
        }
        for f in old.terminals.iter().filter(|f| !new.terminals.contains(f)) {
            eprintln!("explsmd: - terminal {} ({})", f.path.display(), show_key(&f.key));
        }
        for m in new.missing.iter().filter(|m| !old.missing.contains(m)) {
            eprintln!(
                "explsmd:   {} {} of {} does not exist (yet)",
                m.kind.name(),
                m.path.display(),
                name(m.app)
            );
        }
    }

    /// Match the open roots to `resolved`: keep, add, keep moved ones, drop.
    fn update_roots(&mut self, resolved: &Resolved) {
        let mut old = std::mem::take(&mut self.roots);
        let mut new = HashMap::new();
        for f in &resolved.roots {
            if let Some(mut r) = old.remove(&f.key) {
                if r.app == f.app {
                    if r.moved {
                        eprintln!("explsmd:   root {} is back at its path", f.path.display());
                    }
                    r.path = f.path.clone();
                    r.pattern = f.pattern.clone();
                    r.moved = false;
                    new.insert(f.key, r);
                    continue;
                }
                // Now another app's: drop it and open it afresh.
                old.insert(f.key, r);
            }
            match open_root(&f.path) {
                Ok((fd, key)) if key == f.key => {
                    eprintln!(
                        "explsmd: + root {} ({}) of {}",
                        f.path.display(),
                        show_key(&f.key),
                        self.policy.name(f.app)
                    );
                    new.insert(
                        f.key,
                        Root {
                            path: f.path.clone(),
                            app: f.app,
                            pattern: f.pattern.clone(),
                            fd,
                            moved: false,
                            label: None,
                        },
                    );
                }
                // Replaced since it was resolved; the watch brings it back.
                Ok(_) => eprintln!("explsmd: warning: {} changed while resolving", f.path.display()),
                Err(e) => eprintln!("explsmd: warning: opening {}: {e}", f.path.display()),
            }
        }
        for (key, mut r) in old {
            if new.contains_key(&key) {
                self.drop_root(r, false);
                continue;
            }
            let named = self
                .policy
                .app(r.app)
                .is_some_and(|a| a.roots.iter().any(|p| p.text == r.pattern));
            let alive = File::from(r.fd.try_clone().expect("dup of an O_PATH fd"))
                .metadata()
                .is_ok_and(|md| md.nlink() > 0);
            if named && alive {
                if !r.moved {
                    let now = fs::read_link(labels::fd_path(&r.fd)).unwrap_or_default();
                    eprintln!(
                        "explsmd:   root {} moved to {}; still protected",
                        r.path.display(),
                        now.display()
                    );
                    r.moved = true;
                }
                new.insert(key, r);
            } else {
                self.drop_root(r, alive);
            }
        }
        self.roots = new;
    }

    fn drop_root(&self, r: Root, unlabel: bool) {
        eprintln!(
            "explsmd: - root {} of {}",
            r.path.display(),
            self.policy.name(r.app)
        );
        if unlabel && let Err(e) = labels::remove_label(&labels::fd_path(&r.fd)) {
            eprintln!("explsmd: warning: unlabelling {}: {e}", r.path.display());
        }
    }

    /// Write the differences into the maps, label roots, seed new exes.
    pub fn apply(&mut self) -> Result<()> {
        let root_bypass = self.policy.root_bypass && !self.opts.no_root_bypass;
        let mut config: Array<_, u32> =
            Array::try_from(self.ebpf.map_mut("CONFIG").context("CONFIG")?)?;
        config.set(CFG_ROOT_BYPASS, u32::from(root_bypass), 0)?;
        config.set(CFG_DAEMON_TGID, std::process::id(), 0)?;
        config.set(CFG_LOG_EXECS, u32::from(self.opts.log_execs), 0)?;
        let mut path = DaemonPath {
            path: [0; DAEMON_PATH_LEN],
        };
        let bytes = self.opts.daemon.as_os_str().as_encoded_bytes();
        if bytes.len() < DAEMON_PATH_LEN {
            path.path[..bytes.len()].copy_from_slice(bytes);
        }
        let mut daemon_path: Array<_, DaemonPath> =
            Array::try_from(self.ebpf.map_mut("DAEMON_PATH").context("DAEMON_PATH")?)?;
        daemon_path.set(0, path, 0)?;

        for r in self.roots.values_mut() {
            let Some(app) = self.policy.app(r.app) else {
                continue;
            };
            let value = format!("app={} mode={}", app.name, app.mode.name());
            if r.label.as_ref() == Some(&value) {
                continue;
            }
            match labels::write_label(&labels::fd_path(&r.fd), &value) {
                Ok(()) => r.label = Some(value),
                Err(e) => eprintln!("explsmd: warning: labelling {}: {e}", r.path.display()),
            }
        }

        self.linked.retain(|k, _| self.roots.contains_key(k));
        for (key, r) in &self.roots {
            if self.linked.contains_key(key) {
                continue;
            }
            let scan = labels::scan_links(&r.path);
            for (what, err) in &scan.errors {
                eprintln!("explsmd: warning: scanning {what}: {err}");
            }
            if !scan.linked.is_empty() {
                eprintln!(
                    "explsmd:   {} hard-linked files in {} tracked individually",
                    scan.linked.len(),
                    r.path.display()
                );
            }
            self.linked.insert(*key, scan.linked);
        }

        let exes = self.exes();
        let new_exes: HashMap<FileKey, AppId> = exes
            .iter()
            .filter(|(k, v)| self.applied.exes.get(*k) != Some(*v))
            .map(|(k, v)| (*k, *v))
            .collect();
        // Roots last, so a root that is also a hard link inside another tree
        // keeps its own owner.
        let mut roots = HashMap::new();
        for (key, linked) in &self.linked {
            let app = self.roots[key].app;
            roots.extend(linked.iter().map(|k| (*k, app)));
        }
        roots.extend(self.roots.iter().map(|(k, r)| (*k, r.app)));
        // Exes a user could replace, so nothing else can: readable by all,
        // changed only by their app. Their directories take new entries
        // only from the app, so nothing can be planted for a glob, and
        // neither they nor the directories above them that a user could
        // rename may be moved aside by anything but the app. That holds for
        // the path the policy names and, through symlinks, the file itself.
        let mut exe_dirs = HashMap::new();
        let mut exe_paths = HashMap::new();
        let mut writable_exes = HashMap::new();
        let apps = self
            .resolved
            .exes
            .iter()
            .map(|f| (f.key, f.app, f.path.clone()))
            .chain(resolve::file_key(&self.opts.agent).map(|k| (k, APP_AGENT, self.opts.agent.clone())));
        for (key, app, path) in apps {
            let mut paths = vec![path.clone()];
            if let Ok(real) = fs::canonicalize(&path)
                && real != path
            {
                paths.push(real);
            }
            let mut any_writable = false;
            let mut lock_dir = true;
            for p in &paths {
                let (writable, lock) = user_writable(p);
                if !writable {
                    continue;
                }
                any_writable = true;
                lock_dir &= lock;
                let Some(dir) = p.parent() else { continue };
                if lock && let Ok(md) = fs::metadata(dir) {
                    exe_dirs.insert(key_of(&md), app);
                }
                for k in renameable(dir) {
                    // A directory above two apps' exes: the first keeps it.
                    exe_paths.entry(k).or_insert(app);
                }
            }
            if !any_writable {
                continue;
            }
            roots.insert(key, app | OWNER_EXE);
            if !self.writable_exes.contains_key(&key) {
                eprintln!(
                    "explsmd:   exe {} of {} is user-writable: protected as its data{}",
                    path.display(),
                    self.policy.name(app),
                    if lock_dir { "" } else { " (its shared directory is not locked)" }
                );
            }
            writable_exes.insert(key, path);
        }
        self.writable_exes = writable_exes;
        if self.opts.self_protect {
            for path in self.own_paths() {
                if let Ok(key) = resolve::file_key(&path) {
                    roots.insert(key, APP_DAEMON);
                }
            }
            if let Ok(key) = resolve::file_key(&self.opts.pin_dir) {
                roots.insert(key, OWNER_PINS);
            }
        }
        let mut modes: HashMap<AppId, u32> = self.policy.modes().collect();
        // explsm's own processes and files are always guarded: tampering
        // with the agent would let a process answer its own prompts.
        modes.insert(APP_AGENT, MODE_ENFORCE);
        modes.insert(APP_DAEMON, MODE_ENFORCE);
        modes.insert(OWNER_PINS, MODE_ENFORCE);
        let terminals: HashMap<FileKey, u32> =
            self.resolved.terminals.iter().map(|f| (f.key, 1)).collect();
        let new_terminals = terminals
            .keys()
            .any(|k| !self.applied.terminals.contains_key(k));
        self.claim_parents = self
            .users
            .iter()
            .flat_map(|u| {
                CLAIM_PARENTS.iter().filter_map(|rel| {
                    let path = if rel.is_empty() {
                        u.home.clone()
                    } else {
                        u.home.join(rel)
                    };
                    let md = fs::metadata(&path).ok().filter(|m| m.is_dir())?;
                    Some((key_of(&md), (u.uid, path)))
                })
            })
            .collect();
        let claim_parents: HashMap<FileKey, u32> = self
            .claim_parents
            .iter()
            .map(|(k, (uid, _))| (*k, *uid))
            .collect();

        sync_map(&mut self.ebpf, "EXES", &exes, &mut self.applied.exes)?;
        // The BPF side adds roots too (a root replaced by a rename), so the
        // map, not what was last written, is what is applied.
        self.applied.roots = read_map(&self.ebpf, "ROOTS")?;
        let roots_changed = sync_map(&mut self.ebpf, "ROOTS", &roots, &mut self.applied.roots)?;
        sync_map(
            &mut self.ebpf,
            "GRANTS",
            &self.policy.grants,
            &mut self.applied.grants,
        )?;
        sync_map(
            &mut self.ebpf,
            "TERMINALS",
            &terminals,
            &mut self.applied.terminals,
        )?;
        sync_map(
            &mut self.ebpf,
            "CLAIM_PARENTS",
            &claim_parents,
            &mut self.applied.claim_parents,
        )?;
        sync_map(&mut self.ebpf, "EXE_DIRS", &exe_dirs, &mut self.applied.exe_dirs)?;
        sync_map(&mut self.ebpf, "EXE_PATHS", &exe_paths, &mut self.applied.exe_paths)?;
        let mut map: Array<_, u32> = Array::try_from(self.ebpf.map_mut("MODES").context("MODES")?)?;
        for (app, mode) in &modes {
            if self.applied.modes.get(app) != Some(mode) {
                map.set(*app, mode, 0)?;
                self.applied.modes.insert(*app, *mode);
            }
        }
        let mut map: Array<_, u32> =
            Array::try_from(self.ebpf.map_mut("APP_FLAGS").context("APP_FLAGS")?)?;
        for (app, flags) in self.policy.app_flags() {
            if self.applied.app_flags.get(&app) != Some(&flags) {
                map.set(app, flags, 0)?;
                self.applied.app_flags.insert(app, flags);
            }
        }
        let allowed_env: HashMap<EnvKey, u32> =
            self.policy.allowed_env().map(|k| (k, 1)).collect();
        sync_map(
            &mut self.ebpf,
            "ALLOWED_ENV",
            &allowed_env,
            &mut self.applied.allowed_env,
        )?;
        if roots_changed {
            // Cached owners were computed against the old roots. Racing
            // with a bump from BPF is fine: both only increment.
            let mut config: Array<_, u32> =
                Array::try_from(self.ebpf.map_mut("CONFIG").context("CONFIG")?)?;
            let generation = config.get(&CFG_GENERATION, 0)?;
            config.set(CFG_GENERATION, generation.wrapping_add(1), 0)?;
        }

        if self.seeding && !new_exes.is_empty() {
            self.seed(&new_exes)?;
        }
        if self.seeding && new_terminals {
            self.seed_terminals()?;
        }
        Ok(())
    }

    /// Give running processes below a terminal the terminal flag.
    pub fn seed_terminals(&self) -> Result<()> {
        let tasks = self.tasks()?;
        let terminals: HashSet<FileKey> = self.applied.terminals.keys().copied().collect();
        if terminals.is_empty() {
            return Ok(());
        }
        let seeded = seed::terminals(tasks, &terminals, &self.applied.exes)?;
        if seeded.threads > 0 {
            eprintln!(
                "explsmd: {} running processes below a terminal ({} threads)",
                seeded.processes, seeded.threads
            );
        }
        for (tid, err) in &seeded.failures {
            eprintln!("explsmd: warning: could not flag tid {tid}: {err}");
        }
        Ok(())
    }

    /// Auto-claim parent folders by key: (uid, path).
    pub fn claim_parents(&self) -> &HashMap<FileKey, (u32, PathBuf)> {
        &self.claim_parents
    }

    pub fn agent_path(&self) -> &Path {
        &self.opts.agent
    }

    pub fn claims_dir(&self) -> Option<&Path> {
        self.opts.claims.as_deref()
    }

    pub fn resolved(&self) -> &Resolved {
        &self.resolved
    }

    /// The task storage map.
    pub fn tasks(&self) -> Result<&aya::maps::MapData> {
        let Some(Map::Unsupported(tasks)) = self.ebpf.map("TASKS") else {
            anyhow::bail!("TASKS map missing or of an unexpected type");
        };
        Ok(tasks)
    }

    /// Give running processes of `exes` their identity.
    pub fn seed(&self, exes: &HashMap<FileKey, AppId>) -> Result<()> {
        let tasks = self.tasks()?;
        let allowed_env = self.policy.allowed_env().collect();
        let seeded = seed::running_apps(tasks, exes, &allowed_env)?;
        if seeded.threads + seeded.reverted + seeded.failures.len() > 0 {
            eprintln!(
                "explsmd: seeded {} running processes ({} threads, {} passes, {} reverted)",
                seeded.processes, seeded.threads, seeded.passes, seeded.reverted
            );
        }
        for (tid, err) in &seeded.failures {
            eprintln!("explsmd: warning: could not seed tid {tid}: {err}");
        }
        let mut tainted: Vec<_> = seeded.tainted.iter().collect();
        tainted.sort();
        if !tainted.is_empty() {
            eprintln!(
                "explsmd: left unconfined, started with LD_PRELOAD or the like or in a user namespace: pids {tainted:?}"
            );
        }
        Ok(())
    }

    /// The app exes, the agent's and the daemon's: the one running, and
    /// the one at its path, which differs after an upgrade.
    pub fn exes(&self) -> HashMap<FileKey, AppId> {
        let mut exes = self.resolved.exe_map();
        if let Ok(key) = resolve::file_key(&self.opts.agent) {
            exes.entry(key).or_insert(APP_AGENT);
        }
        for path in [Path::new("/proc/self/exe"), &self.opts.daemon] {
            if let Ok(key) = resolve::file_key(path) {
                exes.insert(key, APP_DAEMON);
            }
        }
        exes
    }

    /// explsm's own files: the policy, its state, its programs and how they
    /// are started.
    fn own_paths(&self) -> Vec<PathBuf> {
        let mut paths = vec![
            self.opts.policy.clone(),
            self.opts.state_dir.clone(),
            self.opts.daemon.clone(),
            self.opts.agent.clone(),
        ];
        paths.extend(self.opts.claims.clone());
        if let Some(dir) = self.opts.daemon.parent() {
            paths.push(dir.join("explsmctl"));
        }
        paths.extend(OWN_FILES.iter().map(PathBuf::from));
        paths.retain(|p| p.exists());
        paths
    }

    /// Forget the daemon's tgid, for when it exits and leaves explsm loaded:
    /// a later process with the same pid must not get to change labels.
    pub fn release_tgid(&mut self) -> Result<()> {
        let mut config: Array<_, u32> =
            Array::try_from(self.ebpf.map_mut("CONFIG").context("CONFIG")?)?;
        config.set(CFG_DAEMON_TGID, 0, 0)?;
        Ok(())
    }

    /// Only the daemon may get file descriptors for these objects.
    pub fn set_own_ids(&mut self, ids: &HashMap<OwnKey, u32>) -> Result<()> {
        sync_map(&mut self.ebpf, "OWN_IDS", ids, &mut self.applied.own_ids)?;
        Ok(())
    }

    /// Remove the label of every root, for an unload.
    pub fn unlabel_all(&self) -> Vec<String> {
        let mut errors = Vec::new();
        for r in self.roots.values() {
            if let Err(e) = labels::remove_label(&labels::fd_path(&r.fd)) {
                errors.push(format!("unlabelling {}: {e}", r.path.display()));
            }
        }
        errors
    }

    pub fn stats(&self) -> Result<[u64; STATS_LEN as usize]> {
        let stats: PerCpuArray<_, u64> =
            PerCpuArray::try_from(self.ebpf.map("STATS").context("STATS")?)?;
        let mut out = [0; STATS_LEN as usize];
        for (i, slot) in out.iter_mut().enumerate() {
            *slot = stats.get(&(i as u32), 0)?.iter().sum();
        }
        Ok(out)
    }

    fn generation(&self) -> u32 {
        self.ebpf
            .map("CONFIG")
            .and_then(|m| Array::<_, u32>::try_from(m).ok())
            .and_then(|a| a.get(&CFG_GENERATION, 0).ok())
            .unwrap_or(0)
    }

    pub fn summary(&self) -> String {
        let missing: HashSet<_> = self.resolved.missing.iter().map(|m| &m.path).collect();
        format!(
            "{} apps, {} exes, {} roots ({} paths missing), {} grants, {} users, root bypass {}",
            self.policy.apps.len(),
            self.applied.exes.len(),
            self.roots.len(),
            missing.len(),
            self.policy.grants.len(),
            self.users.len(),
            if self.policy.root_bypass && !self.opts.no_root_bypass {
                "on"
            } else {
                "off"
            }
        )
    }

    pub fn status(&self) -> Status {
        let file = |path: &Path, key: &FileKey, note: String| FileStatus {
            path: path.display().to_string(),
            key: show_key(key),
            note,
        };
        let apps = self
            .policy
            .apps
            .iter()
            .map(|app| {
                let exes = self
                    .resolved
                    .exes
                    .iter()
                    .filter(|f| f.app == app.id)
                    .map(|f| {
                        let note = if self.writable_exes.contains_key(&f.key) {
                            "protected (user-writable)".to_string()
                        } else {
                            String::new()
                        };
                        file(&f.path, &f.key, note)
                    })
                    .collect();
                let mut roots: Vec<_> = self
                    .roots
                    .iter()
                    .filter(|(_, r)| r.app == app.id)
                    .map(|(key, r)| {
                        let mut notes = Vec::new();
                        if r.moved {
                            let now = fs::read_link(labels::fd_path(&r.fd)).unwrap_or_default();
                            notes.push(format!("moved to {}", now.display()));
                        }
                        let linked = self.linked.get(key).map_or(0, Vec::len);
                        if linked > 0 {
                            notes.push(format!("{linked} hard links tracked"));
                        }
                        file(&r.path, key, notes.join(", "))
                    })
                    .collect();
                roots.sort_by(|a: &FileStatus, b| a.path.cmp(&b.path));
                let missing = self
                    .resolved
                    .missing
                    .iter()
                    .filter(|m| m.app == app.id)
                    .map(|m| format!("{} {}", m.kind.name(), m.path.display()))
                    .collect();
                AppStatus {
                    name: app.name.clone(),
                    id: app.id,
                    mode: app.mode.name().into(),
                    inherit: app.inherit,
                    env: app.env.clone(),
                    exes,
                    roots,
                    missing,
                }
            })
            .collect();
        let mut grants: Vec<_> = self
            .policy
            .grants
            .iter()
            .map(|(key, bits)| GrantStatus {
                subject: self.policy.name(key.subject).into(),
                owner: self.policy.name(key.owner).into(),
                perms: if *bits == perm::ALL {
                    vec!["all".into()]
                } else {
                    perm::NAMES
                        .iter()
                        .filter(|(b, _)| bits & b != 0)
                        .map(|(_, n)| n.to_string())
                        .collect()
                },
            })
            .collect();
        grants.sort_by(|a, b| (&a.subject, &a.owner).cmp(&(&b.subject, &b.owner)));
        let stats = self.stats().unwrap_or_default();
        Status {
            policy_dir: self.opts.policy.display().to_string(),
            terminals: self
                .resolved
                .terminals
                .iter()
                .map(|f| file(&f.path, &f.key, String::new()))
                .collect(),
            // Filled in by the main loop, which has them.
            temp_grants: Vec::new(),
            agents: Vec::new(),
            loaded_at: unix_time(self.loaded_at),
            resolved_at: unix_time(self.resolved_at),
            root_bypass: self.policy.root_bypass && !self.opts.no_root_bypass,
            generation: self.generation(),
            users: self.users.iter().map(|u| u.name.clone()).collect(),
            apps,
            grants,
            stats: STAT_NAMES
                .iter()
                .zip(stats)
                .map(|(n, v)| (n.to_string(), v))
                .collect(),
            warnings: self.warnings.clone(),
        }
    }

    /// Directories with paths of the policy, for the watcher.
    pub fn watches(&self) -> &std::collections::BTreeMap<PathBuf, std::collections::BTreeSet<String>> {
        &self.resolved.watches
    }

    pub fn policy_path(&self) -> &Path {
        &self.opts.policy
    }
}
