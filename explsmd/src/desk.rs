//! Prompts end to end: registered agents, denials and new folders put to
//! them, and their answers turned into grants and claims.
//!
//! An agent is a connection on the system bus whose process runs the agent
//! exe (identity `APP_AGENT` in task storage); one per user, the newest
//! wins. A user's denials and claims go to that user's agent only, and only
//! that agent may answer them. When it leaves the bus (logout), the user's
//! session grants end.
//!
//! A new folder is asked about [`CLAIM_DELAY`] after it was reported, and
//! only if it is still there: the hook runs before the folder exists, and
//! many folders apps create are gone again at once.

use std::{
    collections::{HashMap, VecDeque},
    fs::{self, OpenOptions},
    io::Write as _,
    os::{
        fd::{AsFd as _, OwnedFd},
        unix::fs::{MetadataExt as _, OpenOptionsExt as _},
    },
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use explsm_common::{
    ACTION_DENY, APP_AGENT, APP_DAEMON, APP_UNCONFINED, Event, EventKind, OWNER_PINS, REASON_PERMS,
    TempKey, perm, temp_kind,
};
use explsm_ipc::{
    AgentProxy, AgentStatus, HistoryEntry, PROMPT_ACCESS, PROMPT_CLAIM, PromptInfo, Secret,
    UserApp, UserStatus, choice,
};
use explsm_policy::resolve::{file_key, show_key};
use tokio::sync::mpsc;
use zbus::Connection;

use crate::{
    claims,
    events::{self, Line},
    grants::{self, TempGrants},
    procs,
    prompts::{Kind, Outcome, Prompts, Subject},
    seed,
    state::State,
};

/// How long after a folder was created it is asked about.
pub const CLAIM_DELAY: Duration = Duration::from_secs(1);

/// How many answered prompts are kept per user for the GUI.
pub const HISTORY: usize = 200;

struct Agent {
    connection: String,
    pid: u32,
}

/// A new folder to ask about once it has settled.
struct NewFolder {
    due: Instant,
    uid: u32,
    app: u32,
    process: String,
    path: PathBuf,
}

pub struct Desk {
    conn: Option<Connection>,
    agents: HashMap<u32, Agent>,
    prompts: Prompts,
    pub temp: TempGrants,
    exits: mpsc::UnboundedSender<(u32, OwnedFd)>,
    declined_file: PathBuf,
    new_folders: Vec<NewFolder>,
    /// Answered prompts per user, newest last. Not kept across restarts.
    history: HashMap<u32, VecDeque<HistoryEntry>>,
    /// Where each user's [`Secret`] is kept, as `secret-<uid>`: right in
    /// the state directory, as the sandbox lets the daemon make files
    /// there but no directories.
    state_dir: PathBuf,
}

/// What an answer did, beyond the grant.
pub struct Answered {
    /// The policy was reloaded.
    pub reloaded: bool,
}

impl Desk {
    pub fn new(
        conn: Option<Connection>,
        exits: mpsc::UnboundedSender<(u32, OwnedFd)>,
        declined_file: PathBuf,
        state_dir: PathBuf,
    ) -> Self {
        Self {
            conn,
            agents: HashMap::new(),
            prompts: Prompts::new(claims::load_declined(&declined_file)),
            temp: TempGrants::default(),
            exits,
            declined_file,
            new_folders: Vec::new(),
            history: HashMap::new(),
            state_dir,
        }
    }

    /// When [`Self::new_folders`] has something to do.
    pub fn new_folders_due(&self) -> Option<Instant> {
        self.new_folders.iter().map(|f| f.due).min()
    }

    /// Ask about the new folders that have settled and still exist.
    pub fn new_folders(&mut self, state: &State) {
        let now = Instant::now();
        let (due, later): (Vec<_>, Vec<_>) = std::mem::take(&mut self.new_folders)
            .into_iter()
            .partition(|f| f.due <= now);
        self.new_folders = later;
        for f in due {
            if !self.agents.contains_key(&f.uid) || !fs::metadata(&f.path).is_ok_and(|m| m.is_dir())
            {
                continue;
            }
            let resolved = state.resolved();
            let known = resolved.roots.iter().any(|r| r.path == f.path)
                || resolved.missing.iter().any(|m| m.path == f.path);
            let name = state.policy.name(f.app).to_string();
            if let Some(id) = self
                .prompts
                .claim(now, f.uid, f.app, &name, f.path.clone(), known)
            {
                let choices = vec![choice::CLAIM.to_string(), choice::DECLINE.to_string()];
                if let Some(prompt) = self.prompts.get_mut(id) {
                    prompt.choices = choices.clone();
                    prompt.path = f.path.display().to_string();
                    prompt.process = f.process.clone();
                }
                let info = PromptInfo {
                    id,
                    kind: PROMPT_CLAIM.into(),
                    subject: name,
                    process: f.process,
                    path: f.path.display().to_string(),
                    choices,
                    ..PromptInfo::default()
                };
                if let Some(prompt) = self.prompts.get_mut(id) {
                    prompt.info = Some(info.clone());
                }
                self.send(f.uid, info);
            }
        }
    }

    pub fn agents(&self) -> Vec<AgentStatus> {
        let mut out: Vec<_> = self
            .agents
            .iter()
            .map(|(uid, a)| AgentStatus {
                uid: *uid,
                pid: a.pid,
                connection: a.connection.clone(),
            })
            .collect();
        out.sort_by_key(|a| a.uid);
        out
    }

    /// Whether the process behind `pidfd` runs the agent or GUI exe: only
    /// they may see and change what the GUI shows.
    pub fn check_gui(&self, state: &State, pidfd: &OwnedFd) -> Result<(), String> {
        let app = state
            .tasks()
            .and_then(|tasks| seed::app_of(tasks, pidfd.as_fd()).map_err(Into::into))
            .map_err(|e| format!("checking the caller: {e}"))?;
        if app == APP_AGENT {
            Ok(())
        } else {
            Err("only explsm-agent and explsm-gui may call this".into())
        }
    }

    /// What concerns user `uid`, for the GUI.
    pub fn user_status(&self, state: &State, uid: u32) -> UserStatus {
        let status = state.status();
        let apps = status
            .apps
            .into_iter()
            .map(|a| UserApp {
                name: a.name,
                mode: a.mode,
                exes: a.exes.into_iter().map(|f| f.path).collect(),
                roots: a
                    .roots
                    .into_iter()
                    .map(|f| f.path)
                    .chain(a.missing)
                    .collect(),
            })
            .collect();
        let (saved_grants, saved_claims) = state
            .claims_dir()
            .and_then(|d| fs::read_to_string(claims::file_of(d, &claims::user_name(uid))).ok())
            .map(|t| claims::saved(&t))
            .unwrap_or_default();
        UserStatus {
            loaded_at: status.loaded_at,
            generation: status.generation,
            agent: self.agents.contains_key(&uid),
            apps,
            temp_grants: self
                .temp
                .status(&state.policy.ids)
                .into_iter()
                .filter(|g| g.uid == uid)
                .collect(),
            saved_grants,
            saved_claims,
            history: self
                .history
                .get(&uid)
                .map(|h| h.iter().rev().cloned().collect())
                .unwrap_or_default(),
            secret: self.secret(uid),
        }
    }

    /// Open prompt `id` of user `uid`, as it was sent to their agent.
    pub fn prompt_info(&self, uid: u32, id: u64) -> Result<PromptInfo, String> {
        self.prompts
            .get(id)
            .filter(|p| p.uid == uid)
            .and_then(|p| p.info.clone())
            .ok_or_else(|| "no such prompt (answered or expired)".into())
    }

    /// End user `uid`'s temporary grants of `subject` to `owner`.
    pub fn revoke_temp(
        &mut self,
        state: &mut State,
        uid: u32,
        subject: &str,
        owner: &str,
    ) -> Result<u32, String> {
        let n = self
            .temp
            .revoke(&mut state.ebpf, &state.policy.ids, uid, subject, owner)
            .map_err(|e| format!("{e:#}"))?;
        eprintln!("explsmd: uid {uid} revoked {n} temporary grants of {subject} on {owner}");
        Ok(n as u32)
    }

    /// Take user `uid`'s grant of `subject` to `owner` out of their claims
    /// file and reload; put the file back if the policy does not load.
    pub fn revoke_saved(
        &mut self,
        state: &mut State,
        uid: u32,
        subject: &str,
        owner: &str,
    ) -> Result<(), String> {
        let dir = state.claims_dir().ok_or("no claims directory")?;
        let file = claims::file_of(dir, &claims::user_name(uid));
        let old =
            fs::read_to_string(&file).map_err(|e| format!("reading {}: {e}", file.display()))?;
        let new = claims::remove_grant(&old, subject, owner)
            .ok_or_else(|| format!("no grant of {subject} to {owner} in {}", file.display()))?;
        write_atomic(&file, &new, 0o644).map_err(|e| format!("writing {}: {e}", file.display()))?;
        let reply = state.reload();
        if reply.ok {
            eprintln!(
                "explsmd: uid {uid} revoked the grant of {subject} on {owner}; policy reloaded: {}",
                reply.summary
            );
            return Ok(());
        }
        if let Err(e) = write_atomic(&file, &old, 0o644) {
            eprintln!("explsmd: warning: restoring {}: {e}", file.display());
        }
        Err(format!("{}: {}", reply.summary, reply.diagnostics))
    }

    fn secret_file(&self, uid: u32) -> PathBuf {
        self.state_dir.join(format!("secret-{uid}"))
    }

    /// User `uid`'s secret: the icon on the first line, the phrase on the
    /// second.
    pub fn secret(&self, uid: u32) -> Secret {
        let text = fs::read_to_string(self.secret_file(uid)).unwrap_or_default();
        let mut lines = text.lines();
        let secret = Secret {
            icon: lines.next().unwrap_or_default().into(),
            phrase: lines.next().unwrap_or_default().into(),
        };
        if secret.check().is_ok() {
            secret
        } else {
            Secret::default()
        }
    }

    pub fn set_secret(&self, uid: u32, secret: &Secret) -> Result<(), String> {
        secret.check()?;
        write_private(
            &self.secret_file(uid),
            &format!("{}\n{}\n", secret.icon, secret.phrase),
        )
        .map_err(|e| format!("saving the picture: {e}"))?;
        eprintln!("explsmd: uid {uid} set their security picture");
        Ok(())
    }

    fn remember(&mut self, uid: u32, entry: HistoryEntry) {
        let h = self.history.entry(uid).or_default();
        if h.len() >= HISTORY {
            h.pop_front();
        }
        h.push_back(entry);
    }

    /// `connection` (of process `pid`, user `uid`) wants to be an agent.
    pub fn register(
        &mut self,
        state: &State,
        connection: String,
        uid: u32,
        pid: u32,
        pidfd: OwnedFd,
    ) -> Result<(), String> {
        let app = state
            .tasks()
            .and_then(|tasks| seed::app_of(tasks, pidfd.as_fd()).map_err(Into::into))
            .map_err(|e| format!("checking the caller: {e}"))?;
        if app != APP_AGENT {
            eprintln!(
                "explsmd: refused agent registration of pid {pid} (uid {uid}): \
                 not running {}",
                state.agent_path().display()
            );
            return Err(format!(
                "only {} may register as an agent",
                state.agent_path().display()
            ));
        }
        eprintln!("explsmd: agent of uid {uid} registered (pid {pid}, {connection})");
        self.agents.insert(uid, Agent { connection, pid });
        Ok(())
    }

    /// A connection left the bus.
    pub fn connection_gone(&mut self, state: &mut State, connection: &str) {
        let Some(uid) = self
            .agents
            .iter()
            .find(|(_, a)| a.connection == connection)
            .map(|(uid, _)| *uid)
        else {
            return;
        };
        self.agents.remove(&uid);
        self.prompts.drop_uid(uid);
        match self.temp.session_ended(&mut state.ebpf, uid) {
            Ok(n) => eprintln!("explsmd: agent of uid {uid} left; {n} session grants ended"),
            Err(e) => eprintln!("explsmd: warning: ending session grants of uid {uid}: {e:#}"),
        }
    }

    pub fn process_exited(&mut self, state: &mut State, pid: u32) {
        if let Err(e) = self.temp.process_exited(&mut state.ebpf, pid) {
            eprintln!("explsmd: warning: ending grants of pid {pid}: {e:#}");
        }
    }

    /// Put an event to the user, if it is a question for them.
    pub fn event(&mut self, state: &State, ev: &Event, line: &Line) {
        if !self.agents.contains_key(&ev.uid) {
            return;
        }
        let now = Instant::now();
        if ev.kind == EventKind::Claim as u32 {
            let Some(path) = events::claim_path(ev, state.claim_parents()) else {
                return;
            };
            if claims::writable_path(&path) && !self.new_folders.iter().any(|f| f.path == path) {
                self.new_folders.push(NewFolder {
                    due: now + CLAIM_DELAY,
                    uid: ev.uid,
                    app: ev.subject,
                    process: process(ev),
                    path,
                });
            }
            return;
        }
        if ev.kind != EventKind::Access as u32
            || ev.action != ACTION_DENY
            || ev.reason != REASON_PERMS
            || ev.subject == APP_AGENT
            // explsm's own files are not the user's to give away.
            || ev.owner == APP_DAEMON
            || ev.owner == OWNER_PINS
        {
            return;
        }
        let subject = if ev.subject == APP_UNCONFINED {
            if ev.exe.ino == 0 {
                return;
            }
            Subject::Exe(ev.exe)
        } else {
            Subject::App(ev.subject)
        };
        let outcome = self
            .prompts
            .access(now, ev.uid, subject, ev.owner, ev.perms, ev.pid, None, None);
        let Outcome::Ask { id, replaces } = outcome else {
            return;
        };
        if let Some(old) = replaces {
            self.cancel(ev.uid, old);
        }
        // Pin the process and find its exe only now that it is asked.
        // The pid may have been reused since the event: only the process the
        // kernel saw may be allowed.
        let pidfd = seed::pidfd_open(ev.pid)
            .ok()
            .filter(|_| seed::same_process(ev.pid, ev.start_time));
        let exe = exe_path(ev);
        let mut choices = Vec::new();
        if pidfd.is_some() {
            choices.push(choice::ALLOW_PROCESS.to_string());
        }
        choices.push(choice::ALLOW_SESSION.into());
        let (subject_name, warning) = match subject {
            Subject::App(app) => {
                choices.push(choice::ALLOW_ALWAYS.into());
                (state.policy.name(app).to_string(), String::new())
            }
            Subject::Exe(key) => match &exe {
                // A hard-linked exe is one identity under every name
                // (coreutils, busybox): never made an app from a prompt.
                Some(p) if fs::metadata(p).is_ok_and(|m| m.nlink() > 1) => (
                    p.display().to_string(),
                    claims::linked_warning(p, fs::metadata(p).map_or(0, |m| m.nlink())),
                ),
                Some(p) if claims::writable_path(p) => {
                    choices.push(choice::ALLOW_ALWAYS.into());
                    (p.display().to_string(), claims::exe_warning(p, ev.uid))
                }
                Some(p) => (p.display().to_string(), String::new()),
                None => (format!("exe {}", show_key(&key)), String::new()),
            },
        };
        choices.push(choice::DENY.into());
        let path = line
            .fields
            .iter()
            .find(|(k, _)| *k == "EXPLSM_PATH")
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        if let Some(prompt) = self.prompts.get_mut(id) {
            prompt.choices = choices.clone();
            prompt.path = path.clone();
            prompt.process = process(ev);
            if let Kind::Access {
                pidfd: p, exe: e, ..
            } = &mut prompt.kind
            {
                *p = pidfd;
                *e = exe;
            }
        }
        let info = PromptInfo {
            id,
            kind: PROMPT_ACCESS.into(),
            subject: subject_name,
            process: process(ev),
            owner: state.policy.name(ev.owner).into(),
            perms: perm_names(ev.perms),
            path,
            warning,
            choices,
        };
        if let Some(prompt) = self.prompts.get_mut(id) {
            prompt.info = Some(info.clone());
        }
        self.send(ev.uid, info);
    }

    fn send(&self, uid: u32, info: PromptInfo) {
        let (Some(conn), Some(agent)) = (self.conn.clone(), self.agents.get(&uid)) else {
            return;
        };
        let dest = agent.connection.clone();
        tokio::spawn(async move {
            let id = info.id;
            if let Err(e) = agent_proxy(&conn, dest).await?.prompt(info).await {
                eprintln!("explsmd: warning: sending prompt {id} to the agent of uid {uid}: {e}");
            }
            zbus::Result::Ok(())
        });
    }

    fn cancel(&self, uid: u32, id: u64) {
        let (Some(conn), Some(agent)) = (self.conn.clone(), self.agents.get(&uid)) else {
            return;
        };
        let dest = agent.connection.clone();
        tokio::spawn(async move { agent_proxy(&conn, dest).await?.cancel(id).await });
    }

    /// `connection` (of user `uid`) answers prompt `id`.
    pub fn answer(
        &mut self,
        state: &mut State,
        connection: &str,
        uid: u32,
        id: u64,
        choice: &str,
    ) -> Result<Answered, String> {
        let prompt = self
            .prompts
            .get(id)
            .ok_or("no such prompt (answered or expired)")?;
        let is_agent = self
            .agents
            .get(&uid)
            .is_some_and(|a| a.connection == connection);
        if prompt.uid != uid || !is_agent {
            return Err("only the agent of the prompt's user may answer it".into());
        }
        // Only what was offered: e.g. no "always" for a hard-linked exe.
        if !prompt.choices.iter().any(|c| c == choice) {
            return Err(format!("`{choice}` is not an answer to this prompt"));
        }
        let prompt = self.prompts.take(id).expect("looked up above");
        let mut entry = HistoryEntry {
            time: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
            answer: choice.into(),
            ..HistoryEntry::default()
        };
        if choice == choice::DENY {
            self.prompts.denied(&prompt, Instant::now());
        }
        let user = claims::user_name(uid);
        let mut reloaded = false;
        match prompt.kind {
            Kind::Access {
                subject,
                owner,
                perms,
                pid,
                pidfd,
                exe,
            } => {
                let owner_name = state.policy.name(owner).to_string();
                let shown = match (&subject, &exe) {
                    (Subject::App(app), _) => state.policy.name(*app).to_string(),
                    (Subject::Exe(_), Some(p)) => p.display().to_string(),
                    (Subject::Exe(k), None) => format!("exe {}", show_key(k)),
                };
                match choice {
                    choice::ALLOW_PROCESS => {
                        let pidfd = pidfd.ok_or("the process is gone")?;
                        let key = TempKey {
                            kind: temp_kind::PROC,
                            uid,
                            owner,
                            _pad: 0,
                            a: u64::from(pid),
                            b: 0,
                        };
                        self.temp
                            .add(&mut state.ebpf, key, perms, format!("pid {pid} ({shown})"))
                            .map_err(|e| format!("{e:#}"))?;
                        grants::watch_exit(pidfd, pid, self.exits.clone());
                    }
                    choice::ALLOW_SESSION => {
                        let (kind, a, b) = match subject {
                            Subject::App(app) => (temp_kind::APP, u64::from(app), 0),
                            Subject::Exe(k) => (temp_kind::EXE, u64::from(k.dev), k.ino),
                        };
                        let key = TempKey {
                            kind,
                            uid,
                            owner,
                            _pad: 0,
                            a,
                            b,
                        };
                        self.temp
                            .add(&mut state.ebpf, key, perms, shown.clone())
                            .map_err(|e| format!("{e:#}"))?;
                    }
                    choice::ALLOW_ALWAYS => {
                        let text = match subject {
                            Subject::App(app) => {
                                claims::app_grant(&user, state.policy.name(app), perms, &owner_name)
                            }
                            Subject::Exe(_) => {
                                let exe = exe
                                    .filter(|p| claims::writable_path(p))
                                    .ok_or("the exe's path is not known")?;
                                let name =
                                    claims::app_name(&exe, |n| state.policy.ids.get(n).is_some());
                                claims::exe_grant(&user, &name, &exe, perms, &owner_name)
                            }
                        };
                        self.write_policy(state, &user, &text)?;
                        reloaded = true;
                    }
                    _ => {}
                }
                eprintln!(
                    "explsmd: uid {uid} answered {choice} for {shown} on {owner_name} ({})",
                    perm_names(perms).join(",")
                );
                entry.kind = PROMPT_ACCESS.into();
                entry.process = prompt.process.clone();
                entry.subject = shown;
                entry.owner = owner_name;
                entry.perms = perm_names(perms);
                entry.path = prompt.path.clone();
            }
            Kind::Claim { app, path } => {
                let name = state.policy.name(app).to_string();
                if choice == choice::CLAIM {
                    if !fs::metadata(&path).is_ok_and(|m| m.is_dir()) {
                        return Err(format!("{} is gone", path.display()));
                    }
                    self.write_policy(state, &user, &claims::claim(&user, &name, &path))?;
                    reloaded = true;
                } else {
                    claims::add_declined(&self.declined_file, &name, &path)
                        .map_err(|e| format!("recording the answer: {e}"))?;
                    self.prompts.declined(&name, path.clone());
                }
                eprintln!(
                    "explsmd: uid {uid} answered {choice} for {} of {name}",
                    path.display()
                );
                entry.kind = PROMPT_CLAIM.into();
                entry.subject = name;
                entry.process = prompt.process.clone();
                entry.path = path.display().to_string();
            }
        }
        self.remember(uid, entry);
        Ok(Answered { reloaded })
    }

    /// Append to the user's claims file and reload; take it back if the
    /// policy does not load with it.
    fn write_policy(&self, state: &mut State, user: &str, text: &str) -> Result<(), String> {
        let dir = state
            .claims_dir()
            .ok_or("no claims directory")?
            .to_path_buf();
        let appended = claims::append(&dir, user, text)
            .map_err(|e| format!("writing {}: {e}", dir.display()))?;
        let reply = state.reload();
        if reply.ok {
            eprintln!(
                "explsmd: wrote {}; policy reloaded: {}",
                appended.path().display(),
                reply.summary
            );
            return Ok(());
        }
        let path = appended.path().display().to_string();
        if let Err(e) = appended.undo() {
            eprintln!("explsmd: warning: taking back what was written to {path}: {e}");
        }
        eprintln!(
            "explsmd: the answer does not load, taken back: {}\n{}",
            reply.summary, reply.diagnostics
        );
        Err(format!("{}: {}", reply.summary, reply.diagnostics))
    }
}

/// Write `text` to `path`, readable by root only.
pub(crate) fn write_private(path: &Path, text: &str) -> std::io::Result<()> {
    write_atomic(path, text, 0o600)
}

/// Replace `path` with `text` (mode `mode` if it is new) through a
/// temporary file and a rename, so a crash leaves the old or the new file,
/// never a part of one.
fn write_atomic(path: &Path, text: &str, mode: u32) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("new");
    let mut f = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(mode)
        .open(&tmp)?;
    f.write_all(text.as_bytes())?;
    f.sync_all()?;
    fs::rename(&tmp, path)
}

async fn agent_proxy(conn: &Connection, dest: String) -> zbus::Result<AgentProxy<'static>> {
    AgentProxy::builder(conn)
        .destination(dest)
        .cache_properties(zbus::proxy::CacheProperties::No)
        .build()
        .await
}

/// Where the exe of the event's process is: from `/proc` while the process
/// lives, else the process name in the usual bin directories, as long as it
/// is the same inode.
fn exe_path(ev: &Event) -> Option<PathBuf> {
    if let Ok(exe) = procs::exe(ev.pid)
        && exe.key == ev.exe
    {
        return Some(exe.path);
    }
    let end = ev
        .proc_comm
        .iter()
        .position(|b| *b == 0)
        .unwrap_or(ev.proc_comm.len());
    let name = String::from_utf8_lossy(&ev.proc_comm[..end]).into_owned();
    if name.is_empty() || name.contains('/') {
        return None;
    }
    [
        "/usr/local/sbin",
        "/usr/local/bin",
        "/usr/sbin",
        "/usr/bin",
        "/sbin",
        "/bin",
    ]
    .iter()
    .map(|dir| PathBuf::from(dir).join(&name))
    .find(|p| file_key(p).ok() == Some(ev.exe))
    .and_then(|p| fs::canonicalize(p).ok())
}

fn process(ev: &Event) -> String {
    let end = ev
        .proc_comm
        .iter()
        .position(|b| *b == 0)
        .unwrap_or(ev.proc_comm.len());
    format!(
        "{} (pid {})",
        String::from_utf8_lossy(&ev.proc_comm[..end]),
        ev.pid
    )
}

fn perm_names(bits: u32) -> Vec<String> {
    perm::NAMES
        .iter()
        .filter(|(b, _)| bits & b != 0)
        .map(|(_, n)| n.to_string())
        .collect()
}
