//! explsm-agent: asks the user about explsm denials and new folders, with
//! explsm's own dialog or desktop notifications, and passes the answers to
//! explsmd.
//!
//! Runs as a systemd user service (`packaging/explsm-agent.service`). It
//! registers with explsmd on the system bus, which only accepts it if the
//! process runs the installed agent exe, and serves `org.explsm.Agent1` for
//! explsmd's prompts. Each prompt is shown in a dialog, `explsm-gui prompt`
//! (see `explsm-gui`), one at a time: the agent writes the prompt to its
//! stdin and reads the answer from its stdout. A dialog closed without an
//! answer, or one that crashes, changes nothing (the access stays denied).
//! Where the dialog can't be shown (it is not installed, the session is not
//! Wayland, GTK fails to start), the prompt becomes a notification on the
//! session bus with one button per answer instead. When explsmd restarts,
//! the agent registers again.
//!
//! When explsmd is not on the bus at login, or leaves it, the user is told
//! with a notification that stays until explsmd is back: a start that
//! failed at boot would otherwise leave the machine unprotected unnoticed.
//!
//! Built with the `test-answer` feature (smoke tests only), `--answer CHOICE`
//! answers every prompt with CHOICE (or `deny`/`decline` where CHOICE is not
//! offered) and shows nothing. An installed agent must not have it: explsmd
//! trusts the agent by its exe, so any process of the user could run it with
//! `--answer allow-always` and have its own denials allowed.

use std::{
    collections::{HashMap, VecDeque},
    path::{Path, PathBuf},
    process::{ExitStatus, Stdio},
};

use anyhow::{Context as _, Result};
use clap::Parser;
use explsm_ipc::{
    AGENT_PATH, AgentManagerProxy, BUS_NAME, PROMPT_CLAIM, PromptInfo, choice, dialog,
};
use futures_util::{Stream, StreamExt as _};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    process::Command,
    signal::unix::{SignalKind, signal},
    sync::{mpsc, oneshot},
};
use zbus::{Connection, Variant, connection, fdo, message::Header};

#[derive(Parser)]
#[command(about = "explsm desktop agent: prompts for denied accesses and new folders")]
struct Cli {
    /// The dialog program. explsmd must have been given the same path
    /// (`explsmd --gui`), or the dialog can't show the security picture.
    #[arg(long, default_value = "/usr/libexec/explsm-gui")]
    gui: PathBuf,
    /// Use notifications only, never the dialog.
    #[arg(long)]
    no_gui: bool,
    /// Answer every prompt with this choice instead of asking (for tests):
    /// allow-process, allow-session, allow-always, deny, claim, decline.
    /// `force:CHOICE` sends CHOICE even where it is not offered, to check
    /// that explsmd refuses it.
    #[cfg(feature = "test-answer")]
    #[arg(long)]
    answer: Option<String>,
}

impl Cli {
    /// The choice to answer every prompt with, in a test build.
    fn answer(&self) -> Option<&str> {
        #[cfg(feature = "test-answer")]
        return self.answer.as_deref();
        #[cfg(not(feature = "test-answer"))]
        None
    }
}

enum Msg {
    Prompt(PromptInfo),
    Cancel(u64),
}

struct AgentService {
    tx: mpsc::UnboundedSender<Msg>,
}

/// Only explsmd may prompt.
async fn from_daemon(hdr: &Header<'_>, conn: &Connection) -> fdo::Result<()> {
    let sender = hdr
        .sender()
        .ok_or_else(|| fdo::Error::AccessDenied("no sender".into()))?;
    let owner = fdo::DBusProxy::new(conn)
        .await?
        .get_name_owner(BUS_NAME.try_into().expect("valid name"))
        .await?;
    if owner.as_str() == sender.as_str() {
        Ok(())
    } else {
        Err(fdo::Error::AccessDenied("only explsmd may prompt".into()))
    }
}

#[zbus::interface(name = "org.explsm.Agent1")]
impl AgentService {
    async fn prompt(
        &self,
        info: PromptInfo,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> fdo::Result<()> {
        from_daemon(&hdr, conn).await?;
        let _ = self.tx.send(Msg::Prompt(info));
        Ok(())
    }

    async fn cancel(
        &self,
        id: u64,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> fdo::Result<()> {
        from_daemon(&hdr, conn).await?;
        let _ = self.tx.send(Msg::Cancel(id));
        Ok(())
    }
}

#[zbus::proxy(
    interface = "org.freedesktop.Notifications",
    default_service = "org.freedesktop.Notifications",
    default_path = "/org/freedesktop/Notifications"
)]
trait Notifications {
    #[allow(clippy::too_many_arguments)]
    fn notify(
        &self,
        app_name: &str,
        replaces_id: u32,
        app_icon: &str,
        summary: &str,
        body: &str,
        actions: &[&str],
        hints: HashMap<&str, Variant<'_>>,
        expire_timeout: i32,
    ) -> zbus::Result<u32>;

    fn close_notification(&self, id: u32) -> zbus::Result<()>;

    #[zbus(signal)]
    fn action_invoked(&self, id: u32, action_key: String) -> zbus::Result<()>;

    #[zbus(signal)]
    fn notification_closed(&self, id: u32, reason: u32) -> zbus::Result<()>;
}

/// Notification bodies may contain markup.
fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn button(c: &str, info: &PromptInfo) -> String {
    choice::label(c, &info.subject)
}

/// Summary and body of the notification for `info`.
fn text(info: &PromptInfo) -> (String, String) {
    let mut body = Vec::new();
    if info.kind == PROMPT_CLAIM {
        body.push(format!(
            "{} created {}. Should it be {}'s, kept from other programs?",
            escape(&info.subject),
            escape(&info.path),
            escape(&info.subject)
        ));
    } else {
        body.push(format!("{} was denied.", escape(&info.process)));
        body.push(escape(&info.path));
    }
    let summary = info.summary();
    if !info.warning.is_empty() {
        body.push(format!("<b>Note:</b> {}", escape(&info.warning)));
    }
    (summary, body.join("\n"))
}

/// The answer `--answer` gives to `info`.
#[cfg_attr(not(feature = "test-answer"), allow(dead_code))]
fn auto_answer<'a>(wanted: &'a str, info: &PromptInfo) -> &'a str {
    if let Some(forced) = wanted.strip_prefix("force:") {
        forced
    } else if info.choices.iter().any(|c| c == wanted) {
        wanted
    } else if info.kind == PROMPT_CLAIM {
        choice::DECLINE
    } else {
        choice::DENY
    }
}

/// How a dialog ended.
#[derive(Debug, PartialEq, Eq)]
enum Shown {
    Answered(String),
    /// Closed without an answer.
    Closed,
    /// Could not show a window: show a notification instead.
    Unavailable,
    /// The prompt was cancelled and the dialog stopped.
    Cancelled,
    /// Crashed or failed otherwise: no answer.
    Failed(String),
}

impl Shown {
    fn of(status: ExitStatus, out: &str) -> Self {
        match status.code() {
            Some(dialog::ANSWERED) => match out.lines().next() {
                Some(c) if !c.trim().is_empty() => Shown::Answered(c.trim().to_string()),
                _ => Shown::Failed("answered nothing".into()),
            },
            Some(dialog::CLOSED) => Shown::Closed,
            Some(dialog::UNAVAILABLE) => Shown::Unavailable,
            _ => Shown::Failed(status.to_string()),
        }
    }
}

/// The longest answer read from a dialog.
const ANSWER_MAX: u64 = 256;

/// The dialogs: one shown at a time, the others waiting.
struct Dialogs {
    exe: PathBuf,
    queue: VecDeque<PromptInfo>,
    /// The prompt shown, and what stops its dialog when dropped or sent.
    current: Option<(u64, oneshot::Sender<()>)>,
    done: mpsc::UnboundedSender<(PromptInfo, Shown)>,
}

impl Dialogs {
    /// Whether a dialog can be tried at all: it is installed and the
    /// session is Wayland. On X11 any program could read the dialog (and
    /// the security picture in it) and click its buttons.
    fn usable(&self) -> bool {
        self.exe.is_file() && wayland(std::env::var_os("WAYLAND_DISPLAY").as_deref())
    }

    /// Show the next waiting prompt if none is shown. A prompt whose dialog
    /// does not start is returned, for a notification.
    fn next(&mut self) -> Option<PromptInfo> {
        if self.current.is_some() {
            return None;
        }
        let info = self.queue.pop_front()?;
        match spawn_dialog(&self.exe, info.clone(), self.done.clone()) {
            Ok(stop) => {
                self.current = Some((info.id, stop));
                None
            }
            Err(e) => {
                eprintln!("explsm-agent: starting {}: {e}", self.exe.display());
                Some(info)
            }
        }
    }

    /// Prompt `id` is no longer needed.
    fn cancel(&mut self, id: u64) {
        self.queue.retain(|i| i.id != id);
        if self.current.as_ref().is_some_and(|(c, _)| *c == id) {
            // Dropping the sender stops the dialog.
            self.current = None;
        }
    }

    fn clear(&mut self) {
        self.queue.clear();
        self.current = None;
    }
}

/// Whether `WAYLAND_DISPLAY` names a Wayland display.
fn wayland(display: Option<&std::ffi::OsStr>) -> bool {
    display.is_some_and(|d| !d.is_empty())
}

/// Start the dialog for `info`; what it ends with is sent on `done`.
/// Dropping or sending the returned sender stops it.
fn spawn_dialog(
    exe: &Path,
    info: PromptInfo,
    done: mpsc::UnboundedSender<(PromptInfo, Shown)>,
) -> std::io::Result<oneshot::Sender<()>> {
    let mut child = Command::new(exe)
        .arg("prompt")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let json = serde_json::to_vec(&info).map_err(std::io::Error::other)?;
    let (stop, stopped) = oneshot::channel::<()>();
    let mut stdin = child.stdin.take().expect("piped");
    let stdout = child.stdout.take().expect("piped");
    tokio::spawn(async move {
        let ended = {
            let run = async {
                stdin.write_all(&json).await?;
                drop(stdin);
                let mut out = String::new();
                stdout.take(ANSWER_MAX).read_to_string(&mut out).await?;
                let status = child.wait().await?;
                std::io::Result::Ok(Shown::of(status, &out))
            };
            tokio::select! {
                r = run => Some(r),
                _ = stopped => None,
            }
        };
        let shown = match ended {
            Some(Ok(shown)) => shown,
            Some(Err(e)) => {
                let _ = child.kill().await;
                Shown::Failed(e.to_string())
            }
            None => {
                let _ = child.kill().await;
                Shown::Cancelled
            }
        };
        let _ = done.send((info, shown));
    });
    Ok(stop)
}

/// Show `info` as a notification; remembers its id in `shown` and
/// `by_prompt`.
async fn notify_prompt(
    n: &NotificationsProxy<'_>,
    info: &PromptInfo,
    shown: &mut HashMap<u32, u64>,
    by_prompt: &mut HashMap<u64, u32>,
) {
    let (summary, body) = text(info);
    let labels: Vec<String> = info.choices.iter().map(|c| button(c, info)).collect();
    let actions: Vec<&str> = info
        .choices
        .iter()
        .zip(&labels)
        .flat_map(|(c, l)| [c.as_str(), l.as_str()])
        .collect();
    let hints = HashMap::from([
        ("urgency", Variant::U8(2)),
        ("resident", Variant::Bool(true)),
    ]);
    match n
        .notify(
            "explsm",
            0,
            "security-high",
            &summary,
            &body,
            &actions,
            hints,
            0,
        )
        .await
    {
        Ok(nid) => {
            shown.insert(nid, info.id);
            by_prompt.insert(info.id, nid);
        }
        Err(e) => eprintln!("explsm-agent: showing prompt {}: {e}", info.id),
    }
}

/// A stream that is empty when there is none.
async fn next_of<S: Stream + Unpin>(s: &mut Option<S>) -> Option<S::Item> {
    match s {
        Some(s) => s.next().await,
        None => std::future::pending().await,
    }
}

/// Tell the user explsmd is not running; returns the notification's id.
async fn daemon_down(n: &NotificationsProxy<'_>) -> Option<u32> {
    let body = "explsmd is not running, so no prompts are shown and new exes and folders \
                are not protected. If it did not start at boot, nothing is protected. \
                See <tt>systemctl status explsmd</tt>.";
    let hints = HashMap::from([
        ("urgency", Variant::U8(2)),
        ("resident", Variant::Bool(true)),
    ]);
    match n
        .notify(
            "explsm",
            0,
            "security-low",
            "explsm is not running",
            body,
            &[],
            hints,
            0,
        )
        .await
    {
        Ok(nid) => Some(nid),
        Err(e) => {
            eprintln!("explsm-agent: showing that explsmd is not running: {e}");
            None
        }
    }
}

async fn register(manager: &AgentManagerProxy<'_>) -> Result<()> {
    manager
        .register()
        .await
        .context("registering with explsmd (is this the installed explsm-agent?)")?;
    eprintln!("explsm-agent: registered with explsmd");
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let (tx, mut rx) = mpsc::unbounded_channel();
    let system = connection::Builder::system()
        .serve_at(AGENT_PATH, AgentService { tx })
        .build()
        .await
        .context("connecting to the system bus")?;
    let manager = AgentManagerProxy::new(&system).await?;
    let bus = fdo::DBusProxy::new(&system).await?;
    let mut daemon_changes = bus
        .receive_name_owner_changed_with_args(&[(0, BUS_NAME)])
        .await?;
    // explsmd may not be up yet; it is registered with once it appears.
    if let Err(e) = register(&manager).await {
        eprintln!("explsm-agent: {e:#}");
    }

    let notifier = match cli.answer() {
        Some(_) => None,
        None => {
            let session = Connection::session()
                .await
                .context("connecting to the session bus")?;
            Some(NotificationsProxy::new(&session).await?)
        }
    };
    let mut invoked = match &notifier {
        Some(n) => Some(n.receive_action_invoked().await?),
        None => None,
    };
    let mut closed = match &notifier {
        Some(n) => Some(n.receive_notification_closed().await?),
        None => None,
    };
    // Shown while explsmd is not on the bus.
    let mut down = None;
    let up = bus
        .name_has_owner(BUS_NAME.try_into().expect("valid name"))
        .await
        .unwrap_or(false);
    if !up {
        eprintln!("explsm-agent: explsmd is not running");
        if let Some(n) = &notifier {
            down = daemon_down(n).await;
        }
    }
    // Notification id → prompt id, and back.
    let mut shown: HashMap<u32, u64> = HashMap::new();
    let mut by_prompt: HashMap<u64, u32> = HashMap::new();
    let (done_tx, mut done_rx) = mpsc::unbounded_channel();
    let mut dialogs = Dialogs {
        exe: cli.gui.clone(),
        queue: VecDeque::new(),
        current: None,
        done: done_tx,
    };
    let use_dialog = !cli.no_gui && cli.answer().is_none();
    if use_dialog && !dialogs.usable() {
        eprintln!(
            "explsm-agent: {} is missing or this is not a Wayland session; prompts are notifications",
            cli.gui.display()
        );
    }

    let mut term = signal(SignalKind::terminate())?;
    let mut int = signal(SignalKind::interrupt())?;
    loop {
        tokio::select! {
            Some(msg) = rx.recv() => match msg {
                Msg::Prompt(info) => {
                    if let Some(wanted) = cli.answer() {
                        let answer = auto_answer(wanted, &info);
                        eprintln!(
                            "explsm-agent: prompt {} ({} {} {} {} {}): answering {answer}",
                            info.id, info.kind, info.subject, info.perms.join(","), info.owner, info.path
                        );
                        if let Err(e) = manager.answer(info.id, answer).await {
                            eprintln!("explsm-agent: answering prompt {}: {e}", info.id);
                        }
                        continue;
                    }
                    if use_dialog && dialogs.usable() {
                        dialogs.queue.push_back(info);
                        if let (Some(info), Some(n)) = (dialogs.next(), &notifier) {
                            notify_prompt(n, &info, &mut shown, &mut by_prompt).await;
                        }
                        continue;
                    }
                    let Some(n) = &notifier else { continue };
                    notify_prompt(n, &info, &mut shown, &mut by_prompt).await;
                }
                Msg::Cancel(id) => {
                    dialogs.cancel(id);
                    if let (Some(info), Some(n)) = (dialogs.next(), &notifier) {
                        notify_prompt(n, &info, &mut shown, &mut by_prompt).await;
                    }
                    if let (Some(nid), Some(n)) = (by_prompt.remove(&id), &notifier) {
                        shown.remove(&nid);
                        let _ = n.close_notification(nid).await;
                    }
                }
            },
            Some((info, ended)) = done_rx.recv() => {
                // A cancelled dialog was already replaced by the next.
                if ended != Shown::Cancelled
                    && dialogs.current.as_ref().is_some_and(|(id, _)| *id == info.id)
                {
                    dialogs.current = None;
                }
                match ended {
                    Shown::Answered(answer) => {
                        if info.choices.contains(&answer) {
                            if let Err(e) = manager.answer(info.id, &answer).await {
                                eprintln!("explsm-agent: answering prompt {}: {e}", info.id);
                            }
                        } else {
                            eprintln!("explsm-agent: the dialog answered `{answer}`, which was not offered");
                        }
                    }
                    Shown::Unavailable => {
                        eprintln!("explsm-agent: the dialog can't be shown; prompt {} is a notification", info.id);
                        if let Some(n) = &notifier {
                            notify_prompt(n, &info, &mut shown, &mut by_prompt).await;
                        }
                    }
                    Shown::Failed(e) => eprintln!("explsm-agent: the dialog for prompt {} failed: {e}", info.id),
                    Shown::Closed | Shown::Cancelled => {}
                }
                if let (Some(info), Some(n)) = (dialogs.next(), &notifier) {
                    notify_prompt(n, &info, &mut shown, &mut by_prompt).await;
                }
            }
            Some(sig) = next_of(&mut invoked) => {
                let Ok(args) = sig.args() else { continue };
                let Some(id) = shown.remove(&args.id) else { continue };
                by_prompt.remove(&id);
                if let Err(e) = manager.answer(id, &args.action_key).await {
                    eprintln!("explsm-agent: answering prompt {id}: {e}");
                }
                if let Some(n) = &notifier {
                    let _ = n.close_notification(args.id).await;
                }
            }
            Some(sig) = next_of(&mut closed) => {
                let Ok(args) = sig.args() else { continue };
                if down == Some(args.id) {
                    down = None;
                }
                if let Some(id) = shown.remove(&args.id) {
                    by_prompt.remove(&id);
                }
            }
            Some(change) = daemon_changes.next() => {
                let Ok(args) = change.args() else { continue };
                if args.new_owner().is_some() {
                    // A new explsmd knows nothing of the old prompts.
                    if let Some(n) = &notifier {
                        for nid in shown.keys() {
                            let _ = n.close_notification(*nid).await;
                        }
                    }
                    shown.clear();
                    by_prompt.clear();
                    dialogs.clear();
                    if let (Some(nid), Some(n)) = (down.take(), &notifier) {
                        let _ = n.close_notification(nid).await;
                    }
                    if let Err(e) = register(&manager).await {
                        eprintln!("explsm-agent: {e:#}");
                    }
                } else {
                    eprintln!("explsm-agent: explsmd left the bus");
                    if let Some(n) = &notifier
                        && down.is_none()
                    {
                        down = daemon_down(n).await;
                    }
                }
            }
            _ = term.recv() => break,
            _ = int.recv() => break,
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn access() -> PromptInfo {
        PromptInfo {
            id: 1,
            kind: "access".into(),
            subject: "/usr/bin/rg".into(),
            process: "rg (pid 7)".into(),
            owner: "ssh".into(),
            perms: vec!["read".into(), "list".into()],
            path: "/home/me/.ssh/<x>".into(),
            warning: String::new(),
            choices: vec![choice::ALLOW_SESSION.into(), choice::DENY.into()],
        }
    }

    #[test]
    fn texts() {
        let (summary, body) = text(&access());
        assert_eq!(summary, "/usr/bin/rg wants to read, list ssh's data");
        assert_eq!(body, "rg (pid 7) was denied.\n/home/me/.ssh/&lt;x&gt;");
        let claim = PromptInfo {
            kind: PROMPT_CLAIM.into(),
            subject: "claude".into(),
            path: "/home/me/.claude".into(),
            ..PromptInfo::default()
        };
        assert_eq!(text(&claim).0, "New folder of claude");
        assert_eq!(button(choice::CLAIM, &claim), "Protect for claude");
    }

    #[test]
    fn reads_dialog_endings() {
        use std::os::unix::process::ExitStatusExt as _;
        let code = |c: i32| ExitStatus::from_raw(c << 8);
        assert_eq!(
            Shown::of(code(dialog::ANSWERED), "deny\n"),
            Shown::Answered("deny".into())
        );
        assert!(matches!(
            Shown::of(code(dialog::ANSWERED), ""),
            Shown::Failed(_)
        ));
        assert_eq!(Shown::of(code(dialog::CLOSED), ""), Shown::Closed);
        assert_eq!(Shown::of(code(dialog::UNAVAILABLE), ""), Shown::Unavailable);
        // Killed by a signal.
        assert!(matches!(
            Shown::of(ExitStatus::from_raw(9), "deny"),
            Shown::Failed(_)
        ));
    }

    #[test]
    fn dialogs_need_wayland() {
        assert!(wayland(Some("wayland-0".as_ref())));
        assert!(!wayland(Some("".as_ref())));
        assert!(!wayland(None));
    }

    #[tokio::test]
    async fn runs_a_dialog() {
        let dir = std::env::temp_dir().join(format!("explsm-agent-dialog-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("dialog");
        std::fs::write(&script, "#!/bin/sh\ncat >/dev/null\necho allow-session\n").unwrap();
        std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let _stop = spawn_dialog(&script, access(), tx).unwrap();
        let (info, shown) = rx.recv().await.unwrap();
        assert_eq!(info.id, 1);
        assert_eq!(shown, Shown::Answered(choice::ALLOW_SESSION.into()));

        // Stopped while it waits.
        std::fs::write(&script, "#!/bin/sh\nexec sleep 30\n").unwrap();
        let (tx, mut rx) = mpsc::unbounded_channel();
        drop(spawn_dialog(&script, access(), tx).unwrap());
        assert_eq!(rx.recv().await.unwrap().1, Shown::Cancelled);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn auto_answers() {
        let info = access();
        assert_eq!(
            auto_answer(choice::ALLOW_SESSION, &info),
            choice::ALLOW_SESSION
        );
        assert_eq!(auto_answer(choice::ALLOW_ALWAYS, &info), choice::DENY);
        assert_eq!(
            auto_answer("force:allow-always", &info),
            choice::ALLOW_ALWAYS
        );
    }
}
