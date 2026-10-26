//! explsm-agent: asks the user about explsm denials and new folders, with
//! desktop notifications, and passes the answers to explsmd.
//!
//! Runs as a systemd user service (`packaging/explsm-agent.service`). It
//! registers with explsmd on the system bus, which only accepts it if the
//! process runs the installed agent exe, and serves `org.explsm.Agent1` for
//! explsmd's prompts. Each prompt becomes a notification on the session bus
//! with one button per answer; a notification closed without an answer
//! changes nothing (the access stays denied). When explsmd restarts, the
//! agent registers again.
//!
//! Built with the `test-answer` feature (smoke tests only), `--answer CHOICE`
//! answers every prompt with CHOICE (or `deny`/`decline` where CHOICE is not
//! offered) and shows nothing. An installed agent must not have it: explsmd
//! trusts the agent by its exe, so any process of the user could run it with
//! `--answer allow-always` and have its own denials allowed.

use std::collections::HashMap;

use anyhow::{Context as _, Result};
use clap::Parser;
use explsm_ipc::{
    AGENT_PATH, AgentManagerProxy, BUS_NAME, PROMPT_CLAIM, PromptInfo, choice,
};
use futures_util::{Stream, StreamExt as _};
use tokio::{
    signal::unix::{SignalKind, signal},
    sync::mpsc,
};
use zbus::{Connection, Variant, connection, fdo, message::Header};

#[derive(Parser)]
#[command(about = "explsm desktop agent: prompts for denied accesses and new folders")]
struct Cli {
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
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

fn button(choice: &str, info: &PromptInfo) -> String {
    match choice {
        choice::ALLOW_PROCESS => "Allow this process".into(),
        choice::ALLOW_SESSION => "Allow until logout".into(),
        choice::ALLOW_ALWAYS => "Always allow".into(),
        choice::DENY => "Deny".into(),
        choice::CLAIM => format!("Protect for {}", info.subject),
        choice::DECLINE => "Leave unprotected".into(),
        other => other.into(),
    }
}

/// Summary and body of the notification for `info`.
fn text(info: &PromptInfo) -> (String, String) {
    let mut body = Vec::new();
    let summary = if info.kind == PROMPT_CLAIM {
        body.push(format!(
            "{} created {}. Should it be {}'s, kept from other programs?",
            escape(&info.subject),
            escape(&info.path),
            escape(&info.subject)
        ));
        format!("New folder of {}", info.subject)
    } else {
        body.push(format!("{} was denied.", escape(&info.process)));
        body.push(escape(&info.path));
        format!(
            "{} wants to {} {}'s data",
            info.subject,
            info.perms.join(", "),
            info.owner
        )
    };
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

/// A stream that is empty when there is none.
async fn next_of<S: Stream + Unpin>(s: &mut Option<S>) -> Option<S::Item> {
    match s {
        Some(s) => s.next().await,
        None => std::future::pending().await,
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
    let mut daemon_changes = fdo::DBusProxy::new(&system)
        .await?
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
    // Notification id → prompt id, and back.
    let mut shown: HashMap<u32, u64> = HashMap::new();
    let mut by_prompt: HashMap<u64, u32> = HashMap::new();

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
                    let Some(n) = &notifier else { continue };
                    let (summary, body) = text(&info);
                    let labels: Vec<String> = info.choices.iter().map(|c| button(c, &info)).collect();
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
                    match n.notify("explsm", 0, "security-high", &summary, &body, &actions, hints, 0).await {
                        Ok(nid) => {
                            shown.insert(nid, info.id);
                            by_prompt.insert(info.id, nid);
                        }
                        Err(e) => eprintln!("explsm-agent: showing prompt {}: {e}", info.id),
                    }
                }
                Msg::Cancel(id) => {
                    if let (Some(nid), Some(n)) = (by_prompt.remove(&id), &notifier) {
                        shown.remove(&nid);
                        let _ = n.close_notification(nid).await;
                    }
                }
            },
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
                if let Ok(args) = sig.args()
                    && let Some(id) = shown.remove(&args.id)
                {
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
                    if let Err(e) = register(&manager).await {
                        eprintln!("explsm-agent: {e:#}");
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
    fn auto_answers() {
        let info = access();
        assert_eq!(auto_answer(choice::ALLOW_SESSION, &info), choice::ALLOW_SESSION);
        assert_eq!(auto_answer(choice::ALLOW_ALWAYS, &info), choice::DENY);
        assert_eq!(auto_answer("force:allow-always", &info), choice::ALLOW_ALWAYS);
    }
}
