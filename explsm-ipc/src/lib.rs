//! The D-Bus API of explsmd, shared by the daemon, explsmctl and
//! explsm-agent.
//!
//! explsmd owns [`BUS_NAME`] on the system bus and serves [`INTERFACE`] at
//! [`PATH`]. Only root may call it (see
//! `packaging/org.explsm.Daemon1.conf`).
//!
//! Prompts: each user's `explsm-agent` calls [`MANAGER_INTERFACE`]
//! `Register` on the same path, which every user may call. explsmd then
//! calls [`AGENT_INTERFACE`] `Prompt` on the agent's connection for denials
//! of that user's processes, and the agent calls `Answer` with the user's
//! choice. Only a process running the agent exe is taken as an agent.
//!
//! The GUI (`explsm-gui`, started by the agent for each prompt or by the
//! user for its settings window) runs with the agent's identity too, and
//! calls `UserStatus`, `Revoke*` and `SetSecret` on [`MANAGER_INTERFACE`]:
//! explsmd answers those only for processes of the agent or GUI exe, and
//! only about the caller's own user.

use serde::{Deserialize, Serialize};
use zbus::zvariant::Type;

pub const BUS_NAME: &str = "org.explsm.Daemon1";
pub const PATH: &str = "/org/explsm/Daemon1";
pub const INTERFACE: &str = "org.explsm.Daemon1";
pub const MANAGER_INTERFACE: &str = "org.explsm.AgentManager1";
pub const AGENT_PATH: &str = "/org/explsm/Agent1";
pub const AGENT_INTERFACE: &str = "org.explsm.Agent1";

/// Answers to a prompt, in [`PromptInfo::choices`] and `Answer`.
pub mod choice {
    /// Grant the missing perms to the process until it exits.
    pub const ALLOW_PROCESS: &str = "allow-process";
    /// Grant them to the app (or, unconfined, the exe) until the user's
    /// agent goes away, i.e. until logout.
    pub const ALLOW_SESSION: &str = "allow-session";
    /// Write a grant to the policy (`claims.d`).
    pub const ALLOW_ALWAYS: &str = "allow-always";
    /// Keep denying, and don't ask again for a while.
    pub const DENY: &str = "deny";
    /// Make the new folder a root of the app.
    pub const CLAIM: &str = "claim";
    /// Don't, and don't ask again.
    pub const DECLINE: &str = "decline";

    /// What the button for `choice` says; `subject` is
    /// [`super::PromptInfo::subject`].
    pub fn label(choice: &str, subject: &str) -> String {
        match choice {
            ALLOW_PROCESS => "Allow this process".into(),
            ALLOW_SESSION => "Allow until logout".into(),
            ALLOW_ALWAYS => "Always allow".into(),
            DENY => "Deny".into(),
            CLAIM => format!("Protect for {subject}"),
            DECLINE => "Leave unprotected".into(),
            other => other.into(),
        }
    }
}

/// [`PromptInfo::kind`]
pub const PROMPT_ACCESS: &str = "access";
pub const PROMPT_CLAIM: &str = "claim";

/// Reply of `Status`.
#[derive(Serialize, Deserialize, Type, Debug, Clone, Default)]
pub struct Status {
    pub policy_dir: String,
    /// Unix time of the last successful policy load.
    pub loaded_at: u64,
    /// Unix time of the last resolution of paths to inodes.
    pub resolved_at: u64,
    /// `on`, `off` or `audit`, after `explsmd --no-root-bypass`.
    pub root_bypass: String,
    pub generation: u32,
    /// Users whose homes `~` is expanded for.
    pub users: Vec<String>,
    pub apps: Vec<AppStatus>,
    pub grants: Vec<GrantStatus>,
    /// Grants given through prompts, until the process exits or the
    /// session ends.
    pub temp_grants: Vec<TempGrantStatus>,
    /// Registered agents.
    pub agents: Vec<AgentStatus>,
    /// Terminal entry exes (`terminal …`), as resolved.
    pub terminals: Vec<FileStatus>,
    /// Counters of the BPF programs, by name.
    pub stats: Vec<(String, u64)>,
    /// Warnings of the last load or resolution.
    pub warnings: Vec<String>,
}

#[derive(Serialize, Deserialize, Type, Debug, Clone, Default)]
pub struct AppStatus {
    pub name: String,
    pub id: u32,
    pub mode: String,
    /// `inherit`: the identity is kept across execs of exes that are no app.
    pub inherit: bool,
    /// `env`: loader variables that keep the identity.
    pub env: Vec<String>,
    /// `code any`: may map any file as code.
    pub code_any: bool,
    /// `started_by`: who may start the app (`@terminal`, app names, …).
    /// Empty: anyone.
    pub started_by: Vec<String>,
    /// `deny_args`: argument patterns that drop the identity.
    pub deny_args: Vec<String>,
    pub exes: Vec<FileStatus>,
    pub roots: Vec<FileStatus>,
    /// Paths of the policy that match nothing yet.
    pub missing: Vec<String>,
}

#[derive(Serialize, Deserialize, Type, Debug, Clone, Default)]
pub struct FileStatus {
    pub path: String,
    /// `major:minor/inode`.
    pub key: String,
    /// Extra information, e.g. that a root was moved away from its path.
    pub note: String,
}

#[derive(Serialize, Deserialize, Type, Debug, Clone, Default)]
pub struct GrantStatus {
    pub subject: String,
    pub owner: String,
    pub perms: Vec<String>,
}

#[derive(Serialize, Deserialize, Type, Debug, Clone, Default, PartialEq, Eq)]
pub struct TempGrantStatus {
    /// `process` or `session`.
    pub lifetime: String,
    /// The app, `pid N`, or the exe of unconfined processes.
    pub subject: String,
    pub owner: String,
    pub uid: u32,
    pub perms: Vec<String>,
}

#[derive(Serialize, Deserialize, Type, Debug, Clone, Default)]
pub struct AgentStatus {
    pub uid: u32,
    pub pid: u32,
    /// Unique bus name.
    pub connection: String,
}

/// A question for the user, sent to their agent.
#[derive(Serialize, Deserialize, Type, Debug, Clone, Default, PartialEq, Eq)]
pub struct PromptInfo {
    pub id: u64,
    /// [`PROMPT_ACCESS`] or [`PROMPT_CLAIM`].
    pub kind: String,
    /// Access: the app, or the exe path of an unconfined process. Claim: the
    /// app that created the folder.
    pub subject: String,
    /// The process, e.g. `rg (pid 4242)`.
    pub process: String,
    /// Access: the app whose data it is.
    pub owner: String,
    /// Access: the missing permissions.
    pub perms: Vec<String>,
    /// Access: the file. Claim: the new folder.
    pub path: String,
    /// Something to point out, e.g. that the exe is writable by the user.
    pub warning: String,
    /// What may be answered, from [`choice`].
    pub choices: Vec<String>,
}

/// How `explsm-gui prompt` ends, for the agent.
pub mod dialog {
    /// The user answered; the choice is on stdout.
    pub const ANSWERED: i32 = 0;
    /// Closed without an answer.
    pub const CLOSED: i32 = 1;
    /// The dialog could not be shown (no display, GTK failed): the agent
    /// falls back to a notification.
    pub const UNAVAILABLE: i32 = 3;
}

/// The picture and phrase the user chose, shown in every prompt so that a
/// window drawn by another program can be told apart: only explsmd and
/// processes of the agent and GUI exes can read it.
#[derive(Serialize, Deserialize, Type, Debug, Clone, Default, PartialEq, Eq)]
pub struct Secret {
    /// One of [`SECRET_ICONS`]; empty when not set up yet.
    pub icon: String,
    pub phrase: String,
}

/// The pictures a [`Secret`] may use: symbolic icons every GTK theme has.
pub const SECRET_ICONS: &[&str] = &[
    "starred-symbolic",
    "emblem-favorite-symbolic",
    "weather-clear-symbolic",
    "weather-clear-night-symbolic",
    "weather-few-clouds-symbolic",
    "weather-showers-symbolic",
    "weather-snow-symbolic",
    "weather-storm-symbolic",
    "face-smile-symbolic",
    "face-cool-symbolic",
    "face-wink-symbolic",
    "face-angel-symbolic",
    "audio-headphones-symbolic",
    "camera-photo-symbolic",
    "input-gaming-symbolic",
    "applications-science-symbolic",
];

/// The longest [`Secret::phrase`].
pub const SECRET_PHRASE_MAX: usize = 40;

impl Secret {
    /// Why it can't be saved, if it can't.
    pub fn check(&self) -> Result<(), String> {
        if !SECRET_ICONS.contains(&self.icon.as_str()) {
            return Err(format!("unknown picture `{}`", self.icon));
        }
        if self.phrase.chars().count() > SECRET_PHRASE_MAX {
            return Err(format!(
                "the phrase is longer than {SECRET_PHRASE_MAX} characters"
            ));
        }
        if self.phrase.chars().any(char::is_control) {
            return Err("the phrase has control characters".into());
        }
        Ok(())
    }

    pub fn is_set(&self) -> bool {
        !self.icon.is_empty()
    }
}

/// A prompt the user answered, kept by explsmd (in memory) for the GUI.
#[derive(Serialize, Deserialize, Type, Debug, Clone, Default, PartialEq, Eq)]
pub struct HistoryEntry {
    /// Unix time of the answer.
    pub time: u64,
    /// [`PROMPT_ACCESS`] or [`PROMPT_CLAIM`].
    pub kind: String,
    pub subject: String,
    pub process: String,
    pub owner: String,
    pub perms: Vec<String>,
    pub path: String,
    /// From [`choice`].
    pub answer: String,
}

/// A grant in the user's claims file (`claims.d/<user>.explsm`).
#[derive(Serialize, Deserialize, Type, Debug, Clone, Default, PartialEq, Eq)]
pub struct SavedGrant {
    pub subject: String,
    /// The exe, when the subject is an app the claims file made for it.
    pub exe: String,
    pub owner: String,
    pub perms: Vec<String>,
}

/// A `claim` in the user's claims file. Not revocable from the GUI: taking
/// one back unprotects data, which only root should do.
#[derive(Serialize, Deserialize, Type, Debug, Clone, Default, PartialEq, Eq)]
pub struct SavedClaim {
    pub app: String,
    pub path: String,
}

/// An app of the policy, as the GUI shows it.
#[derive(Serialize, Deserialize, Type, Debug, Clone, Default, PartialEq, Eq)]
pub struct UserApp {
    pub name: String,
    pub mode: String,
    pub exes: Vec<String>,
    pub roots: Vec<String>,
}

/// Reply of `UserStatus`: what concerns the calling user.
#[derive(Serialize, Deserialize, Type, Debug, Clone, Default)]
pub struct UserStatus {
    /// Unix time of the last successful policy load.
    pub loaded_at: u64,
    pub generation: u32,
    /// Whether the user's agent is registered.
    pub agent: bool,
    pub apps: Vec<UserApp>,
    /// The user's grants until a process exits or until logout.
    pub temp_grants: Vec<TempGrantStatus>,
    /// The user's grants in the claims file.
    pub saved_grants: Vec<SavedGrant>,
    pub saved_claims: Vec<SavedClaim>,
    /// Answered prompts, newest first.
    pub history: Vec<HistoryEntry>,
    pub secret: Secret,
}

impl PromptInfo {
    /// One line saying what is asked, without markup.
    pub fn summary(&self) -> String {
        if self.kind == PROMPT_CLAIM {
            format!("New folder of {}", self.subject)
        } else {
            format!(
                "{} wants to {} {}'s data",
                self.subject,
                self.perms.join(", "),
                self.owner
            )
        }
    }
}

/// Reply of `Reload`.
#[derive(Serialize, Deserialize, Type, Debug, Clone, Default)]
pub struct ReloadReply {
    /// False if the policy had errors; the old policy stays in force.
    pub ok: bool,
    pub summary: String,
    /// Rendered diagnostics, without colour.
    pub diagnostics: String,
}

#[zbus::proxy(
    interface = "org.explsm.Daemon1",
    default_service = "org.explsm.Daemon1",
    default_path = "/org/explsm/Daemon1"
)]
pub trait Daemon {
    /// The policy in force, as resolved, and the counters.
    async fn status(&self) -> zbus::Result<Status>;

    /// Read the policy directory again and apply it.
    async fn reload(&self) -> zbus::Result<ReloadReply>;

    /// Remove the labels and the pinned programs and maps, then exit. What
    /// the reply says was done.
    async fn unload(&self) -> zbus::Result<String>;
}

/// What agents call. Every user may.
#[zbus::proxy(
    interface = "org.explsm.AgentManager1",
    default_service = "org.explsm.Daemon1",
    default_path = "/org/explsm/Daemon1"
)]
pub trait AgentManager {
    /// Become the agent of the caller's user. Only a process running the
    /// agent exe may.
    async fn register(&self) -> zbus::Result<()>;

    /// Answer prompt `id` with one of its [`PromptInfo::choices`].
    async fn answer(&self, id: u64, choice: &str) -> zbus::Result<()>;

    /// Open prompt `id` of the caller's user, as explsmd sent it to the
    /// agent: the dialog shows this, not what it was started with. Agent
    /// and GUI exes only.
    async fn prompt_info(&self, id: u64) -> zbus::Result<PromptInfo>;

    /// What concerns the caller's user. Agent and GUI exes only.
    async fn user_status(&self) -> zbus::Result<UserStatus>;

    /// End the caller's grants of `subject` (as in
    /// [`TempGrantStatus::subject`]) to `owner`'s data that last until a
    /// process exits or until logout. Returns how many ended. Agent and GUI
    /// exes only.
    async fn revoke_temp(&self, subject: &str, owner: &str) -> zbus::Result<u32>;

    /// Take a grant of `subject` to `owner` out of the caller's claims file
    /// and reload. Agent and GUI exes only.
    async fn revoke_saved(&self, subject: &str, owner: &str) -> zbus::Result<()>;

    /// Set the caller's [`Secret`]. Agent and GUI exes only.
    async fn set_secret(&self, secret: Secret) -> zbus::Result<()>;
}

/// What the daemon calls on an agent, at [`AGENT_PATH`].
#[zbus::proxy(interface = "org.explsm.Agent1", default_path = "/org/explsm/Agent1")]
pub trait Agent {
    /// Ask the user. Returns at once; the answer comes through `Answer`.
    async fn prompt(&self, info: PromptInfo) -> zbus::Result<()>;

    /// The prompt is no longer needed.
    async fn cancel(&self, id: u64) -> zbus::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checks_secrets() {
        let ok = Secret {
            icon: SECRET_ICONS[0].into(),
            phrase: "blue horse".into(),
        };
        assert!(ok.check().is_ok());
        assert!(ok.is_set());
        assert!(!Secret::default().is_set());
        let bad = Secret {
            icon: "evil".into(),
            ..ok.clone()
        };
        assert!(bad.check().is_err());
        let long = Secret {
            phrase: "x".repeat(SECRET_PHRASE_MAX + 1),
            ..ok.clone()
        };
        assert!(long.check().is_err());
        let ctl = Secret {
            phrase: "a\nb".into(),
            ..ok
        };
        assert!(ctl.check().is_err());
    }
}
