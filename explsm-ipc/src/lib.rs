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
    pub root_bypass: bool,
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

#[derive(Serialize, Deserialize, Type, Debug, Clone, Default)]
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
}

/// What the daemon calls on an agent, at [`AGENT_PATH`].
#[zbus::proxy(interface = "org.explsm.Agent1", default_path = "/org/explsm/Agent1")]
pub trait Agent {
    /// Ask the user. Returns at once; the answer comes through `Answer`.
    async fn prompt(&self, info: PromptInfo) -> zbus::Result<()>;

    /// The prompt is no longer needed.
    async fn cancel(&self, id: u64) -> zbus::Result<()>;
}
