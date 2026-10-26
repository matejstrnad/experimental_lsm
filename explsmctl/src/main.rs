//! explsmctl: check policy, talk to explsmd, read its log.
//!
//! - `check` parses and compiles the policy locally; no daemon, no root.
//! - `status`, `load` and `unload` call explsmd over D-Bus (root only).
//!   With no daemon running, `unload` runs `explsmd --unload`: only the
//!   installed explsmd may remove the pins.
//! - `log` and `learn` read the `EXPLSM_*` journal fields that explsmd
//!   writes when it runs under systemd.

mod learn;

use std::{
    io::IsTerminal as _,
    os::unix::process::CommandExt as _,
    path::PathBuf,
    process::{Command, ExitCode},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context as _, Result, bail};
use clap::{Parser, Subcommand};
use explsm_ipc::DaemonProxy;
use explsm_policy::{IdTable, Sources, diag, resolve, users};

#[derive(Parser)]
#[command(about = "Control and inspect explsm")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Check a policy without loading it.
    Check {
        /// Policy directory or file.
        #[arg(default_value = explsm_policy::POLICY_DIR)]
        path: PathBuf,
        /// Also resolve paths to inodes, as the daemon would.
        #[arg(long)]
        resolve: bool,
        /// Directory of the daemon's answers to prompts, read after the
        /// policy if it exists.
        #[arg(long, default_value = explsm_policy::CLAIMS_DIR)]
        claims: PathBuf,
        /// Don't read the claims directory.
        #[arg(long)]
        no_claims: bool,
    },
    /// Make explsmd load its policy again.
    Load,
    /// Turn explsm off until it is started again: remove the labels and
    /// the pinned programs and maps.
    Unload {
        /// The installed explsmd, run if no daemon is running.
        #[arg(long, default_value = "/usr/sbin/explsmd")]
        explsmd: PathBuf,
    },
    /// Show the policy in force, agents, grants from prompts and the
    /// counters.
    Status,
    /// Show denied and audited accesses.
    Log {
        /// Only accesses to data of this app.
        #[arg(long)]
        app: Option<String>,
        /// Only denied accesses.
        #[arg(long, conflicts_with = "audit")]
        deny: bool,
        /// Only audited accesses.
        #[arg(long)]
        audit: bool,
        /// Passed to journalctl, e.g. "1 hour ago" or "today".
        #[arg(long)]
        since: Option<String>,
        /// Keep printing new entries.
        #[arg(short, long)]
        follow: bool,
        /// Show only the last N entries.
        #[arg(short = 'n', long)]
        lines: Option<u32>,
    },
    /// Suggest grants from the logged accesses to an app's data.
    Learn {
        app: String,
        /// Passed to journalctl, e.g. "1 week ago".
        #[arg(long)]
        since: Option<String>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.cmd {
        Cmd::Check {
            path,
            resolve,
            claims,
            no_claims,
        } => check(&path, (!no_claims).then_some(claims.as_path()), resolve),
        Cmd::Load => block_on(load()),
        Cmd::Unload { explsmd } => block_on(unload(explsmd)),
        Cmd::Status => block_on(status()),
        Cmd::Log {
            app,
            deny,
            audit,
            since,
            follow,
            lines,
        } => log(app, deny, audit, since, follow, lines),
        Cmd::Learn { app, since } => learn(&app, since),
    };
    match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("explsmctl: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn block_on<F: Future<Output = Result<ExitCode>>>(f: F) -> Result<ExitCode> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(f)
}

fn check(
    path: &std::path::Path,
    claims: Option<&std::path::Path>,
    resolve: bool,
) -> Result<ExitCode> {
    let sources = Sources::load_with_claims(path, claims)
        .with_context(|| format!("reading {}", path.display()))?;
    if sources.0.is_empty() {
        eprintln!("explsmctl: warning: no *.{} files in {}", explsm_policy::EXTENSION, path.display());
    }
    let policy = match explsm_policy::check(&sources, &IdTable::default()) {
        Ok(p) => p,
        Err(d) => {
            eprint!("{}", diag::render(&d, &sources, std::io::stderr().is_terminal()));
            let errors = d.len();
            eprintln!("explsmctl: {errors} error{}", if errors == 1 { "" } else { "s" });
            return Ok(ExitCode::FAILURE);
        }
    };
    let color = std::io::stderr().is_terminal();
    eprint!("{}", diag::render(&policy.warnings, &sources, color));
    println!(
        "policy ok: {} files, {} apps, {} grants, root bypass {}",
        sources.0.len(),
        policy.apps.len(),
        policy.grants.len(),
        if policy.root_bypass { "on" } else { "off" }
    );
    if !resolve {
        return Ok(ExitCode::SUCCESS);
    }
    let (users, warnings) = users::system(policy.users.as_deref()).context("reading users")?;
    for w in &warnings {
        eprintln!("warning: {w}");
    }
    let names: Vec<_> = users.iter().map(|u| u.name.as_str()).collect();
    println!("users: {}", names.join(", "));
    let resolved = match resolve::resolve(&policy, &users) {
        Ok(r) => r,
        Err(errors) => {
            for e in &errors {
                eprintln!("error: {e}");
            }
            return Ok(ExitCode::FAILURE);
        }
    };
    for app in &policy.apps {
        println!("app {} ({})", app.name, app.mode.name());
        for f in resolved.exes.iter().filter(|f| f.app == app.id) {
            println!("  exe     {}  {}", f.path.display(), resolve::show_key(&f.key));
        }
        for f in resolved.roots.iter().filter(|f| f.app == app.id) {
            println!("  root    {}  {}", f.path.display(), resolve::show_key(&f.key));
        }
        for m in resolved.missing.iter().filter(|m| m.app == app.id) {
            println!("  missing {} {}", m.kind.name(), m.path.display());
        }
    }
    if !policy.terminals.is_empty() {
        println!("terminals");
        for f in &resolved.terminals {
            println!("  exe     {}  {}", f.path.display(), resolve::show_key(&f.key));
        }
        for m in resolved.missing.iter().filter(|m| m.kind == resolve::Kind::Terminal) {
            println!("  missing {}", m.path.display());
        }
    }
    Ok(ExitCode::SUCCESS)
}

async fn proxy() -> Result<DaemonProxy<'static>> {
    let conn = zbus::Connection::system()
        .await
        .context("connecting to the system bus")?;
    Ok(DaemonProxy::new(&conn).await?)
}

/// The D-Bus error name of a failed call. zbus reports the standard
/// `org.freedesktop.DBus.Error.*` ones as [`zbus::Error::FDO`], others as
/// [`zbus::Error::MethodError`].
fn error_name(e: &zbus::Error) -> Option<String> {
    use zbus::DBusError as _;
    match e {
        zbus::Error::MethodError(name, _, _) => Some(name.to_string()),
        zbus::Error::FDO(e) => Some(e.name().to_string()),
        _ => None,
    }
}

/// Whether the call failed because no explsmd owns the bus name.
fn not_running(e: &zbus::Error) -> bool {
    error_name(e).is_some_and(|n| {
        matches!(
            n.as_str(),
            "org.freedesktop.DBus.Error.ServiceUnknown" | "org.freedesktop.DBus.Error.NameHasNoOwner"
        )
    })
}

/// Explain the usual D-Bus failures.
fn bus_error(e: zbus::Error) -> anyhow::Error {
    let hint = if not_running(&e) {
        " (is explsmd running?)"
    } else if error_name(&e).as_deref() == Some("org.freedesktop.DBus.Error.AccessDenied") {
        " (explsmd only answers root)"
    } else {
        ""
    };
    anyhow::anyhow!("{e}{hint}")
}

async fn load() -> Result<ExitCode> {
    let reply = proxy().await?.reload().await.map_err(bus_error)?;
    if reply.ok {
        println!("policy loaded: {}", reply.summary);
        if !reply.diagnostics.is_empty() {
            eprintln!("{}", reply.diagnostics);
        }
        Ok(ExitCode::SUCCESS)
    } else {
        eprint!("{}", reply.diagnostics);
        if !reply.diagnostics.ends_with('\n') {
            eprintln!();
        }
        eprintln!("explsmctl: {}", reply.summary);
        Ok(ExitCode::FAILURE)
    }
}

async fn unload(explsmd: PathBuf) -> Result<ExitCode> {
    let reply = proxy().await?.unload().await;
    match reply {
        Ok(notes) => {
            println!("unloaded by explsmd: {}", notes.replace('\n', "\n  "));
            Ok(ExitCode::SUCCESS)
        }
        Err(e) if not_running(&e) => {
            eprintln!("explsmctl: explsmd is not running; running {} --unload", explsmd.display());
            let status = Command::new(&explsmd)
                .arg("--unload")
                .status()
                .with_context(|| format!("running {}", explsmd.display()))?;
            Ok(if status.success() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            })
        }
        Err(e) => Err(bus_error(e)),
    }
}

fn ago(unix: u64) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let s = now.saturating_sub(unix);
    match s {
        0..60 => format!("{s}s ago"),
        60..3600 => format!("{}m ago", s / 60),
        3600..86400 => format!("{}h {}m ago", s / 3600, s % 3600 / 60),
        _ => format!("{}d {}h ago", s / 86400, s % 86400 / 3600),
    }
}

async fn status() -> Result<ExitCode> {
    let s = proxy().await?.status().await.map_err(bus_error)?;
    println!(
        "policy      {} (loaded {}, resolved {})",
        s.policy_dir,
        ago(s.loaded_at),
        ago(s.resolved_at)
    );
    println!(
        "root bypass {}, policy generation {}",
        if s.root_bypass { "on" } else { "off" },
        s.generation
    );
    println!("users       {}", s.users.join(", "));
    for app in &s.apps {
        println!("\napp {} ({}, id {})", app.name, app.mode, app.id);
        for f in &app.exes {
            println!("  exe     {}  {}", f.path, f.key);
        }
        for f in &app.roots {
            let note = if f.note.is_empty() {
                String::new()
            } else {
                format!("  [{}]", f.note)
            };
            println!("  root    {}  {}{note}", f.path, f.key);
        }
        for m in &app.missing {
            println!("  missing {m}");
        }
    }
    if !s.grants.is_empty() {
        println!("\ngrants");
        for g in &s.grants {
            println!("  {} -> {}: {}", g.subject, g.owner, g.perms.join(", "));
        }
    }
    if !s.terminals.is_empty() {
        println!("\nterminals");
        for f in &s.terminals {
            println!("  exe     {}  {}", f.path, f.key);
        }
    }
    println!();
    if s.agents.is_empty() {
        println!("agents      none (no prompts are shown)");
    }
    for a in &s.agents {
        println!("agent       uid {} pid {} ({})", a.uid, a.pid, a.connection);
    }
    for g in &s.temp_grants {
        println!(
            "prompted    uid {}: {} -> {}: {} (until {})",
            g.uid,
            g.subject,
            g.owner,
            g.perms.join(", "),
            if g.lifetime == "process" { "it exits" } else { "logout" }
        );
    }
    let counters: Vec<_> = s.stats.iter().map(|(n, v)| format!("{n}={v}")).collect();
    println!("\ncounters    {}", counters.join(" "));
    for w in &s.warnings {
        println!("warning     {w}");
    }
    Ok(ExitCode::SUCCESS)
}

/// journalctl with explsmd's access events selected.
fn journalctl(app: Option<&str>, since: Option<&str>) -> Command {
    let mut cmd = Command::new("journalctl");
    cmd.args(["--no-pager", "SYSLOG_IDENTIFIER=explsmd", "EXPLSM_KIND=access"]);
    if let Some(app) = app {
        cmd.arg(format!("EXPLSM_OWNER={app}"));
    }
    if let Some(since) = since {
        cmd.args(["--since", since]);
    }
    cmd
}

fn log(
    app: Option<String>,
    deny: bool,
    audit: bool,
    since: Option<String>,
    follow: bool,
    lines: Option<u32>,
) -> Result<ExitCode> {
    let mut cmd = journalctl(app.as_deref(), since.as_deref());
    cmd.args(["-o", "short-iso"]);
    if deny {
        cmd.arg("EXPLSM_ACTION=deny");
    }
    if audit {
        cmd.arg("EXPLSM_ACTION=audit");
    }
    if follow {
        cmd.arg("--follow");
    }
    if let Some(n) = lines {
        cmd.arg(format!("--lines={n}"));
    }
    let err = cmd.exec();
    bail!("running journalctl: {err}")
}

fn learn(app: &str, since: Option<String>) -> Result<ExitCode> {
    let out = journalctl(Some(app), since.as_deref())
        .args(["-o", "json"])
        .output()
        .context("running journalctl")?;
    if !out.status.success() {
        bail!(
            "journalctl failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let records = learn::parse(&String::from_utf8_lossy(&out.stdout));
    if records.is_empty() {
        eprintln!("explsmctl: no logged accesses to data of {app}");
        return Ok(ExitCode::SUCCESS);
    }
    print!("{}", learn::suggest(app, &records));
    Ok(ExitCode::SUCCESS)
}
