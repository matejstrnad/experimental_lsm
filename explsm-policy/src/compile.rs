//! Checking the syntax tree and assigning app ids.

use std::{
    collections::HashMap,
    path::{Component, Path, PathBuf},
};

use explsm_common::{
    APP_AGENT, APP_DAEMON, APP_UNCONFINED, AppId, ArgKey, ENV_CHUNK, EnvKey, GrantKey,
    MAX_ALLOWED_ENV, MAX_DENY_ARGS, MAX_EXES, MAX_GRANTS, MAX_ROOTS, MAX_TERMINALS, MODE_AUDIT,
    MODE_ENFORCE, OWNER_ANY, OWNER_PINS, OWNER_UNKNOWN, SUBJECT_DESKTOP, SUBJECT_ROOT,
    SUBJECT_TERMINAL, StartKey, app_flag, perm, root_bypass,
};

use crate::{
    Span, Spanned,
    ast::{self, Item},
    diag::{Diagnostic, Severity},
    users::User,
};

/// Most app names one daemon run can use: ids `1..=MAX_NAMES`. The ids after
/// them are reserved: [`OWNER_UNKNOWN`], [`OWNER_PINS`], [`APP_DAEMON`] and
/// [`APP_AGENT`].
pub const MAX_NAMES: usize = OWNER_UNKNOWN as usize - 1;

/// Names no app may have: the names of the builtin ids.
pub const RESERVED_NAMES: [&str; 9] = [
    "unconfined",
    "all",
    "terminal",
    "desktop",
    "root",
    "unknown",
    "explsm-agent",
    "explsmd",
    "explsm-pins",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Mode {
    #[default]
    Audit,
    Enforce,
}

impl Mode {
    pub fn name(self) -> &'static str {
        match self {
            Self::Audit => "audit",
            Self::Enforce => "enforce",
        }
    }

    /// Value of the `MODES` map.
    pub fn map_value(self) -> u32 {
        match self {
            Self::Audit => MODE_AUDIT,
            Self::Enforce => MODE_ENFORCE,
        }
    }
}

/// `root_bypass on|off|audit`: what a task with fsuid 0 gets past.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum RootBypass {
    /// Every check except label changes and `EXDEV`, silently.
    On,
    /// None: root is the `@root` subject.
    Off,
    /// As `On`, and every access only the bypass let through is logged.
    #[default]
    Audit,
}

impl RootBypass {
    pub fn name(self) -> &'static str {
        match self {
            Self::On => "on",
            Self::Off => "off",
            Self::Audit => "audit",
        }
    }

    /// Value of `CONFIG[CFG_ROOT_BYPASS]`.
    pub fn config_value(self) -> u32 {
        match self {
            Self::On => root_bypass::ON,
            Self::Off => root_bypass::OFF,
            Self::Audit => root_bypass::AUDIT,
        }
    }
}

/// App names → ids. Ids are never reused for another name while a daemon
/// runs: running tasks keep their id in task storage after the app is gone
/// from the policy.
#[derive(Clone, Debug, Default)]
pub struct IdTable {
    /// Name of id `i + 1`.
    names: Vec<String>,
}

impl IdTable {
    pub fn get(&self, name: &str) -> Option<AppId> {
        self.names
            .iter()
            .position(|n| n == name)
            .map(|i| i as AppId + 1)
    }

    /// Name of an id, including ids of apps that were removed since.
    pub fn name(&self, id: AppId) -> &str {
        match id {
            APP_UNCONFINED => "unconfined",
            OWNER_ANY => "*",
            SUBJECT_TERMINAL => "terminal",
            SUBJECT_ROOT => "root",
            SUBJECT_DESKTOP => "desktop",
            APP_AGENT => "explsm-agent",
            APP_DAEMON => "explsmd",
            OWNER_PINS => "explsm-pins",
            OWNER_UNKNOWN => "unknown",
            _ => self.names.get(id as usize - 1).map_or("?", String::as_str),
        }
    }

    fn assign(&mut self, name: &str) -> Option<AppId> {
        if let Some(id) = self.get(name) {
            return Some(id);
        }
        if self.names.len() >= MAX_NAMES {
            return None;
        }
        self.names.push(name.into());
        Some(self.names.len() as AppId)
    }

    /// A table with these names for ids `1..`, as [`Self::names`] gave
    /// them. Too many names are cut off.
    pub fn from_names(mut names: Vec<String>) -> Self {
        names.truncate(MAX_NAMES);
        Self { names }
    }

    /// Name of every id ever assigned, in id order from 1.
    pub fn names(&self) -> &[String] {
        &self.names
    }

    /// Every id ever assigned.
    pub fn ids(&self) -> impl Iterator<Item = AppId> {
        1..=self.names.len() as AppId
    }
}

/// A path as written in the policy: absolute, or below each user's home.
/// Only the last component may be a glob.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathPat {
    /// As written, used to recognise the same pattern across reloads.
    pub text: String,
    /// `~/…`: `path` is relative to each user's home.
    pub home: bool,
    pub path: PathBuf,
    /// The last component has glob characters.
    pub glob: bool,
    pub span: Span,
}

impl PathPat {
    fn parse(s: &Spanned<String>) -> Result<Self, Diagnostic> {
        let err = |msg: &str| Diagnostic::error(s.span, msg.to_string());
        let text = s.value.trim_end_matches('/');
        if text.is_empty() && s.value.starts_with('/') {
            return Err(err("`/` can't be owned"));
        }
        let (home, rest) = match text.strip_prefix("~/") {
            Some(rest) => (true, rest),
            None if text.starts_with('/') => (false, text),
            None if text == "~" => {
                return Err(err("a whole home directory can't be owned")
                    .note("own the folders inside it instead"));
            }
            None => {
                return Err(err("path must be absolute or start with `~/`").label("relative path"));
            }
        };
        let path = Path::new(rest);
        // `components()` drops `.` after the start (`/a/.`), so look at the
        // text as written.
        if rest.split('/').any(|n| n == "." || n == "..") {
            return Err(err("path must not contain `.` or `..`"));
        }
        let mut names = Vec::new();
        for c in path.components() {
            match c {
                Component::Normal(n) => names.push(n.to_string_lossy()),
                Component::RootDir => {}
                _ => return Err(err("path must not contain `.` or `..`")),
            }
        }
        if rest.contains("//") {
            return Err(err("path must not contain empty components (`//`)"));
        }
        if names.is_empty() {
            return Err(err("`/` can't be owned"));
        }
        let is_glob = |n: &str| n.contains(['*', '?', '[']);
        let (last, dirs) = names.split_last().expect("checked above");
        if dirs.iter().any(|n| is_glob(n)) {
            return Err(
                err("only the last path component may contain `*`, `?` or `[`")
                    .note("the daemon watches the parent directory of each path for changes"),
            );
        }
        let glob = is_glob(last);
        if glob && let Err(e) = glob::Pattern::new(last) {
            return Err(err(&format!("bad glob: {}", e.msg)));
        }
        Ok(Self {
            text: s.value.clone(),
            home,
            path: path.to_path_buf(),
            glob,
            span: s.span,
        })
    }

    /// Concrete paths (still patterns if [`Self::glob`]) for `users`.
    pub fn expand(&self, users: &[User]) -> Vec<PathBuf> {
        if self.home {
            users.iter().map(|u| u.home.join(&self.path)).collect()
        } else {
            vec![self.path.clone()]
        }
    }
}

#[derive(Clone, Debug)]
pub struct App {
    pub id: AppId,
    pub name: String,
    pub mode: Mode,
    pub exes: Vec<PathPat>,
    pub roots: Vec<PathPat>,
    /// `inherit`: processes keep the identity across execs of exes that are
    /// no app.
    pub inherit: bool,
    /// `env`: loader variables, as `NAME=VALUE`, that keep the identity.
    pub env: Vec<String>,
    /// `code any`: may map any file as code. The default, `code trusted`,
    /// allows only files that root alone can change, and the app's own.
    pub code_any: bool,
    /// `started_by`: the subjects (app ids, [`APP_UNCONFINED`],
    /// [`SUBJECT_TERMINAL`], [`SUBJECT_DESKTOP`]) that may start the app.
    /// Empty: anyone may.
    pub started_by: Vec<AppId>,
    /// `deny_args`: argument patterns that drop the identity, exact or
    /// ending in `*` (a prefix).
    pub deny_args: Vec<String>,
    /// Exe pattern ([`PathPat::text`]) → the hashes a file it matches must
    /// have (`sha256`, `hashes`). Exes without an entry are not pinned.
    pub pins: HashMap<String, Pin>,
}

/// What a pinned exe may be: one of `sha256`, or a hash in one of the
/// `hashes` files (`sha256sum` output, owned by root).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Pin {
    pub sha256: Vec<[u8; 32]>,
    pub lists: Vec<PathBuf>,
}

/// A SHA-256 written in hex.
pub fn parse_sha256(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 || !hex.is_ascii() {
        return None;
    }
    let mut out = [0; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

impl App {
    /// Value of the `APP_FLAGS` map.
    pub fn flags(&self) -> u32 {
        let mut flags = 0;
        if self.inherit {
            flags |= app_flag::INHERIT;
        }
        if self.code_any {
            flags |= app_flag::CODE_ANY;
        }
        if !self.started_by.is_empty() {
            flags |= app_flag::STARTED_BY;
        }
        if !self.deny_args.is_empty() {
            flags |= app_flag::DENY_ARGS;
        }
        flags
    }

    /// Name of a `started_by` subject.
    pub fn spawner_name(id: AppId, ids: &IdTable) -> String {
        match id {
            APP_UNCONFINED => "@unconfined".into(),
            SUBJECT_TERMINAL => "@terminal".into(),
            SUBJECT_DESKTOP => "@desktop".into(),
            _ => ids.name(id).into(),
        }
    }
}

/// Launchers that start whatever they are asked to: naming one in
/// `started_by` lets anyone start the app through it.
pub const UNTRUSTED_LAUNCHERS: [&str; 10] = [
    "systemd",
    "systemd-run",
    "dbus-daemon",
    "dbus-broker",
    "gnome-session",
    "gnome-session-binary",
    "gnome-terminal-server",
    "xdg-open",
    "gio",
    "gio-launch-desktop",
];

fn check_arg(arg: &Spanned<String>) -> Result<(), Diagnostic> {
    let err = |msg: String| Diagnostic::error(arg.span, msg);
    let body = arg.value.strip_suffix('*').unwrap_or(&arg.value);
    if body.is_empty() {
        return Err(err(
            "an empty `deny_args` pattern would match every argument".into(),
        ));
    }
    if body.contains(['*', '?', '[']) {
        return Err(
            err("a `deny_args` pattern is an argument, or a prefix ending in `*`".into())
                .note("`*` may only be the last character; there are no other globs"),
        );
    }
    // The exec hook reads an argument with its NUL in one chunk.
    if body.len() + 1 >= ENV_CHUNK {
        return Err(err(format!(
            "`deny_args` patterns have at most {} bytes",
            ENV_CHUNK - 2
        )));
    }
    Ok(())
}

/// An error if more distinct absolute paths without a glob are in `pats` than
/// `cap` entries of the map they go into.
fn too_many_paths(what: &str, map: &str, cap: usize, pats: &[&PathPat]) -> Option<Diagnostic> {
    let mut seen = std::collections::HashSet::new();
    let over = pats
        .iter()
        .filter(|p| !p.home && !p.glob)
        .find(|p| seen.insert(&p.path) && seen.len() > cap)?;
    Some(
        Diagnostic::error(over.span, format!("too many {what} paths: at most {cap}"))
            .note(format!("each file they name is an entry of the {map} map")),
    )
}

/// The variables the exec hook looks at; only these can be allowed by `env`.
pub const LOADER_VARS: [&str; 3] = ["LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT"];

/// The paths in the value of an `env` string (`NAME=VALUE`): the loader
/// separates them by `:`, and also by spaces and `;` in some variables.
pub fn env_paths(var: &str) -> impl Iterator<Item = &str> {
    let value = var.split_once('=').map_or("", |(_, v)| v);
    value.split([':', ';', ' '])
}

fn check_env(var: &Spanned<String>) -> Result<(), Diagnostic> {
    let err = |msg: String| Diagnostic::error(var.span, msg);
    let Some((name, value)) = var.value.split_once('=') else {
        return Err(err("an `env` string is `NAME=VALUE`".into()));
    };
    if !LOADER_VARS.contains(&name) {
        return Err(err(format!("`{name}` is no loader variable")).note(
            "only LD_PRELOAD, LD_LIBRARY_PATH and LD_AUDIT drop an identity, so only \
                   they can be allowed",
        ));
    }
    if value.is_empty() {
        return Err(err(format!("`{name}` has no value")));
    }
    // The exec hook reads the string with its NUL in one chunk.
    if var.value.len() + 1 >= ENV_CHUNK {
        return Err(err(format!(
            "`env` strings have at most {} bytes",
            ENV_CHUNK - 2
        )));
    }
    for path in env_paths(&var.value) {
        let p = Path::new(path);
        if path.is_empty() {
            return Err(err("an empty entry means the current directory".into())
                .note("the loader would look in whatever directory the app runs in"));
        }
        if path.contains('$') {
            return Err(err(format!(
                "`{path}`: `$ORIGIN` and the like are not supported"
            )));
        }
        if !p.is_absolute()
            || p.components()
                .any(|c| matches!(c, Component::CurDir | Component::ParentDir))
        {
            return Err(err(format!(
                "`{path}` is not an absolute path without `.` and `..`"
            )));
        }
    }
    Ok(())
}

/// A checked policy.
#[derive(Clone, Debug)]
pub struct Compiled {
    pub root_bypass: RootBypass,
    /// `fail_closed on`: logins wait for explsmd at boot (see
    /// `packaging/explsm-gate.service`).
    pub fail_closed: bool,
    /// `require_sandbox on`: explsmd refuses to start without its Landlock
    /// sandbox.
    pub require_sandbox: bool,
    /// `require_dbus on`: explsmd refuses to start without its D-Bus API.
    pub require_dbus: bool,
    /// `users …`: names or uids. `None`: every regular user.
    pub users: Option<Vec<Spanned<String>>>,
    pub apps: Vec<App>,
    pub grants: HashMap<GrantKey, u32>,
    /// Terminal entry exes (`terminal …`): their descendants get `@terminal`
    /// grants while they have a controlling tty.
    pub terminals: Vec<PathPat>,
    /// `shell …`: exes that keep a chain of shells from a terminal going
    /// (`started_by @terminal`).
    pub shells: Vec<PathPat>,
    /// `desktop …`: the exes of `@desktop`.
    pub desktops: Vec<PathPat>,
    /// The id table this policy was compiled with, including earlier ids.
    pub ids: IdTable,
    /// Warnings, e.g. statements of `claims.d` that name apps that are gone.
    pub warnings: Vec<Diagnostic>,
}

impl Compiled {
    pub fn name(&self, id: AppId) -> &str {
        self.ids.name(id)
    }

    pub fn app(&self, id: AppId) -> Option<&App> {
        self.apps.iter().find(|a| a.id == id)
    }

    /// App id → value of the `MODES` map, for every id ever assigned. Apps
    /// that were removed are in audit mode.
    pub fn modes(&self) -> impl Iterator<Item = (AppId, u32)> + '_ {
        self.ids
            .ids()
            .map(|id| (id, self.app(id).map_or(MODE_AUDIT, |a| a.mode.map_value())))
    }

    /// App id → value of the `APP_FLAGS` map, for every id ever assigned.
    /// Apps that were removed have none.
    pub fn app_flags(&self) -> impl Iterator<Item = (AppId, u32)> + '_ {
        self.ids
            .ids()
            .map(|id| (id, self.app(id).map_or(0, App::flags)))
    }

    /// Keys of the `STARTED_BY` map: every app's `started_by` subjects.
    pub fn started_by(&self) -> impl Iterator<Item = StartKey> + '_ {
        self.apps.iter().flat_map(|a| {
            a.started_by
                .iter()
                .map(|&spawner| StartKey { app: a.id, spawner })
        })
    }

    /// Keys of the `DENY_ARGS` trie: every app's `deny_args` patterns.
    pub fn deny_args(&self) -> impl Iterator<Item = ArgKey> + '_ {
        self.apps.iter().flat_map(|a| {
            a.deny_args.iter().map(|pat| {
                let mut val = [0; ENV_CHUNK];
                // An exact pattern with its NUL, a prefix without the `*`.
                let (body, len) = match pat.strip_suffix('*') {
                    Some(body) => (body, body.len()),
                    None => (pat.as_str(), pat.len() + 1),
                };
                // check_arg keeps them shorter than a chunk.
                val[..body.len()].copy_from_slice(body.as_bytes());
                ArgKey {
                    prefixlen: 32 + 8 * len as u32,
                    app: a.id,
                    val,
                }
            })
        })
    }

    /// Keys of the `ALLOWED_ENV` map: every app's `env` strings.
    pub fn allowed_env(&self) -> impl Iterator<Item = EnvKey> + '_ {
        self.apps.iter().flat_map(|a| {
            a.env.iter().map(|var| {
                let mut val = [0; ENV_CHUNK];
                // check_env keeps them shorter than a chunk.
                val[..var.len()].copy_from_slice(var.as_bytes());
                EnvKey { app: a.id, val }
            })
        })
    }
}

/// Builtin subjects of grants.
fn builtin_subject(s: &Spanned<String>) -> Result<AppId, Diagnostic> {
    match s.value.as_str() {
        "@unconfined" => Ok(APP_UNCONFINED),
        "@terminal" => Ok(SUBJECT_TERMINAL),
        "@root" => Ok(SUBJECT_ROOT),
        other => Err(
            Diagnostic::error(s.span, format!("unknown builtin `{other}`"))
                .note("the builtin subjects are `@unconfined`, `@root` and `@terminal`"),
        ),
    }
}

/// An unknown app in a file the daemon wrote is a warning: the statement is
/// skipped. Anywhere else it is an error.
fn soften(d: Diagnostic, lenient: &[usize]) -> Diagnostic {
    if lenient.contains(&d.span.file) && d.message.starts_with("unknown app") {
        let mut d = d.note("the statement is skipped");
        d.severity = Severity::Warning;
        d
    } else {
        d
    }
}

fn perm_bits(p: &Spanned<String>) -> Result<u32, Diagnostic> {
    if p.value == "all" {
        return Ok(perm::ALL);
    }
    perm::NAMES
        .iter()
        .find(|(_, n)| *n == p.value)
        .map(|(bit, _)| *bit)
        .ok_or_else(|| {
            let names: Vec<_> = perm::NAMES.iter().map(|(_, n)| *n).collect();
            Diagnostic::error(p.span, format!("unknown permission `{}`", p.value))
                .note(format!("permissions are {}, or `all`", names.join(", ")))
        })
}

/// Check `policy` and assign app ids, keeping the ids of `ids`.
pub fn compile(policy: &ast::Policy, ids: &IdTable) -> Result<Compiled, Vec<Diagnostic>> {
    let mut diags = Vec::new();
    let mut ids = ids.clone();
    let mut root_bypass: Option<&Spanned<RootBypass>> = None;
    let mut fail_closed: Option<&Spanned<bool>> = None;
    let mut require_sandbox: Option<&Spanned<bool>> = None;
    let mut require_dbus: Option<&Spanned<bool>> = None;
    let mut users: Option<&Spanned<Vec<Spanned<String>>>> = None;
    let mut apps: Vec<App> = Vec::new();
    let mut app_spans: HashMap<&str, Span> = HashMap::new();
    let mut terminals = Vec::new();
    let mut shells = Vec::new();
    let mut desktops = Vec::new();
    // The maps the daemon writes them into are of a fixed size.
    let mut env_count = 0;
    let mut args_count = 0;

    for item in &policy.items {
        match item {
            Item::RootBypass(v) => {
                if let Some(first) = root_bypass {
                    diags.push(
                        Diagnostic::error(v.span, "`root_bypass` is set twice")
                            .also(first.span, "first set here"),
                    );
                }
                root_bypass = Some(v);
            }
            Item::FailClosed(v) => {
                if let Some(first) = fail_closed {
                    diags.push(
                        Diagnostic::error(v.span, "`fail_closed` is set twice")
                            .also(first.span, "first set here"),
                    );
                }
                fail_closed = Some(v);
            }
            Item::RequireSandbox(v) => {
                if let Some(first) = require_sandbox {
                    diags.push(
                        Diagnostic::error(v.span, "`require_sandbox` is set twice")
                            .also(first.span, "first set here"),
                    );
                }
                require_sandbox = Some(v);
            }
            Item::RequireDbus(v) => {
                if let Some(first) = require_dbus {
                    diags.push(
                        Diagnostic::error(v.span, "`require_dbus` is set twice")
                            .also(first.span, "first set here"),
                    );
                }
                require_dbus = Some(v);
            }
            Item::Users(u) => {
                if let Some(first) = users {
                    diags.push(
                        Diagnostic::error(u.span, "`users` is given twice")
                            .also(first.span, "first given here"),
                    );
                }
                users = Some(u);
            }
            Item::App(a) => {
                if let Some(app) = compile_app(a, &mut ids, &mut app_spans, &mut diags) {
                    let before_args = args_count;
                    args_count += app.deny_args.len();
                    if before_args <= MAX_DENY_ARGS as usize && args_count > MAX_DENY_ARGS as usize
                    {
                        diags.push(Diagnostic::error(
                            a.name.span,
                            format!(
                                "too many `deny_args` patterns: at most {MAX_DENY_ARGS} in all apps"
                            ),
                        ));
                    }
                    let before = env_count;
                    env_count += app.env.len();
                    if before <= MAX_ALLOWED_ENV as usize && env_count > MAX_ALLOWED_ENV as usize {
                        diags.push(Diagnostic::error(
                            a.name.span,
                            format!(
                                "too many `env` strings: at most {MAX_ALLOWED_ENV} in all apps"
                            ),
                        ));
                    }
                    apps.push(app);
                }
            }
            Item::Terminal(paths) | Item::Shell(paths) | Item::Desktop(paths) => {
                let list = match item {
                    Item::Terminal(_) => &mut terminals,
                    Item::Shell(_) => &mut shells,
                    _ => &mut desktops,
                };
                for p in paths {
                    match PathPat::parse(p) {
                        Ok(p) => list.push(p),
                        Err(d) => diags.push(d),
                    }
                }
            }
            Item::Grant(_) | Item::Claim(_) => {}
        }
    }

    for item in &policy.items {
        let Item::Claim(c) = item else { continue };
        let id = match app_id(&c.app, &apps, "claiming app") {
            Ok(id) => id,
            Err(d) => {
                diags.push(soften(d, &policy.lenient));
                continue;
            }
        };
        for p in &c.paths {
            match PathPat::parse(p) {
                Ok(p) => apps
                    .iter_mut()
                    .find(|a| a.id == id)
                    .expect("found above")
                    .roots
                    .push(p),
                Err(d) => diags.push(d),
            }
        }
    }

    // `started_by` after every app, so it may name apps of later files.
    for item in &policy.items {
        let Item::App(a) = item else { continue };
        let Some(i) = apps.iter().position(|app| app.name == a.name.value) else {
            continue;
        };
        let mut ids_of = Vec::new();
        for who in &a.started_by {
            let id = match who.value.as_str() {
                "@terminal" => {
                    if terminals.is_empty() {
                        diags.push(
                            Diagnostic::warning(
                                who.span,
                                "`started_by @terminal` without any `terminal` exe",
                            )
                            .note("no process is typed in a shell until the policy names terminal exes"),
                        );
                    }
                    if shells.is_empty() {
                        diags.push(
                            Diagnostic::warning(
                                who.span,
                                "`started_by @terminal` without any `shell` exe",
                            )
                            .note(
                                "only the terminal exe itself counts until the policy names \
                                 shells, e.g. `shell \"/usr/bin/bash\"`",
                            ),
                        );
                    }
                    Ok(SUBJECT_TERMINAL)
                }
                "@desktop" => {
                    if desktops.is_empty() {
                        diags.push(
                            Diagnostic::warning(
                                who.span,
                                "`started_by @desktop` without any `desktop` exe",
                            )
                            .note("e.g. `desktop \"/usr/bin/gnome-shell\"`"),
                        );
                    }
                    Ok(SUBJECT_DESKTOP)
                }
                "@unconfined" => {
                    diags.push(
                        Diagnostic::warning(
                            who.span,
                            "`started_by @unconfined` lets any program start the app",
                        )
                        .note("every process that is no app is @unconfined, malware included"),
                    );
                    Ok(APP_UNCONFINED)
                }
                o if o.starts_with('@') => Err(Diagnostic::error(
                    who.span,
                    format!("unknown builtin `{o}`"),
                )
                .note("`started_by` takes apps, `@terminal`, `@desktop` and `@unconfined`")),
                _ => app_id(who, &apps, "starting app"),
            };
            match id {
                Ok(id) if id == apps[i].id => diags.push(Diagnostic::error(
                    who.span,
                    format!("{} always starts itself", who.value),
                )),
                Ok(id) => {
                    if let Some(launcher) = apps.iter().find(|x| x.id == id).and_then(|x| {
                        x.exes.iter().find(|e| {
                            e.path.file_name().is_some_and(|n| {
                                UNTRUSTED_LAUNCHERS.contains(&n.to_string_lossy().as_ref())
                            })
                        })
                    }) {
                        diags.push(
                            Diagnostic::warning(
                                who.span,
                                format!(
                                    "{} runs {}, which starts programs for anyone who asks",
                                    who.value, launcher.text
                                ),
                            )
                            .note("any process could have it start the app"),
                        );
                    }
                    if !ids_of.contains(&id) {
                        ids_of.push(id);
                    }
                }
                Err(d) => diags.push(soften(d, &policy.lenient)),
            }
        }
        apps[i].started_by = ids_of;
    }

    // Grants after every app, so files may grant to apps of later files.
    let mut grants: HashMap<GrantKey, u32> = HashMap::new();
    let mut grants_full = false;
    for item in &policy.items {
        let Item::Grant(g) = item else { continue };
        let subject = if g.subject.value.starts_with('@') {
            builtin_subject(&g.subject)
        } else {
            app_id(&g.subject, &apps, "subject")
        };
        if matches!(subject, Ok(SUBJECT_TERMINAL)) && terminals.is_empty() {
            diags.push(
                Diagnostic::warning(
                    g.subject.span,
                    "`@terminal` grant without any `terminal` exe",
                )
                .note(
                    "no process is a terminal until the policy names terminal exes, \
                           e.g. `terminal \"/usr/bin/konsole\"`",
                ),
            );
        }
        let owner = match g.owner.value.as_str() {
            "*" => Ok(OWNER_ANY),
            "@explsm" => Ok(APP_DAEMON),
            o if o.starts_with('@') => Err(Diagnostic::error(
                g.owner.span,
                "the owner of a grant must be an app, `@explsm` or `*`",
            )),
            _ => app_id(&g.owner, &apps, "owner"),
        };
        let mut bits = 0;
        for p in &g.perms {
            match perm_bits(p) {
                Ok(b) => bits |= b,
                Err(d) => diags.push(d),
            }
        }
        match (subject, owner) {
            (Ok(subject), Ok(owner)) => {
                // explsm's own files: only to an app such as dpkg, never
                // to every unconfined or root process.
                if owner == APP_DAEMON && !(1..=MAX_NAMES as AppId).contains(&subject) {
                    diags.push(
                        Diagnostic::error(g.subject.span, "only an app can be granted `@explsm`")
                            .label("a builtin subject")
                            .note(
                                "define an app for the program that changes explsm's files, \
                                   e.g. `app dpkg { exe \"/usr/bin/dpkg\" }`",
                            ),
                    );
                    continue;
                }
                if subject == owner {
                    diags.push(
                        Diagnostic::error(
                            g.span,
                            format!("{} already owns its data", g.subject.value),
                        )
                        .label("grant to itself"),
                    );
                    continue;
                }
                let key = GrantKey { subject, owner };
                if !grants.contains_key(&key) && grants.len() == MAX_GRANTS as usize {
                    if !grants_full {
                        diags.push(
                            Diagnostic::error(
                                g.span,
                                format!("too many grants: at most {MAX_GRANTS}"),
                            )
                            .note("grants of the same subject and owner count once"),
                        );
                        grants_full = true;
                    }
                    continue;
                }
                *grants.entry(key).or_insert(0) |= bits;
            }
            (s, o) => diags.extend(
                s.err()
                    .into_iter()
                    .chain(o.err())
                    .map(|d| soften(d, &policy.lenient)),
            ),
        }
    }

    // What the paths resolve to is only known to the daemon, which checks
    // it again; an absolute path without a glob is at least one entry.
    // explsmd and explsm-agent take up to three exes.
    let exes = apps.iter().flat_map(|a| &a.exes);
    let roots = apps.iter().flat_map(|a| &a.roots);
    for (what, map, cap, pats) in [
        (
            "exe",
            "EXES",
            MAX_EXES as usize - 3,
            exes.collect::<Vec<_>>(),
        ),
        ("owned", "ROOTS", MAX_ROOTS as usize, roots.collect()),
        (
            "terminal, shell and desktop",
            "TERMINALS",
            MAX_TERMINALS as usize,
            terminals.iter().chain(&shells).chain(&desktops).collect(),
        ),
    ] {
        if let Some(d) = too_many_paths(what, map, cap, &pats) {
            diags.push(d);
        }
    }

    if diags.iter().any(|d| d.severity == Severity::Error) {
        return Err(diags);
    }
    Ok(Compiled {
        root_bypass: root_bypass.map_or(RootBypass::default(), |v| v.value),
        fail_closed: fail_closed.is_some_and(|v| v.value),
        require_sandbox: require_sandbox.is_some_and(|v| v.value),
        require_dbus: require_dbus.is_some_and(|v| v.value),
        users: users.map(|u| u.value.clone()),
        apps,
        grants,
        terminals,
        shells,
        desktops,
        ids,
        warnings: diags,
    })
}

fn app_id(name: &Spanned<String>, apps: &[App], role: &str) -> Result<AppId, Diagnostic> {
    apps.iter()
        .find(|a| a.name == name.value)
        .map(|a| a.id)
        .ok_or_else(|| {
            Diagnostic::error(name.span, format!("unknown app `{}`", name.value))
                .label(format!("{role} is not defined by any `app`"))
        })
}

fn compile_app<'a>(
    a: &'a ast::App,
    ids: &mut IdTable,
    spans: &mut HashMap<&'a str, Span>,
    diags: &mut Vec<Diagnostic>,
) -> Option<App> {
    let name = a.name.value.as_str();
    let before = diags.len();
    if RESERVED_NAMES.contains(&name) {
        diags.push(Diagnostic::error(
            a.name.span,
            format!("`{name}` is a reserved name"),
        ));
    }
    if let Some(first) = spans.insert(name, a.name.span) {
        diags.push(
            Diagnostic::error(a.name.span, format!("app {name} is defined twice"))
                .also(first, "first defined here"),
        );
    }
    if a.exes.is_empty() {
        diags.push(
            Diagnostic::error(a.name.span, format!("app {name} has no `exe`"))
                .note("an app is identified by its executables"),
        );
    }
    let mut exes = Vec::new();
    let mut pins: HashMap<String, Pin> = HashMap::new();
    for exe in &a.exes {
        if !exe.sha256.is_empty() || !exe.hashes.is_empty() {
            let pin = pins.entry(exe.path.value.clone()).or_default();
            for h in &exe.sha256 {
                match parse_sha256(&h.value) {
                    Some(h) => pin.sha256.push(h),
                    None => diags.push(
                        Diagnostic::error(h.span, "not a SHA-256")
                            .note("64 hex digits, as `sha256sum` prints them"),
                    ),
                }
            }
            for list in &exe.hashes {
                let p = Path::new(&list.value);
                if p.is_absolute() {
                    pin.lists.push(p.to_path_buf());
                } else {
                    diags.push(Diagnostic::error(
                        list.span,
                        "a hash list must be an absolute path",
                    ));
                }
            }
        }
        if let Some(script) = &exe.script {
            diags.push(
                Diagnostic::error(script.span, "`script` is not supported yet").note(
                    "interpreter identity (`node …/cli.js`) is planned for a later phase; \
                           without it every script of the interpreter would be the app",
                ),
            );
        }
        match PathPat::parse(&exe.path) {
            Ok(p) => exes.push(p),
            Err(d) => diags.push(d),
        }
    }
    let mut roots = Vec::new();
    for root in &a.owns {
        match PathPat::parse(root) {
            Ok(p) => roots.push(p),
            Err(d) => diags.push(d),
        }
    }
    let mut mode = Mode::Audit;
    for (i, m) in a.modes.iter().enumerate() {
        if i > 0 {
            diags.push(
                Diagnostic::error(m.span, format!("app {name} has more than one `mode`"))
                    .also(a.modes[0].span, "first set here"),
            );
        }
        match m.value.as_str() {
            "audit" => mode = Mode::Audit,
            "enforce" => mode = Mode::Enforce,
            other => diags.push(
                Diagnostic::error(m.span, format!("unknown mode `{other}`"))
                    .note("modes are `audit` and `enforce`"),
            ),
        }
    }
    for (i, span) in a.inherit.iter().enumerate() {
        if i > 0 {
            diags.push(
                Diagnostic::error(*span, format!("app {name} has more than one `inherit`"))
                    .also(a.inherit[0], "first set here"),
            );
        }
    }
    let mut env = Vec::new();
    for var in &a.env {
        match check_env(var) {
            Ok(()) if !env.contains(&var.value) => env.push(var.value.clone()),
            Ok(()) => {}
            Err(d) => diags.push(d),
        }
    }
    let mut code_any = false;
    for (i, c) in a.code.iter().enumerate() {
        if i > 0 {
            diags.push(
                Diagnostic::error(c.span, format!("app {name} has more than one `code`"))
                    .also(a.code[0].span, "first set here"),
            );
        }
        match c.value.as_str() {
            "trusted" => code_any = false,
            "any" => code_any = true,
            other => diags.push(
                Diagnostic::error(c.span, format!("unknown `code` value `{other}`"))
                    .note("`code trusted` (the default) or `code any`"),
            ),
        }
    }
    let mut deny_args = Vec::new();
    for arg in &a.deny_args {
        match check_arg(arg) {
            Ok(()) if !deny_args.contains(&arg.value) => deny_args.push(arg.value.clone()),
            Ok(()) => {}
            Err(d) => diags.push(d),
        }
    }
    if diags.len() > before {
        return None;
    }
    let Some(id) = ids.assign(name) else {
        diags.push(Diagnostic::error(
            a.name.span,
            format!("too many apps: at most {MAX_NAMES} per daemon run"),
        ));
        return None;
    };
    Some(App {
        id,
        name: name.into(),
        mode,
        exes,
        roots,
        inherit: !a.inherit.is_empty(),
        env,
        code_any,
        started_by: Vec::new(),
        deny_args,
        pins,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Sources, diag::render, parse};

    fn compiled(text: &str) -> Compiled {
        compiled_with(text, &IdTable::default())
    }

    fn compiled_with(text: &str, ids: &IdTable) -> Compiled {
        let sources = Sources::single("t", text);
        let ast = parse(&sources).unwrap();
        match compile(&ast, ids) {
            Ok(c) => c,
            Err(d) => panic!("{}", render(&d, &sources, false)),
        }
    }

    fn errors(text: &str) -> Vec<String> {
        let ast = parse(&Sources::single("t", text)).unwrap();
        compile(&ast, &IdTable::default())
            .unwrap_err()
            .into_iter()
            .map(|d| d.message)
            .collect()
    }

    #[test]
    fn full_example() {
        let c = compiled(
            r#"
            root_bypass off
            app ssh { exe "/usr/bin/ssh" owns "~/.ssh" mode enforce }
            app backup { exe "/usr/bin/restic" }
            grant backup read, list to ssh
            grant backup read to ssh
            grant @unconfined all to *
            "#,
        );
        assert_eq!(c.root_bypass, RootBypass::Off);
        assert!(!c.fail_closed);
        assert!(!c.require_sandbox);
        assert!(!c.require_dbus);
        assert_eq!(c.apps[0].mode, Mode::Enforce);
        assert_eq!(c.apps[1].mode, Mode::Audit);
        assert_eq!(c.name(2), "backup");
        assert_eq!(c.name(APP_UNCONFINED), "unconfined");
        assert_eq!(
            c.grants[&GrantKey {
                subject: 2,
                owner: 1
            }],
            perm::READ | perm::LIST
        );
        assert_eq!(
            c.grants[&GrantKey {
                subject: APP_UNCONFINED,
                owner: OWNER_ANY
            }],
            perm::ALL
        );
        assert_eq!(c.grants.len(), 2);
        let modes: Vec<_> = c.modes().collect();
        assert_eq!(modes, [(1, MODE_ENFORCE), (2, MODE_AUDIT)]);
        let root = &c.apps[0].roots[0];
        assert!(root.home && !root.glob);
        assert_eq!(root.path, Path::new(".ssh"));
    }

    #[test]
    fn defaults() {
        let c = compiled("");
        assert_eq!(c.root_bypass, RootBypass::Audit);
        assert_eq!(c.root_bypass.config_value(), root_bypass::AUDIT);
        assert_eq!(compiled("root_bypass on").root_bypass, RootBypass::On);
        assert!(c.users.is_none());
    }

    #[test]
    fn grants_may_name_later_apps() {
        let c = compiled("grant b read to a\napp a { exe \"/a\" }\napp b { exe \"/b\" }");
        assert_eq!(c.grants.len(), 1);
    }

    #[test]
    fn ids_are_stable_across_reloads() {
        let first = compiled("app a { exe \"/a\" }\napp b { exe \"/b\" }");
        // a is gone, c is new, b keeps its id.
        let second = compiled_with("app c { exe \"/c\" }\napp b { exe \"/b\" }", &first.ids);
        assert_eq!(second.ids.get("b"), Some(2));
        assert_eq!(second.ids.get("c"), Some(3));
        assert_eq!(second.name(1), "a");
        let modes: Vec<_> = second.modes().collect();
        assert_eq!(modes, [(1, MODE_AUDIT), (2, MODE_AUDIT), (3, MODE_AUDIT)]);
        // a comes back with its old id.
        let third = compiled_with("app a { exe \"/a\" }", &second.ids);
        assert_eq!(third.apps[0].id, 1);
    }

    #[test]
    fn paths() {
        let c = compiled(r#"app a { exe "~/.local/bin/a-*", "/opt/a/" owns "~/.a", "/srv/a" }"#);
        let a = &c.apps[0];
        assert!(a.exes[0].glob && a.exes[0].home);
        assert_eq!(a.exes[1].path, Path::new("/opt/a"));
        let users = [
            User {
                name: "x".into(),
                uid: 1000,
                home: "/home/x".into(),
            },
            User {
                name: "y".into(),
                uid: 1001,
                home: "/home/y".into(),
            },
        ];
        assert_eq!(
            a.roots[0].expand(&users),
            [PathBuf::from("/home/x/.a"), PathBuf::from("/home/y/.a")]
        );
        assert_eq!(a.roots[1].expand(&users), [PathBuf::from("/srv/a")]);
    }

    #[test]
    fn rejects_bad_policies() {
        let app = |name: &str| format!("app {name} {{ exe \"/bin/x\" owns \"/r\" }}\n");
        assert_eq!(
            errors(&format!("{}{}", app("a"), app("a"))),
            ["app a is defined twice"]
        );
        assert_eq!(
            errors(&app("unconfined")),
            ["`unconfined` is a reserved name"]
        );
        assert_eq!(errors("app a { owns \"/r\" }"), ["app a has no `exe`"]);
        assert_eq!(
            errors(r#"app a { exe "x", "/a/*/b", "/" owns "~", "/a/../b", "/c/[" }"#),
            [
                "path must be absolute or start with `~/`",
                "only the last path component may contain `*`, `?` or `[`",
                "`/` can't be owned",
                "a whole home directory can't be owned",
                "path must not contain `.` or `..`",
                "bad glob: invalid range pattern",
            ]
        );
        assert_eq!(
            errors(r#"app a { exe "/a" owns "/.", "/./", "~/a/.", "/a/./b" }"#),
            ["path must not contain `.` or `..`"; 4]
        );
        // A reserved name may not be what a prompt names an app either.
        for name in RESERVED_NAMES {
            assert_eq!(
                errors(&format!("app {name} {{ exe \"/a\" }}")),
                [format!("`{name}` is a reserved name")]
            );
        }
        assert_eq!(
            errors(r#"app a { exe "/n" script "/s.js" }"#),
            ["`script` is not supported yet"]
        );
        assert_eq!(
            errors("app a { exe \"/a\" mode strict }"),
            ["unknown mode `strict`"]
        );
        assert_eq!(
            errors("app a { exe \"/a\" mode audit mode enforce }"),
            ["app a has more than one `mode`"]
        );
        assert_eq!(
            errors("app a { exe \"/a\" inherit inherit }"),
            ["app a has more than one `inherit`"]
        );
        let env = |v: &str| errors(&format!("app a {{ exe \"/a\" env \"{v}\" }}"));
        assert_eq!(env("LD_PRELOAD"), ["an `env` string is `NAME=VALUE`"]);
        assert_eq!(env("PATH=/bin"), ["`PATH` is no loader variable"]);
        assert_eq!(env("LD_AUDIT="), ["`LD_AUDIT` has no value"]);
        assert_eq!(
            env("LD_LIBRARY_PATH=/a::/b"),
            ["an empty entry means the current directory"]
        );
        assert_eq!(
            env("LD_LIBRARY_PATH=$ORIGIN/lib"),
            ["`$ORIGIN/lib`: `$ORIGIN` and the like are not supported"]
        );
        assert_eq!(
            env("LD_PRELOAD=lib.so"),
            ["`lib.so` is not an absolute path without `.` and `..`"]
        );
        assert_eq!(
            env("LD_PRELOAD=/a/../b.so"),
            ["`/a/../b.so` is not an absolute path without `.` and `..`"]
        );
        let long = format!("LD_PRELOAD=/{}", "a".repeat(115));
        assert_eq!(long.len(), 127);
        assert_eq!(env(&long), ["`env` strings have at most 126 bytes"]);
        assert_eq!(
            errors(
                "root_bypass on\nroot_bypass off\nusers a\nusers b\nfail_closed on\nfail_closed off"
            ),
            [
                "`root_bypass` is set twice",
                "`users` is given twice",
                "`fail_closed` is set twice"
            ]
        );
        let grant = |g: &str| errors(&format!("{}grant {g}", app("a")));
        assert_eq!(grant("b read to a"), ["unknown app `b`"]);
        assert_eq!(grant("@unconfined read to b"), ["unknown app `b`"]);
        assert_eq!(
            grant("@unconfined exec to a"),
            ["unknown permission `exec`"]
        );

        assert_eq!(grant("@nobody read to a"), ["unknown builtin `@nobody`"]);
        assert_eq!(
            grant("a read to @unconfined"),
            ["the owner of a grant must be an app, `@explsm` or `*`"]
        );
        assert_eq!(grant("a read to a"), ["a already owns its data"]);
    }

    #[test]
    fn started_by_code_and_deny_args() {
        let c = compiled(
            r#"terminal "/t"
               shell "/bin/bash"
               desktop "/usr/bin/gnome-shell"
               app helper { exe "/h" }
               app ssh {
                   exe "/usr/bin/ssh"
                   started_by @terminal, @desktop, helper, later
                   deny_args "-I", "-oPKCS11Provider*"
                   code any
               }
               app later { exe "/l" }"#,
        );
        let ssh = c.apps.iter().find(|a| a.name == "ssh").unwrap();
        let (helper, later) = (c.ids.get("helper").unwrap(), c.ids.get("later").unwrap());
        assert_eq!(
            ssh.started_by,
            [SUBJECT_TERMINAL, SUBJECT_DESKTOP, helper, later]
        );
        assert!(ssh.code_any);
        assert_eq!(
            ssh.flags(),
            app_flag::CODE_ANY | app_flag::STARTED_BY | app_flag::DENY_ARGS
        );
        assert_eq!(c.started_by().count(), 4);
        let keys: Vec<_> = c.deny_args().collect();
        assert_eq!(keys[0].prefixlen, 32 + 8 * 3, "exact: with the NUL");
        assert_eq!(&keys[0].val[..3], b"-I\0");
        assert_eq!(keys[1].prefixlen, 32 + 8 * 16, "a prefix: without the `*`");
        assert_eq!(&keys[1].val[..16], b"-oPKCS11Provider");
        assert_eq!((c.shells.len(), c.desktops.len()), (1, 1));
        assert!(c.warnings.is_empty(), "{:?}", c.warnings);

        let c = compiled(
            r#"app systemd { exe "/usr/lib/systemd/systemd" }
               app a { exe "/a" started_by systemd, @terminal }"#,
        );
        let w: Vec<_> = c.warnings.iter().map(|d| d.message.as_str()).collect();
        assert_eq!(
            w,
            [
                "systemd runs /usr/lib/systemd/systemd, which starts programs for anyone who asks",
                "`started_by @terminal` without any `terminal` exe",
                "`started_by @terminal` without any `shell` exe",
            ]
        );
        assert_eq!(
            errors("app a { exe \"/a\" started_by a }"),
            ["a always starts itself"]
        );
        assert_eq!(
            errors("app a { exe \"/a\" started_by @root }"),
            ["unknown builtin `@root`"]
        );
        assert_eq!(
            errors("app a { exe \"/a\" code sometimes }"),
            ["unknown `code` value `sometimes`"]
        );
        assert_eq!(
            errors("app a { exe \"/a\" deny_args \"*\", \"-a*b\" }"),
            [
                "an empty `deny_args` pattern would match every argument",
                "a `deny_args` pattern is an argument, or a prefix ending in `*`",
            ]
        );
    }

    #[test]
    fn inherit_and_env() {
        let c = compiled(
            r#"app a {
                exe "/opt/a/a"
                inherit
                env "LD_PRELOAD=/usr/lib/x.so /usr/lib/y.so", "LD_LIBRARY_PATH=/opt/a/lib:/opt/a/lib64"
                env "LD_PRELOAD=/usr/lib/x.so /usr/lib/y.so"
            }
            app b { exe "/b" }"#,
        );
        assert!(c.apps[0].inherit);
        assert_eq!(c.apps[0].flags(), app_flag::INHERIT);
        assert_eq!(c.apps[0].env.len(), 2);
        let paths: Vec<_> = env_paths(&c.apps[0].env[1]).collect();
        assert_eq!(paths, ["/opt/a/lib", "/opt/a/lib64"]);
        assert!(!c.apps[1].inherit && c.apps[1].env.is_empty());
        assert_eq!(c.apps[1].flags(), 0);
        let flags: Vec<_> = c.app_flags().collect();
        assert_eq!(flags, [(1, app_flag::INHERIT), (2, 0)]);
        let keys: Vec<_> = c.allowed_env().collect();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].app, 1);
        assert_eq!(&keys[1].val[..16], b"LD_LIBRARY_PATH=");
        assert_eq!(keys[1].val[39..], [0; ENV_CHUNK - 39]);
    }

    #[test]
    fn too_many_apps() {
        let text: String = (0..=MAX_NAMES)
            .map(|i| format!("app a{i} {{ exe \"/a\" }}\n"))
            .collect();
        assert_eq!(errors(&text), ["too many apps: at most 251 per daemon run"]);
    }

    #[test]
    fn fail_closed() {
        assert!(compiled("fail_closed on").fail_closed);
        assert!(!compiled("fail_closed off").fail_closed);
        assert!(compiled("require_sandbox on").require_sandbox);
        assert!(!compiled("require_sandbox off").require_sandbox);
        assert!(compiled("require_dbus on").require_dbus);
        assert_eq!(
            errors("require_dbus on\nrequire_dbus on"),
            ["`require_dbus` is set twice"]
        );
    }

    #[test]
    fn too_many_grants() {
        let mut text: String = (0..70)
            .map(|i| format!("app a{i} {{ exe \"/a{i}\" }}\n"))
            .collect();
        for s in 0..70 {
            for o in (0..70).filter(|o| *o != s) {
                text.push_str(&format!("grant a{o} read to a{s}\n"));
            }
        }
        assert_eq!(
            errors(&text),
            [format!("too many grants: at most {MAX_GRANTS}")]
        );
    }

    #[test]
    fn too_many_paths() {
        let exes: Vec<_> = (0..MAX_EXES - 3)
            .map(|i| format!("\"/bin/e{i}\""))
            .collect();
        let text = format!("app a {{ exe {} }}", exes.join(", "));
        compiled(&text);
        // The same path twice is one entry; one more is too many.
        let more = format!("app a {{ exe {}, \"/bin/e0\" }}", exes.join(", "));
        compiled(&more);
        let more = format!("app a {{ exe {}, \"/bin/x\" }}", exes.join(", "));
        assert_eq!(
            errors(&more),
            [format!("too many exe paths: at most {}", MAX_EXES - 3)]
        );
        // Globs and home paths may match nothing; only the daemon can tell.
        let globs = format!("app a {{ exe {}, \"/bin/x*\", \"~/x\" }}", exes.join(", "));
        compiled(&globs);

        let terminals: Vec<_> = (0..=MAX_TERMINALS)
            .map(|i| format!("\"/bin/t{i}\""))
            .collect();
        let text = format!("terminal {}", terminals.join(", "));
        assert_eq!(
            errors(&text),
            [format!(
                "too many terminal, shell and desktop paths: at most {MAX_TERMINALS}"
            )]
        );
    }

    #[test]
    fn too_many_env() {
        let env: Vec<_> = (0..=MAX_ALLOWED_ENV)
            .map(|i| format!("\"LD_LIBRARY_PATH=/opt/{i}\""))
            .collect();
        let text = format!("app a {{ exe \"/a\" env {} }}", env.join(", "));
        assert_eq!(
            errors(&text),
            [format!(
                "too many `env` strings: at most {MAX_ALLOWED_ENV} in all apps"
            )]
        );
    }

    #[test]
    fn terminals_and_claims() {
        let c = compiled(
            r#"terminal "/usr/bin/konsole", "/usr/sbin/sshd"
               app a { exe "/a" owns "~/.a" }
               claim a "/home/me/.a-cache", "~/.a2"
               grant @terminal read, list to a"#,
        );
        assert_eq!(c.terminals.len(), 2);
        let roots: Vec<_> = c.apps[0].roots.iter().map(|r| r.text.as_str()).collect();
        assert_eq!(roots, ["~/.a", "/home/me/.a-cache", "~/.a2"]);
        assert_eq!(
            c.grants[&GrantKey {
                subject: SUBJECT_TERMINAL,
                owner: 1
            }],
            perm::READ | perm::LIST
        );
        assert!(c.warnings.is_empty());
        assert_eq!(c.name(SUBJECT_TERMINAL), "terminal");

        let c = compiled("app a { exe \"/a\" }\ngrant @terminal read to a");
        let w: Vec<_> = c.warnings.iter().map(|d| d.message.as_str()).collect();
        assert_eq!(w, ["`@terminal` grant without any `terminal` exe"]);
        assert_eq!(errors("claim b \"/x\""), ["unknown app `b`"]);
        assert_eq!(
            errors("app terminal { exe \"/t\" }"),
            ["`terminal` is a reserved name"]
        );
    }

    #[test]
    fn explsm_grants() {
        let c = compiled(
            "app dpkg { exe \"/usr/bin/dpkg\" }\n\
             grant dpkg write, create, delete, rename, setattr to @explsm",
        );
        assert_eq!(
            c.grants[&GrantKey {
                subject: 1,
                owner: APP_DAEMON
            }],
            perm::WRITE | perm::CREATE | perm::DELETE | perm::RENAME | perm::SETATTR
        );
        assert_eq!(c.name(APP_DAEMON), "explsmd");
        for subject in ["@root", "@unconfined", "@terminal"] {
            assert_eq!(
                errors(&format!(
                    "terminal \"/t\"\ngrant {subject} write to @explsm"
                )),
                ["only an app can be granted `@explsm`"]
            );
        }
        assert_eq!(
            errors("app a { exe \"/a\" }\ngrant a read to @explsmd"),
            ["the owner of a grant must be an app, `@explsm` or `*`"]
        );
    }

    #[test]
    fn root_grants() {
        let c = compiled(
            "app a { exe \"/a\" }\ngrant @root read, list to a\ngrant @root list to *\n\
             grant @root write to a",
        );
        assert_eq!(
            c.grants[&GrantKey {
                subject: SUBJECT_ROOT,
                owner: 1
            }],
            perm::READ | perm::LIST | perm::WRITE
        );
        assert_eq!(
            c.grants[&GrantKey {
                subject: SUBJECT_ROOT,
                owner: OWNER_ANY
            }],
            perm::LIST
        );
        assert!(c.warnings.is_empty());
        assert_eq!(c.name(SUBJECT_ROOT), "root");
        assert_eq!(
            errors("app root { exe \"/r\" }"),
            ["`root` is a reserved name"]
        );
        assert_eq!(
            errors("app a { exe \"/a\" }\ngrant a read to @root"),
            ["the owner of a grant must be an app, `@explsm` or `*`"]
        );
    }

    #[test]
    fn unknown_apps_in_claims_files_are_warnings() {
        let sources = Sources(vec![
            crate::Source {
                name: "policy".into(),
                text: "app a { exe \"/a\" }".into(),
                lenient: false,
            },
            crate::Source {
                name: "claims".into(),
                text: "claim gone \"/x\"\ngrant a read to gone\ngrant gone read to a\n\
                       app rg { exe \"/rg\" }\ngrant rg read to a"
                    .into(),
                lenient: true,
            },
        ]);
        let c = compile(&parse(&sources).unwrap(), &IdTable::default()).unwrap();
        assert_eq!(c.warnings.len(), 3);
        assert!(c.warnings.iter().all(|d| d.severity == Severity::Warning));
        assert_eq!(c.grants.len(), 1);
        // Bad permissions stay errors.
        let sources = Sources(vec![crate::Source {
            name: "claims".into(),
            text: "app a { exe \"/a\" }\ngrant @unconfined exec to a".into(),
            lenient: true,
        }]);
        assert!(compile(&parse(&sources).unwrap(), &IdTable::default()).is_err());
    }

    #[test]
    fn renders_diagnostics() {
        let sources = Sources::single(
            "ssh.explsm",
            "app ssh { exe \"/usr/bin/ssh\" }\ngrant bob read to ssh\n",
        );
        let ast = parse(&sources).unwrap();
        let d = compile(&ast, &IdTable::default()).unwrap_err();
        let text = render(&d, &sources, false);
        assert!(text.contains("unknown app `bob`"), "{text}");
        assert!(text.contains("ssh.explsm:2:7"), "{text}");
        assert!(
            text.contains("subject is not defined by any `app`"),
            "{text}"
        );
    }
}
