//! Checking the syntax tree and assigning app ids.

use std::{
    collections::HashMap,
    path::{Component, Path, PathBuf},
};

use explsm_common::{
    APP_AGENT, APP_DAEMON, APP_UNCONFINED, AppId, GrantKey, MODE_AUDIT, MODE_ENFORCE, OWNER_ANY,
    OWNER_PINS, SUBJECT_TERMINAL, perm,
};

use crate::{
    Span, Spanned,
    ast::{self, Item},
    diag::{Diagnostic, Severity},
    users::User,
};

/// Most app names one daemon run can use: ids `1..=MAX_NAMES`. The ids after
/// them are reserved: [`OWNER_PINS`], [`APP_DAEMON`] and [`APP_AGENT`].
pub const MAX_NAMES: usize = OWNER_PINS as usize - 1;

/// Names no app may have: the names of the builtin ids.
pub const RESERVED_NAMES: [&str; 6] =
    ["unconfined", "all", "terminal", "explsm-agent", "explsmd", "explsm-pins"];

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
            APP_AGENT => "explsm-agent",
            APP_DAEMON => "explsmd",
            OWNER_PINS => "explsm-pins",
            _ => self
                .names
                .get(id as usize - 1)
                .map_or("?", String::as_str),
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
                return Err(err("path must be absolute or start with `~/`")
                    .label("relative path"));
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
            return Err(err("only the last path component may contain `*`, `?` or `[`")
                .note("the daemon watches the parent directory of each path for changes"));
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
}

/// A checked policy.
#[derive(Clone, Debug)]
pub struct Compiled {
    pub root_bypass: bool,
    /// `users …`: names or uids. `None`: every regular user.
    pub users: Option<Vec<Spanned<String>>>,
    pub apps: Vec<App>,
    pub grants: HashMap<GrantKey, u32>,
    /// Terminal entry exes (`terminal …`): their descendants get `@terminal`
    /// grants while they have a controlling tty.
    pub terminals: Vec<PathPat>,
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
        self.ids.ids().map(|id| {
            (
                id,
                self.app(id).map_or(MODE_AUDIT, |a| a.mode.map_value()),
            )
        })
    }
}

/// Builtin subjects of grants.
fn builtin_subject(s: &Spanned<String>) -> Result<AppId, Diagnostic> {
    match s.value.as_str() {
        "@unconfined" => Ok(APP_UNCONFINED),
        "@terminal" => Ok(SUBJECT_TERMINAL),
        "@root" => Err(Diagnostic::error(s.span, "`@root` can't be granted to")
            .note("root bypasses every check by default; use `root_bypass off` to turn that off")),
        other => Err(Diagnostic::error(s.span, format!("unknown builtin `{other}`"))
            .note("the builtin subjects are `@unconfined` and `@terminal`")),
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
    let mut root_bypass: Option<&Spanned<bool>> = None;
    let mut users: Option<&Spanned<Vec<Spanned<String>>>> = None;
    let mut apps: Vec<App> = Vec::new();
    let mut app_spans: HashMap<&str, Span> = HashMap::new();
    let mut terminals = Vec::new();

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
                    apps.push(app);
                }
            }
            Item::Terminal(paths) => {
                for p in paths {
                    match PathPat::parse(p) {
                        Ok(p) => terminals.push(p),
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

    // Grants after every app, so files may grant to apps of later files.
    let mut grants: HashMap<GrantKey, u32> = HashMap::new();
    for item in &policy.items {
        let Item::Grant(g) = item else { continue };
        let subject = if g.subject.value.starts_with('@') {
            builtin_subject(&g.subject)
        } else {
            app_id(&g.subject, &apps, "subject")
        };
        if matches!(subject, Ok(SUBJECT_TERMINAL)) && terminals.is_empty() {
            diags.push(
                Diagnostic::warning(g.subject.span, "`@terminal` grant without any `terminal` exe")
                    .note("no process is a terminal until the policy names terminal exes, \
                           e.g. `terminal \"/usr/bin/konsole\"`"),
            );
        }
        let owner = match g.owner.value.as_str() {
            "*" => Ok(OWNER_ANY),
            o if o.starts_with('@') => Err(Diagnostic::error(
                g.owner.span,
                "the owner of a grant must be an app or `*`",
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
                if subject == owner {
                    diags.push(
                        Diagnostic::error(g.span, format!("{} already owns its data", g.subject.value))
                            .label("grant to itself"),
                    );
                    continue;
                }
                *grants.entry(GrantKey { subject, owner }).or_insert(0) |= bits;
            }
            (s, o) => diags.extend(
                s.err()
                    .into_iter()
                    .chain(o.err())
                    .map(|d| soften(d, &policy.lenient)),
            ),
        }
    }

    if diags.iter().any(|d| d.severity == Severity::Error) {
        return Err(diags);
    }
    Ok(Compiled {
        root_bypass: root_bypass.is_none_or(|v| v.value),
        users: users.map(|u| u.value.clone()),
        apps,
        grants,
        terminals,
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
        diags.push(Diagnostic::error(a.name.span, format!("`{name}` is a reserved name")));
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
    for exe in &a.exes {
        if let Some(script) = &exe.script {
            diags.push(
                Diagnostic::error(script.span, "`script` is not supported yet")
                    .note("interpreter identity (`node …/cli.js`) is planned for a later phase; \
                           without it every script of the interpreter would be the app"),
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
        assert!(!c.root_bypass);
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
        assert!(c.root_bypass);
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
        assert_eq!(errors(&app("unconfined")), ["`unconfined` is a reserved name"]);
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
            errors("root_bypass on\nroot_bypass off\nusers a\nusers b"),
            ["`root_bypass` is set twice", "`users` is given twice"]
        );
        let grant = |g: &str| errors(&format!("{}grant {g}", app("a")));
        assert_eq!(grant("b read to a"), ["unknown app `b`"]);
        assert_eq!(grant("@unconfined read to b"), ["unknown app `b`"]);
        assert_eq!(grant("@unconfined exec to a"), ["unknown permission `exec`"]);
        assert_eq!(grant("@root read to a"), ["`@root` can't be granted to"]);

        assert_eq!(grant("@nobody read to a"), ["unknown builtin `@nobody`"]);
        assert_eq!(
            grant("a read to @unconfined"),
            ["the owner of a grant must be an app or `*`"]
        );
        assert_eq!(grant("a read to a"), ["a already owns its data"]);
    }

    #[test]
    fn too_many_apps() {
        let text: String = (0..=MAX_NAMES)
            .map(|i| format!("app a{i} {{ exe \"/a\" }}\n"))
            .collect();
        assert_eq!(errors(&text), ["too many apps: at most 252 per daemon run"]);
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
        assert_eq!(errors("app terminal { exe \"/t\" }"), ["`terminal` is a reserved name"]);
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
        let sources = Sources::single("ssh.explsm", "app ssh { exe \"/usr/bin/ssh\" }\ngrant bob read to ssh\n");
        let ast = parse(&sources).unwrap();
        let d = compile(&ast, &IdTable::default()).unwrap_err();
        let text = render(&d, &sources, false);
        assert!(text.contains("unknown app `bob`"), "{text}");
        assert!(text.contains("ssh.explsm:2:7"), "{text}");
        assert!(text.contains("subject is not defined by any `app`"), "{text}");
    }
}
