//! Recursive descent over the tokens of each file. After an error the parser
//! skips to the next statement, so one run reports every broken statement.

use crate::{
    Sources, Span, Spanned,
    ast::{App, Claim, Exe, Grant, Item, Policy},
    diag::{Diagnostic, Severity},
    lexer::{Tok, lex},
};

const TOP_LEVEL: [&str; 6] = ["app", "grant", "claim", "terminal", "root_bypass", "users"];
const EXPECTED_TOP: &str = "`app`, `grant`, `claim`, `terminal`, `root_bypass` or `users`";
const APP_BODY: [&str; 5] = ["exe", "owns", "mode", "inherit", "env"];
const EXPECTED_APP: &str = "`exe`, `owns`, `mode`, `inherit`, `env` or `}`";

/// Parse every file into one policy. Fails if any diagnostic is an error.
pub fn parse(sources: &Sources) -> Result<Policy, Vec<Diagnostic>> {
    let mut policy = Policy::default();
    let mut diags = Vec::new();
    for (file, source) in sources.0.iter().enumerate() {
        if source.lenient {
            policy.lenient.push(file);
        }
        let (toks, lex_diags) = lex(file, &source.text);
        diags.extend(lex_diags);
        let end = source.text.len();
        let mut p = Parser {
            toks,
            pos: 0,
            eof: Span {
                file,
                start: end,
                end,
            },
            diags: Vec::new(),
        };
        p.items(&mut policy.items);
        diags.extend(p.diags);
    }
    if diags.iter().any(|d| d.severity == Severity::Error) {
        Err(diags)
    } else {
        Ok(policy)
    }
}

/// The error was reported; the caller recovers.
struct Failed;

type PResult<T> = Result<T, Failed>;

struct Parser {
    toks: Vec<(Tok, Span)>,
    pos: usize,
    eof: Span,
    diags: Vec<Diagnostic>,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos).map(|(t, _)| t)
    }

    fn span(&self) -> Span {
        self.toks.get(self.pos).map_or(self.eof, |(_, s)| *s)
    }

    fn prev_span(&self) -> Span {
        self.pos
            .checked_sub(1)
            .and_then(|i| self.toks.get(i))
            .map_or(self.eof, |(_, s)| *s)
    }

    fn peek_word(&self, words: &[&str]) -> bool {
        matches!(self.peek(), Some(Tok::Word(w)) if words.contains(&w.as_str()))
    }

    fn eat(&mut self, tok: &Tok) -> bool {
        if self.peek() == Some(tok) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn unexpected(&mut self, expected: &str) -> Failed {
        let found = self.peek().map_or("end of file".into(), Tok::describe);
        let span = self.span();
        self.diags.push(
            Diagnostic::error(span, format!("expected {expected}, found {found}"))
                .label(format!("expected {expected}")),
        );
        Failed
    }

    fn word(&mut self, expected: &str) -> PResult<Spanned<String>> {
        match self.peek() {
            Some(Tok::Word(w)) => {
                let value = w.clone();
                let span = self.span();
                self.pos += 1;
                Ok(Spanned { value, span })
            }
            _ => Err(self.unexpected(expected)),
        }
    }

    fn string(&mut self, expected: &str) -> PResult<Spanned<String>> {
        match self.peek() {
            Some(Tok::Str(s)) => {
                let value = s.clone();
                let span = self.span();
                self.pos += 1;
                Ok(Spanned { value, span })
            }
            _ => Err(self.unexpected(expected)),
        }
    }

    /// An app name, `@builtin` (kept with its `@`) or `*`.
    fn party(&mut self, expected: &str, star: bool) -> PResult<Spanned<String>> {
        let span = self.span();
        let value = match self.peek() {
            Some(Tok::Word(w)) => w.clone(),
            Some(Tok::Builtin(b)) => format!("@{b}"),
            Some(Tok::Star) if star => "*".into(),
            _ => return Err(self.unexpected(expected)),
        };
        self.pos += 1;
        Ok(Spanned { value, span })
    }

    /// `item {, item}`
    fn list<T>(&mut self, mut item: impl FnMut(&mut Self) -> PResult<T>) -> PResult<Vec<T>> {
        let mut out = vec![item(self)?];
        while self.eat(&Tok::Comma) {
            out.push(item(self)?);
        }
        Ok(out)
    }

    /// Skip to the next top-level statement (outside braces).
    fn recover_top(&mut self) {
        let mut depth = 0usize;
        while let Some(t) = self.peek() {
            match t {
                Tok::LBrace => depth += 1,
                Tok::RBrace => depth = depth.saturating_sub(1),
                Tok::Word(w) if depth == 0 && TOP_LEVEL.contains(&w.as_str()) => return,
                _ => {}
            }
            self.pos += 1;
        }
    }

    fn items(&mut self, items: &mut Vec<Item>) {
        while self.peek().is_some() {
            if let Ok(item) = self.item() {
                items.push(item);
            } else {
                self.recover_top();
            }
        }
    }

    fn item(&mut self) -> PResult<Item> {
        let kw = self.word(EXPECTED_TOP)?;
        match kw.value.as_str() {
            "app" => self.app().map(Item::App),
            "grant" => self.grant(kw.span).map(Item::Grant),
            "terminal" => Ok(Item::Terminal(self.list(|p| p.string("an exe path"))?)),
            "claim" => {
                let app = self.word("an app name")?;
                let paths = self.list(|p| p.string("a path"))?;
                Ok(Item::Claim(Claim { app, paths }))
            }
            "root_bypass" => {
                let v = self.word("`on` or `off`")?;
                let on = match v.value.as_str() {
                    "on" => true,
                    "off" => false,
                    _ => {
                        self.pos -= 1;
                        return Err(self.unexpected("`on` or `off`"));
                    }
                };
                Ok(Item::RootBypass(Spanned {
                    value: on,
                    span: v.span,
                }))
            }
            "users" => {
                let users = self.list(|p| p.word("a user name or uid"))?;
                let span = join(kw.span, self.prev_span());
                Ok(Item::Users(Spanned { value: users, span }))
            }
            _ => {
                self.pos -= 1;
                Err(self.unexpected(EXPECTED_TOP))
            }
        }
    }

    fn app(&mut self) -> PResult<App> {
        let name = self.word("an app name")?;
        if !self.eat(&Tok::LBrace) {
            return Err(self.unexpected("`{`"));
        }
        let mut app = App {
            name,
            exes: Vec::new(),
            owns: Vec::new(),
            modes: Vec::new(),
            inherit: Vec::new(),
            env: Vec::new(),
        };
        loop {
            if self.eat(&Tok::RBrace) {
                return Ok(app);
            }
            if self.peek().is_none() || self.peek_word(&TOP_LEVEL) {
                let span = self.span();
                self.diags.push(
                    Diagnostic::error(span, format!("app {} is missing its `}}`", app.name.value))
                        .label("expected `}` before this")
                        .also(app.name.span, "app starts here"),
                );
                // Keep what was parsed; the error fails the parse anyway.
                return Ok(app);
            }
            if self.app_line(&mut app).is_err() {
                // Skip to the next line of the body.
                while let Some(t) = self.peek() {
                    if *t == Tok::RBrace || self.peek_word(&APP_BODY) || self.peek_word(&TOP_LEVEL)
                    {
                        break;
                    }
                    self.pos += 1;
                }
            }
        }
    }

    fn app_line(&mut self, app: &mut App) -> PResult<()> {
        let kw = self.word(EXPECTED_APP)?;
        match kw.value.as_str() {
            "exe" => {
                let exes = self.list(|p| {
                    let path = p.string("an exe path")?;
                    let script = if p.peek_word(&["script"]) {
                        p.pos += 1;
                        Some(p.string("a script path")?)
                    } else {
                        None
                    };
                    Ok(Exe { path, script })
                })?;
                app.exes.extend(exes);
            }
            "owns" => {
                let paths = self.list(|p| p.string("a path"))?;
                app.owns.extend(paths);
            }
            "mode" => app.modes.push(self.word("`audit` or `enforce`")?),
            "inherit" => app.inherit.push(kw.span),
            "env" => {
                let vars = self.list(|p| p.string("a `NAME=VALUE` string"))?;
                app.env.extend(vars);
            }
            _ => {
                self.pos -= 1;
                return Err(self.unexpected(EXPECTED_APP));
            }
        }
        Ok(())
    }

    fn grant(&mut self, start: Span) -> PResult<Grant> {
        let subject = self.party("an app name or `@unconfined`", false)?;
        let mut perms = Vec::new();
        loop {
            perms.push(self.word("a permission")?);
            if !self.eat(&Tok::Comma) {
                break;
            }
        }
        // `grant a read to b`: a perm list followed by `to`.
        let to = perms.pop_if(|p| p.value == "to");
        if to.is_none() {
            if !self.peek_word(&["to"]) {
                return Err(self.unexpected("`,` or `to`"));
            }
            self.pos += 1;
        }
        if perms.is_empty() {
            let span = to.map_or(self.span(), |t| t.span);
            self.diags
                .push(Diagnostic::error(span, "grant without permissions").label("expected a permission before `to`"));
            return Err(Failed);
        }
        let owner = self.party("an app name or `*`", true)?;
        Ok(Grant {
            span: join(start, owner.span),
            subject,
            perms,
            owner,
        })
    }
}

fn join(a: Span, b: Span) -> Span {
    Span {
        file: a.file,
        start: a.start,
        end: if b.file == a.file { b.end.max(a.end) } else { a.end },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(text: &str) -> Policy {
        match parse(&Sources::single("t", text)) {
            Ok(p) => p,
            Err(d) => panic!("{d:?}"),
        }
    }

    fn errors(text: &str) -> Vec<String> {
        parse(&Sources::single("t", text))
            .unwrap_err()
            .into_iter()
            .map(|d| d.message)
            .collect()
    }

    #[test]
    fn full_policy() {
        let p = ok(r#"
            root_bypass off
            users 1000, alice
            app claude {
                exe "/usr/bin/node" script "*/cli.js", "~/.local/share/claude/versions/*"
                owns "~/.claude", "~/.claude.json"
                mode audit
                inherit
                env "LD_PRELOAD=/usr/lib/libx.so", "LD_LIBRARY_PATH=/opt/a/lib"
            }
            grant backup read to claude
            grant @unconfined read, list to *
            terminal "/usr/bin/konsole", "/usr/sbin/sshd"
            claim claude "/home/me/.claude-extra"
        "#);
        assert_eq!(p.items.len(), 7);
        let Item::Terminal(t) = &p.items[5] else { panic!() };
        assert_eq!(t.len(), 2);
        let Item::Claim(c) = &p.items[6] else { panic!() };
        assert_eq!(c.app.value, "claude");
        assert_eq!(c.paths[0].value, "/home/me/.claude-extra");
        let Item::App(app) = &p.items[2] else {
            panic!()
        };
        assert_eq!(app.name.value, "claude");
        assert_eq!(app.exes.len(), 2);
        assert_eq!(app.exes[0].script.as_ref().unwrap().value, "*/cli.js");
        assert!(app.exes[1].script.is_none());
        assert_eq!(app.owns.len(), 2);
        assert_eq!(app.inherit.len(), 1);
        assert_eq!(app.env[1].value, "LD_LIBRARY_PATH=/opt/a/lib");
        let Item::Grant(g) = &p.items[4] else {
            panic!()
        };
        assert_eq!(g.subject.value, "@unconfined");
        let perms: Vec<_> = g.perms.iter().map(|p| p.value.as_str()).collect();
        assert_eq!(perms, ["read", "list"]);
        assert_eq!(g.owner.value, "*");
        let Item::Users(u) = &p.items[1] else { panic!() };
        assert_eq!(u.value.len(), 2);
    }

    #[test]
    fn reports_every_broken_statement() {
        let e = errors(
            r#"
            bogus
            app a { exe "/x" frobnicate "y" mode audit }
            grant a to b
            root_bypass maybe
            grant a read b
            app b { owns "/r"
        "#,
        );
        assert_eq!(
            e,
            [
                "expected `app`, `grant`, `claim`, `terminal`, `root_bypass` or `users`, found `bogus`",
                "expected `exe`, `owns`, `mode`, `inherit`, `env` or `}`, found `frobnicate`",
                "grant without permissions",
                "expected `on` or `off`, found `maybe`",
                "expected `,` or `to`, found `b`",
                "app b is missing its `}`",
            ]
        );
    }

    #[test]
    fn spans_point_into_the_right_file() {
        let sources = Sources(vec![
            crate::Source {
                name: "a".into(),
                text: "app a { exe \"/a\" }".into(),
                lenient: false,
            },
            crate::Source {
                name: "b".into(),
                text: "grant".into(),
                lenient: false,
            },
        ]);
        let d = parse(&sources).unwrap_err();
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].span, Span { file: 1, start: 5, end: 5 });
    }
}
