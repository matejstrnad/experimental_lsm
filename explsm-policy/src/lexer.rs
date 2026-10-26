//! Tokens. Newlines carry no meaning: every statement starts with a keyword.

use crate::{Span, diag::Diagnostic};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Tok {
    /// A bare word: keyword, app name, perm, mode, user name or uid.
    Word(String),
    /// `@name`
    Builtin(String),
    /// `"…"`, with escapes resolved.
    Str(String),
    Comma,
    LBrace,
    RBrace,
    Star,
}

impl Tok {
    pub fn describe(&self) -> String {
        match self {
            Self::Word(w) => format!("`{w}`"),
            Self::Builtin(b) => format!("`@{b}`"),
            Self::Str(_) => "a string".into(),
            Self::Comma => "`,`".into(),
            Self::LBrace => "`{`".into(),
            Self::RBrace => "`}`".into(),
            Self::Star => "`*`".into(),
        }
    }
}

fn word_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')
}

pub fn lex(file: usize, text: &str) -> (Vec<(Tok, Span)>, Vec<Diagnostic>) {
    let mut toks = Vec::new();
    let mut diags = Vec::new();
    let span = |start, end| Span { file, start, end };
    let mut chars = text.char_indices().peekable();
    while let Some((start, c)) = chars.next() {
        let simple = match c {
            ',' => Some(Tok::Comma),
            '{' => Some(Tok::LBrace),
            '}' => Some(Tok::RBrace),
            '*' => Some(Tok::Star),
            _ => None,
        };
        if let Some(tok) = simple {
            toks.push((tok, span(start, start + 1)));
            continue;
        }
        if c.is_whitespace() {
            continue;
        }
        if c == '#' {
            while chars.next_if(|(_, c)| *c != '\n').is_some() {}
            continue;
        }
        if c == '"' {
            let mut s = String::new();
            let mut end = None;
            while let Some((i, c)) = chars.next() {
                match c {
                    '"' => {
                        end = Some(i + 1);
                        break;
                    }
                    '\n' => break,
                    '\\' => match chars.next() {
                        Some((_, e @ ('"' | '\\'))) => s.push(e),
                        Some((j, e)) => {
                            diags.push(Diagnostic::error(
                                span(i, j + e.len_utf8()),
                                format!("unknown escape `\\{e}`"),
                            ));
                            s.push(e);
                        }
                        None => break,
                    },
                    c => s.push(c),
                }
            }
            match end {
                Some(end) => toks.push((Tok::Str(s), span(start, end))),
                None => diags.push(
                    Diagnostic::error(span(start, start + 1), "unterminated string")
                        .label("this string has no closing `\"` on its line"),
                ),
            }
            continue;
        }
        if c == '@' || word_char(c) {
            let mut end = start + c.len_utf8();
            while let Some((i, c)) = chars.next_if(|(_, c)| word_char(*c)) {
                end = i + c.len_utf8();
            }
            let tok = if c == '@' {
                Tok::Builtin(text[start + 1..end].into())
            } else {
                Tok::Word(text[start..end].into())
            };
            toks.push((tok, span(start, end)));
            continue;
        }
        diags.push(Diagnostic::error(
            span(start, start + c.len_utf8()),
            format!("unexpected character `{c}`"),
        ));
    }
    (toks, diags)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn toks(text: &str) -> Vec<Tok> {
        let (t, d) = lex(0, text);
        assert!(d.is_empty(), "{d:?}");
        t.into_iter().map(|(t, _)| t).collect()
    }

    #[test]
    fn tokens() {
        assert_eq!(
            toks("app a-1 { # comment\n exe \"/x \\\"y\\\"\", @unconfined * }"),
            [
                Tok::Word("app".into()),
                Tok::Word("a-1".into()),
                Tok::LBrace,
                Tok::Word("exe".into()),
                Tok::Str("/x \"y\"".into()),
                Tok::Comma,
                Tok::Builtin("unconfined".into()),
                Tok::Star,
                Tok::RBrace,
            ]
        );
    }

    #[test]
    fn errors() {
        let (_, d) = lex(0, "\"open\n$");
        let msgs: Vec<_> = d.iter().map(|d| d.message.as_str()).collect();
        assert_eq!(msgs, ["unterminated string", "unexpected character `$`"]);
    }
}
