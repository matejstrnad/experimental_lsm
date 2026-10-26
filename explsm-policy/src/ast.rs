//! Syntax tree, as written. Names and paths are not checked yet.

use crate::{Span, Spanned};

#[derive(Debug, Default)]
pub struct Policy {
    pub items: Vec<Item>,
    /// Indexes of the files written by the daemon (`claims.d`), in which a
    /// reference to an unknown app is a warning instead of an error.
    pub lenient: Vec<usize>,
}

#[derive(Debug)]
pub enum Item {
    /// `root_bypass on|off`
    RootBypass(Spanned<bool>),
    /// `users 1000, alice`
    Users(Spanned<Vec<Spanned<String>>>),
    App(App),
    Grant(Grant),
    /// `terminal "/usr/bin/konsole", …`
    Terminal(Vec<Spanned<String>>),
    /// `claim APP "PATH", …`
    Claim(Claim),
}

#[derive(Debug)]
pub struct Claim {
    pub app: Spanned<String>,
    pub paths: Vec<Spanned<String>>,
}

#[derive(Debug)]
pub struct App {
    pub name: Spanned<String>,
    pub exes: Vec<Exe>,
    pub owns: Vec<Spanned<String>>,
    /// Every `mode` line, so duplicates can be reported.
    pub modes: Vec<Spanned<String>>,
}

#[derive(Debug)]
pub struct Exe {
    pub path: Spanned<String>,
    pub script: Option<Spanned<String>>,
}

#[derive(Debug)]
pub struct Grant {
    pub span: Span,
    /// An app name, or `@…`.
    pub subject: Spanned<String>,
    pub perms: Vec<Spanned<String>>,
    /// An app name, or `*`.
    pub owner: Spanned<String>,
}
