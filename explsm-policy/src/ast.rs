//! Syntax tree, as written. Names and paths are not checked yet.

use crate::{Span, Spanned, compile::RootBypass};

#[derive(Debug, Default)]
pub struct Policy {
    pub items: Vec<Item>,
    /// Indexes of the files written by the daemon (`claims.d`), in which a
    /// reference to an unknown app is a warning instead of an error.
    pub lenient: Vec<usize>,
}

#[derive(Debug)]
pub enum Item {
    /// `root_bypass on|off|audit`
    RootBypass(Spanned<RootBypass>),
    /// `fail_closed on|off`
    FailClosed(Spanned<bool>),
    /// `require_sandbox on|off`
    RequireSandbox(Spanned<bool>),
    /// `require_dbus on|off`
    RequireDbus(Spanned<bool>),
    /// `users 1000, alice`
    Users(Spanned<Vec<Spanned<String>>>),
    App(App),
    Grant(Grant),
    /// `terminal "/usr/bin/konsole", …`
    Terminal(Vec<Spanned<String>>),
    /// `shell "/usr/bin/bash", …`: exes that keep `@terminal` going.
    Shell(Vec<Spanned<String>>),
    /// `desktop "/usr/bin/gnome-shell", …`: the exes of `@desktop`.
    Desktop(Vec<Spanned<String>>),
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
    /// Every `inherit` line, so duplicates can be reported.
    pub inherit: Vec<Span>,
    /// `env "NAME=VALUE", …`: loader variables that keep the identity.
    pub env: Vec<Spanned<String>>,
    /// Every `code trusted|any` line, so duplicates can be reported.
    pub code: Vec<Spanned<String>>,
    /// `started_by APP, @terminal, …`: who may start the app.
    pub started_by: Vec<Spanned<String>>,
    /// `deny_args "-I", "-oPKCS11Provider*", …`
    pub deny_args: Vec<Spanned<String>>,
}

#[derive(Debug)]
pub struct Exe {
    pub path: Spanned<String>,
    pub script: Option<Spanned<String>>,
    /// `sha256 "HEX"`, any number: the file must have one of these hashes.
    pub sha256: Vec<Spanned<String>>,
    /// `hashes "FILE"`, any number: root-owned lists of allowed hashes.
    pub hashes: Vec<Spanned<String>>,
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
