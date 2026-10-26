//! The explsm policy language: parsing, validation and compilation into what
//! the daemon writes into the BPF maps.
//!
//! ```text
//! # /etc/explsm/policy.d/ssh.explsm
//! app ssh {
//!     exe  "/usr/bin/ssh", "/usr/bin/ssh-add"
//!     owns "~/.ssh"
//!     mode enforce
//! }
//! grant @unconfined list to ssh
//! ```
//!
//! [`parse`] turns [`Sources`] into an [`ast::Policy`], [`compile`] checks it
//! and assigns app ids ([`Compiled`]). Both are pure. [`users`] expands `~`
//! for every user the policy covers, and [`resolve`] turns the paths into
//! inodes. See `docs/dsl.md` for the language.

// Diagnostics are only built on the error path; their size does not matter.
#![allow(clippy::result_large_err)]

pub mod ast;
pub mod compile;
pub mod diag;
mod lexer;
mod parser;
pub mod resolve;
pub mod users;

use std::{fs, io, path::Path};

pub use compile::{App, Compiled, IdTable, Mode, PathPat, compile};
pub use diag::{Diagnostic, Severity};
pub use parser::parse;

/// Extension of policy files in a policy directory.
pub const EXTENSION: &str = "explsm";

/// Default policy directory.
pub const POLICY_DIR: &str = "/etc/explsm/policy.d";

/// Default directory of the policy the daemon writes for answered prompts,
/// one file per user. Read after the policy directory.
pub const CLAIMS_DIR: &str = "/etc/explsm/claims.d";

/// A byte range in one of the [`Sources`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Span {
    pub file: usize,
    pub start: usize,
    pub end: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Spanned<T> {
    pub value: T,
    pub span: Span,
}

pub struct Source {
    /// Shown in diagnostics.
    pub name: String,
    pub text: String,
    /// Written by the daemon: references to apps that are gone are skipped
    /// with a warning, so removing an app never breaks the whole policy.
    pub lenient: bool,
}

/// The policy files, parsed together as one policy.
#[derive(Default)]
pub struct Sources(pub Vec<Source>);

impl Sources {
    pub fn single(name: &str, text: &str) -> Self {
        Self(vec![Source {
            name: name.into(),
            text: text.into(),
            lenient: false,
        }])
    }

    /// A policy file, or every `*.explsm` file of a directory in name order.
    pub fn load(path: &Path) -> io::Result<Self> {
        Self::load_files(path, false)
    }

    /// [`Self::load`] the policy, then the claims directory if it exists.
    pub fn load_with_claims(policy: &Path, claims: Option<&Path>) -> io::Result<Self> {
        let mut out = Self::load(policy)?;
        if let Some(claims) = claims
            && claims.is_dir()
        {
            out.0.extend(Self::load_files(claims, true)?.0);
        }
        Ok(out)
    }

    fn load_files(path: &Path, lenient: bool) -> io::Result<Self> {
        if !path.is_dir() {
            let text = fs::read_to_string(path)?;
            return Ok(Self(vec![Source {
                name: path.display().to_string(),
                text,
                lenient,
            }]));
        }
        let mut files: Vec<_> = fs::read_dir(path)?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|e| e == EXTENSION) && p.is_file())
            .collect();
        files.sort();
        let mut out = Vec::new();
        for file in files {
            let text = fs::read_to_string(&file)?;
            out.push(Source {
                name: file.display().to_string(),
                text,
                lenient,
            });
        }
        Ok(Self(out))
    }
}

/// Parse and compile in one go.
pub fn check(sources: &Sources, ids: &IdTable) -> Result<Compiled, Vec<Diagnostic>> {
    let ast = parse(sources)?;
    compile(&ast, ids)
}
