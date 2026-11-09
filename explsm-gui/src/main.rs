//! explsm-gui: explsm's own windows, in GTK4 with libadwaita.
//!
//! - `explsm-gui prompt` is started by explsm-agent for each prompt. It
//!   reads the [`PromptInfo`] as JSON on stdin, asks the user, prints the
//!   chosen answer on stdout and exits with [`dialog::ANSWERED`]; closed
//!   without an answer it exits with [`dialog::CLOSED`], and when it can't
//!   show a window at all with [`dialog::UNAVAILABLE`], so the agent falls
//!   back to a notification. A crash answers nothing.
//! - `explsm-gui settings` is the window the user opens from the desktop:
//!   the security picture, the grants given through prompts (and revoking
//!   them), the history of answers and the apps.
//!
//! explsmd gives this exe the agent's identity (`--gui`), so no other
//! process of the user can ptrace it, and only it and the agent may read the
//! user's security picture and history from explsmd.
//!
//! It runs with an environment cut down to [`KEPT_ENV`] before GTK starts:
//! explsmd drops the identity only for the loader's variables (`LD_*`), and
//! GLib, GTK and Mesa load code named by others (`GIO_EXTRA_MODULES`,
//! `GDK_PIXBUF_MODULE_FILE`, `LIBGL_DRIVERS_PATH`, …), which would run with
//! the agent's identity and could read the security picture.
//!
//! `--preview FILE` reads the [`UserStatus`] from a JSON file instead of
//! asking explsmd, to try the windows out without a running daemon.

mod daemon;
mod prompt;
mod secret;
mod settings;

use std::{io::Read as _, path::PathBuf, process::ExitCode};

use explsm_ipc::{PromptInfo, UserStatus, dialog};

/// Where the windows get the user's status from.
#[derive(Clone)]
pub enum Source {
    Daemon,
    Preview(PathBuf),
}

impl Source {
    /// The user's status, from explsmd or the preview file.
    pub fn user_status(&self) -> Result<UserStatus, String> {
        match self {
            Source::Daemon => daemon::user_status(),
            Source::Preview(p) => std::fs::read_to_string(p)
                .map_err(|e| format!("reading {}: {e}", p.display()))
                .and_then(|t| {
                    serde_json::from_str(&t).map_err(|e| format!("{}: {e}", p.display()))
                }),
        }
    }
}

/// The variables kept, by name or prefix (ending in `_`): enough to reach
/// the display, the session bus and the user's language.
const KEPT_ENV: &[&str] = &[
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "XAUTHORITY",
    "XDG_RUNTIME_DIR",
    "XDG_SESSION_TYPE",
    "XDG_CURRENT_DESKTOP",
    "DBUS_SESSION_BUS_ADDRESS",
    "HOME",
    "USER",
    "LOGNAME",
    "LANG",
    "LANGUAGE",
    "LC_",
    "TZ",
];

fn kept(name: &str) -> bool {
    KEPT_ENV.iter().any(|k| {
        if k.ends_with('_') {
            name.starts_with(k) && name.len() > k.len()
        } else {
            name == *k
        }
    })
}

/// Drop every variable not in [`KEPT_ENV`].
fn clean_env() {
    let dropped: Vec<_> = std::env::vars_os()
        .map(|(k, _)| k)
        .filter(|k| !k.to_str().is_some_and(kept))
        .collect();
    for k in dropped {
        // SAFETY: called first thing in main, before any other thread runs.
        unsafe { std::env::remove_var(k) };
    }
    // SAFETY: as above.
    unsafe { std::env::set_var("PATH", "/usr/bin:/bin") };
}

fn usage() -> ExitCode {
    eprintln!("usage: explsm-gui prompt|settings [--preview USER-STATUS.json]");
    ExitCode::from(2)
}

fn main() -> ExitCode {
    clean_env();
    let mut args = std::env::args().skip(1);
    let Some(mode) = args.next() else {
        return usage();
    };
    let mut source = Source::Daemon;
    while let Some(a) = args.next() {
        match (a.as_str(), args.next()) {
            ("--preview", Some(file)) => source = Source::Preview(file.into()),
            _ => return usage(),
        }
    }
    match mode.as_str() {
        "prompt" => {
            let mut input = String::new();
            if let Err(e) = std::io::stdin().read_to_string(&mut input) {
                eprintln!("explsm-gui: reading the prompt: {e}");
                return ExitCode::from(dialog::UNAVAILABLE as u8);
            }
            let info: PromptInfo = match serde_json::from_str(&input) {
                Ok(i) => i,
                Err(e) => {
                    eprintln!("explsm-gui: the prompt is not valid: {e}");
                    return ExitCode::from(dialog::UNAVAILABLE as u8);
                }
            };
            if let Err(e) = gtk::init() {
                eprintln!("explsm-gui: can't show a window: {e}");
                return ExitCode::from(dialog::UNAVAILABLE as u8);
            }
            match prompt::run(info, source) {
                Some(answer) => {
                    println!("{answer}");
                    ExitCode::from(dialog::ANSWERED as u8)
                }
                None => ExitCode::from(dialog::CLOSED as u8),
            }
        }
        "settings" => {
            if let Err(e) = gtk::init() {
                eprintln!("explsm-gui: can't show a window: {e}");
                return ExitCode::FAILURE;
            }
            settings::run(source);
            ExitCode::SUCCESS
        }
        _ => usage(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_only_the_session() {
        for k in [
            "DISPLAY",
            "WAYLAND_DISPLAY",
            "LC_ALL",
            "LC_MESSAGES",
            "HOME",
        ] {
            assert!(kept(k), "{k}");
        }
        for k in [
            "GIO_EXTRA_MODULES",
            "GDK_PIXBUF_MODULE_FILE",
            "LIBGL_DRIVERS_PATH",
            "GTK_MODULES",
            "LD_PRELOAD",
            "LC_",
            "DISPLAYX",
            "XDG_DATA_DIRS",
        ] {
            assert!(!kept(k), "{k}");
        }
    }
}
