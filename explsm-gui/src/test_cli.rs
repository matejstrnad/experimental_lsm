//! `explsm-gui test …`: explsmd's GUI methods from the command line, for
//! `tests/gui-smoke.sh`. Only in builds with the `test-cli` feature, which
//! must never be installed: the GUI exe has the agent's identity, so this
//! would let any process of the user read their security picture.
//!
//! - `status`: the user status as JSON
//! - `prompt ID`: open prompt ID as JSON
//! - `revoke-temp SUBJECT OWNER`: how many grants ended
//! - `revoke-saved SUBJECT OWNER`
//! - `set-secret ICON PHRASE`
//!
//! Errors go to stderr with exit code 1.

use std::process::ExitCode;

use explsm_ipc::Secret;

use crate::daemon;

pub fn run(args: Vec<String>) -> ExitCode {
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let result = match args.as_slice() {
        ["status"] => daemon::user_status()
            .and_then(|s| serde_json::to_string_pretty(&s).map_err(|e| e.to_string())),
        ["prompt", id] => id
            .parse()
            .map_err(|e| format!("prompt id: {e}"))
            .and_then(daemon::prompt_info)
            .and_then(|p| serde_json::to_string_pretty(&p).map_err(|e| e.to_string())),
        ["revoke-temp", subject, owner] => {
            daemon::revoke_temp(subject.to_string(), owner.to_string()).map(|n| n.to_string())
        }
        ["revoke-saved", subject, owner] => {
            daemon::revoke_saved(subject.to_string(), owner.to_string()).map(|()| "ok".into())
        }
        ["set-secret", icon, phrase] => daemon::set_secret(Secret {
            icon: icon.to_string(),
            phrase: phrase.to_string(),
        })
        .map(|()| "ok".into()),
        _ => {
            eprintln!(
                "usage: explsm-gui test status | prompt ID | revoke-temp SUBJECT OWNER | \
                 revoke-saved SUBJECT OWNER | set-secret ICON PHRASE"
            );
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(out) => {
            println!("{out}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("explsm-gui: {e}");
            ExitCode::FAILURE
        }
    }
}
