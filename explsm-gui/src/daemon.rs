//! Calls to explsmd. Each runs on a tokio runtime of its own, in the
//! calling thread; the windows call them through [`gtk::gio::spawn_blocking`]
//! so the UI does not wait.

use std::time::Duration;

use explsm_ipc::{AgentManagerProxy, Secret, UserStatus};

/// How long a call may take before the window gives up on it.
const TIMEOUT: Duration = Duration::from_secs(10);

fn call<T>(
    f: impl AsyncFnOnce(&AgentManagerProxy<'static>) -> zbus::Result<T>,
) -> Result<T, String> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    rt.block_on(async {
        let run = async {
            let conn = zbus::Connection::system().await?;
            let manager = AgentManagerProxy::new(&conn).await?;
            f(&manager).await
        };
        match tokio::time::timeout(TIMEOUT, run).await {
            Ok(r) => r.map_err(explain),
            Err(_) => Err("explsmd did not answer".into()),
        }
    })
}

/// A D-Bus error as the user should read it.
fn explain(e: zbus::Error) -> String {
    match e {
        zbus::Error::MethodError(name, Some(msg), _) => {
            if name.as_str() == "org.freedesktop.DBus.Error.ServiceUnknown" {
                "explsmd is not running".into()
            } else {
                msg
            }
        }
        zbus::Error::FDO(e) => match *e {
            zbus::fdo::Error::ServiceUnknown(_) => "explsmd is not running".into(),
            zbus::fdo::Error::AccessDenied(m) | zbus::fdo::Error::Failed(m) => m,
            other => other.to_string(),
        },
        other => other.to_string(),
    }
}

pub fn user_status() -> Result<UserStatus, String> {
    call(async |m| m.user_status().await)
}

pub fn revoke_temp(subject: String, owner: String) -> Result<u32, String> {
    call(async move |m| m.revoke_temp(&subject, &owner).await)
}

pub fn revoke_saved(subject: String, owner: String) -> Result<(), String> {
    call(async move |m| m.revoke_saved(&subject, &owner).await)
}

pub fn set_secret(secret: Secret) -> Result<(), String> {
    call(async move |m| m.set_secret(secret).await)
}
