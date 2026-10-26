//! The D-Bus service. Calls are passed to the main loop, which owns the
//! state, and answered from there.
//!
//! `org.explsm.Daemon1` is for root only. `org.explsm.AgentManager1` may be
//! called by every user; the main loop decides who is an agent (`desk.rs`).

use std::os::fd::{AsFd as _, OwnedFd};

use explsm_ipc::{BUS_NAME, PATH, ReloadReply, Status};
use tokio::sync::{mpsc, oneshot};
use zbus::{Connection, connection, fdo, message::Header};

use crate::seed;

pub enum Request {
    Status(oneshot::Sender<Status>),
    Reload(oneshot::Sender<ReloadReply>),
    Unload(oneshot::Sender<String>),
    Register {
        connection: String,
        uid: u32,
        pid: u32,
        pidfd: OwnedFd,
        reply: oneshot::Sender<Result<(), String>>,
    },
    Answer {
        connection: String,
        uid: u32,
        id: u64,
        choice: String,
        reply: oneshot::Sender<Result<(), String>>,
    },
}

async fn ask<T>(
    tx: &mpsc::Sender<Request>,
    make: impl FnOnce(oneshot::Sender<T>) -> Request,
) -> fdo::Result<T> {
    let (reply, rx) = oneshot::channel();
    tx.send(make(reply))
        .await
        .map_err(|_| fdo::Error::Failed("explsmd is stopping".into()))?;
    rx.await
        .map_err(|_| fdo::Error::Failed("explsmd is stopping".into()))
}

/// The unique name and uid of the caller.
async fn caller(hdr: &Header<'_>, conn: &Connection) -> fdo::Result<(String, u32)> {
    let sender = hdr
        .sender()
        .ok_or_else(|| fdo::Error::AccessDenied("no sender".into()))?;
    let uid = fdo::DBusProxy::new(conn)
        .await?
        .get_connection_unix_user(sender.clone().into())
        .await?;
    Ok((sender.to_string(), uid))
}

struct Service {
    tx: mpsc::Sender<Request>,
}

impl Service {
    /// The bus policy already limits callers to root; this keeps it so if
    /// the policy file is changed.
    async fn check_root(hdr: &Header<'_>, conn: &Connection) -> fdo::Result<()> {
        if caller(hdr, conn).await?.1 == 0 {
            Ok(())
        } else {
            Err(fdo::Error::AccessDenied("explsmd only answers root".into()))
        }
    }
}

#[zbus::interface(name = "org.explsm.Daemon1")]
impl Service {
    async fn status(
        &self,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> fdo::Result<Status> {
        Self::check_root(&hdr, conn).await?;
        ask(&self.tx, Request::Status).await
    }

    async fn reload(
        &self,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> fdo::Result<ReloadReply> {
        Self::check_root(&hdr, conn).await?;
        ask(&self.tx, Request::Reload).await
    }

    async fn unload(
        &self,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> fdo::Result<String> {
        Self::check_root(&hdr, conn).await?;
        ask(&self.tx, Request::Unload).await
    }
}

struct Manager {
    tx: mpsc::Sender<Request>,
}

#[zbus::interface(name = "org.explsm.AgentManager1")]
impl Manager {
    async fn register(
        &self,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> fdo::Result<()> {
        let sender = hdr
            .sender()
            .ok_or_else(|| fdo::Error::AccessDenied("no sender".into()))?;
        let creds = fdo::DBusProxy::new(conn)
            .await?
            .get_connection_credentials(sender.clone().into())
            .await?;
        let uid = creds
            .unix_user_id()
            .ok_or_else(|| fdo::Error::AccessDenied("caller's uid unknown".into()))?;
        let pid = creds
            .process_id()
            .ok_or_else(|| fdo::Error::AccessDenied("caller's pid unknown".into()))?;
        // The bus pins the caller's process if it can; otherwise open a
        // pidfd by pid, which a quick exit and reuse could fool.
        let pidfd = match creds.process_fd() {
            Some(fd) => fd.as_fd().try_clone_to_owned(),
            None => seed::pidfd_open(pid),
        }
        .map_err(|e| fdo::Error::Failed(format!("pinning the caller: {e}")))?;
        let connection = sender.to_string();
        ask(&self.tx, |reply| Request::Register {
            connection,
            uid,
            pid,
            pidfd,
            reply,
        })
        .await?
        .map_err(fdo::Error::AccessDenied)
    }

    async fn answer(
        &self,
        id: u64,
        choice: String,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> fdo::Result<()> {
        let (connection, uid) = caller(&hdr, conn).await?;
        ask(&self.tx, |reply| Request::Answer {
            connection,
            uid,
            id,
            choice,
            reply,
        })
        .await?
        .map_err(fdo::Error::Failed)
    }
}

/// Own the bus name on the system bus and serve the interfaces.
pub async fn serve(tx: mpsc::Sender<Request>) -> zbus::Result<Connection> {
    connection::Builder::system()
        .name(BUS_NAME)
        .serve_at(PATH, Service { tx: tx.clone() })
        .serve_at(PATH, Manager { tx })
        .build()
        .await
}
