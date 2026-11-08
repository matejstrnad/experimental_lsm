//! systemd's readiness protocol (`Type=notify`, `sd_notify(3)`). explsmd says
//! it is ready once explsm is attached and the daemon is set up, so a start
//! that fails, or takes too long, is seen as such at once, D-Bus or not.

use std::os::{
    linux::net::SocketAddrExt as _,
    unix::net::{SocketAddr, UnixDatagram},
};

/// The socket systemd gave in `$NOTIFY_SOCKET`, if any.
pub struct Notifier(Option<UnixDatagram>);

impl Notifier {
    /// Connect before the sandbox, which allows no new connections.
    pub fn from_env() -> Self {
        let Some(path) = std::env::var_os("NOTIFY_SOCKET") else {
            return Self(None);
        };
        let connect = || -> std::io::Result<UnixDatagram> {
            let bytes = path.as_encoded_bytes();
            let addr = match bytes.strip_prefix(b"@") {
                Some(name) => SocketAddr::from_abstract_name(name)?,
                None => SocketAddr::from_pathname(&path)?,
            };
            let sock = UnixDatagram::unbound()?;
            sock.connect_addr(&addr)?;
            Ok(sock)
        };
        match connect() {
            Ok(sock) => Self(Some(sock)),
            Err(e) => {
                eprintln!(
                    "explsmd: warning: NOTIFY_SOCKET {}: {e}; systemd won't hear that explsmd is ready",
                    path.display()
                );
                Self(None)
            }
        }
    }

    /// Send `NAME=value` lines, e.g. `READY=1`.
    pub fn send(&self, state: &str) {
        if let Some(sock) = &self.0
            && let Err(e) = sock.send(state.as_bytes())
        {
            eprintln!("explsmd: warning: telling systemd {state:?}: {e}");
        }
    }
}
