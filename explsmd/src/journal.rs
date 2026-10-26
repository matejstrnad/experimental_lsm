//! Where event lines go: stdout, or under systemd the journal's native
//! protocol, so the `EXPLSM_*` fields can be queried with `journalctl`.

use std::{env, io, os::unix::net::UnixDatagram};

use crate::events::Line;

const SOCKET: &str = "/run/systemd/journal/socket";

pub enum Sink {
    Stdout,
    Journal(UnixDatagram),
}

impl Sink {
    /// The journal if stdout already goes there (`JOURNAL_STREAM`, set by
    /// systemd), else stdout.
    pub fn from_env() -> Self {
        if env::var_os("JOURNAL_STREAM").is_none() {
            return Self::Stdout;
        }
        let sock = UnixDatagram::unbound().and_then(|s| {
            s.connect(SOCKET)?;
            s.set_nonblocking(true)?;
            Ok(s)
        });
        match sock {
            Ok(s) => Self::Journal(s),
            Err(e) => {
                eprintln!("explsmd: warning: journal socket {SOCKET}: {e}; logging to stdout");
                Self::Stdout
            }
        }
    }

    pub fn emit(&self, line: &Line) {
        if let Self::Journal(sock) = self {
            match sock.send(&encode(line)) {
                Ok(_) => return,
                // A full journal must not stall the event loop; the line
                // still reaches the journal through stdout, without fields.
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => eprintln!("explsmd: warning: journal: {e}"),
            }
        }
        println!("{}", line.text);
    }
}

/// The native journal protocol: `KEY=value\n`, or for values with a
/// newline `KEY\n`, a little-endian u64 length, the value and `\n`.
fn encode(line: &Line) -> Vec<u8> {
    let mut out = Vec::with_capacity(line.text.len() * 3);
    let mut field = |key: &str, value: &str| {
        out.extend_from_slice(key.as_bytes());
        if value.contains('\n') {
            out.push(b'\n');
            out.extend_from_slice(&(value.len() as u64).to_le_bytes());
        } else {
            out.push(b'=');
        }
        out.extend_from_slice(value.as_bytes());
        out.push(b'\n');
    };
    field("MESSAGE", &line.text);
    field("PRIORITY", &line.priority.to_string());
    field("SYSLOG_IDENTIFIER", "explsmd");
    for (key, value) in &line.fields {
        field(key, value);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_fields() {
        let line = Line {
            text: "deny x".into(),
            priority: 4,
            fields: vec![("EXPLSM_PATH", "/a\nb".into())],
        };
        let mut want = b"MESSAGE=deny x\nPRIORITY=4\nSYSLOG_IDENTIFIER=explsmd\nEXPLSM_PATH\n".to_vec();
        want.extend_from_slice(&4u64.to_le_bytes());
        want.extend_from_slice(b"/a\nb\n");
        assert_eq!(encode(&line), want);
    }
}
