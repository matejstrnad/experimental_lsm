//! Repeated reports of read-only ptrace probes, merged.
//!
//! Process monitors (`ps`, `top`, GNOME's Resources) open
//! `/proc/<pid>/environ` of every process each time they look, and an app's
//! (or the agent's) is refused each time. The refusal stays; the log gets
//! the first line of a program (exe and uid) on an app's processes, and at
//! the end of the window one more with `repeated=N` if there were more.
//! Attach-mode probes (`/proc/<pid>/mem`, ptrace attach) are always logged.

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use explsm_common::{AppId, Event, FileKey, Op, REASON_TAMPER};

use crate::events::Line;

/// How long repeats are merged by default.
pub const WINDOW: Duration = Duration::from_secs(600);

/// `PTRACE_MODE_ATTACH` in `Event::flags` of a ptrace report.
const PTRACE_MODE_ATTACH: u32 = 2;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct Key {
    uid: u32,
    exe: FileKey,
    owner: AppId,
}

struct Window {
    ends: Instant,
    /// Reports not logged since the first one.
    repeated: u64,
    /// The last of them.
    last: Option<Line>,
}

pub struct Quiet {
    window: Duration,
    open: HashMap<Key, Window>,
}

impl Quiet {
    pub fn new(window: Duration) -> Self {
        Self {
            window,
            open: HashMap::new(),
        }
    }

    /// Whether `line`, the rendering of `ev`, is to be logged now. If not, it
    /// is counted and kept for the summary.
    pub fn admit(&mut self, ev: &Event, line: &Line, now: Instant) -> bool {
        let read_probe = ev.reason == REASON_TAMPER
            && ev.op == Op::Ptrace as u32
            && ev.flags & PTRACE_MODE_ATTACH == 0;
        if !read_probe || self.window.is_zero() {
            return true;
        }
        let key = Key {
            uid: ev.uid,
            exe: ev.exe,
            owner: ev.owner,
        };
        match self.open.get_mut(&key) {
            Some(w) if now < w.ends => {
                w.repeated += 1;
                w.last = Some(line.clone());
                false
            }
            _ => {
                self.open.insert(
                    key,
                    Window {
                        ends: now + self.window,
                        repeated: 0,
                        last: None,
                    },
                );
                true
            }
        }
    }

    /// When the next window ends.
    pub fn due(&self) -> Option<Instant> {
        self.open.values().map(|w| w.ends).min()
    }

    /// Close the windows that ended by `now`: the last report of each that
    /// had repeats, with their number.
    pub fn close(&mut self, now: Instant) -> Vec<Line> {
        self.close_where(|w| w.ends <= now)
    }

    /// Close every window, for when the daemon stops.
    pub fn close_all(&mut self) -> Vec<Line> {
        self.close_where(|_| true)
    }

    fn close_where(&mut self, ended: impl Fn(&Window) -> bool) -> Vec<Line> {
        let mut out = Vec::new();
        self.open.retain(|_, w| {
            if !ended(w) {
                return true;
            }
            if let Some(mut line) = w.last.take() {
                line.text.push_str(&format!(" repeated={}", w.repeated));
                line.fields.push(("EXPLSM_REPEATED", w.repeated.to_string()));
                out.push(line);
            }
            false
        });
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe(exe: u64, mode: u32) -> Event {
        // SAFETY: plain data; all zeroes is a valid Event.
        let mut ev: Event = unsafe { std::mem::zeroed() };
        ev.uid = 1000;
        ev.owner = 3;
        ev.reason = REASON_TAMPER;
        ev.op = Op::Ptrace as u32;
        ev.flags = mode;
        ev.exe.ino = exe;
        ev
    }

    fn line(text: &str) -> Line {
        Line {
            text: text.into(),
            priority: 4,
            fields: Vec::new(),
        }
    }

    #[test]
    fn merges_read_probes() {
        let mut q = Quiet::new(Duration::from_secs(10));
        let t = Instant::now();
        let ps = probe(1, 0x11);
        assert!(q.admit(&ps, &line("a"), t));
        assert!(!q.admit(&ps, &line("b"), t + Duration::from_secs(1)));
        assert!(!q.admit(&ps, &line("c"), t + Duration::from_secs(2)));
        // Another program, and an attach, are logged.
        assert!(q.admit(&probe(2, 0x11), &line("d"), t));
        assert!(q.admit(&probe(1, PTRACE_MODE_ATTACH), &line("e"), t));
        assert!(q.close(t + Duration::from_secs(5)).is_empty());
        let closed = q.close(t + Duration::from_secs(10));
        assert_eq!(closed.len(), 1);
        assert_eq!(closed[0].text, "c repeated=2");
        assert_eq!(q.due(), None);
        // A new window starts with a logged line.
        assert!(q.admit(&ps, &line("f"), t + Duration::from_secs(11)));
    }
}
