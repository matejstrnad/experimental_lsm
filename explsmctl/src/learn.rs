//! `explsmctl learn`: turn logged accesses into suggested grants, in the
//! style of `aa-logprof`: those to an app's data ([`suggest`]), or those of
//! root processes that are no app ([`suggest_root`], `learn @root`), from
//! `bypass` lines of `root_bypass audit` as much as `deny` and `audit` ones.

use std::collections::BTreeMap;

use explsm_common::perm;

/// The fields of one logged access that matter here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub subject: String,
    /// Empty if not logged.
    pub owner: String,
    pub need: String,
    pub proc: String,
    pub path: String,
    /// From below a terminal (`EXPLSM_TERMINAL`).
    pub terminal: bool,
}

/// Records from `journalctl -o json` output, one object per line. Fields
/// journald stored as binary (arrays) are skipped.
pub fn parse(json_lines: &str) -> Vec<Record> {
    json_lines
        .lines()
        .filter_map(|line| {
            let v: serde_json::Value = serde_json::from_str(line).ok()?;
            let field = |k: &str| v.get(k).and_then(|f| f.as_str()).map(str::to_string);
            Some(Record {
                subject: field("EXPLSM_SUBJECT")?,
                owner: field("EXPLSM_OWNER").unwrap_or_default(),
                need: field("EXPLSM_NEED")?,
                proc: field("EXPLSM_PROC").unwrap_or_default(),
                path: field("EXPLSM_PATH").unwrap_or_default(),
                terminal: field("EXPLSM_TERMINAL").is_some_and(|t| t == "1"),
            })
        })
        .collect()
}

#[derive(Default)]
struct Seen {
    perms: u32,
    events: usize,
    example: String,
    procs: BTreeMap<String, usize>,
    /// Events from below a terminal.
    terminal: usize,
}

impl Seen {
    /// What the events were, for the comment of a suggestion.
    fn comment(&self) -> String {
        let procs: Vec<_> = self
            .procs
            .iter()
            .map(|(p, n)| format!("{p} ({n})"))
            .collect();
        let terminal = if self.terminal > 0 {
            format!("; {} from a terminal", self.terminal)
        } else {
            String::new()
        };
        format!(
            "{} event{}, e.g. {}; from {}{terminal}",
            self.events,
            plural(self.events),
            self.example,
            procs.join(", ")
        )
    }
}

fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

/// Grantable records by `key`, and the others counted per kind.
type Tally<'a> = (BTreeMap<&'a str, Seen>, BTreeMap<(&'static str, &'static str), usize>);

fn tally<'a>(records: &'a [Record], key: impl Fn(&'a Record) -> &'a str) -> Tally<'a> {
    let mut by_key: BTreeMap<&str, Seen> = BTreeMap::new();
    let mut skipped = BTreeMap::new();
    for r in records {
        let bits = r
            .need
            .split(',')
            .filter_map(|n| perm::NAMES.iter().find(|(_, name)| *name == n.trim()))
            .fold(0, |acc, (bit, _)| acc | bit);
        if bits == 0 {
            *skipped.entry(ungrantable(r.need.trim())).or_default() += 1;
            continue;
        }
        let seen = by_key.entry(key(r)).or_default();
        seen.perms |= bits;
        seen.events += 1;
        if seen.example.is_empty() {
            seen.example = r.path.clone();
        }
        *seen.procs.entry(r.proc.clone()).or_default() += 1;
        seen.terminal += usize::from(r.terminal);
    }
    (by_key, skipped)
}

/// The comments that count what can't be granted.
fn skipped_lines(skipped: &BTreeMap<(&str, &str), usize>) -> String {
    skipped
        .iter()
        .map(|((kind, what), n)| format!("# {n} {kind} event{} can't be granted ({what})\n", plural(*n)))
        .collect()
}

/// The comment for accesses of builtin subjects to explsm's own files.
fn own_files_comment(subject: &str, seen: &Seen) -> String {
    format!(
        "# {subject} processes needed {} on explsm's own files ({})\n\
         # only an app can be granted @explsm: define one for the program \
         (see examples/dpkg.explsm)\n",
        perm_list(seen.perms),
        seen.comment(),
    )
}

fn perm_list(bits: u32) -> String {
    if bits == perm::ALL {
        return "all".into();
    }
    let names: Vec<_> = perm::NAMES
        .iter()
        .filter(|(b, _)| bits & b != 0)
        .map(|(_, n)| *n)
        .collect();
    names.join(", ")
}

/// What the events of a `need` that no grant covers were, for the comment
/// that counts them.
fn ungrantable(need: &str) -> (&'static str, &'static str) {
    match need {
        "xdev" => ("xdev", "rename or link across owners"),
        "label" => ("label", "label change"),
        "tamper" => (
            "tamper",
            "ptrace, signal, rlimit or exe dir of the app's processes",
        ),
        "self" => ("self", "access to explsm itself"),
        n if n.starts_with("deep(") => ("deep", "too deep to tell its owner"),
        _ => ("other", "unknown need"),
    }
}

/// Suggested policy lines for the accesses to data of `app`. Renames and
/// links across owners (`xdev`), label changes, tampering with the app's
/// processes and access to explsm itself can't be granted; they are only
/// counted, per kind. Unconfined accessors only get comments: `@unconfined`
/// means every process without an app, which is rarely what is wanted.
pub fn suggest(app: &str, records: &[Record]) -> String {
    let (by_subject, skipped) = tally(records, |r| r.subject.as_str());
    let mut out = String::new();
    for (subject, seen) in &by_subject {
        let comment = seen.comment();
        // explsm's own files (owner explsmd) are granted as `@explsm`, and
        // only to apps.
        let own = app == "explsmd";
        let target = if own { "@explsm" } else { app };
        if own && matches!(*subject, "unconfined" | "root") {
            out.push_str(&own_files_comment(subject, seen));
        } else if *subject == "unconfined" {
            out.push_str(&format!(
                "# unconfined processes needed {} ({comment})\n\
                 # define an app for them and grant it, or (broad):\n\
                 # grant @unconfined {} to {app}\n",
                perm_list(seen.perms),
                perm_list(seen.perms).replace(' ', ""),
            ));
        } else {
            // Builtin subjects other than @unconfined.
            let subject = if *subject == "root" { "@root" } else { subject };
            out.push_str(&format!(
                "grant {subject} {} to {target}    # {comment}\n",
                perm_list(seen.perms).replace(' ', "")
            ));
        }
    }
    out.push_str(&skipped_lines(&skipped));
    out
}

/// Suggested `@root` grants for the accesses of root processes that are no
/// app (`subject=root`), one per owner. With `root_bypass audit` these are
/// the `bypass` lines: what root would lose with `root_bypass off`.
/// explsm's own files, tampering with apps' processes and the other kinds
/// `suggest` skips can't be granted to `@root`; they are only counted.
pub fn suggest_root(records: &[Record]) -> String {
    let root: Vec<_> = records.iter().filter(|r| r.subject == "root").cloned().collect();
    let (by_owner, skipped) = tally(&root, |r| r.owner.as_str());
    let mut out = String::new();
    for (owner, seen) in &by_owner {
        if *owner == "explsmd" {
            out.push_str(&own_files_comment("root", seen));
        } else {
            out.push_str(&format!(
                "grant @root {} to {owner}    # {}\n",
                perm_list(seen.perms).replace(' ', ""),
                seen.comment()
            ));
        }
    }
    out.push_str(&skipped_lines(&skipped));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(subject: &str, need: &str, proc: &str, path: &str) -> Record {
        Record {
            subject: subject.into(),
            owner: String::new(),
            need: need.into(),
            proc: proc.into(),
            path: path.into(),
            terminal: false,
        }
    }

    fn root(owner: &str, need: &str, proc: &str, path: &str, terminal: bool) -> Record {
        Record {
            owner: owner.into(),
            terminal,
            ..rec("root", need, proc, path)
        }
    }

    #[test]
    fn parses_journal_json() {
        let json = r#"{"MESSAGE":"audit …","EXPLSM_SUBJECT":"backup","EXPLSM_NEED":"read","EXPLSM_PROC":"restic","EXPLSM_PATH":"/h/.ssh/config"}
{"MESSAGE":"other"}
not json
{"EXPLSM_SUBJECT":"unconfined","EXPLSM_NEED":[1,2],"EXPLSM_PROC":"cat"}"#;
        assert_eq!(parse(json), [rec("backup", "read", "restic", "/h/.ssh/config")]);

        let json = r#"{"EXPLSM_ACTION":"bypass","EXPLSM_SUBJECT":"root","EXPLSM_OWNER":"ssh","EXPLSM_NEED":"read","EXPLSM_PROC":"cat","EXPLSM_PATH":"/h/.ssh/id","EXPLSM_TERMINAL":"1"}"#;
        assert_eq!(parse(json), [root("ssh", "read", "cat", "/h/.ssh/id", true)]);
    }

    #[test]
    fn suggests_root_grants() {
        let records = [
            root("ssh", "list", "updatedb", "/h/.ssh", false),
            root("ssh", "read", "cat", "/h/.ssh/config", true),
            root("claude", "list", "updatedb", "/h/.claude", false),
            root("claude", "tamper", "gdb", "target=42", true),
            root("explsmd", "write", "vim", "/etc/explsm/policy.d/a.explsm", true),
            // Not @root's: an app's root process, and a user's.
            Record {
                owner: "ssh".into(),
                ..rec("backup", "read", "restic", "/h/.ssh/id")
            },
            Record {
                owner: "ssh".into(),
                ..rec("unconfined", "read", "cat", "/h/.ssh/id")
            },
        ];
        assert_eq!(
            suggest_root(&records),
            "grant @root list to claude    # 1 event, e.g. /h/.claude; from updatedb (1)\n\
             # root processes needed write on explsm's own files (1 event, e.g. \
             /etc/explsm/policy.d/a.explsm; from vim (1); 1 from a terminal)\n\
             # only an app can be granted @explsm: define one for the program \
             (see examples/dpkg.explsm)\n\
             grant @root read,list to ssh    # 2 events, e.g. /h/.ssh; from cat (1), updatedb (1); \
             1 from a terminal\n\
             # 1 tamper event can't be granted (ptrace, signal, rlimit or exe dir of the app's processes)\n"
        );
        assert_eq!(suggest_root(&records[5..]), "");
    }

    #[test]
    fn suggests_grants() {
        let records = [
            rec("backup", "read", "restic", "/h/.ssh/config"),
            rec("backup", "list", "restic", "/h/.ssh"),
            rec("backup", "read", "restic", "/h/.ssh/id"),
            rec("unconfined", "read", "cat", "/h/.ssh/id"),
            rec("unconfined", "read,write", "vim", "/h/.ssh/config"),
            rec("unconfined", "xdev", "mv", "/h/.ssh/a"),
            rec("editor", "all-unknown", "x", "/h/.ssh/b"),
            rec("root", "list", "updatedb", "/h/.ssh"),
        ];
        assert_eq!(
            suggest("ssh", &records),
            "grant backup read,list to ssh    # 3 events, e.g. /h/.ssh/config; from restic (3)\n\
             grant @root list to ssh    # 1 event, e.g. /h/.ssh; from updatedb (1)\n\
             # unconfined processes needed read, write (2 events, e.g. /h/.ssh/id; from cat (1), vim (1))\n\
             # define an app for them and grant it, or (broad):\n\
             # grant @unconfined read,write to ssh\n\
             # 1 other event can't be granted (unknown need)\n\
             # 1 xdev event can't be granted (rename or link across owners)\n"
        );
    }

    #[test]
    fn grants_explsms_own_files_to_apps_only() {
        let records = [
            rec("dpkg", "delete", "dpkg", "/usr/sbin/explsmd.dpkg-tmp"),
            rec("root", "write", "vim", "/etc/explsm/policy.d/a.explsm"),
        ];
        assert_eq!(
            suggest("explsmd", &records),
            "grant dpkg delete to @explsm    # 1 event, e.g. /usr/sbin/explsmd.dpkg-tmp; from dpkg (1)\n\
             # root processes needed write on explsm's own files (1 event, e.g. \
             /etc/explsm/policy.d/a.explsm; from vim (1))\n\
             # only an app can be granted @explsm: define one for the program \
             (see examples/dpkg.explsm)\n"
        );
    }

    #[test]
    fn names_each_ungrantable_kind() {
        let records = [
            rec("unconfined", "tamper", "runtime-worker", "target=18296"),
            rec("unconfined", "tamper", "gdb", "target=18296"),
            rec("unconfined", "label", "setfattr", "/h/.ssh"),
            rec("ssh", "xdev", "mv", "/h/.ssh/a -> /tmp/a"),
            rec("unconfined", "self", "bpftool", "id=17"),
            rec("unconfined", "deep(read,write)", "vim", "…/d64/file"),
        ];
        assert_eq!(
            suggest("ssh", &records),
            "# 1 deep event can't be granted (too deep to tell its owner)\n\
             # 1 label event can't be granted (label change)\n\
             # 1 self event can't be granted (access to explsm itself)\n\
             # 2 tamper events can't be granted (ptrace, signal, rlimit or exe dir of the app's processes)\n\
             # 1 xdev event can't be granted (rename or link across owners)\n"
        );
    }
}
