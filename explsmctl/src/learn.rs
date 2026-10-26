//! `explsmctl learn`: turn logged accesses into suggested grants, in the
//! style of `aa-logprof`.

use std::collections::BTreeMap;

use explsm_common::perm;

/// The fields of one logged access that matter here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub subject: String,
    pub need: String,
    pub proc: String,
    pub path: String,
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
                need: field("EXPLSM_NEED")?,
                proc: field("EXPLSM_PROC").unwrap_or_default(),
                path: field("EXPLSM_PATH").unwrap_or_default(),
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
        _ => ("other", "unknown need"),
    }
}

/// Suggested policy lines for the accesses to data of `app`. Renames and
/// links across owners (`xdev`), label changes, tampering with the app's
/// processes and access to explsm itself can't be granted; they are only
/// counted, per kind. Unconfined accessors only get comments: `@unconfined`
/// means every process without an app, which is rarely what is wanted.
pub fn suggest(app: &str, records: &[Record]) -> String {
    let mut by_subject: BTreeMap<&str, Seen> = BTreeMap::new();
    let mut skipped: BTreeMap<(&str, &str), usize> = BTreeMap::new();
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
        let seen = by_subject.entry(&r.subject).or_default();
        seen.perms |= bits;
        seen.events += 1;
        if seen.example.is_empty() {
            seen.example = r.path.clone();
        }
        *seen.procs.entry(r.proc.clone()).or_default() += 1;
    }

    let mut out = String::new();
    let plural = |n: usize| if n == 1 { "" } else { "s" };
    for (subject, seen) in &by_subject {
        let procs: Vec<_> = seen
            .procs
            .iter()
            .map(|(p, n)| format!("{p} ({n})"))
            .collect();
        let comment = format!(
            "{} event{}, e.g. {}; from {}",
            seen.events,
            plural(seen.events),
            seen.example,
            procs.join(", ")
        );
        if *subject == "unconfined" {
            out.push_str(&format!(
                "# unconfined processes needed {} ({comment})\n\
                 # define an app for them and grant it, or (broad):\n\
                 # grant @unconfined {} to {app}\n",
                perm_list(seen.perms),
                perm_list(seen.perms).replace(' ', ""),
            ));
        } else {
            out.push_str(&format!(
                "grant {subject} {} to {app}    # {comment}\n",
                perm_list(seen.perms).replace(' ', "")
            ));
        }
    }
    for ((kind, what), n) in skipped {
        out.push_str(&format!(
            "# {n} {kind} event{} can't be granted ({what})\n",
            plural(n)
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(subject: &str, need: &str, proc: &str, path: &str) -> Record {
        Record {
            subject: subject.into(),
            need: need.into(),
            proc: proc.into(),
            path: path.into(),
        }
    }

    #[test]
    fn parses_journal_json() {
        let json = r#"{"MESSAGE":"audit …","EXPLSM_SUBJECT":"backup","EXPLSM_NEED":"read","EXPLSM_PROC":"restic","EXPLSM_PATH":"/h/.ssh/config"}
{"MESSAGE":"other"}
not json
{"EXPLSM_SUBJECT":"unconfined","EXPLSM_NEED":[1,2],"EXPLSM_PROC":"cat"}"#;
        assert_eq!(parse(json), [rec("backup", "read", "restic", "/h/.ssh/config")]);
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
        ];
        assert_eq!(
            suggest("ssh", &records),
            "grant backup read,list to ssh    # 3 events, e.g. /h/.ssh/config; from restic (3)\n\
             # unconfined processes needed read, write (2 events, e.g. /h/.ssh/id; from cat (1), vim (1))\n\
             # define an app for them and grant it, or (broad):\n\
             # grant @unconfined read,write to ssh\n\
             # 1 other event can't be granted (unknown need)\n\
             # 1 xdev event can't be granted (rename or link across owners)\n"
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
        ];
        assert_eq!(
            suggest("ssh", &records),
            "# 1 label event can't be granted (label change)\n\
             # 1 self event can't be granted (access to explsm itself)\n\
             # 2 tamper events can't be granted (ptrace, signal, rlimit or exe dir of the app's processes)\n\
             # 1 xdev event can't be granted (rename or link across owners)\n"
        );
    }
}
