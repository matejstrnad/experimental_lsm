//! The users whose homes `~/…` paths are expanded for.

use std::{fs, io, path::Path, path::PathBuf};

use crate::Spanned;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct User {
    pub name: String,
    pub uid: u32,
    pub home: PathBuf,
}

pub fn parse_passwd(text: &str) -> Vec<User> {
    text.lines()
        .filter_map(|line| {
            let f: Vec<_> = line.split(':').collect();
            if f.len() < 7 || line.starts_with('#') {
                return None;
            }
            Some(User {
                name: f[0].into(),
                uid: f[2].parse().ok()?,
                home: f[5].into(),
            })
        })
        .collect()
}

/// `UID_MIN` and `UID_MAX` of `/etc/login.defs`: the range of regular users.
pub fn uid_range(login_defs: &str) -> (u32, u32) {
    let mut range = (1000, 60000);
    for line in login_defs.lines() {
        let mut f = line.split_whitespace();
        match (f.next(), f.next().and_then(|v| v.parse().ok())) {
            (Some("UID_MIN"), Some(v)) => range.0 = v,
            (Some("UID_MAX"), Some(v)) => range.1 = v,
            _ => {}
        }
    }
    range
}

/// The users the policy covers: those it names (by name or uid), or every
/// regular user whose home is a directory. Returns warnings for names that
/// match nobody.
pub fn select(
    all: &[User],
    wanted: Option<&[Spanned<String>]>,
    range: (u32, u32),
    home_ok: impl Fn(&Path) -> bool,
) -> (Vec<User>, Vec<String>) {
    let mut out: Vec<User> = Vec::new();
    let mut warnings = Vec::new();
    match wanted {
        None => out.extend(
            all.iter()
                .filter(|u| (range.0..=range.1).contains(&u.uid))
                .filter(|u| u.home.is_absolute() && u.home != Path::new("/"))
                .filter(|u| home_ok(&u.home))
                .cloned(),
        ),
        Some(wanted) => {
            for w in wanted {
                let found = all
                    .iter()
                    .find(|u| u.name == w.value || w.value.parse() == Ok(u.uid));
                match found {
                    Some(u) => out.push(u.clone()),
                    None => warnings.push(format!("user {} does not exist", w.value)),
                }
            }
        }
    }
    let mut seen = Vec::new();
    out.retain(|u| {
        let new = !seen.contains(&u.home);
        seen.push(u.home.clone());
        new
    });
    (out, warnings)
}

/// [`select`] from `/etc/passwd` and `/etc/login.defs`.
pub fn system(wanted: Option<&[Spanned<String>]>) -> io::Result<(Vec<User>, Vec<String>)> {
    let passwd = fs::read_to_string("/etc/passwd")?;
    let defs = fs::read_to_string("/etc/login.defs").unwrap_or_default();
    Ok(select(&parse_passwd(&passwd), wanted, uid_range(&defs), |p| p.is_dir()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Span;

    const PASSWD: &str = "root:x:0:0:root:/root:/bin/bash\n\
        nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n\
        alice:x:1000:1000:Alice,,,:/home/alice:/bin/bash\n\
        gone:x:1001:1001::/home/gone:/bin/sh\n\
        twin:x:1002:1002::/home/alice:/bin/sh\n\
        broken line\n";

    fn names(users: &[User]) -> Vec<&str> {
        users.iter().map(|u| u.name.as_str()).collect()
    }

    #[test]
    fn defaults_to_regular_users_with_a_home() {
        let all = parse_passwd(PASSWD);
        assert_eq!(all.len(), 5);
        let (users, warnings) = select(&all, None, uid_range("UID_MIN 1000\n"), |p| {
            p != Path::new("/home/gone")
        });
        // `twin` shares alice's home, which is only expanded once.
        assert_eq!(names(&users), ["alice"]);
        assert!(warnings.is_empty());
    }

    #[test]
    fn named_users() {
        let all = parse_passwd(PASSWD);
        let w = |v: &str| Spanned {
            value: v.into(),
            span: Span::default(),
        };
        let (users, warnings) = select(
            &all,
            Some(&[w("0"), w("gone"), w("nope")]),
            (1000, 60000),
            |_| false,
        );
        assert_eq!(names(&users), ["root", "gone"]);
        assert_eq!(warnings, ["user nope does not exist"]);
    }

    #[test]
    fn login_defs() {
        assert_eq!(uid_range("# x\nUID_MIN\t\t 500\nUID_MAX 999\n"), (500, 999));
        assert_eq!(uid_range(""), (1000, 60000));
    }
}
