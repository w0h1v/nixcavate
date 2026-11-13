//! `/etc/security/opasswd`: the password history of `pam_pwhistory` and `pam_unix remember=`.
//! Format: one line per user, `user:uid:count:hash,hash,...`, oldest hash first.
//!
//! The hashes are never output: only how many there are and which algorithm each one uses
//! (from its `$id$` prefix), which says when an account's password policy or algorithm changed.

use crate::text::for_each_line;
use crate::{Artifact, Category, Input, LINUX};
use nixcavate_core::{Loc, Record, Result, Sink};
use serde::Serialize;

pub const ARTIFACT: Artifact = Artifact::new(
    "opasswd",
    "Password history (algorithms and counts only)",
    Category::Accounts,
    LINUX,
    &["etc/security/opasswd"],
    parse,
);

#[derive(Serialize)]
struct History<'a> {
    user: &'a str,
    uid: Option<u32>,
    /// The count the file states.
    count: Option<u32>,
    /// The hashes actually present.
    hashes: usize,
    /// The algorithm of each hash, oldest first: `sha512`, `yescrypt`, `md5`...
    algorithms: Vec<&'static str>,
}

impl Record for History<'_> {}

/// The algorithm behind a crypt(3) hash, from its prefix.
fn algorithm(hash: &str) -> &'static str {
    // `!` and `*` are what shadow holds for a locked or passwordless account; a locked
    // account keeps its hash after the `!`.
    let hash = hash.trim_start_matches(['!', '*']);
    if hash.is_empty() {
        return "locked";
    }
    let id = hash.strip_prefix('$').and_then(|rest| rest.split('$').next()).unwrap_or("");
    match id {
        "1" => "md5",
        "2" | "2a" | "2b" | "2x" | "2y" => "bcrypt",
        "3" => "nt",
        "5" => "sha256",
        "6" => "sha512",
        "7" => "scrypt",
        "y" => "yescrypt",
        "gy" => "gost-yescrypt",
        "sha1" => "sha1",
        "" if hash.len() == 13 => "des",
        _ => "unknown",
    }
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    for_each_line(input, |line| {
        let text = String::from_utf8_lossy(line.bytes);
        let mut fields = text.splitn(4, ':');
        let (Some(user), Some(uid), Some(count), Some(hashes)) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            sink.warn(format!("line {}: not a user:uid:count:hashes line", line.number));
            return Ok(());
        };
        let list: Vec<&str> = hashes.split(',').filter(|h| !h.is_empty()).collect();
        sink.emit(
            Loc::Line(line.number),
            &History {
                user,
                uid: uid.parse().ok(),
                count: count.parse().ok(),
                hashes: list.len(),
                algorithms: list.iter().map(|h| algorithm(h)).collect(),
            },
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    /// The reference lists, per line, `user uid count $id$,$id$,...` (made with awk from the
    /// real file); the records must agree and must not contain the hashes themselves.
    #[test]
    fn matches_the_reference_for_real_histories() {
        let mut lines = 0;
        for host in ["debian12"] {
            let data = fixture(&format!("opasswd/{host}/opasswd"));
            let out = run(&ARTIFACT, "etc/security/opasswd", &data, 0);
            let reference = String::from_utf8(fixture(&format!("opasswd/{host}/reference.txt"))).unwrap();
            let recs: Vec<serde_json::Value> = out
                .lines()
                .take_while(|l| !l.starts_with("---"))
                .filter_map(|l| serde_json::from_str(l).ok())
                .collect();
            assert_eq!(recs.len(), reference.lines().count(), "{host}");
            for (rec, line) in recs.iter().zip(reference.lines()) {
                let f: Vec<&str> = line.split(' ').collect();
                assert_eq!(rec["user"], f[0]);
                assert_eq!(rec["uid"].to_string(), f[1]);
                assert_eq!(rec["count"].to_string(), f[2]);
                let ids: Vec<&str> = f[3].split(',').collect();
                assert_eq!(rec["hashes"].as_u64().unwrap() as usize, ids.len());
                let names: Vec<&str> =
                    rec["algorithms"].as_array().unwrap().iter().map(|a| a.as_str().unwrap()).collect();
                // awk shows a locked account's `!` as an empty `$$`.
                let expected: Vec<&str> =
                    ids.iter().map(|id| if *id == "$$" { "locked" } else { algorithm(id) }).collect();
                assert_eq!(names, expected, "{host} {line}");
                assert!(!names.contains(&"unknown"), "{host}: {line}");
                lines += 1;
            }
            for hash in String::from_utf8_lossy(&data).split([',', ':', '\n']).filter(|h| h.len() > 20) {
                assert!(!out.contains(hash), "{host}: a hash was output");
            }
        }
        assert_eq!(lines, 2);
    }

    #[test]
    fn algorithms_empty_and_bad_lines() {
        let out = run(
            &ARTIFACT,
            "etc/security/opasswd",
            b"u:1000:3:$1$a$b,$y$j9T$c$d,abcdefghijklm,$7$xyz,!,!$6$s$h\nbroken\nv:5:0:\n",
            0,
        );
        assert!(
            out.contains(r#""algorithms":["md5","yescrypt","des","scrypt","locked","sha512"]"#)
                && out.contains(r#""hashes":0,"algorithms":[]"#),
            "{out}"
        );
        assert!(out.contains("not a user:uid:count:hashes line"), "{out}");
        assert_eq!(run(&ARTIFACT, "etc/security/opasswd", b"", 0), "");
    }
}
