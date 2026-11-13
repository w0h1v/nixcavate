//! `master.passwd`: the BSD account database, with password hashes and password ageing.
//! Format: passwd(5) (BSD): `name:hash:uid:gid:class:change:expire:gecos:home:shell`. The hash
//! itself is never output: it is credential material and the record carries only its algorithm.
//! `spwd.db` and `pwd.db` are binary indexes of this file and are not read.

use crate::linux::shadow::hash_type;
use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, BSD};
use nixcavate_core::{Basis, Loc, Record, Result, Sink, Timestamp};
use serde::Serialize;

pub const ARTIFACT: Artifact = Artifact::new(
    "master-passwd",
    "BSD accounts with password hash types (never the hashes)",
    Category::Accounts,
    BSD,
    &["etc/master.passwd", "etc/master.passwd-"],
    parse,
);

#[derive(Serialize)]
struct Account<'a> {
    user: &'a str,
    /// Algorithm from the crypt(3) prefix; `none` for `*` and `*LOCKED*`; `empty` for a blank field.
    hash_type: &'static str,
    /// The account is disabled (`*LOCKED*` prefix, FreeBSD `pw lock`).
    locked: bool,
    /// An empty field means login with no password.
    passwordless: bool,
    uid: Option<u32>,
    gid: Option<u32>,
    /// The login class (`login.conf`).
    class: &'a str,
    /// The deadline for changing the password; empty for never. Not a record of a change.
    password_change: Option<Timestamp>,
    /// When the account expires; empty for never.
    expire: Option<Timestamp>,
    gecos: &'a str,
    home: &'a str,
    shell: &'a str,
}

impl Record for Account<'_> {}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        if text.trim().is_empty() || text.starts_with('#') {
            return Ok(());
        }
        let f: Vec<&str> = text.split(':').collect();
        if f.len() != 10 {
            sink.warn(format!("line {}: expected 10 fields, found {}", line.number, f.len()));
            if f.len() < 2 {
                return Ok(());
            }
        }
        let num = |i: usize| f.get(i).and_then(|v| v.trim().parse::<i64>().ok());
        let text_at = |i: usize| f.get(i).copied().unwrap_or_default();
        let locked = f[1].starts_with("*LOCKED*");
        let hash = f[1].strip_prefix("*LOCKED*").unwrap_or(f[1]);
        let when = |i: usize| num(i).filter(|&t| t > 0).map(|t| Timestamp::from_secs(t, Basis::Recorded));
        let kind = match (hash.is_empty(), locked) {
            (true, false) => "empty",
            (true, true) => "none",
            _ => hash_type(hash),
        };
        sink.emit(
            Loc::Line(line.number),
            &Account {
                user: f[0],
                hash_type: kind,
                locked,
                passwordless: hash.is_empty() && !locked,
                uid: num(2).and_then(|v| u32::try_from(v).ok()),
                gid: num(3).and_then(|v| u32::try_from(v).ok()),
                class: text_at(4),
                password_change: when(5),
                expire: when(6),
                gecos: text_at(7),
                home: text_at(8),
                shell: text_at(9),
            },
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    #[test]
    fn hash_types_and_never_the_hashes() {
        let data = fixture("master-passwd/master.passwd");
        let out = run(&ARTIFACT, "etc/master.passwd", &data, 0);
        insta::assert_snapshot!(out);
        for secret in ["FakeSalt", "HASHBODY", "ExampleHash"] {
            assert!(!out.contains(secret), "output leaks {secret}");
        }
    }

    #[test]
    fn locked_empty_and_malformed_accounts() {
        let data =
            b"root:$2b$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ012345:0:0::0:0:Charlie &:/root:/bin/sh\n\
                     toor:*:0:0::0:0:Bourne-again Superuser:/root:\n\
                     locked:*LOCKED*$6$salt$hash:1001:1001::0:0:L:/home/l:/bin/sh\n\
                     empty::1002:1002::0:0:E:/home/e:/bin/sh\n\
                     short:x\n\
                     nofields\n";
        let out = run(&ARTIFACT, "etc/master.passwd", data, 0);
        assert!(out.contains("\"user\":\"root\",\"hash_type\":\"bcrypt\""), "{out}");
        assert!(out.contains("\"user\":\"toor\",\"hash_type\":\"none\""));
        assert!(out.contains("\"user\":\"locked\",\"hash_type\":\"sha512crypt\",\"locked\":true"));
        assert!(out.contains("\"user\":\"empty\",\"hash_type\":\"empty\",\"locked\":false,\"passwordless\":true"));
        assert_eq!(out.matches("--- warning").count(), 2, "{out}");
        assert!(!out.contains("hash\"") && !out.contains("abcdefghijkl"));
    }
}
