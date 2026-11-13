//! `/etc/shadow`: password ageing and the kind of password hash. Format: shadow(5), hash
//! prefixes from crypt(5). The hash itself is never output: it is credential material and
//! the record carries only its algorithm.

use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input};
use nixcavate_core::{Basis, Event, Loc, Record, Result, Sink, Timestamp};
use nixcavate_source::Os;
use serde::Serialize;

pub const ARTIFACT: Artifact = Artifact::new(
    "shadow",
    "Password ageing and hash types (never the hashes)",
    Category::Accounts,
    // ESXi keeps the same file, with the same crypt(5) hashes.
    &[Os::Linux, Os::Esxi],
    &["etc/shadow", "etc/shadow-"],
    parse,
);

#[derive(Serialize)]
struct Shadow<'a> {
    user: &'a str,
    /// Algorithm from the crypt(5) prefix; `none` for `*`, `!`, `!!`, `x`; `empty` for a blank field.
    hash_type: &'static str,
    /// The field is a hash disabled with a leading `!` (`passwd -l`).
    locked: bool,
    /// An empty field means login with no password.
    passwordless: bool,
    /// Day 0 in `last_change` means the user must change the password at next login.
    must_change: bool,
    last_change: Option<Timestamp>,
    min_days: Option<i64>,
    max_days: Option<i64>,
    warn_days: Option<i64>,
    inactive_days: Option<i64>,
    expire: Option<Timestamp>,
}

impl Record for Shadow<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let message = format!("password of {} changed", self.user);
        self.last_change.map(|ts| Event::new(ts, "password_changed", message)).into_iter()
    }
}

/// Names the algorithm of a hash with any `!` lock prefix already removed.
pub(crate) fn hash_type(hash: &str) -> &'static str {
    const PREFIXES: [(&str, &str); 12] = [
        ("$gy$", "gost-yescrypt"),
        ("$y$", "yescrypt"),
        ("$7$", "scrypt"),
        ("$2a$", "bcrypt"),
        ("$2b$", "bcrypt"),
        ("$2x$", "bcrypt"),
        ("$2y$", "bcrypt"),
        ("$6$", "sha512crypt"),
        ("$5$", "sha256crypt"),
        ("$1$", "md5crypt"),
        ("$sha1$", "sha1crypt"),
        ("$md5$", "sunmd5"),
    ];
    if matches!(hash, "" | "!" | "x") || hash.starts_with('*') {
        return "none";
    }
    if let Some((_, name)) = PREFIXES.iter().find(|(prefix, _)| hash.starts_with(prefix)) {
        return name;
    }
    let des = hash.len() == 13 && hash.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'/');
    if des {
        "des"
    } else {
        "unknown"
    }
}

/// A user name as useradd writes it: no longer than 64, from `[A-Za-z0-9._$-]`.
fn plausible_user(name: &str) -> bool {
    name.len() <= 64 && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'$'))
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        if text.trim().is_empty() || text.starts_with('#') {
            return Ok(());
        }
        let fields: Vec<&str> = text.split(':').collect();
        if fields.len() < 2 {
            sink.warn(format!("line {}: expected at least 2 fields, found {}", line.number, fields.len()));
            return Ok(());
        }
        if fields.len() != 9 {
            sink.warn(format!("line {}: expected 9 fields, found {}", line.number, fields.len()));
        }
        // A hash wrapped onto a second line leaves a line whose first field is the tail of the
        // hash (and whose second is already the change date). Its "user" must not be output.
        let is_tail = fields.len() < 9
            && (!plausible_user(fields[0]) || (!fields[1].is_empty() && fields[1].bytes().all(|b| b.is_ascii_digit())));
        let number = |i: usize| fields.get(i).and_then(|f| f.trim().parse::<i64>().ok());
        let field = fields[1];
        let unlocked = field.strip_prefix('!').unwrap_or(field);
        let locked = unlocked.len() != field.len() && hash_type(unlocked) != "none";
        let last = number(2);
        sink.emit(
            Loc::Line(line.number),
            &Shadow {
                user: if is_tail { "" } else { fields[0] },
                hash_type: if field.is_empty() { "empty" } else { hash_type(unlocked) },
                locked,
                passwordless: field.is_empty(),
                must_change: last == Some(0),
                last_change: last.filter(|&d| d != 0).map(|d| Timestamp::from_days(d, Basis::Recorded)),
                min_days: number(3),
                max_days: number(4),
                warn_days: number(5),
                inactive_days: number(6),
                expire: number(7).map(|d| Timestamp::from_days(d, Basis::Recorded)),
            },
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    #[test]
    fn parses_shadow_without_leaking_hashes() {
        let data = fixture("shadow/shadow");
        let out = run(&ARTIFACT, "etc/shadow", &data, 0);
        insta::assert_snapshot!(out);
        // Every distinctive piece of salt/hash text in the fixture must be absent.
        for secret in ["FakeSalt", "AAAA", "ExampleHash", "abcdefghijk", "Zq9", "saltsalt"] {
            assert!(!out.contains(secret), "output leaks {secret}");
        }
    }

    #[test]
    fn no_hash_text_survives_in_any_field() {
        let line = "bob:$6$Sa1tSa1t$HASHBODYHASHBODY:19000:0:99999:7:::\n";
        let out = run(&ARTIFACT, "etc/shadow-", line.as_bytes(), 0);
        assert!(!out.contains("HASHBODY") && !out.contains("Sa1tSa1t"), "{out}");
        assert!(out.contains("sha512crypt"));
    }

    #[test]
    fn wrapped_hash_half_is_never_output_as_a_user() {
        let data = b"root:$6$saltsalt$FIRSTHALFOFHASH\nSECONDHALFOFHASH:19000:0:99999:7:::\nWEIRD/HALF+x=:19000:0:99999:7:::\n";
        let out = run(&ARTIFACT, "etc/shadow", data, 0);
        assert!(!out.contains("HALF") && !out.contains("saltsalt"), "{out}");
        assert_eq!(out.matches("\"user\":\"\"").count(), 2, "{out}");
        assert!(out.contains("\"user\":\"root\""), "{out}");
    }

    #[test]
    fn empty_input_emits_nothing() {
        assert_eq!(run(&ARTIFACT, "etc/shadow", b"", 0), "");
    }
}
