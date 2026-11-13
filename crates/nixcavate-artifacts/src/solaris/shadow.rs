//! `etc/shadow` on Solaris and illumos: the same nine fields as Linux, with Solaris's own markers
//! in the password field: `*LK*` (account locked by `passwd -l`, optionally followed by the
//! hash), `NP` (no password: password login is impossible) and `UP` (password unset, a login
//! with it set at first use). Hashes are named by their `crypt(3C)` prefix: `$md5$` and `$sha1$`
//! are Sun's own. Only the type is output, never the hash.
//!
//! Verified on illumos (OmniOS): `$5$` (sha256) hashes, `NP` and `*LK*` entries of the stock
//! accounts, and the day numbers of `passwd` changes. Oracle Solaris 10 (`$md5$`, `__unix__`
//! style DES) is from the documentation only.

use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, SOLARIS};
use nixcavate_core::{Basis, Event, Loc, Record, Result, Sink, Timestamp};
use serde::Serialize;

pub const ARTIFACT: Artifact = Artifact::new(
    "solaris-shadow",
    "Password ageing and hash types (Solaris/illumos; never the hashes)",
    Category::Accounts,
    SOLARIS,
    &["etc/shadow", "etc/shadow-", "etc/oshadow"],
    parse,
);

#[derive(Serialize)]
struct Shadow<'a> {
    user: &'a str,
    /// Algorithm from the crypt(3C) prefix; `none` for `*`, `NP`, `UP`, `*LK*` and `x`.
    hash_type: &'static str,
    /// `*LK*` in front of the field, or a `!` in front of a hash.
    locked: bool,
    /// The field is `NP`: no password; a password login cannot succeed.
    no_password: bool,
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

fn hash_type(hash: &str) -> &'static str {
    const PREFIXES: [(&str, &str); 11] = [
        ("$2a$", "bcrypt"),
        ("$2b$", "bcrypt"),
        ("$2x$", "bcrypt"),
        ("$2y$", "bcrypt"),
        ("$6$", "sha512crypt"),
        ("$5$", "sha256crypt"),
        ("$1$", "md5crypt"),
        ("$sha1$", "sha1crypt"),
        ("$md5$", "sunmd5"),
        ("$7$", "scrypt"),
        ("$y$", "yescrypt"),
    ];
    if matches!(hash, "" | "NP" | "UP" | "x") || hash.starts_with('*') {
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

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        if text.trim().is_empty() || text.starts_with('#') {
            return Ok(());
        }
        let fields: Vec<&str> = text.split(':').collect();
        let (Some(user), Some(field)) = (fields.first(), fields.get(1)) else {
            sink.warn(format!("line {}: expected at least 2 fields, found {}", line.number, fields.len()));
            return Ok(());
        };
        if fields.len() != 9 {
            sink.warn(format!("line {}: expected 9 fields, found {}", line.number, fields.len()));
        }
        let number = |i: usize| fields.get(i).and_then(|f| f.trim().parse::<i64>().ok());
        // `*LK*` is a lock; what follows it is the hash that `passwd -u` restores.
        let (locked_marker, rest) = match field.strip_prefix("*LK*") {
            Some(rest) => (true, rest),
            None => (false, *field),
        };
        let unlocked = rest.strip_prefix('!').unwrap_or(rest);
        let locked = locked_marker || (unlocked.len() != rest.len() && hash_type(unlocked) != "none");
        let last = number(2);
        sink.emit(
            Loc::Line(line.number),
            &Shadow {
                user,
                hash_type: if field.is_empty() { "none" } else { hash_type(unlocked) },
                locked,
                no_password: *field == "NP",
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
    fn a_real_shadow_without_leaking_hashes() {
        let out = run(&ARTIFACT, "etc/shadow", &fixture("solaris-shadow/shadow"), 0);
        insta::assert_snapshot!(out);
        for secret in ["FakeSalt", "AAAA", "BBBB"] {
            assert!(!out.contains(secret), "output leaks {secret}");
        }
        // The stock accounts have `NP` (no password), `*LK*` (locked) or a `*`; the added ones a `$5$` hash.
        assert!(out.contains(r#""user":"alice","hash_type":"sha512crypt","locked":false"#), "{out}");
        assert!(out.contains(r#""no_password":true"#) && out.contains(r#""locked":true"#), "{out}");
    }

    #[test]
    fn solaris_markers_and_hash_types() {
        let data = b"a:*LK*:1:::::: \nb:*LK*$md5$s$h:1::::::\nc:UP:0::::::\nd:$sha1$x$y:1::::::\ne:abcdefghijklm:1::::::\nf::1::::::\ng:!$6$s$h:1::::::\n";
        let out = run(&ARTIFACT, "etc/shadow", data, 0);
        let row = |user: &str| out.lines().find(|l| l.contains(&format!(r#""user":"{user}""#))).unwrap().to_string();
        assert!(row("a").contains(r#""hash_type":"none","locked":true"#));
        assert!(row("b").contains(r#""hash_type":"sunmd5","locked":true"#));
        assert!(row("c").contains(
            r#""hash_type":"none","locked":false,"no_password":false,"passwordless":false,"must_change":true"#
        ));
        assert!(row("d").contains(r#""hash_type":"sha1crypt""#) && row("e").contains(r#""hash_type":"des""#));
        assert!(
            row("f").contains(r#""passwordless":true"#)
                && row("g").contains(r#""hash_type":"sha512crypt","locked":true"#)
        );
        assert!(!out.contains("$md5$") && !out.contains("$sha1$"));
    }

    #[test]
    fn short_lines_warn_and_files_mutate_safely() {
        assert!(run(&ARTIFACT, "etc/shadow", b"lonely\n", 0).contains("expected at least 2 fields"));
        super::super::never_panics(&ARTIFACT, "etc/shadow", &fixture("solaris-shadow/shadow"));
    }
}
