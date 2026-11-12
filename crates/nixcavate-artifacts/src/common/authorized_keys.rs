//! SSH `authorized_keys`: public keys that can log in as a user, with the options that restrict
//! (or abuse) them. Format: sshd(8), AUTHORIZED_KEYS FILE FORMAT:
//! `[options] keytype base64-key [comment]`.

use super::home::user_from_path;
use super::ssh_key;
use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, ANY_OS};
use nixcavate_core::{Loc, Record, Result, Sink};
use serde::Serialize;

pub const ARTIFACT: Artifact = Artifact::new(
    "authorized-keys",
    "SSH authorized_keys",
    Category::Persistence,
    ANY_OS,
    &[
        "home/*/.ssh/authorized_keys*",
        "root/.ssh/authorized_keys*",
        "Users/*/.ssh/authorized_keys*",
        "private/var/root/.ssh/authorized_keys*",
        "var/root/.ssh/authorized_keys*",
    ],
    parse,
);

#[derive(Serialize)]
struct Key<'a> {
    user: &'a str,
    key_type: &'a str,
    /// OpenSSH form: `SHA256:` and the unpadded base64 of the SHA-256 of the key blob.
    fingerprint: String,
    comment: &'a str,
    /// The raw options text, as written.
    options: &'a str,
    /// Value of the `command="..."` option: what runs instead of the login shell.
    forced_command: Option<String>,
    /// Value of the `from="..."` option.
    from: Option<String>,
}

impl Record for Key<'_> {}

fn is_key_type(word: &str) -> bool {
    word.starts_with("ssh-") || word.starts_with("ecdsa-sha2-") || word.starts_with("sk-")
}

/// Splits `text` at the first whitespace that is not inside a double-quoted string.
fn split_unquoted(text: &str) -> (&str, &str) {
    let (mut quoted, mut escaped) = (false, false);
    for (i, c) in text.char_indices() {
        match c {
            _ if escaped => escaped = false,
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            c if c.is_whitespace() && !quoted => return (&text[..i], text[i..].trim_start()),
            _ => {}
        }
    }
    (text, "")
}

/// The value of option `name` (case-insensitive), unquoted and unescaped.
fn option_value(options: &str, name: &str) -> Option<String> {
    let (mut quoted, mut escaped, mut start) = (false, false, 0);
    let mut pieces = Vec::new();
    for (i, c) in options.char_indices() {
        match c {
            _ if escaped => escaped = false,
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            ',' if !quoted => {
                pieces.push(&options[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    pieces.push(&options[start..]);
    pieces.into_iter().find_map(|piece| {
        let (key, value) = piece.split_once('=')?;
        if !key.trim().eq_ignore_ascii_case(name) {
            return None;
        }
        let value = value.trim().strip_prefix('"')?;
        let mut out = String::new();
        let mut chars = value.chars();
        while let Some(c) = chars.next() {
            match c {
                '"' => break,
                '\\' => match chars.next() {
                    Some('"') | None => out.push('"'),
                    Some(other) => {
                        out.push('\\');
                        out.push(other);
                    }
                },
                c => out.push(c),
            }
        }
        Some(out)
    })
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    let user = user_from_path(input.path);
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let text = text.trim();
        if text.is_empty() || text.starts_with('#') {
            return Ok(());
        }
        let (first, rest) = split_unquoted(text);
        let (options, key_type, rest) = if is_key_type(first) {
            ("", first, rest)
        } else {
            let (key_type, rest) = split_unquoted(rest);
            (first, key_type, rest)
        };
        let (blob, comment) = split_unquoted(rest);
        let fingerprint = is_key_type(key_type).then(|| ssh_key::fingerprint(key_type, blob)).flatten();
        let Some(fingerprint) = fingerprint else {
            sink.warn(format!("line {}: not a valid authorized_keys entry", line.number));
            return Ok(());
        };
        sink.emit(
            Loc::Line(line.number),
            &Key {
                user,
                key_type,
                fingerprint,
                comment,
                options,
                forced_command: option_value(options, "command"),
                from: option_value(options, "from"),
            },
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    #[test]
    fn var_root_home_is_covered() {
        use nixcavate_source::glob::Pattern;
        assert!(ARTIFACT.paths.iter().any(|p| Pattern::new(p).matches("var/root/.ssh/authorized_keys")));
    }

    #[test]
    fn parses_keys_options_and_forced_commands() {
        insta::assert_snapshot!(run(
            &ARTIFACT,
            "home/alice/.ssh/authorized_keys",
            &fixture("authorized-keys/authorized_keys"),
            0
        ));
    }

    /// Fingerprints printed by `ssh-keygen -lf` (OpenSSH 9.2, Debian 12) for the fixture keys.
    #[test]
    fn fingerprints_match_ssh_keygen() {
        let out = run(&ARTIFACT, "root/.ssh/authorized_keys", &fixture("authorized-keys/authorized_keys"), 0);
        for expected in [
            "SHA256:Cqoak1mXSSwXboEF+H1NZG3RT6Emffr+a3DyzkB/4GA",
            "SHA256:dA6ZG8GQnhe/BIXxZ9pad5Le2sTs5Uk4kHPXSnE5bi0",
            "SHA256:GioSZzPOX6d+sD0TVLKiIOjIHi2NHg28pKbHx/R/Za8",
            "SHA256:PGB5utDn6RjZzH21JMD5g35igJKtxUpl2D28E9z+ADo",
        ] {
            assert!(out.contains(expected), "missing {expected}");
        }
    }

    #[test]
    fn empty_truncated_and_corrupt_inputs_do_not_panic() {
        let data = fixture("authorized-keys/authorized_keys");
        let path = "home/alice/.ssh/authorized_keys";
        run(&ARTIFACT, path, b"", 0);
        run(&ARTIFACT, path, b"\"\\\"\xff, = ssh-rsa \"", 0);
        for n in 0..=data.len() {
            run(&ARTIFACT, path, &data[..n], 0);
        }
        for i in (0..data.len()).step_by(7) {
            let mut flipped = data.clone();
            flipped[i] ^= 0xff;
            run(&ARTIFACT, path, &flipped, 0);
        }
    }
}
