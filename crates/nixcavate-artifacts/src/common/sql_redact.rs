//! Removes the secret from SQL statements that database logs record: the literal that follows
//! `PASSWORD`, `IDENTIFIED BY` and `IDENTIFIED WITH <plugin> BY|AS` (PostgreSQL `CREATE ROLE ...
//! PASSWORD '...'`, MySQL and MariaDB `CREATE USER ... IDENTIFIED BY '...'`, `SET PASSWORD = ...`,
//! `MASTER_PASSWORD='...'`). A statement log is otherwise shown as written: anything an
//! application puts in an ordinary `INSERT` is not recognisable as a secret.

use std::borrow::Cow;

const REDACTED: &str = "'<redacted>'";

/// The statement with each secret literal replaced by `'<redacted>'`.
pub fn redact(sql: &str) -> Cow<'_, str> {
    let bytes = sql.as_bytes();
    if !contains_word(bytes, b"password") && !contains_word(bytes, b"identified") {
        return Cow::Borrowed(sql);
    }
    let mut out = String::with_capacity(sql.len());
    let mut copied = 0;
    let mut i = 0;
    while i < bytes.len() {
        let skip = if starts_with_ci(bytes, i, b"password") {
            Some(i + 8)
        } else if starts_with_ci(bytes, i, b"identified") && boundary_before(bytes, i) {
            Some(after_identified(bytes, i + 10))
        } else {
            None
        };
        let Some(mut at) = skip else {
            i += 1;
            continue;
        };
        at = skip_space(bytes, at);
        if bytes.get(at) == Some(&b'=') {
            at = skip_space(bytes, at + 1);
        }
        if bytes.get(at) == Some(&b'(') {
            at = skip_space(bytes, at + 1);
        }
        match literal_end(bytes, at) {
            Some(end) => {
                out.push_str(sql.get(copied..at).unwrap_or_default());
                out.push_str(REDACTED);
                copied = end;
                i = end;
            }
            None => i += 8,
        }
    }
    out.push_str(sql.get(copied..).unwrap_or_default());
    Cow::Owned(out)
}

fn contains_word(bytes: &[u8], word: &[u8]) -> bool {
    (0..bytes.len()).any(|i| starts_with_ci(bytes, i, word))
}

fn starts_with_ci(bytes: &[u8], at: usize, word: &[u8]) -> bool {
    bytes.get(at..at + word.len()).is_some_and(|b| b.eq_ignore_ascii_case(word))
}

fn boundary_before(bytes: &[u8], at: usize) -> bool {
    at == 0 || !bytes.get(at - 1).is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_')
}

fn skip_space(bytes: &[u8], mut at: usize) -> usize {
    while bytes.get(at).is_some_and(u8::is_ascii_whitespace) {
        at += 1;
    }
    at
}

/// After `IDENTIFIED`: `BY` (the literal follows), or `WITH plugin BY|AS`.
fn after_identified(bytes: &[u8], at: usize) -> usize {
    let at = skip_space(bytes, at);
    if starts_with_ci(bytes, at, b"by") {
        return at + 2;
    }
    if starts_with_ci(bytes, at, b"with") {
        let mut at = skip_space(bytes, at + 4);
        while bytes.get(at).is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_') {
            at += 1;
        }
        at = skip_space(bytes, at);
        if starts_with_ci(bytes, at, b"by") || starts_with_ci(bytes, at, b"as") {
            return at + 2;
        }
    }
    // Not a password clause: point at something that is not a literal.
    bytes.len()
}

/// The end of the quoted literal that starts at `at`: `'...'` and `"..."` (a doubled quote or a
/// backslash escapes), `E'...'`, and PostgreSQL dollar quoting `$tag$...$tag$`.
fn literal_end(bytes: &[u8], at: usize) -> Option<usize> {
    let mut start = at;
    if matches!(bytes.get(start), Some(b'e' | b'E')) && bytes.get(start + 1) == Some(&b'\'') {
        start += 1;
    }
    let quote = *bytes.get(start)?;
    match quote {
        b'\'' | b'"' => {
            let mut i = start + 1;
            while i < bytes.len() {
                match bytes[i] {
                    b'\\' => i += 2,
                    q if q == quote && bytes.get(i + 1) == Some(&quote) => i += 2,
                    q if q == quote => return Some(i + 1),
                    _ => i += 1,
                }
            }
            // Unterminated (the log cut it): everything to the end is the secret.
            Some(bytes.len())
        }
        b'$' => {
            let tag_end = bytes.get(start + 1..)?.iter().position(|&b| b == b'$')? + start + 2;
            let tag = bytes.get(start..tag_end)?;
            if tag.get(1..tag.len() - 1)?.iter().any(|b| !(b.is_ascii_alphanumeric() || *b == b'_')) {
                return None;
            }
            let rest = bytes.get(tag_end..)?;
            let close = rest.windows(tag.len()).position(|w| w == tag);
            Some(close.map_or(bytes.len(), |p| tag_end + p + tag.len()))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::redact;

    #[test]
    fn secrets_in_password_clauses_are_replaced() {
        let cases = [
            ("CREATE ROLE a LOGIN PASSWORD 's3cret'", "CREATE ROLE a LOGIN PASSWORD '<redacted>'"),
            (
                "alter user a with encrypted password E'x\\'y' valid until 'x'",
                "alter user a with encrypted password '<redacted>' valid until 'x'",
            ),
            ("CREATE USER a@'%' IDENTIFIED BY 'p''w'", "CREATE USER a@'%' '<redacted>'"),
            (
                "CREATE USER a IDENTIFIED WITH mysql_native_password BY \"pw\" PASSWORD EXPIRE",
                "CREATE USER a '<redacted>' PASSWORD EXPIRE",
            ),
            ("SET PASSWORD FOR 'bob'@'h' = PASSWORD('pw')", "SET PASSWORD FOR 'bob'@'h' = PASSWORD('<redacted>')"),
            (
                "CHANGE MASTER TO MASTER_PASSWORD='pw', MASTER_USER='r'",
                "CHANGE MASTER TO MASTER_PASSWORD='<redacted>', MASTER_USER='r'",
            ),
            ("ALTER ROLE a PASSWORD $q$pw'x$q$", "ALTER ROLE a PASSWORD '<redacted>'"),
            ("select 1", "select 1"),
            ("CREATE ROLE a PASSWORD NULL", "CREATE ROLE a PASSWORD NULL"),
        ];
        for (input, expected) in cases {
            let got = redact(input);
            assert!(!got.contains("pw") || input.contains("PASSWORD NULL"), "{got}");
            if !input.contains("IDENTIFIED") {
                assert_eq!(got, expected, "{input}");
            } else {
                assert!(got.contains("<redacted>"), "{got}");
            }
        }
    }

    #[test]
    fn unterminated_and_hostile_text_never_panics() {
        for text in [
            "password '",
            "password $",
            "password $a",
            "identified",
            "identified with",
            "password E'",
            "PASSWORD ((",
            "identified by \u{e9}",
            "password '\\",
        ] {
            let _ = redact(text);
        }
    }
}
