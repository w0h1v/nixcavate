//! Backslash line continuation for the config formats that have it, in the three flavours
//! they really differ by. In every flavour a comment line is skipped before a trailing
//! backslash is considered, so `# note \` can never swallow the real line after it (sudo,
//! Linux-PAM and udev all read comments that way; systemd.syntax(7) says the same: a line
//! starting with `#` or `;` is ignored, and lines ending in a backslash are concatenated).
//!
//! A logical line is capped at [`MAX_LOGICAL`] bytes; the rest is dropped and
//! [`Logical::truncated`] is set so the parser can warn.

use crate::text::{for_each_line, lossy};
use crate::Input;
use nixcavate_core::Result;
use std::borrow::Cow;

/// systemd documents a 1 MB limit on a line; the same cap keeps every format bounded.
pub const MAX_LOGICAL: usize = 1 << 20;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Dialect {
    /// sudoers, udev: the backslash must be the last byte; joined with nothing; lines inside a
    /// continuation are text (a `#` there is not a comment); leading blanks of them are dropped.
    Strict,
    /// systemd: lines are trimmed (so blanks after a backslash are ignored), joined with a
    /// space, and comment lines inside a continuation are skipped.
    Systemd,
    /// Linux-PAM: like systemd, and blank lines inside a continuation are skipped.
    Pam,
}

pub struct Logical<'a> {
    /// Line number of the first physical line.
    pub number: u64,
    pub text: Cow<'a, str>,
    /// The text hit [`MAX_LOGICAL`] and was cut.
    pub truncated: bool,
}

/// Calls `f` for every logical line. `comment_at` is given a line with leading blanks removed
/// and returns where a comment starts in it: 0 for a comment line, later for a trailing
/// comment (cut off, and a backslash after it does not continue the line), `None` for none.
pub fn for_each_logical(
    input: &Input,
    dialect: Dialect,
    comment_at: fn(&str) -> Option<usize>,
    mut f: impl FnMut(Logical<'_>) -> Result<()>,
) -> Result<()> {
    let mut open: Option<(u64, String, bool)> = None;
    let strict = dialect == Dialect::Strict;
    let sep = if strict { "" } else { " " };
    let mut result = for_each_line(input, |line| {
        let raw = lossy(line.bytes);
        let continuing = open.is_some();
        let mut text = raw.trim_start();
        match comment_at(text) {
            // In a strict continuation a `#` line is text.
            Some(0) if !(strict && continuing) => return Ok(()),
            Some(i) if i > 0 => text = text[..i].trim_end(),
            _ => {}
        }
        if !strict {
            text = text.trim_end();
            if dialect == Dialect::Pam && continuing && text.is_empty() {
                return Ok(());
            }
        }
        let (body, continues) = match text.strip_suffix('\\') {
            Some(body) if strict => (body, true),
            Some(body) => (body.trim_end(), true),
            None => (text, false),
        };
        if !continuing && !continues {
            if body.trim().is_empty() {
                return Ok(());
            }
            return f(Logical { number: line.number, text: Cow::Borrowed(body), truncated: false });
        }
        let (number, mut joined, mut truncated) = open.take().unwrap_or((line.number, String::new(), false));
        if joined.len() + body.len() + sep.len() > MAX_LOGICAL {
            truncated = true;
        } else {
            joined.push_str(body);
            if continues {
                joined.push_str(sep);
            }
        }
        if continues {
            open = Some((number, joined, truncated));
            Ok(())
        } else {
            f(Logical { number, text: Cow::Owned(joined), truncated })
        }
    });
    // A file that ends on a continuation still holds a rule.
    if let (Ok(()), Some((number, joined, truncated))) = (&result, open.take()) {
        result = f(Logical { number, text: Cow::Owned(joined), truncated });
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::with_input;

    fn comment_at(t: &str) -> Option<usize> {
        t.find('#')
    }

    fn lines(dialect: Dialect, data: &[u8]) -> Vec<(u64, String, bool)> {
        with_input("etc/x", data, 0, |input| {
            let mut out = Vec::new();
            for_each_logical(input, dialect, comment_at, |l| {
                out.push((l.number, l.text.into_owned(), l.truncated));
                Ok(())
            })
            .unwrap();
            out
        })
    }

    #[test]
    fn comment_before_continuation() {
        for d in [Dialect::Strict, Dialect::Systemd, Dialect::Pam] {
            let got = lines(d, b"# note \\\nreal\n");
            assert_eq!(got, vec![(2, "real".into(), false)], "{}", d as u8);
        }
    }

    #[test]
    fn strict_joins_exact_backslash_only() {
        assert_eq!(
            lines(Dialect::Strict, b"a \\\n  b\nc \\ \nd\n"),
            vec![(1, "a b".into(), false), (3, "c \\ ".into(), false), (4, "d".into(), false)]
        );
        // A `#` inside a continuation is text.
        assert_eq!(lines(Dialect::Strict, b"a \\\n# b\n"), vec![(1, "a # b".into(), false)]);
    }

    #[test]
    fn pam_flavour() {
        let got = lines(Dialect::Pam, b"auth \\ \n\n# x\nsufficient m # c \\\nnext\n");
        assert_eq!(got, vec![(1, "auth sufficient m".into(), false), (5, "next".into(), false)]);
    }

    #[test]
    fn systemd_skips_comments_inside_continuation_and_blank_ends_it() {
        assert_eq!(
            lines(Dialect::Systemd, b"A=1 \\\n# c\n2\n\nB=3\n"),
            vec![(1, "A=1 2".into(), false), (5, "B=3".into(), false)]
        );
        assert_eq!(
            lines(Dialect::Systemd, b"A=1 \\\n\nB=3\n"),
            vec![(1, "A=1 ".into(), false), (3, "B=3".into(), false)]
        );
    }

    #[test]
    fn caps_and_flags_huge_lines_and_keeps_a_trailing_continuation() {
        let mut data = Vec::new();
        for _ in 0..40 {
            data.extend_from_slice(&[b'x'; 50_000]);
            data.extend_from_slice(b"\\\n");
        }
        let got = lines(Dialect::Strict, &data);
        assert_eq!(got.len(), 1);
        assert!(got[0].2 && got[0].1.len() <= MAX_LOGICAL);
        assert_eq!(lines(Dialect::Strict, b"a\\"), vec![(1, "a".into(), false)]);
    }
}
