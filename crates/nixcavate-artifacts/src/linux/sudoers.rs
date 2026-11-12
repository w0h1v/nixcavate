//! `/etc/sudoers` and `/etc/sudoers.d/*`: who may run what as whom. Format: sudoers(5).
//! The rule grammar is parsed best-effort: `who hosts = (run_as) TAGS: commands`. Anything
//! that does not fit keeps its full text and gets a warning.

use crate::logical_lines::{for_each_logical, Dialect};
use crate::{Artifact, Category, Input, LINUX};
use nixcavate_core::{Loc, Record, Result, Sink};
use serde::Serialize;

pub const ARTIFACT: Artifact = Artifact::new(
    "sudoers",
    "sudo rules, aliases and defaults",
    Category::Accounts,
    LINUX,
    &["etc/sudoers", "etc/sudoers.d/*"],
    parse,
);

#[derive(Serialize, Default)]
struct Entry<'a> {
    /// `rule`, `alias`, `defaults` or `include`.
    kind: &'static str,
    /// User, `%group` or `#uid` of a rule; the alias name of an alias.
    who: &'a str,
    hosts: &'a str,
    run_as: &'a str,
    /// Any `NOPASSWD:` tag in the rule.
    nopasswd: bool,
    commands: &'a str,
    /// The whole logical line, continuation lines joined.
    text: &'a str,
}

impl Record for Entry<'_> {}

const ALIAS_KEYWORDS: [&str; 5] = ["User_Alias", "Runas_Alias", "Host_Alias", "Cmnd_Alias", "Cmd_Alias"];

/// True for `#include`, `#includedir`, `@include`, `@includedir` (and not for `#includes`).
fn is_include(text: &str) -> bool {
    let word = text.split(char::is_whitespace).next().unwrap_or("");
    matches!(word, "#include" | "#includedir" | "@include" | "@includedir")
}

/// Where a comment starts: a `#` at the start of the line or after blanks, except an include
/// directive or `#<digits>` (a numeric uid or gid).
fn comment_at(text: &str) -> Option<usize> {
    if is_include(text) {
        return None;
    }
    text.match_indices('#').map(|(i, _)| i).find(|&i| {
        (i == 0 || text.as_bytes()[i - 1].is_ascii_whitespace())
            && !text[i + 1..].starts_with(|c: char| c.is_ascii_digit())
    })
}

/// Splits `who hosts` at the first whitespace run that is not next to a list comma.
fn split_who_hosts(lhs: &str) -> Option<(&str, &str)> {
    let lhs = lhs.trim();
    let bytes = lhs.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if !bytes[i].is_ascii_whitespace() {
            i += 1;
            continue;
        }
        // `i` starts a whitespace run, so the byte before it is not whitespace.
        let end = i + bytes[i..].iter().take_while(|b| b.is_ascii_whitespace()).count();
        if i > 0 && bytes[i - 1] != b',' && bytes.get(end) != Some(&b',') {
            return Some((&lhs[..i], &lhs[end..]));
        }
        i = end;
    }
    None
}

/// Removes leading `TAG:` words (`NOPASSWD:`, `SETENV:`...) from a command list.
fn strip_tags(mut rest: &str) -> &str {
    loop {
        let word_end = rest.find(|c: char| !(c.is_ascii_uppercase() || c == '_')).unwrap_or(rest.len());
        let after = rest[word_end..].trim_start();
        if word_end > 0 && after.starts_with(':') {
            rest = after[1..].trim_start();
        } else {
            return rest;
        }
    }
}

fn has_nopasswd(rest: &str) -> bool {
    rest.match_indices("NOPASSWD").any(|(i, tag)| {
        let before_ok = !rest[..i].ends_with(|c: char| c.is_ascii_alphanumeric() || c == '_');
        before_ok && rest[i + tag.len()..].trim_start().starts_with(':')
    })
}

fn classify<'a>(text: &'a str) -> (Entry<'a>, Option<&'static str>) {
    let first = text.split(char::is_whitespace).next().unwrap_or("");
    if is_include(text) {
        return (Entry { kind: "include", text, ..Default::default() }, None);
    }
    if first.starts_with("Defaults") {
        return (Entry { kind: "defaults", text, ..Default::default() }, None);
    }
    if ALIAS_KEYWORDS.contains(&first) {
        let name = text[first.len()..].split('=').next().unwrap_or("").trim();
        return (Entry { kind: "alias", who: name, text, ..Default::default() }, None);
    }
    let parsed = text.split_once('=').and_then(|(lhs, rhs)| Some((split_who_hosts(lhs)?, rhs.trim())));
    let Some(((who, hosts), rhs)) = parsed else {
        return (Entry { kind: "rule", text, ..Default::default() }, Some("does not match who hosts = commands"));
    };
    let (run_as, rest) = match rhs.strip_prefix('(').and_then(|r| r.split_once(')')) {
        Some((run_as, rest)) => (run_as.trim(), rest.trim_start()),
        None => ("", rhs),
    };
    let entry =
        Entry { kind: "rule", who, hosts, run_as, nopasswd: has_nopasswd(rest), commands: strip_tags(rest), text };
    (entry, None)
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    // A trailing backslash joins the next physical line; the record sits at the first one.
    for_each_logical(input, Dialect::Strict, comment_at, |logical| {
        if logical.truncated {
            sink.warn(format!("line {}: logical line longer than 1 MiB was cut", logical.number));
        }
        let text = logical.text.trim();
        let (entry, problem) = classify(text);
        if let Some(problem) = problem {
            sink.warn(format!("line {}: {problem}", logical.number));
        }
        sink.emit(Loc::Line(logical.number), &entry)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    #[test]
    fn parses_sudoers() {
        insta::assert_snapshot!(run(&ARTIFACT, "etc/sudoers", &fixture("sudoers/sudoers"), 0));
    }

    #[test]
    fn parses_dropin() {
        insta::assert_snapshot!(run(&ARTIFACT, "etc/sudoers.d/deploy", &fixture("sudoers/dropin"), 0));
    }

    fn rules(data: &[u8]) -> Vec<(String, bool, u64)> {
        let out = run(&ARTIFACT, "etc/sudoers.d/x", data, 0);
        out.lines()
            .filter(|l| l.starts_with('{'))
            .map(|l| {
                let v: serde_json::Value = serde_json::from_str(l).unwrap();
                (
                    v["who"].as_str().unwrap().to_string(),
                    v["nopasswd"].as_bool().unwrap(),
                    v["source_line"].as_u64().unwrap(),
                )
            })
            .collect()
    }

    #[test]
    fn comment_ending_in_backslash_does_not_hide_the_next_rule() {
        let got = rules(b"# maintenance note \\\nmallory ALL=(ALL) NOPASSWD: ALL\n");
        assert_eq!(got, vec![("mallory".to_string(), true, 2)]);
    }

    #[test]
    fn trailing_comment_continuation_stays_a_separate_rule() {
        let got = rules(b"alice ALL=/bin/ls # see ticket \\\nbob ALL=(ALL) NOPASSWD: ALL\n");
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].0, "alice");
        assert!(!got[0].1);
        assert_eq!(got[1].0, "bob");
    }

    #[test]
    fn long_whitespace_runs_before_a_comma_are_linear() {
        let line = format!("a{},b ALL = /bin/true\n", " ".repeat(200_000));
        let t = std::time::Instant::now();
        let out = run(&ARTIFACT, "etc/sudoers", line.as_bytes(), 0);
        assert!(t.elapsed().as_secs() < 2);
        assert!(out.contains("/bin/true"));
    }

    #[test]
    fn empty_and_comment_only_inputs_emit_nothing() {
        assert_eq!(run(&ARTIFACT, "etc/sudoers", b"", 0), "");
        assert_eq!(run(&ARTIFACT, "etc/sudoers", b"# nothing\n\n", 0), "");
    }
}
