//! udev rules that execute programs: `RUN`, `PROGRAM` and `IMPORT{program}`, which fire when a
//! matching device appears. Format: udev(7).

use crate::logical_lines::{for_each_logical, Dialect};
use crate::{Artifact, Category, Input, LINUX};
use nixcavate_core::{Loc, Record, Result, Sink};
use serde::Serialize;

pub const ARTIFACT: Artifact = Artifact::new(
    "udev-rules",
    "udev rules that run programs",
    Category::Persistence,
    LINUX,
    &[
        "etc/udev/rules.d/*.rules",
        "run/udev/rules.d/*.rules",
        "usr/lib/udev/rules.d/*.rules",
        "lib/udev/rules.d/*.rules",
    ],
    parse,
);

#[derive(Serialize)]
struct Exec<'a> {
    /// `run`, `program` or `import_program`.
    action: &'static str,
    command: &'a str,
    /// The whole rule, continuations joined.
    rule: &'a str,
}

impl Record for Exec<'_> {}

/// Calls `f(action, command)` for every executing key of one rule. A rule is a list of
/// `KEY<op>"value"` terms separated by commas.
fn for_each_exec<'a>(rule: &'a str, mut f: impl FnMut(&'static str, &'a str) -> Result<()>) -> Result<()> {
    let mut rest = rule;
    loop {
        rest = rest.trim_start_matches(|c: char| c.is_whitespace() || c == ',');
        // The key ends at the operator; braces hold the attribute and may contain `-` or `=`.
        let mut depth = 0;
        let key_end = rest.find(|c: char| match c {
            '{' => {
                depth += 1;
                false
            }
            '}' => {
                depth -= 1;
                false
            }
            '=' | '!' | '+' | '-' | ':' => depth <= 0,
            _ => false,
        });
        let Some(key_end) = key_end else { return Ok(()) };
        let key = &rest[..key_end];
        let after_key = &rest[key_end..];
        let Some(op) = ["==", "!=", "+=", "-=", ":=", "="].into_iter().find(|op| after_key.starts_with(op)) else {
            return Ok(());
        };
        let Some(value_start) = after_key[op.len()..].trim_start().strip_prefix('"') else { return Ok(()) };
        // The value ends at the first quote that is not escaped.
        let (mut escaped, mut end) = (false, None);
        for (i, c) in value_start.char_indices() {
            match c {
                _ if escaped => escaped = false,
                '\\' => escaped = true,
                '"' => {
                    end = Some(i);
                    break;
                }
                _ => {}
            }
        }
        let Some(end) = end else { return Ok(()) };
        let value = &value_start[..end];
        rest = &value_start[end + 1..];

        // `RUN==` only matches on the list; assignments and PROGRAM/IMPORT matches execute.
        let assigns = matches!(op, "=" | "+=" | ":=");
        let action = match key.trim().to_ascii_lowercase().as_str() {
            "run" | "run{program}" | "run{builtin}" if assigns => "run",
            "program" if op != "!=" => "program",
            "import{program}" if op != "!=" => "import_program",
            _ => continue,
        };
        f(action, value)?;
    }
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    for_each_logical(
        input,
        Dialect::Strict,
        |t| t.starts_with('#').then_some(0),
        |logical| {
            if logical.truncated {
                sink.warn(format!("line {}: logical line longer than 1 MiB was cut", logical.number));
            }
            let rule = logical.text.trim();
            for_each_exec(rule, |action, command| sink.emit(Loc::Line(logical.number), &Exec { action, command, rule }))
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    const PATH: &str = "etc/udev/rules.d/99-local.rules";

    #[test]
    fn lists_rules_that_execute_programs() {
        insta::assert_snapshot!(run(&ARTIFACT, PATH, &fixture("udev-rules/99-local.rules"), 0));
    }

    #[test]
    fn comment_ending_in_backslash_does_not_hide_the_next_rule() {
        let out = run(&ARTIFACT, PATH, b"# note \\\nACTION==\"add\", RUN+=\"/tmp/implant\"\n", 0);
        assert!(out.contains("\"command\":\"/tmp/implant\""), "{out}");
        assert!(out.contains("\"source_line\":2"), "{out}");
    }

    #[test]
    fn empty_truncated_and_corrupt_inputs_do_not_panic() {
        let data = fixture("udev-rules/99-local.rules");
        run(&ARTIFACT, PATH, b"", 0);
        run(&ARTIFACT, PATH, b"RUN+=\"\\\n\xff{{{ \"\"\" ,,, KEY", 0);
        for n in 0..=data.len() {
            run(&ARTIFACT, PATH, &data[..n], 0);
        }
        for i in (0..data.len()).step_by(5) {
            let mut flipped = data.clone();
            flipped[i] ^= 0xff;
            run(&ARTIFACT, PATH, &flipped, 0);
        }
    }
}
