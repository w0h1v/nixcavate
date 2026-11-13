//! PAM configuration: modules consulted for authentication. A malicious module or a
//! `pam_exec` line is a login backdoor. Format: pam.conf(5).

use crate::logical_lines::{for_each_logical, Dialect};
use crate::{Artifact, Category, Input, ANY_OS};
use nixcavate_core::{Error, Loc, Record, Result, Sink};
use serde::Serialize;

pub const ARTIFACT: Artifact = Artifact::new(
    "pam",
    "PAM configuration",
    Category::Persistence,
    ANY_OS,
    &["etc/pam.d/*", "etc/pam.conf", "usr/lib/pam.d/*", "usr/etc/pam.d/*", "private/etc/pam.d/*"],
    parse,
);

#[derive(Serialize)]
struct Rule<'a> {
    service: &'a str,
    /// `auth`, `account`, `password`, `session`, a leading `-` as written (optional module),
    /// or `@include` (then `module` is the included file).
    module_type: &'a str,
    /// `required`, `sufficient`, ... or the bracketed `[value=action ...]` list as written.
    control: &'a str,
    module: &'a str,
    arguments: String,
}

impl Record for Rule<'_> {}

/// Whitespace-separated words; a `[...]` group stays one word, and `#` outside one starts a comment.
fn words(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let (mut start, mut in_bracket, mut escaped) = (None, false, false);
    for (i, c) in text.char_indices() {
        if in_bracket {
            match c {
                _ if escaped => escaped = false,
                '\\' => escaped = true,
                ']' => in_bracket = false,
                _ => {}
            }
        } else if c.is_whitespace() {
            if let Some(s) = start.take() {
                out.push(&text[s..i]);
            }
        } else if c == '#' && start.is_none() {
            return out;
        } else {
            start.get_or_insert(i);
            in_bracket = c == '[';
        }
    }
    if let Some(s) = start {
        out.push(&text[s..]);
    }
    out
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    // `pam.conf` carries a service column; files in `pam.d` are named after the service.
    let has_service_column = input.path == "etc/pam.conf";
    let file_service = input.path.rsplit('/').next().unwrap_or_default();
    if !has_service_column && file_service == "README" {
        return Err(Error::skipped("the README of a pam.d directory is not a service"));
    }
    for_each_logical(
        input,
        Dialect::Pam,
        |t| t.find('#'),
        |logical| {
            let number = logical.number;
            if logical.truncated {
                sink.warn(format!("line {number}: logical line longer than 1 MiB was cut"));
            }
            let mut words = words(&logical.text).into_iter();
            let service = if has_service_column { words.next() } else { Some(file_service) };
            let Some(service) = service else { return Ok(()) };
            let rest: Vec<&str> = words.collect();
            let loc = Loc::Line(number);
            match rest.as_slice() {
                [] => Ok(()),
                [include, name, ..] if include.starts_with('@') => sink.emit(
                    loc,
                    &Rule { service, module_type: include, control: "", module: name, arguments: String::new() },
                ),
                [module_type, control, module, args @ ..] => {
                    sink.emit(loc, &Rule { service, module_type, control, module, arguments: args.join(" ") })
                }
                _ => {
                    sink.warn(format!("line {number}: expected type, control and module"));
                    Ok(())
                }
            }
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    #[test]
    fn pam_d_file_takes_service_from_name() {
        insta::assert_snapshot!(run(&ARTIFACT, "etc/pam.d/sshd", &fixture("pam/sshd"), 0));
    }

    /// FreeBSD and NetBSD keep a `README` beside the service files.
    #[test]
    fn the_readme_in_pam_d_is_not_a_service() {
        let out = run(&ARTIFACT, "etc/pam.d/README", b"This directory holds\nthe PAM policy files\n", 0);
        assert!(out.contains("skipped") && !out.contains("warning"), "{out}");
    }

    #[test]
    fn pam_conf_has_a_service_column() {
        insta::assert_snapshot!(run(&ARTIFACT, "etc/pam.conf", &fixture("pam/pam.conf"), 0));
    }

    fn modules(data: &[u8]) -> Vec<String> {
        let out = run(&ARTIFACT, "etc/pam.d/sshd", data, 0);
        out.lines()
            .filter(|l| l.starts_with('{'))
            .map(|l| {
                let v: serde_json::Value = serde_json::from_str(l).unwrap();
                format!(
                    "{} {} {} {}",
                    v["module_type"].as_str().unwrap(),
                    v["control"].as_str().unwrap(),
                    v["module"].as_str().unwrap(),
                    v["arguments"].as_str().unwrap()
                )
            })
            .collect()
    }

    #[test]
    fn comment_ending_in_backslash_does_not_hide_the_next_rule() {
        assert_eq!(modules(b"# harmless \\\nauth sufficient pam_permit.so\n"), ["auth sufficient pam_permit.so "]);
    }

    #[test]
    fn blank_after_backslash_still_continues() {
        let got = modules(b"auth \\ \nsufficient pam_exec.so /tmp/x\nauth required pam_unix.so\n");
        assert_eq!(got, ["auth sufficient pam_exec.so /tmp/x", "auth required pam_unix.so "]);
    }

    #[test]
    fn inline_comment_ends_the_logical_line() {
        let got = modules(b"auth required pam_unix.so # note \\\nauth sufficient pam_permit.so\n");
        assert_eq!(got, ["auth required pam_unix.so ", "auth sufficient pam_permit.so "]);
    }

    #[test]
    fn patterns_cover_vendor_directories() {
        use nixcavate_source::glob::Pattern;
        for path in ["usr/lib/pam.d/sshd", "usr/etc/pam.d/login"] {
            assert!(ARTIFACT.paths.iter().any(|p| Pattern::new(p).matches(path)), "{path}");
        }
    }

    #[test]
    fn empty_truncated_and_corrupt_inputs_do_not_panic() {
        let data = fixture("pam/sshd");
        for path in ["etc/pam.d/sshd", "etc/pam.conf"] {
            run(&ARTIFACT, path, b"", 0);
            run(&ARTIFACT, path, b"[[[ ] \\\n\xff# \\", 0);
            for n in 0..=data.len() {
                run(&ARTIFACT, path, &data[..n], 0);
            }
            for i in (0..data.len()).step_by(5) {
                let mut flipped = data.clone();
                flipped[i] ^= 0xff;
                run(&ARTIFACT, path, &flipped, 0);
            }
        }
    }
}
