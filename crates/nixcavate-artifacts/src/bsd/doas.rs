//! `doas.conf`: who may run what as another user. Format: doas.conf(5) (OpenBSD; the same file
//! is read by the portable doas on FreeBSD and Linux at `/usr/local/etc/doas.conf`).

use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, BSD};
use nixcavate_core::{Loc, Record, Result, Sink};
use serde::Serialize;

pub const ARTIFACT: Artifact = Artifact::new(
    "doas-conf",
    "doas rules (permit and deny)",
    Category::Accounts,
    BSD,
    &[
        "etc/doas.conf",
        "usr/local/etc/doas.conf",
        "usr/pkg/etc/doas.conf",
        "etc/doas.d/*.conf",
        "usr/local/etc/doas.d/*.conf",
    ],
    parse,
);

#[derive(Serialize)]
struct Rule<'a> {
    /// `permit` or `deny`.
    action: &'a str,
    /// `nopass`, `persist`, `keepenv`, `nolog`, `setenv {...}`: joined by spaces.
    options: String,
    nopass: bool,
    /// User, `:group` or `:gid` the rule is for.
    identity: &'a str,
    /// The account it may run as (`as`); empty means root.
    target: &'a str,
    /// The command it is limited to (`cmd`); empty means every command.
    command: &'a str,
    arguments: String,
    text: &'a str,
}

impl Record for Rule<'_> {}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        // A comment may follow the rule; `#` inside a word is not one in doas.conf, but a
        // space-separated `#` starts it.
        let rule = text.split(" #").next().unwrap_or_default().trim();
        let mut words = rule.split_whitespace();
        let Some(action) = words.next().filter(|a| matches!(*a, "permit" | "deny")) else { return Ok(()) };
        let mut options = Vec::new();
        let mut identity = "";
        // Options come before the identity; `setenv { A=b }` is one option with a brace group.
        let rest: Vec<&str> = words.collect();
        let mut i = 0;
        while i < rest.len() {
            let w = rest[i];
            if w == "setenv" {
                let mut group = vec![w];
                i += 1;
                while i < rest.len() {
                    group.push(rest[i]);
                    let closed = rest[i].ends_with('}');
                    i += 1;
                    if closed {
                        break;
                    }
                }
                options.push(group.join(" "));
            } else if matches!(w, "nopass" | "persist" | "keepenv" | "nolog" | "nodir") || w.starts_with("setenv") {
                options.push(w.to_string());
                i += 1;
            } else {
                identity = w;
                i += 1;
                break;
            }
        }
        let (mut target, mut command, mut args) = ("", "", Vec::new());
        while i < rest.len() {
            match rest[i] {
                "as" if command.is_empty() => {
                    target = rest.get(i + 1).copied().unwrap_or_default();
                    i += 2;
                }
                "cmd" if command.is_empty() => {
                    command = rest.get(i + 1).copied().unwrap_or_default();
                    i += 2;
                }
                "args" => {
                    args.extend(rest[i + 1..].iter().copied());
                    break;
                }
                _ => i += 1,
            }
        }
        sink.emit(
            Loc::Line(line.number),
            &Rule {
                action,
                nopass: options.iter().any(|o| o == "nopass"),
                options: options.join(" "),
                identity,
                target,
                command,
                arguments: args.join(" "),
                text: rule,
            },
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    #[test]
    fn a_real_openbsd_doas_conf() {
        let out = run(&ARTIFACT, "etc/doas.conf", &fixture("doas-conf/doas.conf"), 0);
        assert!(out.contains("\"action\":\"permit\",\"options\":\"nopass\",\"nopass\":true,\"identity\":\"alice\",\"target\":\"root\",\"command\":\"\""), "{out}");
        assert!(out.contains("\"identity\":\"bob\",\"target\":\"root\",\"command\":\"/bin/sh\""), "{out}");
    }

    #[test]
    fn rules_with_options_identities_targets_and_commands() {
        let conf = b"# comment\npermit nopass alice as root\npermit persist keepenv :wheel\npermit setenv { PATH=/bin FOO } bob cmd /usr/bin/id args -u\ndeny carol cmd rm # trailing\nbogus line\n";
        let out = run(&ARTIFACT, "etc/doas.conf", conf, 0);
        insta::assert_snapshot!(out);
        assert!(out.contains("\"nopass\":true,\"identity\":\"alice\",\"target\":\"root\",\"command\":\"\""));
        assert!(out.contains("\"identity\":\":wheel\""));
        assert!(out.contains("\"command\":\"/usr/bin/id\",\"arguments\":\"-u\""));
        assert!(out.contains("\"action\":\"deny\",\"options\":\"\",\"nopass\":false,\"identity\":\"carol\""));
    }
}
