//! logrotate configuration: the scripts of `prerotate`, `postrotate`, `firstaction` and
//! `lastaction` blocks run as root every time a log is rotated, which makes them a quiet
//! place to persist. Format: logrotate(8). Only lines inside such a block are listed; the
//! rotation directives around them say nothing about what runs.

use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, LINUX};
use nixcavate_core::{Loc, Record, Result, Sink};
use serde::Serialize;

pub const ARTIFACT: Artifact = Artifact::new(
    "logrotate-scripts",
    "logrotate prerotate/postrotate script lines",
    Category::Persistence,
    LINUX,
    &["etc/logrotate.conf", "etc/logrotate.d/*"],
    parse,
);

#[derive(Serialize)]
struct ScriptLine<'a> {
    /// `prerotate`, `postrotate`, `firstaction`, `lastaction` or `preremove`.
    section: &'a str,
    text: &'a str,
}

impl Record for ScriptLine<'_> {}

const SECTIONS: [&str; 5] = ["prerotate", "postrotate", "firstaction", "lastaction", "preremove"];

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    let mut section: Option<&'static str> = None;
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let text = text.trim();
        match section {
            Some(_) if text == "endscript" => section = None,
            Some(name) => {
                if !text.is_empty() && !text.starts_with('#') {
                    sink.emit(Loc::Line(line.number), &ScriptLine { section: name, text })?;
                }
            }
            None => section = SECTIONS.iter().find(|s| **s == text).copied(),
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::run;

    #[test]
    fn lists_only_script_lines() {
        let data = b"/var/log/x.log {\n  weekly\n  rotate 4\n  postrotate\n    # reload\n    /tmp/.x/agent &\n    invoke-rc.d x reload\n  endscript\n  create 0640 root adm\n}\n";
        let out = run(&ARTIFACT, "etc/logrotate.d/x", data, 0);
        assert_eq!(out.matches("\"section\":\"postrotate\"").count(), 2, "{out}");
        assert!(out.contains("\"text\":\"/tmp/.x/agent &\"") && !out.contains("weekly"), "{out}");
        assert!(!out.contains("create 0640"), "{out}");
    }

    #[test]
    fn unterminated_block_and_garbage_do_not_panic() {
        run(&ARTIFACT, "etc/logrotate.d/x", b"postrotate\n/bin/true", 0);
        run(&ARTIFACT, "etc/logrotate.d/x", b"\xff\0postrotate\n\xff\n", 0);
    }
}
