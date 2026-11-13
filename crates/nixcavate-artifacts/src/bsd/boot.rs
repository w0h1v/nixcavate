//! Boot loader and terminal configuration: FreeBSD `loader.conf` (kernel modules loaded before
//! the system starts) and `ttys` (programs the init process runs on terminals). Formats:
//! loader.conf(5) and ttys(5).

use super::assignment;
use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, BSD, FREEBSD};
use nixcavate_core::{Loc, Record, Result, Sink};
use serde::Serialize;

pub const LOADER_CONF: Artifact = Artifact::new(
    "loader-conf",
    "FreeBSD boot loader settings and kernel modules loaded at boot",
    Category::Persistence,
    FREEBSD,
    &["boot/loader.conf", "boot/loader.conf.local", "boot/loader.conf.d/*", "boot/defaults/loader.conf.d/*"],
    parse_loader,
);

pub const TTYS: Artifact = Artifact::new(
    "ttys",
    "Terminals init runs a program on (ttys)",
    Category::Persistence,
    BSD,
    &["etc/ttys"],
    parse_ttys,
);

#[derive(Serialize)]
struct Loader<'a> {
    variable: &'a str,
    value: &'a str,
    /// `module_load` (`name_load="YES"`), `module_file` (`name_name`, `name_type`), or `setting`.
    kind: &'static str,
    /// The module a `module_load` or `module_file` line is about.
    module: &'a str,
    /// For `module_load`: whether it loads (`YES`).
    enabled: Option<bool>,
}

impl Record for Loader<'_> {}

fn parse_loader(input: &Input, sink: &mut Sink) -> Result<()> {
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let Some((variable, value)) = assignment(&text) else { return Ok(()) };
        let (kind, module, enabled) = if let Some(name) = variable.strip_suffix("_load") {
            ("module_load", name, Some(value.eq_ignore_ascii_case("yes")))
        } else if let Some(name) = variable.strip_suffix("_name") {
            ("module_file", name, None)
        } else if let Some(name) = variable.strip_suffix("_type") {
            ("module_file", name, None)
        } else {
            ("setting", "", None)
        };
        sink.emit(Loc::Line(line.number), &Loader { variable, value, kind, module, enabled })
    })
}

#[derive(Serialize)]
struct Tty<'a> {
    tty: &'a str,
    /// The program run on the terminal, with its arguments, quotes removed.
    command: String,
    terminal_type: &'a str,
    /// `on`, `off`, or `onifexists`; `secure` is split out below.
    status: &'a str,
    /// `secure` lets root log in on this terminal.
    secure: bool,
}

impl Record for Tty<'_> {}

/// Splits a `ttys` line into words, keeping a `"..."` group as one word.
fn words(line: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = line.trim_start();
    while !rest.is_empty() {
        if let Some(quoted) = rest.strip_prefix('"') {
            let end = quoted.find('"').unwrap_or(quoted.len());
            out.push(&quoted[..end]);
            rest = quoted.get(end + 1..).unwrap_or_default();
        } else {
            let end = rest.find([' ', '\t']).unwrap_or(rest.len());
            if rest.starts_with('#') {
                break;
            }
            out.push(&rest[..end]);
            rest = &rest[end..];
        }
        rest = rest.trim_start();
    }
    out
}

fn parse_ttys(input: &Input, sink: &mut Sink) -> Result<()> {
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let w = words(&text);
        // `tty "command" type status [secure] [window=...]`; OpenBSD/NetBSD write the command
        // unquoted when it has no arguments, so a short line is still a record.
        if w.len() < 3 {
            return Ok(());
        }
        let status = w.get(3).copied().unwrap_or_default();
        sink.emit(
            Loc::Line(line.number),
            &Tty {
                tty: w[0],
                command: w[1].to_string(),
                terminal_type: w[2],
                status,
                secure: w.iter().skip(3).any(|x| *x == "secure"),
            },
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    #[test]
    fn loader_conf_modules_and_settings() {
        let conf = b"autoboot_delay=\"3\"\nzfs_load=\"YES\"\nnxmk_load=\"YES\"\nnxmk_name=\"/boot/modules/nxmk.ko\"\nfoo_load=\"NO\"\n# x_load=YES\n";
        let out = run(&LOADER_CONF, "boot/loader.conf", conf, 0);
        insta::assert_snapshot!(out);
        assert!(out.contains("\"kind\":\"module_load\",\"module\":\"nxmk\",\"enabled\":true"));
        assert!(out.contains("\"module\":\"foo\",\"enabled\":false"));
    }

    #[test]
    fn ttys_entries_with_quoted_commands() {
        let ttys = b"# comment\nconsole\tnone\t\t\t\tunknown\toff secure\nttyv0\t\"/usr/libexec/getty Pc\"\txterm\ton  secure\nnxmk\t\"/tmp/x -d\"\tvt100\toff\nshort line\n";
        let out = run(&TTYS, "etc/ttys", ttys, 0);
        insta::assert_snapshot!(out);
        assert!(out.contains(
            "\"command\":\"/usr/libexec/getty Pc\",\"terminal_type\":\"xterm\",\"status\":\"on\",\"secure\":true"
        ));
    }

    #[test]
    fn a_real_ttys_and_loader_conf() {
        insta::assert_snapshot!("ttys", run(&TTYS, "etc/ttys", &fixture("boot/ttys"), 0));
        insta::assert_snapshot!("loader", run(&LOADER_CONF, "boot/loader.conf", &fixture("boot/loader.conf"), 0));
    }
}
