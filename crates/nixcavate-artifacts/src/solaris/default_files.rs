//! `etc/default/*`: `KEY=value` settings that configure `login`, `su`, `passwd`, `init`, `cron`,
//! `inetinit` and other commands. Format: the file named after the command, one `NAME=value`
//! per line, `#` comments. A later line for the same name wins. `etc/TIMEZONE` and
//! `etc/default/init` hold the system's `TZ`. Settings with a security effect include
//! `PASSREQ` and `CONSOLE` (`login`), `SUPATH` and `PATH` (`su`), and `UMASK`.
//!
//! Verified on illumos (OmniOS): the stock `login`, `su`, `init`, `passwd` and `cron` files and
//! the harness's added `PASSREQ=NO` and `SUPATH` lines.

use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, SOLARIS};
use nixcavate_core::{Loc, Record, Result, Sink};
use serde::Serialize;

pub const ARTIFACT: Artifact = Artifact::new(
    "default-files",
    "Command defaults (etc/default/login, su, passwd, init...)",
    Category::Persistence,
    SOLARIS,
    &["etc/default/*"],
    parse,
);

#[derive(Serialize)]
struct Setting<'a> {
    /// The command whose defaults these are (`login`, `su`...), from the file name.
    command: &'a str,
    name: &'a str,
    value: &'a str,
}

impl Record for Setting<'_> {}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    let command = input.path.rsplit('/').next().unwrap_or_default();
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let text = text.trim();
        if text.is_empty() || text.starts_with('#') {
            return Ok(());
        }
        // `export NAME=value` is accepted by some of the files.
        let text = text.strip_prefix("export ").unwrap_or(text);
        match text.split_once('=') {
            Some((name, value)) => {
                let value = value.trim();
                let value = value.strip_prefix('"').and_then(|v| v.strip_suffix('"')).unwrap_or(value);
                sink.emit(Loc::Line(line.number), &Setting { command, name: name.trim(), value })
            }
            None => {
                sink.warn(format!("line {}: not a NAME=value setting", line.number));
                Ok(())
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    #[test]
    fn real_default_files() {
        insta::assert_snapshot!("login", run(&ARTIFACT, "etc/default/login", &fixture("default-files/login"), 0));
        insta::assert_snapshot!("su", run(&ARTIFACT, "etc/default/su", &fixture("default-files/su"), 0));
        let out = run(&ARTIFACT, "etc/default/login", &fixture("default-files/login"), 0);
        assert!(
            out.contains(r#""command":"login","name":"PASSREQ","value":"NO""#)
                && out.contains(r#""name":"PASSREQ","value":"YES""#),
            "{out}"
        );
        let out = run(&ARTIFACT, "etc/default/su", &fixture("default-files/su"), 0);
        assert!(out.contains(r#""name":"SUPATH","value":"/tmp/.NXMK_DEFSU:/usr/sbin:/usr/bin""#), "{out}");
    }

    #[test]
    fn quotes_exports_and_odd_lines() {
        let out = run(&ARTIFACT, "etc/default/init", b"TZ=UTC\nexport LANG=\"en_US.UTF-8\"\nCMASK=022\nnoequals\n", 0);
        assert!(
            out.contains(r#""name":"LANG","value":"en_US.UTF-8""#) && out.contains(r#""command":"init","name":"TZ""#),
            "{out}"
        );
        assert!(out.contains("not a NAME=value setting"), "{out}");
        super::super::never_panics(&ARTIFACT, "etc/default/login", &fixture("default-files/login"));
    }
}
