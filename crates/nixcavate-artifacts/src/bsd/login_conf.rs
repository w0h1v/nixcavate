//! `login.conf`: per-class limits and environment for BSD logins. Format: login.conf(5), a
//! termcap-style file: `class|alias:\` followed by `:capability=value:\` lines. Only the
//! capabilities that run code or change the environment of every login are interesting; all
//! are listed, one record each.

use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, BSD};
use nixcavate_core::{Loc, Record, Result, Sink};
use serde::Serialize;

pub const ARTIFACT: Artifact = Artifact::new(
    "login-conf",
    "BSD login classes (login.conf)",
    Category::Accounts,
    BSD,
    &["etc/login.conf", "etc/login.conf.d/*"],
    parse,
);

#[derive(Serialize)]
struct Capability<'a> {
    class: &'a str,
    capability: &'a str,
    value: &'a str,
}

impl Record for Capability<'_> {}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    let mut class = String::new();
    // A logical entry continues over lines ending in a backslash; capabilities are `:`-separated.
    let mut new_entry = true;
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let t = text.trim();
        if t.is_empty() || t.starts_with('#') {
            return Ok(());
        }
        let continues = t.ends_with('\\');
        let body = t.trim_end_matches('\\').trim();
        let was_new = new_entry;
        new_entry = !continues;
        let capabilities = if was_new && !body.starts_with(':') {
            let (names, rest) = body.split_once(':').unwrap_or((body, ""));
            class = names.split('|').next().unwrap_or_default().to_string();
            rest
        } else {
            body
        };
        for part in capabilities.split(':').map(str::trim).filter(|p| !p.is_empty()) {
            let (capability, value) = part.split_once(['=', '#']).unwrap_or((part, ""));
            sink.emit(Loc::Line(line.number), &Capability { class: &class, capability, value })?;
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    #[test]
    fn classes_and_capabilities() {
        let conf = b"# comment\ndefault:\\\n\t:passwd_format=sha512:\\\n\t:copyright=/etc/COPYRIGHT:\\\n\t:setenv=LD_PRELOAD=/tmp/x.so,FOO=bar:\n\nroot:\\\n\t:ignorenologin:\\\n\t:tc=default:\n";
        let out = run(&ARTIFACT, "etc/login.conf", conf, 0);
        insta::assert_snapshot!(out);
        assert!(out.contains("\"class\":\"root\",\"capability\":\"ignorenologin\""));
    }

    #[test]
    fn a_real_login_conf() {
        let out = run(&ARTIFACT, "etc/login.conf", &fixture("login-conf/login.conf"), 0);
        assert!(out.contains("\"class\":\"default\",\"capability\":\"passwd_format\",\"value\":\"sha512\""), "{out}");
    }
}
