//! `etc/pam.conf`: the PAM stack on Solaris and illumos, one line per module: `service
//! module-type control-flag module-path [options]`. A `module-path` that is not absolute is
//! relative to `/usr/lib/security/$ISA/` (the stock modules). Format: pam.conf(5). Linux PAM
//! uses a different layout (one file per service, no service column in `/etc/pam.d`).
//!
//! Verified on illumos (OmniOS): the stock file (`login`, `rlogin`, `krlogin`, `sshd-*`, `other`
//! and more services) and the harness's added line. Oracle Solaris 11 moves some services to
//! `/etc/pam.d`; that layout is not read.

use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, SOLARIS};
use nixcavate_core::{Loc, Record, Result, Sink};
use serde::Serialize;

pub const ARTIFACT: Artifact = Artifact::new(
    "pam-conf",
    "PAM stack (Solaris/illumos pam.conf)",
    Category::Persistence,
    SOLARIS,
    &["etc/pam.conf"],
    parse,
);

#[derive(Serialize)]
struct Rule<'a> {
    service: &'a str,
    module_type: &'a str,
    control: &'a str,
    module: &'a str,
    arguments: String,
}

impl Record for Rule<'_> {}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let text = text.split('#').next().unwrap_or_default().trim();
        if text.is_empty() {
            return Ok(());
        }
        let words: Vec<&str> = text.split_whitespace().collect();
        let &[service, module_type, control, module, ref rest @ ..] = &words[..] else {
            sink.warn(format!("line {}: expected service, type, control and module", line.number));
            return Ok(());
        };
        sink.emit(Loc::Line(line.number), &Rule { service, module_type, control, module, arguments: rest.join(" ") })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    #[test]
    fn a_real_pam_conf() {
        let out = run(&ARTIFACT, "etc/pam.conf", &fixture("pam-conf/pam.conf"), 0);
        insta::assert_snapshot!(out);
        assert!(out.contains(r#""service":"nxmk-svc","module_type":"session","control":"optional","module":"/tmp/.NXMK_PAM/pam_nxmk.so.1","arguments":"""#), "{out}");
        assert!(
            out.contains(
                r#""service":"login","module_type":"auth","control":"requisite","module":"pam_authtok_get.so.1""#
            ),
            "{out}"
        );
    }

    #[test]
    fn options_comments_and_short_lines() {
        let out = run(
            &ARTIFACT,
            "etc/pam.conf",
            b"# c\nother password required pam_authtok_store.so.1 nowarn  # tail\nshort line here\n",
            0,
        );
        assert!(
            out.contains(r#""arguments":"nowarn""#) && out.contains("expected service, type, control and module"),
            "{out}"
        );
        super::super::never_panics(&ARTIFACT, "etc/pam.conf", &fixture("pam-conf/pam.conf"));
    }
}
