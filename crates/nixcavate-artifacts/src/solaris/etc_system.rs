//! `etc/system`: kernel configuration read at boot. Format: system(5). Lines are `set [module:]var
//! = value`, `forceload: drv/name`, `exclude: drv/name`, `moddir: /path /path`, `rootdev:`,
//! `rootfs:`, `include: name`, `infile:`; `*` starts a comment. A `forceload` makes the kernel
//! load a module at boot, and `moddir` changes where modules are searched for: both are ways to
//! get code into the kernel.
//!
//! Verified on illumos (OmniOS): the stock file (comments only) and the harness's added
//! `forceload`/`set` lines. Oracle Solaris additionally reads `/etc/system.d/*`: those fragments are
//! read here too, from the documentation only.

use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, SOLARIS};
use nixcavate_core::{Loc, Record, Result, Sink};
use serde::Serialize;

pub const ARTIFACT: Artifact = Artifact::new(
    "etc-system",
    "Kernel configuration: set, forceload, moddir, exclude",
    Category::Persistence,
    SOLARIS,
    &["etc/system", "etc/system.d/*"],
    parse,
);

#[derive(Serialize)]
struct Directive<'a> {
    /// `set`, `forceload`, `exclude`, `moddir`, `rootdev`, `rootfs`, `include`, `infile`...
    directive: &'a str,
    /// For `set`: the variable (`module:variable`); otherwise the first word.
    name: &'a str,
    value: &'a str,
}

impl Record for Directive<'_> {}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let text = text.trim();
        if text.is_empty() || text.starts_with('*') {
            return Ok(());
        }
        // A trailing `* comment` ends the directive.
        let text = text.split('*').next().unwrap_or_default().trim();
        let loc = Loc::Line(line.number);
        if let Some(rest) = text.strip_prefix("set ").or_else(|| text.strip_prefix("set\t")) {
            let (name, value) = rest.split_once(['=', ' ']).unwrap_or((rest, ""));
            let value = value.trim().trim_start_matches('=').trim();
            return sink.emit(loc, &Directive { directive: "set", name: name.trim(), value });
        }
        match text.split_once(':') {
            Some((directive, rest)) => {
                let rest = rest.trim();
                let (name, value) = rest.split_once(char::is_whitespace).unwrap_or((rest, ""));
                sink.emit(loc, &Directive { directive: directive.trim(), name, value: value.trim() })
            }
            None => {
                sink.warn(format!("line {}: not a directive", line.number));
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
    fn a_real_etc_system_with_added_lines() {
        let out = run(&ARTIFACT, "etc/system", &fixture("etc-system/system"), 0);
        insta::assert_snapshot!(out);
        assert!(
            out.contains(r#""directive":"forceload","name":"drv/nxmk_NXMK_FORCELOAD""#)
                && out.contains(r#""directive":"set","name":"nxmk_tunable","value":"1""#),
            "{out}"
        );
    }

    /// The directives of system(5).
    #[test]
    fn every_directive_form() {
        let text = b"* comment\nset maxusers = 40\nset zfs:zfs_arc_max=0x10000000\nforceload: drv/foo   * trailing\nexclude: drv/bar\nmoddir: /kernel /usr/kernel /opt/mods\nrootdev: /pseudo/rootdev@0:0\nrootfs:ufs\ninclude: other\nnonsense\nset\n";
        let out = run(&ARTIFACT, "etc/system", text, 0);
        for want in [
            r#""directive":"set","name":"maxusers","value":"40""#,
            r#""directive":"set","name":"zfs:zfs_arc_max","value":"0x10000000""#,
            r#""directive":"forceload","name":"drv/foo","value":"""#,
            r#""directive":"moddir","name":"/kernel","value":"/usr/kernel /opt/mods""#,
            r#""directive":"exclude","name":"drv/bar""#,
            r#""directive":"rootfs","name":"ufs""#,
        ] {
            assert!(out.contains(want), "{want}\n{out}");
        }
        assert_eq!(out.matches("not a directive").count(), 2, "{out}");
        super::super::never_panics(&ARTIFACT, "etc/system", &fixture("etc-system/system"));
    }
}
