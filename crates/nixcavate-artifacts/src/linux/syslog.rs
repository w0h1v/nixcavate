//! Text logs written by a syslog daemon: `syslog`, `messages`, `kern.log`, `cron`, ... See
//! `common::syslog` for the line layouts.

use crate::common::syslog::{for_each_header, timeline_message};
use crate::{Artifact, Category, Input, UNIX_NOT_ESXI};
use nixcavate_core::{Basis, Event, Loc, Record, Result, Sink, Timestamp};
use serde::Serialize;

pub const ARTIFACT: Artifact = Artifact::new(
    "syslog",
    "General system logs (syslog, messages, kern.log, cron, ...)",
    Category::Logs,
    UNIX_NOT_ESXI,
    &[
        "var/log/syslog*",
        "var/log/messages*",
        "var/log/kern.log*",
        "var/log/daemon.log*",
        "var/log/user.log*",
        "var/log/debug*",
        "var/log/mail.log*",
        "var/log/cron*",
        "var/log/boot.log*",
        "var/log/maillog*",
        "var/log/ufw.log*",
        // FreeBSD, OpenBSD and NetBSD.
        "var/log/security*",
        "var/log/daemon",
        "var/log/xferlog*",
        "var/log/devd.log*",
        "var/log/dmesg.today",
        "var/log/dmesg.yesterday",
        "var/log/setuid.today",
        "var/log/pkg*",
        "var/log/bsdinstall_log*",
        "var/log/lpd-errs*",
        "var/log/ppp.log*",
        "var/log/daily.out*",
        "var/log/security.out*",
        "var/log/nuageinit.log*",
        "var/adm/messages*",
        "var/adm/messages*",
        "var/adm/syslog*",
        "var/adm/authlog*",
        "var/adm/maillog*",
    ],
    parse,
)
.split_lines();

#[derive(Serialize)]
struct Entry<'a> {
    time: Option<Timestamp>,
    time_basis: Option<Basis>,
    log_host: &'a str,
    program: &'a str,
    pid: Option<u32>,
    message: &'a str,
}

impl Record for Entry<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        self.time.map(|ts| Event::new(ts, "log", timeline_message(self.program, self.message))).into_iter()
    }
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    for_each_header(input, |offset, h| {
        let entry = Entry {
            time: h.time,
            time_basis: h.time.map(|t| t.basis),
            log_host: &h.log_host,
            program: &h.program,
            pid: h.pid,
            message: &h.message,
        };
        sink.emit(Loc::Offset(offset), &entry)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run, run_on_host};
    use std::io::Write;

    const MAR_10_2024: i64 = 1_710_028_800;
    const JAN_10_2024: i64 = 1_704_844_800;

    #[test]
    fn classic_lines() {
        insta::assert_snapshot!(run(&ARTIFACT, "var/log/syslog", &fixture("syslog/syslog"), MAR_10_2024));
    }

    #[test]
    fn classic_lines_without_mtime_have_no_time() {
        insta::assert_snapshot!(run(&ARTIFACT, "var/log/syslog", &fixture("syslog/syslog"), 0));
    }

    #[test]
    fn years_are_inferred_across_a_year_boundary() {
        insta::assert_snapshot!(run(&ARTIFACT, "var/log/messages", &fixture("syslog/year_boundary"), JAN_10_2024));
    }

    #[test]
    fn iso_lines() {
        insta::assert_snapshot!(run(&ARTIFACT, "var/log/syslog", &fixture("syslog/rsyslog_iso"), MAR_10_2024));
    }

    #[test]
    fn rfc5424_lines() {
        insta::assert_snapshot!(run(&ARTIFACT, "var/log/syslog", &fixture("syslog/rfc5424"), MAR_10_2024));
    }

    #[test]
    fn host_zone_applies_to_lines_without_one() {
        let zone = fixture("syslog/Europe_Berlin.tzif");
        let mut files = vec![("etc/localtime", &zone[..]), ("var/log/syslog", &[][..])];
        let classic = fixture("syslog/syslog");
        files[1].1 = &classic;
        insta::assert_snapshot!("zone_classic", run_on_host(&ARTIFACT, &files, "var/log/syslog", MAR_10_2024));
        let iso = fixture("syslog/rsyslog_iso");
        files[1].1 = &iso;
        insta::assert_snapshot!("zone_iso", run_on_host(&ARTIFACT, &files, "var/log/syslog", MAR_10_2024));
    }

    #[test]
    fn gzip_rotation_matches_plain() {
        let plain = fixture("syslog/syslog");
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(&plain).unwrap();
        let packed = gz.finish().unwrap();
        let from_gz = run(&ARTIFACT, "var/log/syslog.2.gz", &packed, MAR_10_2024);
        assert_eq!(from_gz.replace("syslog.2.gz", "syslog"), run(&ARTIFACT, "var/log/syslog", &plain, MAR_10_2024));
        assert!(from_gz.contains("sshd"));
    }

    #[test]
    fn garbage_and_binary_lines_are_kept() {
        let data = b"\x00\x01\x02\xff\xfe binary\nMar  9 25:61:61 web01 x[1]: bad clock\n\n   \nMar  9 01:02:03 web01 tag[abc]: odd pid\n<999999999999>1 x\n\r\n";
        insta::assert_snapshot!(run(&ARTIFACT, "var/log/syslog", data, MAR_10_2024));
    }

    #[test]
    fn long_messages_are_cut_in_the_timeline_at_a_char_boundary() {
        let line = format!("Mar  9 01:02:03 web01 app[1]: {}\n", "\u{e9}".repeat(400));
        let out = run(&ARTIFACT, "var/log/syslog", line.as_bytes(), MAR_10_2024);
        let timeline = out.split("--- timeline ---\n").nth(1).unwrap();
        assert_eq!(timeline.matches('\u{e9}').count(), 300);
    }

    #[test]
    fn empty_file() {
        assert_eq!(run(&ARTIFACT, "var/log/syslog", b"", MAR_10_2024), "");
    }

    #[test]
    fn truncated_and_corrupted_input_never_panics() {
        for name in ["syslog/syslog", "syslog/rsyslog_iso", "syslog/rfc5424"] {
            let data = fixture(name);
            for len in 0..data.len() {
                run(&ARTIFACT, "var/log/syslog", &data[..len], MAR_10_2024);
            }
            for i in (0..data.len()).step_by(3) {
                let mut flipped = data.clone();
                flipped[i] ^= 0x5a;
                run(&ARTIFACT, "var/log/syslog", &flipped, MAR_10_2024);
            }
        }
    }

    /// illumos `/var/adm/messages`: the facility and level come after the tag as `[ID n kern.notice]` and stay in the message.
    #[test]
    fn solaris_messages_keep_the_message_id() {
        const NOV_13_2026: i64 = 1_794_535_000;
        let out = run(&ARTIFACT, "var/adm/messages", &fixture("syslog/solaris_messages"), NOV_13_2026);
        insta::assert_snapshot!(out);
        assert!(out.contains(r#""program":"svc.startd","pid":9,"message":"[ID 748625 daemon.error] site/nxmk-smf-lib:default failed: transitioned to maintenance"#), "{out}");
        assert!(out.contains(r#""program":"/sbin/dhcpagent""#), "{out}");
    }
}
