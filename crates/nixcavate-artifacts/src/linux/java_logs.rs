//! Apache Tomcat server logs (`catalina.out`, `catalina.<date>.log`, `localhost.<date>.log`,
//! `manager.<date>.log`): java.util.logging with Tomcat's `OneLineFormatter`, the format of its
//! default `logging.properties`: `13-Nov-2026 01:35:02.966 INFO [main]
//! org.apache.catalina.startup.Catalina.start Server startup in [1234] milliseconds`. Format:
//! Tomcat documentation, "Logging in Tomcat" (`org.apache.juli.OneLineFormatter`).
//!
//! Not read: the two-line `SimpleFormatter` layout (`Nov 13, 2026 1:35:02 AM class method` then
//! `INFO: message`). Lines that are not entries (stack traces, application output written to
//! `catalina.out`) continue the entry before them. The time has no zone and is marked as an
//! assumed zone. The access valve's `localhost_access_log.<date>.txt` is read by `web-access-log`.

use crate::common::stamped_log::{parse, Parsed};
use crate::{Artifact, Category, Input, UNIX};
use nixcavate_core::time::{month_from_abbrev, parse_uint, secs_from_civil};
use nixcavate_core::Precision;

pub const TOMCAT: Artifact = Artifact::new(
    "tomcat-log",
    "Apache Tomcat catalina and host logs",
    Category::Logs,
    UNIX,
    &[
        "var/log/tomcat*/catalina.out*",
        "var/log/tomcat*/catalina.*.log*",
        "var/log/tomcat*/localhost.*.log*",
        "var/log/tomcat*/manager.*.log*",
        "var/log/tomcat*/host-manager.*.log*",
        "var/lib/tomcat*/logs/catalina.*",
        "var/lib/tomcat*/logs/localhost.*.log*",
        "usr/local/tomcat/logs/catalina.*",
        "usr/local/tomcat/logs/localhost.*.log*",
        "usr/local/tomcat/logs/manager.*.log*",
        "opt/tomcat*/logs/catalina.*",
        "opt/tomcat*/logs/localhost.*.log*",
        "opt/tomcat*/logs/manager.*.log*",
        "opt/apache-tomcat*/logs/catalina.*",
        "opt/apache-tomcat*/logs/localhost.*.log*",
    ],
    |input, sink| parse(input, sink, "a Tomcat log", "tomcat_log", tomcat_line),
);

/// `13-Nov-2026 01:35:02.966 INFO [main] org.apache.catalina.startup.Catalina.start message`
fn tomcat_line<'a>(input: &Input, line: &'a str) -> Option<Parsed<'a>> {
    let b = line.as_bytes();
    let num = |from: usize, len: usize| parse_uint(b.get(from..from + len)?).and_then(|v| u32::try_from(v).ok());
    if b.get(2) != Some(&b'-')
        || b.get(6) != Some(&b'-')
        || b.get(11) != Some(&b' ')
        || b.get(14) != Some(&b':')
        || b.get(17) != Some(&b':')
        || b.get(20) != Some(&b'.')
    {
        return None;
    }
    let wall = secs_from_civil(
        i64::from(num(7, 4)?),
        month_from_abbrev(b.get(3..6)?)?,
        num(0, 2)?,
        num(12, 2)?,
        num(15, 2)?,
        num(18, 2)?,
    )?;
    let nanos = num(21, 3)?.checked_mul(1_000_000)?;
    let rest = line.get(25..)?.trim_start();
    let (level, rest) = rest.split_once(' ')?;
    if level.is_empty() || !level.bytes().all(|c| c.is_ascii_uppercase()) {
        return None;
    }
    // `[thread] class.method message`
    let rest = rest.strip_prefix('[')?;
    let (_thread, rest) = rest.split_once("] ")?;
    let (source, message) = rest.split_once(' ').unwrap_or((rest, ""));
    Some(Parsed {
        time: Some(input.local_time(wall, nanos, Precision::Millis)),
        level: Some(level),
        source: Some(source),
        pid: None,
        message,
        timeline: matches!(level, "SEVERE" | "WARNING")
            || message.starts_with("Server startup")
            || message.starts_with("Starting service"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    fn records(out: &str) -> Vec<&str> {
        out.lines().take_while(|l| !l.starts_with("---")).collect()
    }

    /// Fixture: real Tomcat 10.1 (official image, `catalina.sh start`): `catalina.out`, the
    /// juli `catalina.<date>.log` and the host log.
    #[test]
    fn catalina_and_host_logs() {
        for name in ["catalina.out", "catalina.2026-11-13.log", "localhost.2026-11-13.log"] {
            let data = fixture(&format!("svclogs/tomcat/{name}"));
            let out = run(&TOMCAT, &format!("var/log/tomcat10/{name}"), &data, 0);
            assert!(!out.contains("--- warning") && !out.contains("--- failed"), "{name}: {out}");
            assert_eq!(records(&out).len(), data.split(|b| *b == b'\n').filter(|l| !l.is_empty()).count(), "{name}");
        }
        let out = run(&TOMCAT, "var/log/tomcat10/catalina.out", &fixture("svclogs/tomcat/catalina.out"), 0);
        assert!(out.contains("\"time\":\"2026-11-13T01:35:02.966Z\",\"level\":\"INFO\",\"source\":\"org.apache.catalina.startup.VersionLoggerListener.log\""), "{out}");
        assert!(out.contains("Server startup in ["), "{out}");
        insta::assert_snapshot!(out);
    }

    /// The access valve's common log format is the existing web-access-log's: 6 requests, 1 of them a POST.
    #[test]
    fn tomcat_access_log_is_read_by_the_web_access_artifact() {
        use nixcavate_source::glob::Pattern;
        let path = "var/log/tomcat10/localhost_access_log.2026-11-13.txt";
        assert!(crate::common::web_logs::ACCESS.paths.iter().any(|p| Pattern::new(p).matches(path)));
        let out = run(
            &crate::common::web_logs::ACCESS,
            path,
            &fixture("svclogs/tomcat/localhost_access_log.2026-11-13.txt"),
            0,
        );
        assert!(!out.contains("--- warning") && !out.contains("--- failed"), "{out}");
        assert_eq!(records(&out).len(), 6);
        assert!(out.contains("\"method\":\"POST\",\"request\":\"/docs/x\"") && out.contains("\"status\":401"), "{out}");
    }

    #[test]
    fn stack_traces_continue_the_entry_and_other_files_are_refused() {
        let data = b"13-Nov-2026 01:35:02.966 SEVERE [main] a.B.c boom\njava.lang.Exception: x\n\tat a.B.c(B.java:1)\n";
        let out = run(&TOMCAT, "var/log/tomcat10/catalina.out", data, 0);
        assert_eq!(records(&out).len(), 3);
        assert_eq!(out.matches("\"time\":null").count(), 2);
        assert!(run(&TOMCAT, "var/log/tomcat10/catalina.out", b"Nov 13, 2026 1:35:02 AM x y\nINFO: z\n", 0)
            .contains("not a Tomcat log"));
    }

    #[test]
    fn hostile_lines_never_panic() {
        let full = fixture("svclogs/tomcat/catalina.out");
        for cut in (0..full.len()).step_by(5) {
            run(&TOMCAT, "var/log/tomcat10/catalina.out", &full[..cut], 0);
        }
        for data in [
            &b"13-Nov-2026 01:35:02.966"[..],
            b"99-Xxx-2026 99:99:99.999 INFO [x] y",
            b"13-Nov-2026 01:35:02.966 INFO [",
            b"\xff\xfe",
        ] {
            run(&TOMCAT, "var/log/tomcat10/catalina.out", data, 0);
        }
    }
}
