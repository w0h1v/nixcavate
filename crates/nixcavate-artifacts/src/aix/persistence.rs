//! AIX start-up and trust configuration read as records: `etc/inittab`, the `rc` scripts,
//! `etc/inetd.conf`, and the remote-trust files (`.rhosts`, `etc/hosts.equiv`).
//!
//! Sources, all System V relatives of AIX's own files (IBM's pages were not reachable): the
//! illumos manual pages `inittab(5)` (`id:rstate:action:process`; actions `respawn`, `wait`,
//! `once`, `boot`, `bootwait`, `sysinit`, `initdefault`, `off`...), `inetd.conf(5)` (`service-name
//! endpoint-type protocol wait-status uid server-program server-arguments`) and `hosts.equiv(5)`
//! (one `[+|-]host [user]` per line, `+@netgroup`, a bare `+` trusts everyone). AIX's comment
//! markers in `inittab` (`:` and `#`) are as remembered. **No real AIX file was available**:
//! synthetic only, and no list of AIX's stock `inittab` entries is built in.

use super::home_user;
use crate::common::script;
use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, AIX};
use nixcavate_core::{Basis, Event, Timestamp};
use nixcavate_core::{Loc, Record, Result, Sink};
use serde::Serialize;

pub const INITTAB: Artifact =
    Artifact::new("aix-inittab", "AIX init table entries", Category::Persistence, AIX, &["etc/inittab"], parse_inittab);
pub const RC_SCRIPTS: Artifact = Artifact::new(
    "aix-rc-scripts",
    "AIX boot scripts (rc, rc.local, rc.tcpip, rc.nfs, rc.d)",
    Category::Persistence,
    AIX,
    &[
        "etc/rc",
        "etc/rc.local",
        "etc/rc.tcpip",
        "etc/rc.nfs",
        "etc/rc.net",
        "etc/rc.d/rc",
        "etc/rc.d/rc2.d/*",
        "etc/rc.d/init.d/*",
    ],
    script::content_lines,
);
pub const INETD: Artifact =
    Artifact::new("aix-inetd-conf", "AIX inetd services", Category::Persistence, AIX, &["etc/inetd.conf"], parse_inetd);
pub const TRUST: Artifact = Artifact::new(
    "aix-rhosts",
    "AIX remote-trust files (.rhosts, hosts.equiv)",
    Category::Security,
    AIX,
    &["etc/hosts.equiv", ".rhosts", "home/*/.rhosts", "root/.rhosts", "usr/home/*/.rhosts"],
    parse_trust,
);

/// AIX names a queued job `<epoch seconds>.<queue letter>` (as remembered; **no real file was
/// available**, and the Linux `at-jobs` parser's `a0000101c858d6` names and headers do not apply).
/// The record has the file's metadata and the last lines of the script, where `at` puts the
/// command after the saved environment; that position is an assumption.
pub const AT_JOBS: Artifact = Artifact::new(
    "aix-at-jobs",
    "AIX jobs queued with at(1)",
    Category::Persistence,
    AIX,
    &["var/spool/cron/atjobs/*"],
    parse_at,
);

#[derive(Serialize)]
struct InitEntry<'a> {
    id: &'a str,
    runlevels: &'a str,
    action: &'a str,
    command: &'a str,
}

impl Record for InitEntry<'_> {}

fn parse_inittab(input: &Input, sink: &mut Sink) -> Result<()> {
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let text = text.trim();
        if text.is_empty() || text.starts_with('#') || text.starts_with(':') {
            return Ok(());
        }
        let mut fields = text.splitn(4, ':');
        let (Some(id), Some(runlevels), Some(action)) = (fields.next(), fields.next(), fields.next()) else {
            sink.warn(format!("line {}: expected id:runlevels:action:command", line.number));
            return Ok(());
        };
        sink.emit(
            Loc::Line(line.number),
            &InitEntry { id, runlevels, action, command: fields.next().unwrap_or("").trim() },
        )
    })
}

#[derive(Serialize)]
struct AtJob<'a> {
    queue: Option<&'a str>,
    /// When the job is due, from the file name; `None` when the name is not `<epoch>.<letter>`.
    due: Option<Timestamp>,
    uid: u32,
    lines: u64,
    /// The last (up to five) lines of the script that are not blank or comments, joined by `; `.
    command_tail: String,
}

impl Record for AtJob<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        self.due.map(|ts| Event::new(ts, "scheduled_job", format!("at job due: {}", self.command_tail))).into_iter()
    }
}

fn parse_at(input: &Input, sink: &mut Sink) -> Result<()> {
    let name = input.path.rsplit('/').next().unwrap_or_default();
    let decoded = name.split_once('.').and_then(|(epoch, queue)| {
        let secs: i64 = epoch.parse().ok().filter(|_| epoch.len() >= 9 && epoch.len() <= 11)?;
        (queue.len() == 1 && queue.bytes().all(|b| b.is_ascii_lowercase()))
            .then(|| (queue, Timestamp::from_secs(secs, Basis::Recorded)))
    });
    if decoded.is_none() {
        sink.warn(format!("{name}: not named <epoch>.<queue letter>; the due time is not known"));
    }
    let text = lossy(input.data);
    let body: Vec<&str> = text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')).collect();
    let tail = &body[body.len().saturating_sub(5)..];
    sink.emit(
        Loc::None,
        &AtJob {
            queue: decoded.map(|(queue, _)| queue),
            due: decoded.map(|(_, ts)| ts),
            uid: input.uid,
            lines: text.lines().count() as u64,
            command_tail: tail.join("; "),
        },
    )
}

#[derive(Serialize)]
struct Service<'a> {
    service: &'a str,
    socket_type: &'a str,
    protocol: &'a str,
    wait: &'a str,
    user: &'a str,
    program: &'a str,
    arguments: String,
}

impl Record for Service<'_> {}

fn parse_inetd(input: &Input, sink: &mut Sink) -> Result<()> {
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let text = text.trim();
        if text.is_empty() || text.starts_with('#') {
            return Ok(());
        }
        let words: Vec<&str> = text.split_whitespace().collect();
        let [service, socket_type, protocol, wait, user, program, rest @ ..] = &words[..] else {
            sink.warn(format!("line {}: expected at least six fields", line.number));
            return Ok(());
        };
        sink.emit(
            Loc::Line(line.number),
            &Service { service, socket_type, protocol, wait, user, program, arguments: rest.join(" ") },
        )
    })
}

#[derive(Serialize)]
struct Trust<'a> {
    /// `hosts.equiv` or `.rhosts`.
    file: &'a str,
    /// The owner of a `.rhosts`; empty for `hosts.equiv`.
    owner: &'a str,
    /// The host or `@netgroup` the entry names (`+` for every host).
    peer: &'a str,
    user: Option<&'a str>,
    /// A `-` entry denies; a `+` host or user is a wildcard that trusts everything.
    denied: bool,
    wildcard: bool,
}

impl Record for Trust<'_> {}

fn parse_trust(input: &Input, sink: &mut Sink) -> Result<()> {
    let file = input.path.rsplit('/').next().unwrap_or(input.path);
    let owner = if file == ".rhosts" { home_user(input.path) } else { "" };
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let text = text.split('#').next().unwrap_or_default().trim();
        let mut words = text.split_whitespace();
        let Some(peer) = words.next() else { return Ok(()) };
        let user = words.next();
        let denied = peer.starts_with('-');
        let wildcard = peer == "+" || user == Some("+");
        sink.emit(Loc::Line(line.number), &Trust { file, owner, peer, user, denied, wildcard })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::run;

    #[test]
    fn inittab_entries() {
        let data = b": a comment\ninit:2:initdefault:\nbrc::sysinit:/sbin/rc.boot 3 >/dev/console 2>&1 # Phase 3\nrc:2:wait:/etc/rc 2>&1 | alog -tboot > /dev/console\nbackdoor:2:respawn:/tmp/.x/sh -c 'a:b'\nshort:2\n";
        let out = run(&INITTAB, "etc/inittab", data, 0);
        assert!(
            out.contains(r#""id":"backdoor","runlevels":"2","action":"respawn","command":"/tmp/.x/sh -c 'a:b'""#),
            "{out}"
        );
        assert!(out.contains("expected id:runlevels:action:command"), "{out}");
        insta::assert_snapshot!(out);
    }

    #[test]
    fn at_jobs() {
        let data = b"#!/bin/ksh
# at job
HOME=/home/alice; export HOME
PATH=/usr/bin
cd /home/alice
/tmp/.x/agent --once
";
        let out = run(&AT_JOBS, "var/spool/cron/atjobs/1710032400.a", data, 0);
        assert!(
            out.contains(r#""queue":"a","due":"2024-03-10T01:00:00Z""#) && out.contains("/tmp/.x/agent --once"),
            "{out}"
        );
        let out = run(&AT_JOBS, "var/spool/cron/atjobs/.SEQ", b"0000a\n", 0);
        assert!(out.contains("not named <epoch>"), "{out}");
    }

    #[test]
    fn inetd_services() {
        let data = b"#ftp stream tcp6 nowait root /usr/sbin/ftpd ftpd\nshell stream tcp6 nowait root /usr/sbin/rshd rshd\nbind stream tcp nowait root /bin/ksh ksh -i\nbroken stream\n";
        let out = run(&INETD, "etc/inetd.conf", data, 0);
        assert!(out.contains(r#""program":"/bin/ksh","arguments":"ksh -i""#) && !out.contains("ftpd"), "{out}");
        assert!(out.contains("at least six fields"), "{out}");
    }

    #[test]
    fn trust_files() {
        let out = run(&TRUST, "home/alice/.rhosts", b"+ +\nhost1 bob # c\n-evil\n+@group\n", 0);
        assert_eq!(out.matches(r#""wildcard":true"#).count(), 1, "{out}");
        assert!(out.contains(r#""owner":"alice""#) && out.contains(r#""denied":true"#), "{out}");
        let out = run(&TRUST, ".rhosts", b"host2\n", 0);
        assert!(out.contains(r#""owner":"root""#), "{out}");
        insta::assert_snapshot!(run(&TRUST, "etc/hosts.equiv", b"peer1\npeer2 +\n", 0));
    }

    #[test]
    fn hostile() {
        for data in [&b""[..], b"\xff\xfe\0::::\n:\n::\n", &[b':'; 4000][..]] {
            for artifact in [&INITTAB, &INETD, &TRUST, &RC_SCRIPTS, &AT_JOBS] {
                let _ = run(artifact, "etc/inittab", data, 0);
            }
        }
    }
}
