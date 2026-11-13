//! IBM AIX artifacts. There was no AIX system to test against: each module's comment says what
//! its format rests on, and docs/LIMITATIONS.md lists what is synthetic only.

pub mod audit_stream;
pub mod clock;
pub mod cron_log;
pub mod errpt;
pub mod history;
pub mod live;
pub mod lslpp;
pub mod persistence;
pub mod security;
pub mod stanza;
pub mod sulog;
pub mod utmp;

use crate::Artifact;

pub static ARTIFACTS: &[Artifact] = &[
    utmp::WTMP,
    utmp::UTMP,
    utmp::FAILEDLOGIN,
    security::LASTLOG,
    security::PASSWD,
    security::USER,
    security::GROUP,
    security::CONFIG,
    sulog::ARTIFACT,
    cron_log::ARTIFACT,
    persistence::INITTAB,
    persistence::RC_SCRIPTS,
    persistence::INETD,
    persistence::TRUST,
    persistence::AT_JOBS,
    history::SH_HISTORY,
    history::SMIT,
    history::ALOG,
    audit_stream::ARTIFACT,
    errpt::ARTIFACT,
    lslpp::ARTIFACT,
    lslpp::RPM_DB,
    live::NETWORK,
    live::RMSOCK,
    live::SRC,
    live::KERNEL_EXTENSIONS,
];

/// The user a file in a home directory belongs to. AIX's `root` home is `/`, so a file with no
/// directory (`.rhosts`, `.sh_history`, `smit.script`) is root's.
pub(crate) fn home_user(path: &str) -> &str {
    let path = path.trim_start_matches('/');
    for prefix in ["home/", "usr/home/"] {
        if let Some((user, _)) = path.strip_prefix(prefix).and_then(|rest| rest.split_once('/')) {
            return user;
        }
    }
    if !path.contains('/') || path.starts_with("root/") {
        "root"
    } else {
        ""
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::run;
    use crate::{find, AIX};
    use nixcavate_source::glob::Pattern;
    use nixcavate_source::Os;

    #[test]
    fn every_aix_artifact_is_for_aix_only_and_prefixed() {
        for artifact in ARTIFACTS {
            assert_eq!(artifact.os, AIX, "{}", artifact.id);
            assert!(artifact.id.starts_with("aix-"), "{}", artifact.id);
        }
    }

    /// The shared artifacts read AIX's files because AIX is in their OS set and its paths are in
    /// their lists; the Linux-only ones do not run on an AIX host.
    #[test]
    fn shared_artifacts_cover_aix() {
        let covers = |id: &str, path: &str| {
            let artifact = find(id).unwrap();
            artifact.os.contains(&Os::Aix) && artifact.paths.iter().any(|p| Pattern::new(p).matches(path))
        };
        assert!(covers("passwd", "etc/passwd") && covers("group", "etc/group"));
        assert!(covers("syslog", "var/adm/messages") && covers("syslog", "var/adm/messages.1.gz"));
        assert!(covers("cron", "var/spool/cron/crontabs/root"));
        assert!(!find("at-jobs").unwrap().os.contains(&Os::Aix));
        assert!(covers("shell-profiles", ".profile") && covers("shell-profiles", "etc/environment"));
        assert!(covers("shell-profiles", "home/alice/.kshrc"));
        assert!(
            covers("authorized-keys", ".ssh/authorized_keys")
                && covers("authorized-keys", "home/a/.ssh/authorized_keys")
        );
        assert!(covers("live-processes", "live_response/process/ps_-ef.txt"));
        assert!(!find("wtmp").unwrap().os.contains(&Os::Aix));
    }

    #[test]
    fn aix_style_syslog_and_account_lines_parse() {
        let log = b"Mar 10 01:02:03 aixhost sshd[123456]: Failed password for invalid user admin from 198.51.100.4 port 4444 ssh2\nMar 10 01:02:04 aixhost syslogd: restart\n";
        let out = run(find("syslog").unwrap(), "var/adm/messages", log, 1_710_115_200);
        assert!(out.contains(r#""program":"sshd","pid":123456"#) && !out.contains("warning"), "{out}");
        let out = run(
            find("passwd").unwrap(),
            "etc/passwd",
            b"root:!:0:0::/:/usr/bin/ksh\nguest:*:100:100::/home/guest:/usr/bin/ksh\n",
            0,
        );
        assert_eq!(out.matches("\"user\"").count(), 2, "{out}");
    }

    #[test]
    fn home_users() {
        assert_eq!(home_user(".rhosts"), "root");
        assert_eq!(home_user("root/.rhosts"), "root");
        assert_eq!(home_user("home/alice/.sh_history"), "alice");
        assert_eq!(home_user("usr/home/bob/smit.log"), "bob");
        assert_eq!(home_user("etc/hosts.equiv"), "");
    }
}
