//! FreeBSD, OpenBSD and NetBSD artifacts: login databases, package databases, boot and service
//! configuration. Formats shared with Linux (syslog, passwd, cron, sudoers) are read by the
//! `common` and `linux` artifacts, which list the BSD paths too.

pub mod boot;
pub mod devd;
pub mod doas;
pub mod jail;
pub mod login_conf;
pub mod master_passwd;
pub mod pkg_db;
pub mod pkg_log;
pub mod pkgsrc;
pub mod rc;
pub mod userlog;
pub mod utmp;
pub mod utx;

use crate::Artifact;

pub static ARTIFACTS: &[Artifact] = &[
    utx::ARTIFACT,
    utmp::UTMP,
    utmp::LASTLOG,
    utmp::UTMPX,
    master_passwd::ARTIFACT,
    doas::ARTIFACT,
    rc::RC_CONF,
    rc::RC_D,
    rc::RC_LOCAL,
    rc::AT_JOBS,
    boot::LOADER_CONF,
    boot::TTYS,
    devd::ARTIFACT,
    jail::ARTIFACT,
    login_conf::ARTIFACT,
    userlog::ARTIFACT,
    pkg_db::PKG_DB,
    pkg_db::OPENBSD_PKG_DB,
    pkgsrc::PKGSRC_DB,
    pkgsrc::PKGIN,
    pkg_log::ARTIFACT,
];

/// One shell-style `name=value` assignment, as `rc.conf` and `loader.conf` write them. The
/// value is unquoted but not unescaped; text after the closing quote (a comment) is dropped.
/// `name+=value` is accepted. Returns `None` for comments, blank lines and anything else.
pub(crate) fn assignment(line: &str) -> Option<(&str, &str)> {
    let line = line.trim();
    let line = line.strip_prefix("export ").map_or(line, str::trim_start);
    if line.starts_with('#') {
        return None;
    }
    let (name, value) = line.split_once('=')?;
    let name = name.strip_suffix('+').unwrap_or(name);
    if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-')) {
        return None;
    }
    let value = match value.chars().next() {
        Some(quote @ ('"' | '\'')) => {
            let rest = &value[1..];
            rest.find(quote).map_or(rest, |end| &rest[..end])
        }
        _ => value.split(['#', ' ', '\t']).next().unwrap_or_default(),
    };
    Some((name, value))
}

/// True for the spellings rc.subr treats as "on" (`checkyesno`).
pub(crate) fn yes(value: &str) -> bool {
    ["yes", "true", "on", "1"].iter().any(|y| value.eq_ignore_ascii_case(y))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assignments_are_unquoted() {
        assert_eq!(assignment("sshd_enable=\"YES\" # note"), Some(("sshd_enable", "YES")));
        assert_eq!(assignment("  hostname='web 1'"), Some(("hostname", "web 1")));
        assert_eq!(assignment("zfs_enable=YES"), Some(("zfs_enable", "YES")));
        assert_eq!(assignment("kld_list+=\"a b\""), Some(("kld_list", "a b")));
        assert_eq!(assignment("# nothing=1"), None);
        assert_eq!(assignment("not an assignment"), None);
        assert!(yes("YES") && yes("on") && !yes("NO"));
    }
}
