//! yum's own state on RHEL/CentOS 6 and 7, Oracle Linux 7 and Amazon Linux 1: the transaction
//! history (`/var/lib/yum/history/history-*.sqlite`: who ran which command, when, and which
//! packages it changed) and the per-package database `yumdb` (`/var/lib/yum/yumdb/<letter>/
//! <checksum>-<name>-<version>-<release>-<arch>/<attribute>`, one tiny file per attribute:
//! why and from where a package was installed). Schemas from yum's `yum/history.py`, checked
//! against CentOS 7 and Amazon Linux 1 databases.
//!
//! The history database is in rollback-journal mode: a `-journal` file next to it holds
//! an unfinished write, and is not applied.

use crate::sqlite::{int_at, open_with_tables, sql_error, text_at};
use crate::{Artifact, Category, Input, LINUX};
use nixcavate_core::{Basis, Error, Event, Loc, Precision, Record, Result, Sink, Timestamp};
use nixcavate_source::Pattern;
use serde::Serialize;

pub const HISTORY: Artifact = Artifact::new(
    "yum-history",
    "yum transaction history",
    Category::Software,
    LINUX,
    &["var/lib/yum/history/history-*.sqlite"],
    parse_history,
)
.companions(&["var/lib/yum/history/history-*.sqlite-wal", "etc/passwd"]);

/// One task for the whole yumdb: a task per package attribute file would be thousands. The
/// `uuid` file yum creates on its first run stands in for the directory, and the parser walks
/// the packages itself.
pub const YUMDB: Artifact = Artifact::new(
    "yumdb",
    "yum per-package install records (yumdb)",
    Category::Software,
    LINUX,
    &["var/lib/yum/uuid"],
    parse_yumdb,
);

// ---- yum-history ----

#[derive(Serialize)]
struct Change {
    time: Option<Timestamp>,
    end_time: Option<Timestamp>,
    transaction_id: i64,
    /// The login uid of the session that ran yum; empty when it had none (a daemon, a boot script).
    login_uid: Option<u32>,
    /// The account name of `login_uid` in the host's `/etc/passwd`; empty when there is no uid or no such account.
    login_user: String,
    /// 0 for success; empty for a transaction with no end record (interrupted).
    return_code: Option<i64>,
    command: String,
    /// yum's state word, lower case: `install`, `dep-install`, `true-install`, `update`,
    /// `updated` (the old version replaced), `erase`, `obsoleting`, `obsoleted`, `downgrade`,
    /// `downgraded`, `reinstall`, `reinstalled`. Empty for a transaction that changed nothing.
    action: String,
    /// False when the package change was recorded but yum did not finish it.
    completed: Option<bool>,
    package: String,
    epoch: String,
    version: String,
    release: String,
    architecture: String,
}

impl Record for Change {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let nevra = format!("{}-{}-{}.{}", self.package, self.version, self.release, self.architecture);
        let (kind, message) = match self.action.as_str() {
            "install" | "dep-install" | "true-install" => {
                ("package_installed", format!("{} {nevra} ({})", self.action, self.command))
            }
            "update" => ("package_upgraded", format!("update {nevra} ({})", self.command)),
            "erase" => ("package_removed", format!("erase {nevra} ({})", self.command)),
            "downgrade" | "reinstall" | "obsoleting" => {
                ("package_changed", format!("{} {nevra} ({})", self.action, self.command))
            }
            // The old side of an update, downgrade or obsolete: the new package has the event.
            "" => ("package_command", format!("yum {}", self.command)),
            _ => return None.into_iter(),
        };
        self.time.map(|time| Event::new(time, kind, message)).into_iter()
    }
}

fn time_at(row: &rusqlite::Row, i: usize) -> Option<Timestamp> {
    Timestamp::checked(int_at(row, i)?, 0, Precision::Seconds, Basis::Recorded)
}

fn parse_history(input: &Input, sink: &mut Sink) -> Result<()> {
    let db = open_with_tables(input, &["trans_beg", "pkgtups", "trans_data_pkgs"])?;
    // `trans_end` and `trans_cmdline` can be missing for a transaction: left joins keep it.
    let mut statement = db
        .conn
        .prepare(
            "SELECT b.tid, b.timestamp, e.timestamp, b.loginuid, e.return_code, c.cmdline, \
                    d.state, d.done, p.name, p.epoch, p.version, p.release, p.arch \
             FROM trans_beg b LEFT JOIN trans_end e ON e.tid = b.tid \
             LEFT JOIN trans_cmdline c ON c.tid = b.tid \
             LEFT JOIN trans_data_pkgs d ON d.tid = b.tid \
             LEFT JOIN pkgtups p ON p.pkgtupid = d.pkgtupid ORDER BY b.tid, d.pkgtupid, d.state",
        )
        .map_err(sql_error)?;
    // uid -> name from the host's passwd; the first entry for a uid wins, as in getpwuid.
    let mut users = std::collections::HashMap::new();
    for line in input.host.read_text("etc/passwd").unwrap_or_default().lines() {
        let mut fields = line.split(':');
        if let (Some(name), Some(_), Some(uid)) = (fields.next(), fields.next(), fields.next()) {
            if let Ok(uid) = uid.parse::<u32>() {
                users.entry(uid).or_insert_with(|| name.to_string());
            }
        }
    }
    let mut rows = statement.query([]).map_err(sql_error)?;
    while let Some(row) = rows.next().map_err(sql_error)? {
        let text = |i| text_at(row, i).unwrap_or_default();
        let package = text(8);
        // 4294967295 is (uid_t)-1: no login session.
        let login_uid = int_at(row, 3).and_then(|uid| u32::try_from(uid).ok()).filter(|uid| *uid != u32::MAX);
        let change = Change {
            time: time_at(row, 1),
            end_time: time_at(row, 2),
            transaction_id: int_at(row, 0).unwrap_or(0),
            login_uid,
            login_user: login_uid.and_then(|uid| users.get(&uid).cloned()).unwrap_or_default(),
            return_code: int_at(row, 4),
            command: text(5),
            action: if package.is_empty() { String::new() } else { text(6).to_ascii_lowercase() },
            completed: text_at(row, 7).map(|done| done.eq_ignore_ascii_case("true") || done == "1"),
            package,
            epoch: text(9),
            version: text(10),
            release: text(11),
            architecture: text(12),
        };
        sink.emit(Loc::None, &change)?;
    }
    Ok(())
}

// ---- yumdb ----

#[derive(Serialize, Default)]
struct YumdbPackage {
    /// The oldest attribute file's modification time: when yum wrote the entry, normally the
    /// install. File metadata, not something yum records.
    time: Option<Timestamp>,
    package: String,
    version: String,
    release: String,
    architecture: String,
    /// `user` (asked for) or `dep` (pulled in), as yum records it.
    reason: String,
    from_repo: String,
    /// The uid that installed it; empty when it had no login session.
    installed_by: Option<u32>,
    changed_by: Option<u32>,
    /// The yum command line, when yum recorded it.
    command_line: String,
    releasever: String,
    origin_url: String,
    /// The package checksum that prefixes the directory name.
    checksum: String,
    /// The attributes, by file name, that were not given a column of their own.
    other_attributes: usize,
}

impl Record for YumdbPackage {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let by = if self.command_line.is_empty() { String::new() } else { format!(" ({})", self.command_line) };
        let message = format!("installed {}-{}-{}.{}{by}", self.package, self.version, self.release, self.architecture);
        self.time.map(|time| Event::new(time, "package_installed", message)).into_iter()
    }
}

/// `<checksum>-<name>-<version>-<release>-<arch>`: the checksum has no `-`, the name may.
fn split_dir(dir: &str) -> Option<(&str, &str, &str, &str, &str)> {
    let (checksum, rest) = dir.split_once('-')?;
    let (rest, arch) = rest.rsplit_once('-')?;
    let (rest, release) = rest.rsplit_once('-')?;
    let (name, version) = rest.rsplit_once('-')?;
    Some((checksum, name, version, release, arch))
}

/// Attribute files are a few bytes to a URL; a longer one is not an attribute.
const MAX_ATTRIBUTE: u64 = 4 << 10;

fn parse_yumdb(input: &Input, sink: &mut Sink) -> Result<()> {
    let attributes = Pattern::new("var/lib/yum/yumdb/*/*/*");
    let mut current: Option<(String, YumdbPackage)> = None;
    let mut found = false;
    let flush = |sink: &mut Sink, current: &mut Option<(String, YumdbPackage)>| -> Result<()> {
        match current.take() {
            Some((_, package)) => sink.emit(Loc::None, &package),
            None => Ok(()),
        }
    };
    for entry in input.host.find(&attributes).filter(|e| e.link.is_none()) {
        let path = input.host.rel(entry);
        let Some((dir, attribute)) = path.rsplit_once('/') else { continue };
        found = true;
        if current.as_ref().is_none_or(|(open, _)| open != dir) {
            flush(sink, &mut current)?;
            let name = dir.rsplit('/').next().unwrap_or(dir);
            let Some((checksum, package, version, release, architecture)) = split_dir(name) else {
                sink.warn(format!("{dir}: directory name is not checksum-name-version-release-arch"));
                continue;
            };
            let record = YumdbPackage {
                checksum: checksum.to_string(),
                package: package.to_string(),
                version: version.to_string(),
                release: release.to_string(),
                architecture: architecture.to_string(),
                ..YumdbPackage::default()
            };
            current = Some((dir.to_string(), record));
        }
        let Some((_, package)) = current.as_mut().filter(|(open, _)| open == dir) else { continue };
        if entry.mtime > 0 {
            let seen = Timestamp::checked(entry.mtime, 0, Precision::Seconds, Basis::Recorded);
            package.time = match (package.time, seen) {
                (Some(old), Some(new)) if old.utc <= new.utc => Some(old),
                (_, new) => new,
            };
        }
        let value = || -> String {
            if entry.size > MAX_ATTRIBUTE {
                return String::new();
            }
            let data = input.host.open(entry).map(|d| String::from_utf8_lossy(&d).trim().to_string());
            data.unwrap_or_default()
        };
        let uid = |text: String| text.parse::<u32>().ok().filter(|uid| *uid != u32::MAX);
        match attribute {
            "reason" => package.reason = value(),
            "from_repo" => package.from_repo = value(),
            "installed_by" => package.installed_by = uid(value()),
            "changed_by" => package.changed_by = uid(value()),
            "command_line" => package.command_line = value(),
            "releasever" => package.releasever = value(),
            "origin_url" => package.origin_url = value(),
            _ => package.other_attributes += 1,
        }
    }
    flush(sink, &mut current)?;
    if !found {
        return Err(Error::skipped("no packages under var/lib/yum/yumdb"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run, run_on_host};

    #[test]
    fn parses_a_real_history() {
        insta::assert_snapshot!(run(
            &HISTORY,
            "var/lib/yum/history/history-2020-11-13.sqlite",
            &fixture("yum-history/history-2020-11-13.sqlite"),
            0
        ));
    }

    #[test]
    fn names_the_login_user_from_passwd() {
        let path = "var/lib/yum/history/history-2020-11-13.sqlite";
        let db = fixture("yum-history/history-2020-11-13.sqlite");
        // The fixture's transactions have no login uid; give them uid 1000.
        let tmp = std::env::temp_dir().join(format!("nixcavate-yum-uid-{}.sqlite", std::process::id()));
        std::fs::write(&tmp, &db).unwrap();
        let conn = rusqlite::Connection::open(&tmp).unwrap();
        conn.execute("UPDATE trans_beg SET loginuid = 1000", []).unwrap();
        drop(conn);
        let changed = std::fs::read(&tmp).unwrap();
        let _ = std::fs::remove_file(&tmp);
        let passwd: &[u8] =
            b"root:x:0:0::/root:/bin/sh\nalice:x:1000:1000::/home/alice:/bin/sh\nalias:x:1000:1000::/x:/bin/sh\n";
        let out = run_on_host(&HISTORY, &[(path, &changed), ("etc/passwd", passwd)], path, 0);
        assert!(out.contains("\"login_uid\":1000,\"login_user\":\"alice\""), "{out}");
        let out = run(&HISTORY, path, &changed, 0);
        assert!(out.contains("\"login_uid\":1000,\"login_user\":\"\""), "{out}");
    }

    #[test]
    fn rejects_other_files() {
        let path = "var/lib/yum/history/history-2020-11-13.sqlite";
        assert!(run(&HISTORY, path, b"text", 0).contains("skipped: not an SQLite database"));
        let other = fixture("dnf-history/history.sqlite");
        assert!(run(&HISTORY, path, &other, 0).contains("skipped: no trans_beg table"));
    }

    #[test]
    fn splits_yumdb_directory_names() {
        assert_eq!(split_dir("81ff-tree-1.6.0-10.el7-aarch64"), Some(("81ff", "tree", "1.6.0", "10.el7", "aarch64")));
        assert_eq!(split_dir("ab-foo-bar-2-1-noarch"), Some(("ab", "foo-bar", "2", "1", "noarch")));
        assert_eq!(split_dir("nohyphens"), None);
        assert_eq!(split_dir("a-b-c"), None);
    }

    const DIRS: [&str; 2] = [
        "n/b4a8577b1e26738e571f0796bf4c1ddb726382dd-nano-2.3.1-10.el7-x86_64",
        "t/a09f99f73ee3fe352489e734c63c32fa41b1be56-tree-1.6.0-10.el7-x86_64",
    ];
    const ATTRIBUTES: [&str; 8] = [
        "command_line",
        "from_repo",
        "installed_by",
        "origin_url",
        "reason",
        "releasever",
        "checksum_type",
        "var_uuid",
    ];

    fn yumdb() -> Vec<(String, Vec<u8>)> {
        let mut files = vec![("var/lib/yum/uuid".to_string(), b"51e5fa0e-6da6-4d11-abd2-6ca7c8999389".to_vec())];
        for dir in DIRS {
            for attribute in ATTRIBUTES {
                files.push((
                    format!("var/lib/yum/yumdb/{dir}/{attribute}"),
                    fixture(&format!("yumdb/{dir}/{attribute}")),
                ));
            }
        }
        files
    }

    #[test]
    fn reads_the_yumdb_through_one_file() {
        let files = yumdb();
        let refs: Vec<(&str, &[u8])> = files.iter().map(|(p, d)| (p.as_str(), d.as_slice())).collect();
        insta::assert_snapshot!(run_on_host(&YUMDB, &refs, "var/lib/yum/uuid", 0));
    }

    #[test]
    fn a_yumdb_with_no_packages_is_skipped() {
        let out = run(&YUMDB, "var/lib/yum/uuid", b"abc", 0);
        assert!(out.contains("skipped: no packages under var/lib/yum/yumdb"), "{out}");
    }

    #[test]
    fn a_badly_named_directory_is_a_warning() {
        let mut files = yumdb();
        files.push(("var/lib/yum/yumdb/x/oddname/reason".to_string(), b"user".to_vec()));
        let refs: Vec<(&str, &[u8])> = files.iter().map(|(p, d)| (p.as_str(), d.as_slice())).collect();
        let out = run_on_host(&YUMDB, &refs, "var/lib/yum/uuid", 0);
        assert_eq!(out.matches("\"package\":").count(), 2, "{out}");
        assert!(out.contains("directory name is not checksum-name-version-release-arch"), "{out}");
    }

    #[test]
    fn mutated_histories_never_panic() {
        let db = fixture("yum-history/history-2020-11-13.sqlite");
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let path = "var/lib/yum/history/history-2020-11-13.sqlite";
        for _ in 0..150 {
            let mut copy = db.clone();
            for _ in 0..1 + next() % 6 {
                let at = (next() as usize) % copy.len();
                copy[at] = next() as u8;
            }
            let _ = run(&HISTORY, path, &copy, 0);
        }
        for len in (0..db.len()).step_by(4096) {
            let _ = run(&HISTORY, path, &db[..len], 0);
        }
    }
}
