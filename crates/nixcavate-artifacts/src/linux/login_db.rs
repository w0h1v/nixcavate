//! The SQLite login records that replace `wtmp` and `lastlog` on newer distributions
//! (Debian 13, openSUSE Tumbleweed): wtmpdb and lastlog2. Schemas from the wtmpdb source
//! (`lib/sqlite.c`: table `wtmp`, times in microseconds) and from util-linux liblastlog2
//! (table `Lastlog2`, time in seconds).

use crate::sqlite::{int_at, open_with_tables, sql_error, text_at};
use crate::{Artifact, Category, Input, LINUX};
use nixcavate_core::{Basis, Event, Loc, Record, Result, Sink, Timestamp};
use serde::Serialize;

pub const WTMPDB: Artifact = Artifact::new(
    "wtmpdb",
    "Logins, logouts and boots (wtmpdb)",
    Category::Accounts,
    LINUX,
    &["var/lib/wtmpdb/wtmp.db", "var/log/wtmp.db"],
    parse_wtmpdb,
)
.companions(&["var/lib/wtmpdb/wtmp.db-wal", "var/log/wtmp.db-wal"]);

pub const LASTLOG2: Artifact = Artifact::new(
    "lastlog2",
    "Last login per user (lastlog2)",
    Category::Accounts,
    LINUX,
    &["var/lib/lastlog/lastlog2.db"],
    parse_lastlog2,
)
.companions(&["var/lib/lastlog/lastlog2.db-wal"]);

#[derive(Serialize)]
struct Session {
    time: Option<Timestamp>,
    /// None while the session is open, and for a boot with no recorded shutdown.
    logout_time: Option<Timestamp>,
    #[serde(rename = "type")]
    kind: &'static str,
    user: String,
    line: String,
    remote_host: String,
    service: String,
}

impl Record for Session {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let from = if self.remote_host.is_empty() { "local" } else { &self.remote_host };
        let (start, end) = match self.kind {
            "boot_time" => (("boot", "system boot".to_string()), ("shutdown", "system shutdown".to_string())),
            "user_process" => (
                ("login", format!("{} logged in on {} from {from}", self.user, self.line)),
                ("logout", format!("session of {} ended on {}", self.user, self.line)),
            ),
            _ => return None.into_iter().chain(None),
        };
        let start = self.time.map(|time| Event::new(time, start.0, start.1));
        let end = self.logout_time.map(|time| Event::new(time, end.0, end.1));
        start.into_iter().chain(end)
    }
}

fn micros(value: Option<i64>) -> Option<Timestamp> {
    value.filter(|&v| v != 0).map(|v| Timestamp::from_micros(v, Basis::Recorded))
}

fn parse_wtmpdb(input: &Input, sink: &mut Sink) -> Result<()> {
    let db = open_with_tables(input, &["wtmp"])?;
    let sql = "SELECT Type, User, Login, Logout, TTY, RemoteHost, Service FROM wtmp ORDER BY ID";
    let mut statement = db.conn.prepare(sql).map_err(sql_error)?;
    let mut rows = statement.query([]).map_err(sql_error)?;
    while let Some(row) = rows.next().map_err(sql_error)? {
        let text = |at: usize| text_at(row, at).unwrap_or_default();
        let kind = match int_at(row, 0) {
            Some(1) => "boot_time",
            Some(2) => "run_level",
            Some(3) => "user_process",
            _ => "unknown",
        };
        let session = Session {
            time: micros(int_at(row, 2)),
            logout_time: micros(int_at(row, 3)),
            kind,
            user: text(1),
            line: text(4),
            remote_host: text(5),
            service: text(6),
        };
        sink.emit(Loc::None, &session)?;
    }
    Ok(())
}

#[derive(Serialize)]
struct LastLogin {
    user: String,
    time: Option<Timestamp>,
    line: String,
    remote_host: String,
    service: String,
}

impl Record for LastLogin {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let from = if self.remote_host.is_empty() { "local" } else { &self.remote_host };
        let message = format!("{} last logged in on {} from {from}", self.user, self.line);
        self.time.map(|time| Event::new(time, "last_login", message)).into_iter()
    }
}

fn parse_lastlog2(input: &Input, sink: &mut Sink) -> Result<()> {
    let db = open_with_tables(input, &["Lastlog2"])?;
    let sql = "SELECT Name, Time, TTY, RemoteHost, Service FROM Lastlog2 ORDER BY Name";
    let mut statement = db.conn.prepare(sql).map_err(sql_error)?;
    let mut rows = statement.query([]).map_err(sql_error)?;
    while let Some(row) = rows.next().map_err(sql_error)? {
        let text = |at: usize| text_at(row, at).unwrap_or_default();
        let time = int_at(row, 1).filter(|&secs| secs != 0).map(|secs| Timestamp::from_secs(secs, Basis::Recorded));
        sink.emit(
            Loc::None,
            &LastLogin { user: text(0), time, line: text(2), remote_host: text(3), service: text(4) },
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sqlite::database_bytes;
    use crate::testing::run;

    const WTMP: &str = "CREATE TABLE wtmp(ID INTEGER PRIMARY KEY, Type INTEGER, User TEXT NOT NULL, Login INTEGER, \
        Logout INTEGER, TTY TEXT, RemoteHost TEXT, Service TEXT) STRICT;
        INSERT INTO wtmp VALUES (1, 1, 'reboot', 1710032400000000, NULL, '~', '6.12.0', NULL);
        INSERT INTO wtmp VALUES (2, 3, 'alice', 1710032523000001, 1710036123500000, 'pts/0', '203.0.113.9', 'sshd');
        INSERT INTO wtmp VALUES (3, 3, 'root', 1710040000000000, NULL, 'tty1', NULL, 'login');";

    #[test]
    fn wtmpdb_sessions_give_a_login_and_a_logout() {
        let out = run(&WTMPDB, "var/lib/wtmpdb/wtmp.db", &database_bytes(WTMP), 0);
        assert_eq!(out.lines().filter(|l| l.starts_with('{')).count(), 3, "{out}");
        let alice = r#""time":"2024-03-10T01:02:03.000001Z","logout_time":"2024-03-10T02:02:03.500000Z","type":"user_process","user":"alice","line":"pts/0","remote_host":"203.0.113.9","service":"sshd""#;
        assert!(out.contains(alice), "{out}");
        assert!(out.contains(",login,alice logged in on pts/0 from 203.0.113.9,"), "{out}");
        assert!(out.contains(",logout,session of alice ended on pts/0,"), "{out}");
        assert!(out.contains(",boot,system boot,") && out.contains("root logged in on tty1 from local"), "{out}");
        assert_eq!(out.matches(",logout,").count(), 1, "an open session has no logout: {out}");
    }

    #[test]
    fn lastlog2_lists_each_user_once() {
        let sql =
            "CREATE TABLE Lastlog2 (Name TEXT PRIMARY KEY, Time INTEGER, TTY TEXT, RemoteHost TEXT, Service TEXT);
            INSERT INTO Lastlog2 VALUES ('alice', 1710032523, 'pts/0', '203.0.113.9', 'sshd');
            INSERT INTO Lastlog2 VALUES ('bob', 0, NULL, NULL, NULL);";
        let out = run(&LASTLOG2, "var/lib/lastlog/lastlog2.db", &database_bytes(sql), 0);
        let alice = r#""user":"alice","time":"2024-03-10T01:02:03Z","line":"pts/0","remote_host":"203.0.113.9","service":"sshd""#;
        assert!(out.contains(alice) && out.contains(r#""user":"bob","time":null"#), "{out}");
        assert_eq!(out.matches(",last_login,").count(), 1, "{out}");
    }

    #[test]
    fn other_databases_and_files_are_skipped() {
        let other = database_bytes("CREATE TABLE t(x);");
        assert!(run(&WTMPDB, "var/log/wtmp.db", &other, 0).contains("skipped"));
        assert!(run(&LASTLOG2, "var/lib/lastlog/lastlog2.db", &other, 0).contains("skipped"));
        assert!(!run(&WTMPDB, "var/log/wtmp.db", b"not a database", 0).contains("panicked"));
    }
}
