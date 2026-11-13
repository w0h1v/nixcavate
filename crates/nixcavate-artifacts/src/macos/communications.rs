//! Communication metadata: Messages (`chat.db`), Mail's `Envelope Index` and `CallHistory.storedata`.
//!
//! Content policy, decided here and stated in docs/LIMITATIONS.md: like the Safari and shell
//! history artifacts, which output what the user typed, Messages records include the message
//! TEXT (an analyst needs it for social-engineering cases). It is one field, controlled by
//! [`INCLUDE_MESSAGE_TEXT`]; setting it to false drops the text and leaves the metadata. Mail
//! records have sender, subject, dates and mailbox but never a body. Call records have number,
//! direction, duration and kind. Contacts, notes and calendars are not read: personal content
//! with low incident-response value.
//!
//! `chat.db`: tables `message`, `handle`, `chat`, `chat_message_join`, `attachment`,
//! `message_attachment_join` (layout as in public Messages forensics write-ups). `date` is Mac
//! absolute time in nanoseconds since macOS 10.13 and in seconds before; values above 1e12 are
//! taken as nanoseconds. Newer systems keep rich text in `attributedBody`, which is not decoded:
//! `text` is empty for such messages. `Envelope Index`: `messages` joined to `subjects`,
//! `addresses` and `mailboxes`, dates as Unix seconds. `CallHistory.storedata`: Core Data table
//! `ZCALLRECORD` with Mac-time `ZDATE`.
//!
//! Synthetic only: no real database of these kinds was read. Doubts: Mail's schema changes with
//! the `V<n>` folder; `ZCALLTYPE` values (1 phone, 8 FaceTime video, 16 FaceTime audio) are from
//! public descriptions.

use super::plist_util::{mac_time, or_warn};
use super::tcc::select_columns;
use super::util::clip;
use crate::common::home::user_from_path;
use crate::sqlite::{int_at, open_with_tables, real_at, sql_error, text_at, unique_rows};
use crate::{Artifact, Category, Input, MACOS};
use nixcavate_core::{Basis, Event, Loc, Precision, Record, Result, Sink, Timestamp};
use serde::Serialize;
use std::collections::HashMap;

/// Whether message bodies are copied into records. See the module comment.
pub const INCLUDE_MESSAGE_TEXT: bool = true;

pub const MESSAGES: Artifact = Artifact::new(
    "messages",
    "Messages (iMessage and SMS) metadata and text",
    Category::Activity,
    MACOS,
    &["Users/*/Library/Messages/chat.db"],
    parse_messages,
)
.companions(&["Users/*/Library/Messages/chat.db-wal"]);

pub const MAIL: Artifact = Artifact::new(
    "mail-envelopes",
    "Mail message envelopes (sender, subject, dates, mailbox; no bodies)",
    Category::Activity,
    MACOS,
    &["Users/*/Library/Mail/V*/MailData/Envelope Index"],
    parse_mail,
)
.companions(&["Users/*/Library/Mail/V*/MailData/Envelope Index-wal"]);

pub const CALLS: Artifact = Artifact::new(
    "call-history",
    "Phone and FaceTime call history",
    Category::Activity,
    MACOS,
    &["Users/*/Library/Application Support/CallHistoryDB/CallHistory.storedata"],
    parse_calls,
)
.companions(&["Users/*/Library/Application Support/CallHistoryDB/CallHistory.storedata-wal"]);

const MAX_ATTACHMENTS: usize = 16;

fn q(alias: &str, column: &str) -> String {
    if column == "NULL" {
        column.to_string()
    } else {
        format!("{alias}.{column}")
    }
}

#[derive(Serialize)]
struct Message<'a> {
    user: &'a str,
    time: Option<Timestamp>,
    read_time: Option<Timestamp>,
    /// `sent` or `received`.
    direction: &'static str,
    handle: Option<String>,
    service: Option<String>,
    chat: Option<String>,
    has_attachments: bool,
    /// `name (state)` per attachment, at most 16.
    attachments: Vec<String>,
    text: Option<String>,
}

impl Record for Message<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let who = self.handle.as_deref().or(self.chat.as_deref()).unwrap_or("?");
        let message = if self.direction == "sent" {
            format!("message sent to {who}")
        } else {
            format!("message received from {who}")
        };
        self.time.map(|ts| Event::new(ts, "message", message)).into_iter()
    }
}

/// A `date` cell: Mac time in nanoseconds (macOS 10.13+) or in seconds. Zero means unset.
fn message_time(row: &rusqlite::Row, i: usize) -> Option<Timestamp> {
    use rusqlite::types::ValueRef;
    match row.get_ref(i).ok()? {
        ValueRef::Integer(0) => None,
        ValueRef::Integer(n) if n.unsigned_abs() >= 1_000_000_000_000 => {
            let secs = n.div_euclid(1_000_000_000).checked_add(978_307_200)?;
            Timestamp::checked(secs, n.rem_euclid(1_000_000_000) as u32, Precision::Nanos, Basis::Recorded)
        }
        ValueRef::Integer(n) => mac_time(n as f64),
        ValueRef::Real(f) if f != 0.0 => mac_time(f),
        _ => None,
    }
}

fn parse_messages(input: &Input, sink: &mut Sink) -> Result<()> {
    let db = open_with_tables(input, &["message"])?;
    let msg = select_columns(
        &db,
        "message",
        &["ROWID", "date", "date_read", "is_from_me", "service", "text", "cache_has_attachments", "handle_id"],
    )?;
    let user = user_from_path(input.path);

    // Attachments per message.
    let mut attachments: HashMap<i64, Vec<String>> = HashMap::new();
    if db.has_table("attachment") && db.has_table("message_attachment_join") {
        db.refuse_generated_columns(&["attachment", "message_attachment_join"])?;
        let att = select_columns(&db, "attachment", &["ROWID", "transfer_name", "filename", "transfer_state"])?;
        let sql = format!(
            "SELECT j.message_id, {}, {}, {} FROM message_attachment_join j JOIN attachment a ON a.ROWID = j.attachment_id",
            q("a", &att[1]),
            q("a", &att[2]),
            q("a", &att[3])
        );
        let mut stmt = db.conn.prepare(&sql).map_err(sql_error)?;
        let mut rows = stmt.query([]).map_err(sql_error)?;
        while let Some(row) = rows.next().map_err(sql_error)? {
            let Some(id) = int_at(row, 0) else { continue };
            let name = text_at(row, 1)
                .or_else(|| text_at(row, 2).map(|f| f.rsplit('/').next().unwrap_or_default().to_string()));
            let list = attachments.entry(id).or_default();
            if let (Some(name), true) = (name, list.len() < MAX_ATTACHMENTS) {
                list.push(match int_at(row, 3) {
                    Some(state) => format!("{} (state {state})", clip(&name, 256)),
                    None => clip(&name, 256),
                });
            }
        }
    }

    let has_handle = db.has_table("handle");
    let has_chat = db.has_table("chat") && db.has_table("chat_message_join");
    let handle = if has_handle { select_columns(&db, "handle", &["id"])?[0].clone() } else { "NULL".into() };
    let chat = if has_chat { select_columns(&db, "chat", &["chat_identifier"])?[0].clone() } else { "NULL".into() };
    let mut sql = format!(
        "SELECT {}, {}, {}, {}, {}, {}, {}, {}, {} FROM message m",
        q("m", &msg[0]),
        q("m", &msg[1]),
        q("m", &msg[2]),
        q("m", &msg[3]),
        q("m", &msg[4]),
        q("m", &msg[5]),
        q("m", &msg[6]),
        if has_handle { q("h", &handle) } else { "NULL".into() },
        if has_chat { q("c", &chat) } else { "NULL".into() },
    );
    if has_handle && msg[7] != "NULL" {
        sql.push_str(&format!(" LEFT JOIN {} h ON h.ROWID = m.handle_id", unique_rows("handle", "ROWID")));
    } else if has_handle {
        sql.push_str(" LEFT JOIN (SELECT NULL AS id, NULL AS ROWID) h ON 0");
    }
    if has_chat {
        sql.push_str(&format!(
            " LEFT JOIN {} cj ON cj.message_id = m.ROWID LEFT JOIN {} c ON c.ROWID = cj.chat_id",
            unique_rows("chat_message_join", "message_id"),
            unique_rows("chat", "ROWID")
        ));
    }
    sql.push_str(" ORDER BY m.date, m.rowid");
    let mut stmt = db.conn.prepare(&sql).map_err(sql_error)?;
    let mut rows = stmt.query([]).map_err(sql_error)?;
    while let Some(row) = rows.next().map_err(sql_error)? {
        let time = message_time(row, 1);
        if time.is_none() && real_at(row, 1).is_some_and(|v| v != 0.0) {
            sink.warn("a message date is not a valid time; left empty");
        }
        let read_time = message_time(row, 2);
        let id = int_at(row, 0);
        let text = text_at(row, 5).filter(|t| INCLUDE_MESSAGE_TEXT && !t.is_empty()).map(|t| clip(&t, 4096));
        sink.emit(
            Loc::None,
            &Message {
                user,
                time,
                read_time,
                direction: if int_at(row, 3) == Some(1) { "sent" } else { "received" },
                handle: text_at(row, 7),
                service: text_at(row, 4),
                chat: text_at(row, 8),
                has_attachments: int_at(row, 6).is_some_and(|n| n != 0)
                    || id.is_some_and(|i| attachments.contains_key(&i)),
                attachments: id.and_then(|i| attachments.get(&i)).cloned().unwrap_or_default(),
                text,
            },
        )?;
    }
    Ok(())
}

#[derive(Serialize)]
struct Envelope<'a> {
    user: &'a str,
    sent: Option<Timestamp>,
    received: Option<Timestamp>,
    sender: Option<String>,
    subject: Option<String>,
    mailbox: Option<String>,
    read: Option<bool>,
    message_id: Option<String>,
}

impl Record for Envelope<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let message =
            format!("mail from {}: {}", self.sender.as_deref().unwrap_or("?"), self.subject.as_deref().unwrap_or(""));
        self.received.or(self.sent).map(|ts| Event::new(ts, "mail", message)).into_iter()
    }
}

fn unix_time(raw: Option<f64>) -> Option<Timestamp> {
    let raw = raw.filter(|&t| t != 0.0)?;
    Timestamp::from_secs_f64(raw, Precision::Seconds, Basis::Recorded)
}

fn parse_mail(input: &Input, sink: &mut Sink) -> Result<()> {
    let db = open_with_tables(input, &["messages"])?;
    let m = select_columns(
        &db,
        "messages",
        &["ROWID", "message_id", "subject", "sender", "date_sent", "date_received", "mailbox", "read"],
    )?;
    let user = user_from_path(input.path);
    // `subject`, `sender` and `mailbox` are foreign keys on current systems and text on none we
    // know; the lookup tables, when present, resolve them.
    let (subjects, addresses, mailboxes) =
        (db.has_table("subjects"), db.has_table("addresses"), db.has_table("mailboxes"));
    let mut sql = format!(
        "SELECT {}, {}, {}, {}, {}, {}, {}, {} FROM messages m",
        q("m", &m[1]),
        if subjects { "s.subject".to_string() } else { q("m", &m[2]) },
        if addresses { "a.address".to_string() } else { q("m", &m[3]) },
        q("m", &m[4]),
        q("m", &m[5]),
        if mailboxes { "b.url".to_string() } else { q("m", &m[6]) },
        q("m", &m[7]),
        "NULL",
    );
    if subjects {
        sql.push_str(&format!(" LEFT JOIN {} s ON s.ROWID = m.subject", unique_rows("subjects", "ROWID")));
    }
    if addresses {
        sql.push_str(&format!(" LEFT JOIN {} a ON a.ROWID = m.sender", unique_rows("addresses", "ROWID")));
    }
    if mailboxes {
        sql.push_str(&format!(" LEFT JOIN {} b ON b.ROWID = m.mailbox", unique_rows("mailboxes", "ROWID")));
    }
    sql.push_str(" ORDER BY m.date_received, m.rowid");
    let mut stmt = db.conn.prepare(&sql).map_err(sql_error)?;
    let mut rows = stmt.query([]).map_err(sql_error)?;
    while let Some(row) = rows.next().map_err(sql_error)? {
        sink.emit(
            Loc::None,
            &Envelope {
                user,
                sent: unix_time(real_at(row, 3)),
                received: unix_time(real_at(row, 4)),
                sender: text_at(row, 2).map(|s| clip(&s, 512)),
                subject: text_at(row, 1).map(|s| clip(&s, 1024)),
                mailbox: text_at(row, 5).map(|s| clip(&s, 512)),
                read: int_at(row, 6).map(|n| n != 0),
                message_id: text_at(row, 0).map(|s| clip(&s, 512)),
            },
        )?;
    }
    Ok(())
}

#[derive(Serialize)]
struct Call<'a> {
    user: &'a str,
    time: Option<Timestamp>,
    /// `outgoing` or `incoming`.
    direction: &'static str,
    answered: Option<bool>,
    address: Option<String>,
    name: Option<String>,
    duration_secs: Option<f64>,
    /// `phone`, `facetime_video`, `facetime_audio` or the raw number.
    call_type: String,
}

impl Record for Call<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let message =
            format!("{} {} call with {}", self.direction, self.call_type, self.address.as_deref().unwrap_or("?"));
        self.time.map(|ts| Event::new(ts, "call", message)).into_iter()
    }
}

fn parse_calls(input: &Input, sink: &mut Sink) -> Result<()> {
    let db = open_with_tables(input, &["ZCALLRECORD"])?;
    let c = select_columns(
        &db,
        "ZCALLRECORD",
        &["ZDATE", "ZORIGINATED", "ZANSWERED", "ZADDRESS", "ZNAME", "ZDURATION", "ZCALLTYPE"],
    )?;
    let sql = format!("SELECT {} FROM ZCALLRECORD ORDER BY ZDATE, rowid", c.join(", "));
    let user = user_from_path(input.path);
    let mut stmt = db.conn.prepare(&sql).map_err(sql_error)?;
    let mut rows = stmt.query([]).map_err(sql_error)?;
    while let Some(row) = rows.next().map_err(sql_error)? {
        let time = or_warn(sink, "ZDATE", real_at(row, 0), mac_time);
        sink.emit(
            Loc::None,
            &Call {
                user,
                time,
                direction: if int_at(row, 1) == Some(1) { "outgoing" } else { "incoming" },
                answered: int_at(row, 2).map(|n| n != 0),
                address: text_at(row, 3).map(|s| clip(&s, 256)),
                name: text_at(row, 4).map(|s| clip(&s, 256)),
                duration_secs: real_at(row, 5),
                call_type: match int_at(row, 6) {
                    Some(1) => "phone".into(),
                    Some(8) => "facetime_video".into(),
                    Some(16) => "facetime_audio".into(),
                    Some(n) => n.to_string(),
                    None => String::new(),
                },
            },
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sqlite::database_bytes;
    use crate::testing::{fixture, run};

    const CHAT: &str = "Users/alice/Library/Messages/chat.db";
    const MAIL_PATH: &str = "Users/alice/Library/Mail/V10/MailData/Envelope Index";
    const CALL: &str = "Users/alice/Library/Application Support/CallHistoryDB/CallHistory.storedata";

    #[test]
    fn messages_with_attachments() {
        insta::assert_snapshot!(run(&MESSAGES, CHAT, &fixture("communications/chat.db"), 0));
    }

    #[test]
    fn mail_envelopes_never_include_bodies() {
        let out = run(&MAIL, MAIL_PATH, &fixture("communications/Envelope Index"), 0);
        assert!(!out.contains("PLANTED-MAIL-BODY"), "{out}");
        insta::assert_snapshot!(out);
    }

    #[test]
    fn calls() {
        insta::assert_snapshot!(run(&CALLS, CALL, &fixture("communications/CallHistory.storedata"), 0));
    }

    #[test]
    fn message_times_in_seconds_and_nanoseconds() {
        let out = run(&MESSAGES, CHAT, &fixture("communications/chat.db"), 0);
        assert!(
            out.contains("\"time\":\"2023-03-08T20:26:40.000000000Z\"") && out.contains("2023-03-08T20:30:00Z"),
            "{out}"
        );
    }

    #[test]
    fn other_databases_are_skipped() {
        let db = database_bytes("CREATE TABLE t (a);");
        for (artifact, path) in [(&MESSAGES, CHAT), (&MAIL, MAIL_PATH), (&CALLS, CALL)] {
            assert!(run(artifact, path, &db, 0).contains("skipped: no "), "{path}");
        }
    }

    #[test]
    fn damaged_databases_do_not_panic() {
        crate::macos::util::survives_sparse(&MESSAGES, CHAT, &fixture("communications/chat.db"), 997, 20);
        crate::macos::util::survives_sparse(&MAIL, MAIL_PATH, &fixture("communications/Envelope Index"), 997, 20);
        crate::macos::util::survives_sparse(&CALLS, CALL, &fixture("communications/CallHistory.storedata"), 997, 20);
    }
}
