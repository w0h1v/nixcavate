#!/usr/bin/env python3
"""Builds synthetic chat.db, Envelope Index and CallHistory.storedata from the documented
table layouts. Example data only. Run: python3 generate.py"""
import os, sqlite3
here = os.path.dirname(os.path.abspath(__file__))


def fresh(name):
    path = os.path.join(here, name)
    if os.path.exists(path):
        os.remove(path)
    return sqlite3.connect(path)


db = fresh("chat.db")
db.executescript("""
CREATE TABLE message (ROWID INTEGER PRIMARY KEY, guid TEXT, text TEXT, handle_id INTEGER, service TEXT, date INTEGER, date_read INTEGER,
  is_from_me INTEGER, cache_has_attachments INTEGER);
CREATE TABLE handle (ROWID INTEGER PRIMARY KEY, id TEXT, service TEXT);
CREATE TABLE chat (ROWID INTEGER PRIMARY KEY, chat_identifier TEXT, display_name TEXT);
CREATE TABLE chat_message_join (chat_id INTEGER, message_id INTEGER);
CREATE TABLE attachment (ROWID INTEGER PRIMARY KEY, filename TEXT, mime_type TEXT, transfer_name TEXT, transfer_state INTEGER, total_bytes INTEGER);
CREATE TABLE message_attachment_join (message_id INTEGER, attachment_id INTEGER);
""")
db.execute("INSERT INTO handle VALUES (1, '+15555550100', 'iMessage')")
db.execute("INSERT INTO chat VALUES (1, '+15555550100', NULL)")
ns = 1_000_000_000
db.execute("INSERT INTO message VALUES (1,'g1','hello from example',1,'iMessage',700000000*?,700000060*?,0,0)", (ns, ns))
db.execute("INSERT INTO message VALUES (2,'g2','look at this',1,'iMessage',700000100*?,0,1,1)", (ns,))
db.execute("INSERT INTO message VALUES (3,'g3',NULL,1,'SMS',700000200,0,0,0)")
db.executemany("INSERT INTO chat_message_join VALUES (1,?)", [(1,), (2,), (3,)])
db.execute("INSERT INTO attachment VALUES (1,'~/Library/Messages/Attachments/ab/cd/IMG_0001.heic','image/heic','IMG_0001.heic',5,2048)")
db.execute("INSERT INTO message_attachment_join VALUES (2,1)")
db.commit(); db.close()

db = fresh("Envelope Index")
db.executescript("""
CREATE TABLE messages (ROWID INTEGER PRIMARY KEY, message_id TEXT, subject INTEGER, sender INTEGER, date_sent INTEGER, date_received INTEGER,
  mailbox INTEGER, read INTEGER, body_text TEXT);
CREATE TABLE subjects (ROWID INTEGER PRIMARY KEY, subject TEXT);
CREATE TABLE addresses (ROWID INTEGER PRIMARY KEY, address TEXT, comment TEXT);
CREATE TABLE mailboxes (ROWID INTEGER PRIMARY KEY, url TEXT);
""")
db.execute("INSERT INTO subjects VALUES (1,'Invoice 42')")
db.execute("INSERT INTO addresses VALUES (1,'billing@example.com','Billing')")
db.execute("INSERT INTO mailboxes VALUES (1,'imap://alice@example.com/INBOX')")
db.execute("INSERT INTO messages VALUES (1,'<abc@example.com>',1,1,1700000000,1700000010,1,0,'PLANTED-MAIL-BODY')")
db.commit(); db.close()

db = fresh("CallHistory.storedata")
db.executescript("""
CREATE TABLE ZCALLRECORD (Z_PK INTEGER PRIMARY KEY, ZDATE REAL, ZORIGINATED INTEGER, ZANSWERED INTEGER, ZADDRESS BLOB, ZNAME TEXT, ZDURATION REAL, ZCALLTYPE INTEGER);
""")
db.execute("INSERT INTO ZCALLRECORD VALUES (1,700000000.0,1,1,?,'Example',62.5,1)", (b"+15555550100",))
db.execute("INSERT INTO ZCALLRECORD VALUES (2,700001000.0,0,0,?,NULL,0,16)", (b"friend@example.com",))
db.commit(); db.close()
