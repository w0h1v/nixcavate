#!/usr/bin/env python3
"""Builds synthetic auth.db and ExecPolicy databases from the documented schemas.
Example data only. Run: python3 generate.py"""
import os, sqlite3
here = os.path.dirname(os.path.abspath(__file__))


def fresh(name):
    path = os.path.join(here, name)
    if os.path.exists(path):
        os.remove(path)
    return sqlite3.connect(path)


db = fresh("auth.db")
db.executescript("""
CREATE TABLE rules (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, type INTEGER NOT NULL, class INTEGER, 'group' TEXT,
  kofn INTEGER, timeout INTEGER, flags INTEGER, tries INTEGER, version INTEGER NOT NULL DEFAULT 0, created REAL NOT NULL DEFAULT 0,
  modified REAL NOT NULL DEFAULT 0, hash BLOB, identifier TEXT, requirement BLOB, comment TEXT);
CREATE TABLE delegates_map (r_id INTEGER NOT NULL, d_id INTEGER NOT NULL, ord INTEGER NOT NULL);
CREATE TABLE mechanisms (id INTEGER PRIMARY KEY AUTOINCREMENT, plugin TEXT NOT NULL, param TEXT NOT NULL, privileged INTEGER NOT NULL DEFAULT 0);
CREATE TABLE mechanisms_map (r_id INTEGER NOT NULL, m_id INTEGER NOT NULL, ord INTEGER NOT NULL);
""")
# Mac absolute seconds: 700000000 is 2023-03-08; 700200000 is 2.3 days later.
db.executemany("INSERT INTO rules (id,name,type,class,'group',created,modified,comment) VALUES (?,?,?,?,?,?,?,?)", [
    (1, "system.privilege.admin", 1, 1, "admin", 700000000.0, 700000000.0, "Used by AuthenticationServices"),
    (2, "system.login.console", 2, 3, None, 700000000.0, 700200000.0, "Login mechanism based rule"),
    (3, "example.rule", 1, 2, None, 700000000.0, 700000000.0, "delegates to another rule"),
    (4, "system.preferences", 1, 4, None, 700000000.0, 700000000.0, "an allow rule"),
    (5, "weird", 3, 99, None, 1e300, 0.0, None)])
db.execute("INSERT INTO delegates_map VALUES (3, 1, 0)")
db.executemany("INSERT INTO mechanisms (id,plugin,param) VALUES (?,?,?)", [(1, "builtin", "login-begin"), (2, "ExamplePlugin", "start")])
db.executemany("INSERT INTO mechanisms_map VALUES (?,?,?)", [(2, 1, 0), (2, 2, 1)])
db.commit(); db.close()

db = fresh("ExecPolicy")
db.executescript("""
CREATE TABLE policy_scan_cache (volume_uuid TEXT, object_id INTEGER, fs_type_name TEXT, bundle_id TEXT, cdhash BLOB, team_identifier TEXT,
  signing_identifier TEXT, policy_match INTEGER, malware_result INTEGER, flags INTEGER, mod_time INTEGER, timestamp INTEGER, revocation_check_time INTEGER, scan_version INTEGER);
CREATE TABLE executable_measurements_v2 (pk INTEGER PRIMARY KEY, volume_uuid TEXT, object_id INTEGER, fs_type_name TEXT, bundle_id TEXT,
  cdhash BLOB, team_identifier TEXT, signing_identifier TEXT, policy_match INTEGER, flags INTEGER, mod_time INTEGER, timestamp INTEGER);
""")
db.execute("INSERT INTO policy_scan_cache VALUES ('AAAAAAAA-0000-0000-0000-000000000000',12345,'apfs','com.example.app',x'0102030405060708090a0b0c0d0e0f1011121314','EXAMPLE123','com.example.app',1,0,0,1700000000,1700000100,0,1)")
db.execute("INSERT INTO executable_measurements_v2 VALUES (1,'AAAAAAAA-0000-0000-0000-000000000000',999,'apfs',NULL,x'ff',NULL,'a.out',0,0,1700000200,1700000300)")
db.execute("INSERT INTO executable_measurements_v2 VALUES (2,'AAAAAAAA-0000-0000-0000-000000000000',1000,'apfs',NULL,NULL,NULL,'odd',0,0,1,700000000)")
db.commit(); db.close()
