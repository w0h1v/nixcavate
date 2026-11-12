#!/usr/bin/env python3
"""Builds knowledgeC.db, a synthetic Core Data store shaped like the KnowledgeC layout in
Sarah Edwards' published research. Nothing here comes from a real machine.
Run: python3 generate.py   (writes knowledgeC.db next to this script)"""
import os
import sqlite3

here = os.path.dirname(os.path.abspath(__file__))
path = os.path.join(here, "knowledgeC.db")
if os.path.exists(path):
    os.remove(path)
db = sqlite3.connect(path)
db.executescript("""
CREATE TABLE ZSOURCE (Z_PK INTEGER PRIMARY KEY, ZBUNDLEID VARCHAR, ZDEVICEID VARCHAR);
CREATE TABLE ZSTRUCTUREDMETADATA (
  Z_PK INTEGER PRIMARY KEY, Z_ENT INTEGER,
  Z_DKSAFARIHISTORYMETADATAKEY__TITLE VARCHAR,
  Z_DKNOWPLAYINGMETADATAKEY__TITLE VARCHAR,
  Z_DKNOWPLAYINGMETADATAKEY__DURATION FLOAT,
  Z_DKAPPLICATIONACTIVITYMETADATAKEY__ACTIVITYTYPE VARCHAR,
  Z_DKNOTIFICATIONUSAGEMETADATAKEY__BUNDLEID VARCHAR);
CREATE TABLE ZOBJECT (
  Z_PK INTEGER PRIMARY KEY, Z_ENT INTEGER, ZSTREAMNAME VARCHAR, ZVALUESTRING VARCHAR,
  ZVALUEINTEGER INTEGER, ZVALUEDOUBLE FLOAT, ZSTARTDATE TIMESTAMP, ZENDDATE TIMESTAMP,
  ZCREATIONDATE TIMESTAMP, ZSECONDSFROMGMT INTEGER, ZSOURCE INTEGER, ZSTRUCTUREDMETADATA INTEGER);
""")
db.executemany("INSERT INTO ZSOURCE VALUES (?,?,?)", [
    (1, "com.apple.Safari", None), (2, None, "00000000-0000-0000-0000-000000000001"), (3, "com.example.Notes", None)])
db.executemany("INSERT INTO ZSTRUCTUREDMETADATA (Z_PK,Z_ENT,Z_DKSAFARIHISTORYMETADATAKEY__TITLE,"
               "Z_DKNOWPLAYINGMETADATAKEY__TITLE,Z_DKNOWPLAYINGMETADATAKEY__DURATION,"
               "Z_DKAPPLICATIONACTIVITYMETADATAKEY__ACTIVITYTYPE,Z_DKNOTIFICATIONUSAGEMETADATAKEY__BUNDLEID)"
               " VALUES (?,?,?,?,?,?,?)", [
    (1, 5, "Example Domain", None, None, None, None),
    (2, 6, None, "Example Song", 215.5, None, None),
    (3, 7, None, None, None, "com.example.Notes.editing", None),
    (4, 8, None, None, None, None, "com.example.Mail")])
# Mac absolute time: 720000000.0 is 2023-10-26T08:00:00Z.
T = 720_000_000.0
rows = [  # stream, str, int, dbl, start, end, created, gmt, source, meta
    ("/app/inFocus", "com.apple.Safari", None, None, T, T + 60, T + 61, -18000, 1, None),
    ("/app/usage", "com.example.Notes", None, None, T + 10, T + 310.25, T + 311, -18000, 3, None),
    ("/app/activity", "com.example.Notes", None, None, T + 20, T + 20, T + 21, -18000, 3, 3),
    ("/safari/history", "https://example.com/", None, None, T + 30, T + 30, T + 31, -18000, 1, 1),
    ("/device/isLocked", None, 1, None, T + 400, T + 900, T + 901, -18000, 2, None),
    ("/device/isLocked", None, 0, None, T + 900, None, T + 901, -18000, 2, None),
    ("/display/isBacklit", None, 1, None, T + 5, T + 400, T + 401, -18000, 2, None),
    ("/app/intents", "com.example.Notes", None, None, T + 50, T + 51, T + 52, 3600, 3, None),
    ("/notification/usage", "com.example.Mail", None, None, T + 60, T + 61, T + 62, 0, 3, 4),
    ("/media/nowPlaying", "com.apple.Music", None, 0.75, T + 70, T + 285.5, T + 286, 0, 2, 2),
    ("/app/inFocus", "com.example.Backwards", None, None, T + 500, T + 400, T + 501, 0, None, None),  # end < start
    ("/device/batteryPercentage", None, None, 0.42, T + 600, T + 600, T + 601, 0, 2, None),
]
db.executemany("INSERT INTO ZOBJECT (Z_ENT,ZSTREAMNAME,ZVALUESTRING,ZVALUEINTEGER,ZVALUEDOUBLE,ZSTARTDATE,"
               "ZENDDATE,ZCREATIONDATE,ZSECONDSFROMGMT,ZSOURCE,ZSTRUCTUREDMETADATA) VALUES (1,?,?,?,?,?,?,?,?,?,?)", rows)
db.commit()
db.execute("VACUUM")
db.close()
