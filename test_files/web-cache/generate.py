#!/usr/bin/env python3
"""Builds synthetic Cache.db, Cookies.binarycookies and HSTS.plist from the documented layouts.
Example data only. Run: python3 generate.py"""
import os, plistlib, sqlite3, struct, datetime
here = os.path.dirname(os.path.abspath(__file__))

# --- Cache.db
path = os.path.join(here, "Cache.db")
if os.path.exists(path):
    os.remove(path)
db = sqlite3.connect(path)
db.executescript("""
CREATE TABLE cfurl_cache_response(entry_ID INTEGER PRIMARY KEY, version INTEGER, hash_value INTEGER, storage_policy INTEGER, request_key TEXT UNIQUE, time_stamp DATE DEFAULT CURRENT_TIMESTAMP, partition TEXT);
CREATE TABLE cfurl_cache_receiver_data(entry_ID INTEGER PRIMARY KEY, isDataOnFS INTEGER, receiver_data BLOB);
CREATE TABLE cfurl_cache_blob_data(entry_ID INTEGER PRIMARY KEY, response_object BLOB, request_object BLOB, proto_props BLOB, user_info BLOB);
""")
response = plistlib.dumps({"Array": [{"Content-Type": "text/html", "Server": "example", "Set-Cookie": "PLANTED-SET-COOKIE=1",
                                      "Nested": {"ETag": "\"abc\""}}, {"statusCode": 200}]}, fmt=plistlib.FMT_BINARY)
request = plistlib.dumps({"HTTPMethod": "GET", "Authorization": "PLANTED-AUTH", "User-Agent": "Example/1.0", "Cookie": "PLANTED-AUTH2"}, fmt=plistlib.FMT_BINARY)
db.execute("INSERT INTO cfurl_cache_response VALUES (1,5,1,0,'https://example.com/a.js','2023-11-14 10:00:00','')")
db.execute("INSERT INTO cfurl_cache_receiver_data VALUES (1,0,?)", (b"PLANTED-BODY" * 10,))
db.execute("INSERT INTO cfurl_cache_blob_data VALUES (1,?,?,NULL,NULL)", (response, request))
db.execute("INSERT INTO cfurl_cache_response VALUES (2,5,2,1,'https://example.org/img.png','2023-11-14 11:30:15','part')")
db.execute("INSERT INTO cfurl_cache_receiver_data VALUES (2,1,NULL)")
db.execute("INSERT INTO cfurl_cache_blob_data VALUES (2,x'00010203',NULL,NULL,NULL)")
db.execute("INSERT INTO cfurl_cache_response VALUES (3,5,3,0,'https://example.net/','not a time','')")
db.commit(); db.close()

# --- Cookies.binarycookies
def cookie(domain, name, cpath, value, flags, expires, created):
    strings = [domain, name, cpath, value]
    head = 56
    offsets, body = [], b""
    for s in strings:
        offsets.append(head + len(body))
        body += s.encode() + b"\0"
    size = head + len(body)
    rec = struct.pack("<IIIIIIII", size, 0, flags, 0, offsets[0], offsets[1], offsets[2], offsets[3])
    rec += b"\0" * 8 + struct.pack("<dd", expires, created)
    assert len(rec) == head, len(rec)
    return rec + body

cookies = [cookie(".example.com", "session", "/", "PLANTED-COOKIE-VALUE", 5, 800000000.0, 700000000.0),
           cookie("example.org", "pref", "/app", "PLANTED-COOKIE-VALUE-2", 0, 800000100.0, 700000100.0)]
page = bytes([0, 0, 1, 0]) + struct.pack("<I", len(cookies))
off = 8 + 4 * len(cookies) + 4
offs = []
for c in cookies:
    offs.append(off)
    off += len(c)
page += b"".join(struct.pack("<I", o) for o in offs) + struct.pack("<I", 0) + b"".join(cookies)
data = b"cook" + struct.pack(">I", 1) + struct.pack(">I", len(page)) + page + b"\0" * 8 + bytes.fromhex("0717200500000000")
with open(os.path.join(here, "Cookies.binarycookies"), "wb") as f:
    f.write(data)

# --- HSTS.plist
hsts = {"com.apple.CFNetwork.defaultStorageSession": {
    "example.com": {"Created": 700000000.0, "Expiry": 731000000.0, "Include Subdomains": True},
    "example.org": {"Created": datetime.datetime(2023, 1, 2, 3, 4, 5), "Expiry": datetime.datetime(2024, 1, 2, 3, 4, 5)}}}
with open(os.path.join(here, "HSTS.plist"), "wb") as f:
    plistlib.dump(hsts, f, fmt=plistlib.FMT_BINARY)
