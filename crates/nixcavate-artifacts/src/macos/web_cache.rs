//! Network evidence kept by applications: the CFNetwork URL cache (`Cache.db`), cookies
//! (`Cookies.binarycookies`) and `HSTS.plist`.
//!
//! `Cache.db`: `cfurl_cache_response` (one row per cached URL: `request_key`, `time_stamp`
//! in UTC text, `storage_policy`), `cfurl_cache_receiver_data` (the body, or a flag saying it
//! is in `fsCachedData`) and `cfurl_cache_blob_data` (`response_object` and `request_object`,
//! archived URL response and request). Bodies are never output, only their size. The archived
//! objects are read as property lists and searched, within bounds, for a fixed list of HTTP
//! header names; `Set-Cookie`, `Cookie` and `Authorization`-like headers are never copied.
//!
//! `Cookies.binarycookies`: the format documented in public write-ups of Safari's cookie file
//! (big-endian page table, little-endian cookie records with offsets to NUL-terminated domain,
//! name, path and value strings, and two Mac-time doubles). Cookie VALUES are never read.
//!
//! Synthetic only: no real `Cache.db`, cookie file or `HSTS.plist` was read. Doubts: the exact
//! shape of the archived response and request objects (hence the header search, not a fixed
//! path), and the flag bit meanings (1 secure, 4 HttpOnly) from public descriptions.

use super::keyed_archive::unarchive;
use super::plist_util::{date, mac_time, or_warn, parse};
use super::tcc::select_columns;
use super::util::clip;
use crate::common::home::user_from_path;
use crate::sqlite::{int_at, open_with_tables, sql_error, text_at};
use crate::{Artifact, Category, Input, MACOS};
use nixcavate_core::time::parse_iso8601;
use nixcavate_core::{Error, Event, Loc, Record, Result, Sink, Timestamp};
use plist::Value;
use serde::Serialize;
use std::collections::BTreeMap;

pub const URL_CACHE: Artifact = Artifact::new(
    "url-cache",
    "Per-application URL cache (Cache.db): URLs an application fetched",
    Category::Network,
    MACOS,
    &[
        "Users/*/Library/Caches/*/Cache.db",
        "Users/*/Library/Caches/*/*/Cache.db",
        "Users/*/Library/Containers/*/Data/Library/Caches/*/Cache.db",
        "Users/*/Library/Containers/*/Data/Library/Caches/Cache.db",
    ],
    parse_cache,
)
.companions(&[
    "Users/*/Library/Caches/*/Cache.db-wal",
    "Users/*/Library/Caches/*/*/Cache.db-wal",
    "Users/*/Library/Containers/*/Data/Library/Caches/*/Cache.db-wal",
    "Users/*/Library/Containers/*/Data/Library/Caches/Cache.db-wal",
]);

pub const COOKIES: Artifact = Artifact::new(
    "binary-cookies",
    "Cookie metadata (Cookies.binarycookies; values are not read)",
    Category::Network,
    MACOS,
    &[
        "Users/*/Library/Cookies/Cookies.binarycookies",
        "Users/*/Library/Containers/*/Data/Library/Cookies/Cookies.binarycookies",
        "Library/Cookies/Cookies.binarycookies",
    ],
    parse_cookies,
);

pub const HSTS: Artifact = Artifact::new(
    "hsts",
    "HTTP Strict Transport Security entries (hosts a client connected to over HTTPS)",
    Category::Network,
    MACOS,
    &["Users/*/Library/Cookies/HSTS.plist", "Users/*/Library/Containers/*/Data/Library/Cookies/HSTS.plist"],
    parse_hsts,
);

/// Headers that may be copied (lowercase). Credentials and cookies are not on the list.
const HEADERS: &[&str] = &[
    "content-type",
    "content-length",
    "content-encoding",
    "server",
    "date",
    "last-modified",
    "etag",
    "location",
    "cache-control",
    "expires",
    "user-agent",
    "host",
    "x-powered-by",
];
const MAX_WALK: usize = 5_000;
const MAX_OBJECT: usize = 4 << 20;

#[derive(Serialize)]
struct Cached<'a> {
    user: &'a str,
    /// From the cache folder's name: the application's bundle id.
    bundle_id: &'a str,
    url: Option<String>,
    time: Option<Timestamp>,
    storage_policy: Option<i64>,
    partition: Option<String>,
    body_on_disk: Option<bool>,
    body_size: Option<i64>,
    http_method: Option<String>,
    status: Option<i64>,
    headers: BTreeMap<String, String>,
}

impl Record for Cached<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let message = format!("{} fetched {}", self.bundle_id, self.url.as_deref().unwrap_or("?"));
        self.time.map(|ts| Event::new(ts, "http_request", message)).into_iter()
    }
}

/// The bundle id of the cache folder: `.../Caches/<id>/Cache.db`, or the container's name.
fn cache_owner(path: &str) -> &str {
    let parts: Vec<&str> = path.split('/').collect();
    let n = parts.len();
    if n >= 3 && parts[n - 2] != "Caches" {
        // `Caches/<id>/Cache.db` and `Caches/<id>/<sub>/Cache.db` both name the id first.
        let after_caches = parts.iter().position(|p| *p == "Caches").map_or(n - 2, |i| i + 1);
        return parts.get(after_caches).copied().unwrap_or_default();
    }
    path.split_once("/Containers/").and_then(|(_, rest)| rest.split('/').next()).unwrap_or_default()
}

/// Collects the whitelisted headers, an HTTP method and a status from an archived object.
fn scan(value: &Value, out: &mut Scan, budget: &mut usize) {
    if *budget == 0 {
        return;
    }
    *budget -= 1;
    match value {
        Value::Dictionary(dict) => {
            for (key, value) in dict.iter() {
                let lower = key.to_ascii_lowercase();
                match (lower.as_str(), value) {
                    (k, Value::String(s)) if HEADERS.contains(&k) => {
                        out.headers.entry(lower.clone()).or_insert_with(|| clip(s, 256));
                    }
                    ("httpmethod" | "method", Value::String(s)) if out.method.is_none() => {
                        out.method = Some(clip(s, 16))
                    }
                    ("statuscode" | "status", Value::Integer(i)) if out.status.is_none() => out.status = i.as_signed(),
                    _ => {}
                }
                scan(value, out, budget);
            }
        }
        Value::Array(items) => items.iter().for_each(|v| scan(v, out, budget)),
        _ => {}
    }
}

#[derive(Default)]
struct Scan {
    headers: BTreeMap<String, String>,
    method: Option<String>,
    status: Option<i64>,
}

fn scan_blob(bytes: Option<Vec<u8>>, out: &mut Scan) {
    let Some(bytes) = bytes.filter(|b| b.len() <= MAX_OBJECT) else { return };
    let Ok(value) = parse(&bytes) else { return };
    let value = unarchive(&value).unwrap_or(value);
    scan(&value, out, &mut MAX_WALK.clone());
}

fn blob_at(row: &rusqlite::Row, i: usize) -> Option<Vec<u8>> {
    match row.get_ref(i).ok()? {
        rusqlite::types::ValueRef::Blob(b) => Some(b.to_vec()),
        _ => None,
    }
}

fn parse_cache(input: &Input, sink: &mut Sink) -> Result<()> {
    let db = open_with_tables(input, &["cfurl_cache_response"])?;
    let response =
        select_columns(&db, "cfurl_cache_response", &["request_key", "time_stamp", "storage_policy", "partition"])?;
    let has_body = db.has_table("cfurl_cache_receiver_data");
    let has_blob = db.has_table("cfurl_cache_blob_data");
    if has_body {
        db.refuse_generated_columns(&["cfurl_cache_receiver_data"])?;
    }
    if has_blob {
        db.refuse_generated_columns(&["cfurl_cache_blob_data"])?;
    }
    let mut sql = format!("SELECT {}", response.iter().map(|c| format!("r.{c}")).collect::<Vec<_>>().join(", "));
    sql.push_str(if has_body { ", b.isDataOnFS, length(b.receiver_data)" } else { ", NULL, NULL" });
    sql.push_str(if has_blob { ", o.response_object, o.request_object" } else { ", NULL, NULL" });
    sql.push_str(" FROM cfurl_cache_response r");
    if has_body {
        sql.push_str(&format!(
            " LEFT JOIN {} b ON b.entry_ID = r.entry_ID",
            crate::sqlite::unique_rows("cfurl_cache_receiver_data", "entry_ID")
        ));
    }
    if has_blob {
        sql.push_str(&format!(
            " LEFT JOIN {} o ON o.entry_ID = r.entry_ID",
            crate::sqlite::unique_rows("cfurl_cache_blob_data", "entry_ID")
        ));
    }
    sql.push_str(" ORDER BY r.time_stamp, r.rowid");
    let user = user_from_path(input.path);
    let owner = cache_owner(input.path);
    let mut stmt = db.conn.prepare(&sql).map_err(sql_error)?;
    let mut rows = stmt.query([]).map_err(sql_error)?;
    while let Some(row) = rows.next().map_err(sql_error)? {
        let stamp = text_at(row, 1);
        let time = or_warn(sink, "time_stamp", stamp.as_deref(), |t| {
            parse_iso8601(format!("{}Z", t.trim()).as_bytes()).and_then(|(p, _)| p.recorded())
        });
        let mut scanned = Scan::default();
        scan_blob(blob_at(row, 6), &mut scanned);
        scan_blob(blob_at(row, 7), &mut scanned);
        sink.emit(
            Loc::None,
            &Cached {
                user,
                bundle_id: owner,
                url: text_at(row, 0),
                time,
                storage_policy: int_at(row, 2),
                partition: text_at(row, 3),
                body_on_disk: int_at(row, 4).map(|n| n != 0),
                body_size: int_at(row, 5),
                http_method: scanned.method,
                status: scanned.status,
                headers: scanned.headers,
            },
        )?;
    }
    Ok(())
}

#[derive(Serialize)]
struct Cookie<'a> {
    user: &'a str,
    domain: String,
    name: String,
    path: String,
    secure: bool,
    http_only: bool,
    flags_raw: u32,
    created: Option<Timestamp>,
    expires: Option<Timestamp>,
}

impl Record for Cookie<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let message = format!("cookie {} set for {}", self.name, self.domain);
        self.created.map(|ts| Event::new(ts, "activity", message)).into_iter()
    }
}

fn be32(data: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(data.get(at..at.checked_add(4)?)?.try_into().ok()?))
}

fn le32(data: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(data.get(at..at.checked_add(4)?)?.try_into().ok()?))
}

fn le_f64(data: &[u8], at: usize) -> Option<f64> {
    Some(f64::from_le_bytes(data.get(at..at.checked_add(8)?)?.try_into().ok()?))
}

/// The NUL-terminated string at `offset` in the cookie record (at most 512 bytes).
fn cstr(record: &[u8], offset: u32) -> Option<String> {
    let rest = record.get(usize::try_from(offset).ok()?..)?;
    let rest = &rest[..rest.len().min(512)];
    let end = memchr::memchr(0, rest)?;
    Some(String::from_utf8_lossy(&rest[..end]).into_owned())
}

const MAX_PAGES: usize = 4096;
const MAX_COOKIES_PER_PAGE: usize = 8192;

fn parse_cookies(input: &Input, sink: &mut Sink) -> Result<()> {
    let data = input.data;
    if data.get(..4) != Some(b"cook") {
        return Err(Error::format("not a binarycookies file"));
    }
    let pages = usize::try_from(be32(data, 4).ok_or_else(|| Error::format("truncated header"))?).unwrap_or(usize::MAX);
    if pages > MAX_PAGES {
        return Err(Error::format(format!("{pages} pages is not plausible")));
    }
    let user = user_from_path(input.path);
    let mut start = 8 + pages * 4;
    for page in 0..pages {
        let size = be32(data, 8 + page * 4).and_then(|s| usize::try_from(s).ok());
        let Some(end) = size.and_then(|s| start.checked_add(s)) else {
            sink.warn(format!("page {page}: size is not readable; stopped"));
            break;
        };
        let Some(body) = data.get(start..end) else {
            sink.warn(format!("page {page}: extends past the end of the file; stopped"));
            break;
        };
        let page_start = start;
        start = end;
        if body.get(..4) != Some(&[0, 0, 1, 0]) {
            sink.warn(format!("page {page}: bad page header; skipped"));
            continue;
        }
        let count = le32(body, 4).map_or(0, |c| (c as usize).min(MAX_COOKIES_PER_PAGE));
        for n in 0..count {
            let Some(offset) = le32(body, 8 + n * 4).and_then(|o| usize::try_from(o).ok()) else { break };
            let Some(cookie) = cookie_at(body, offset).and_then(|c| {
                Some(Cookie {
                    user,
                    domain: cstr(c, le32(c, 16)?)?,
                    name: cstr(c, le32(c, 20)?)?,
                    path: cstr(c, le32(c, 24)?)?,
                    secure: le32(c, 8)? & 1 != 0,
                    http_only: le32(c, 8)? & 4 != 0,
                    flags_raw: le32(c, 8)?,
                    expires: le_f64(c, 40).and_then(mac_time),
                    created: le_f64(c, 48).and_then(mac_time),
                })
            }) else {
                sink.warn(format!("page {page} cookie {n}: not readable; skipped"));
                continue;
            };
            sink.emit(Loc::Offset(input.offset + page_start as u64), &cookie)?;
        }
    }
    Ok(())
}

/// The bytes of the cookie record at `offset` in a page.
fn cookie_at(page: &[u8], offset: usize) -> Option<&[u8]> {
    let size = usize::try_from(le32(page, offset)?).ok()?;
    if size < 56 {
        return None;
    }
    page.get(offset..offset.checked_add(size)?)
}

#[derive(Serialize)]
struct Hsts<'a> {
    user: &'a str,
    domain: &'a str,
    created: Option<Timestamp>,
    expires: Option<Timestamp>,
    include_subdomains: Option<bool>,
}

impl Record for Hsts<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let message = format!("HSTS entry created for {}", self.domain);
        self.created.map(|ts| Event::new(ts, "activity", message)).into_iter()
    }
}

/// A time stored either as a plist date or as Mac absolute seconds.
fn hsts_time(value: Option<&Value>) -> Option<Timestamp> {
    match value? {
        Value::Real(secs) => mac_time(*secs),
        Value::Integer(i) => mac_time(i.as_signed()? as f64),
        other => date(other),
    }
}

fn parse_hsts(input: &Input, sink: &mut Sink) -> Result<()> {
    let value = parse(input.data)?;
    let Some(root) = value.as_dictionary() else { return Err(Error::format("not a dictionary")) };
    let user = user_from_path(input.path);
    let mut any = false;
    for (_, storage) in root.iter() {
        let Some(hosts) = storage.as_dictionary() else { continue };
        for (host, entry) in hosts.iter() {
            let Some(entry) = entry.as_dictionary() else { continue };
            any = true;
            let created = hsts_time(entry.get("Created"));
            let expires = hsts_time(entry.get("Expiry"));
            if created.is_none() && entry.contains_key("Created") {
                sink.warn(format!("{host}: Created is not a valid time; left empty"));
            }
            sink.emit(
                Loc::None,
                &Hsts {
                    user,
                    domain: host,
                    created,
                    expires,
                    include_subdomains: entry.get("Include Subdomains").and_then(Value::as_boolean),
                },
            )?;
        }
    }
    if !any {
        return Err(Error::skipped("no HSTS entries"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    const CACHE: &str = "Users/alice/Library/Caches/com.example.app/Cache.db";
    const COOKIE: &str = "Users/alice/Library/Cookies/Cookies.binarycookies";

    #[test]
    fn cache_urls_headers_and_no_body() {
        let out = run(&URL_CACHE, CACHE, &fixture("web-cache/Cache.db"), 0);
        assert!(!out.contains("PLANTED-BODY"), "{out}");
        assert!(!out.contains("PLANTED-SET-COOKIE"), "{out}");
        assert!(!out.contains("PLANTED-AUTH"), "{out}");
        insta::assert_snapshot!(out);
    }

    #[test]
    fn owner_of_a_cache() {
        assert_eq!(cache_owner("Users/a/Library/Caches/com.x.y/Cache.db"), "com.x.y");
        assert_eq!(cache_owner("Users/a/Library/Caches/com.x.y/sub/Cache.db"), "com.x.y");
        assert_eq!(cache_owner("Users/a/Library/Containers/com.c.d/Data/Library/Caches/Cache.db"), "com.c.d");
    }

    #[test]
    fn cookies_never_expose_values() {
        let out = run(&COOKIES, COOKIE, &fixture("web-cache/Cookies.binarycookies"), 0);
        assert!(!out.contains("PLANTED-COOKIE-VALUE"), "{out}");
        insta::assert_snapshot!(out);
    }

    #[test]
    fn hsts_entries() {
        let path = "Users/alice/Library/Cookies/HSTS.plist";
        insta::assert_snapshot!(run(&HSTS, path, &fixture("web-cache/HSTS.plist"), 0));
    }

    #[test]
    fn garbage_is_refused() {
        assert!(run(&COOKIES, COOKIE, b"nope", 0).contains("failed: "));
        assert!(run(&COOKIES, COOKIE, b"", 0).contains("failed: "));
        assert!(run(&URL_CACHE, CACHE, b"", 0).contains("skipped"));
    }

    #[test]
    fn damaged_inputs_do_not_panic() {
        crate::macos::plist_util::tests::survives_damage(&COOKIES, COOKIE, &fixture("web-cache/Cookies.binarycookies"));
        crate::macos::util::survives_sparse(&URL_CACHE, CACHE, &fixture("web-cache/Cache.db"), 499, 30);
        let mut huge = fixture("web-cache/Cookies.binarycookies");
        huge[4..8].copy_from_slice(&u32::MAX.to_be_bytes());
        run(&COOKIES, COOKIE, &huge, 0);
    }
}
