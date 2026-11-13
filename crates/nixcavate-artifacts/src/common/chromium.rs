//! Chromium-family browser history and downloads (Chrome, Chromium, Brave, Edge): the `History`
//! SQLite database. Format reference: Chromium source, `components/history/core/browser`
//! (`url_database`, `visit_database`, `download_database`) and `ui/base/page_transition_types.h`.
//! Both artifacts read the same file, so it is opened twice.
//!
//! The helpers marked `pub(crate)` are shared with the Firefox and Safari parsers.

use crate::common::home::user_from_path;
use crate::macos::plist_util::or_warn;
use crate::sqlite::{int_at, open_with_tables, sql_error, text_at, unique_rows};
use crate::{Artifact, Category, Input, ANY_OS};
use nixcavate_core::{Basis, Error, Event, Loc, Precision, Record, Result, Sink, Timestamp};
use rusqlite::Row;
use serde::Serialize;
use serde_json::Value;
use std::borrow::Cow;

const WEBKIT_TO_UNIX_SECS: i64 = 11_644_473_600;

pub const HISTORY: Artifact = Artifact::new(
    "chromium-history",
    "Chrome, Chromium, Brave and Edge browsing history",
    Category::Activity,
    ANY_OS,
    &[
        "home/*/.config/google-chrome/*/History",
        "home/*/.config/chromium/*/History",
        "home/*/.config/BraveSoftware/Brave-Browser/*/History",
        "home/*/.config/microsoft-edge/*/History",
        "root/.config/google-chrome/*/History",
        "root/.config/chromium/*/History",
        "root/.config/BraveSoftware/Brave-Browser/*/History",
        "root/.config/microsoft-edge/*/History",
        "home/*/snap/chromium/common/chromium/*/History",
        "Users/*/Library/Application Support/Google/Chrome/*/History",
        "Users/*/Library/Application Support/Chromium/*/History",
        "Users/*/Library/Application Support/BraveSoftware/Brave-Browser/*/History",
        "Users/*/Library/Application Support/Microsoft Edge/*/History",
        "home/*/.var/app/com.google.Chrome/config/google-chrome/*/History",
        "home/*/.var/app/org.chromium.Chromium/config/chromium/*/History",
        "home/*/.var/app/com.brave.Browser/config/BraveSoftware/Brave-Browser/*/History",
        "home/*/.var/app/com.microsoft.Edge/config/microsoft-edge/*/History",
        "home/*/snap/brave/common/.config/BraveSoftware/Brave-Browser/*/History",
    ],
    parse_history,
)
.companions(WAL);

pub const DOWNLOADS: Artifact = Artifact::new(
    "chromium-downloads",
    "Chrome, Chromium, Brave and Edge downloads",
    Category::Activity,
    ANY_OS,
    HISTORY.paths,
    parse_downloads,
)
.companions(WAL);

const WAL: &[&str] = &[
    "home/*/.config/google-chrome/*/History-wal",
    "home/*/.config/chromium/*/History-wal",
    "home/*/.config/BraveSoftware/Brave-Browser/*/History-wal",
    "home/*/.config/microsoft-edge/*/History-wal",
    "root/.config/google-chrome/*/History-wal",
    "root/.config/chromium/*/History-wal",
    "root/.config/BraveSoftware/Brave-Browser/*/History-wal",
    "root/.config/microsoft-edge/*/History-wal",
    "home/*/snap/chromium/common/chromium/*/History-wal",
    "Users/*/Library/Application Support/Google/Chrome/*/History-wal",
    "Users/*/Library/Application Support/Chromium/*/History-wal",
    "Users/*/Library/Application Support/BraveSoftware/Brave-Browser/*/History-wal",
    "Users/*/Library/Application Support/Microsoft Edge/*/History-wal",
    "home/*/.var/app/com.google.Chrome/config/google-chrome/*/History-wal",
    "home/*/.var/app/org.chromium.Chromium/config/chromium/*/History-wal",
    "home/*/.var/app/com.brave.Browser/config/BraveSoftware/Brave-Browser/*/History-wal",
    "home/*/.var/app/com.microsoft.Edge/config/microsoft-edge/*/History-wal",
    "home/*/snap/brave/common/.config/BraveSoftware/Brave-Browser/*/History-wal",
];

// ---- helpers shared with firefox.rs and safari.rs ----

/// Cuts a timeline message to about 300 characters, on a character boundary.
pub(crate) fn cap(mut message: String) -> String {
    if let Some((end, _)) = message.char_indices().nth(300) {
        message.truncate(end);
        message.push_str("...");
    }
    message
}

pub(crate) fn visit_message(user: &str, url: Option<&str>, title: Option<&str>) -> String {
    let mut message = format!("{user} visited {}", url.unwrap_or("(unknown URL)"));
    if let Some(title) = title.filter(|t| !t.is_empty()) {
        message.push_str(&format!(" ({title})"));
    }
    cap(message)
}

pub(crate) fn download_message(user: &str, url: Option<&str>, path: Option<&str>) -> String {
    cap(format!("{user} downloaded {} to {}", url.unwrap_or("(unknown URL)"), path.unwrap_or("(unknown path)")))
}

// ---- Chromium ----

/// The browser, from the profile root in the path.
fn browser_of(path: &str) -> &'static str {
    if path.contains("/google-chrome/") || path.contains("/Google/Chrome/") {
        "chrome"
    } else if path.contains("/BraveSoftware/") {
        "brave"
    } else if path.contains("/microsoft-edge/") || path.contains("/Microsoft Edge/") {
        "edge"
    } else {
        "chromium"
    }
}

/// The profile directory name (`Default`, `Profile 1`).
pub(crate) fn profile_of(path: &str) -> &str {
    let mut parts = path.rsplit('/');
    parts.next();
    parts.next().unwrap_or_default()
}

/// Chromium time (microseconds since 1601) to Unix; `None` when it does not fit 1677-2262.
fn webkit_time(micros: i64) -> Option<Timestamp> {
    let unix = micros.checked_sub(WEBKIT_TO_UNIX_SECS * 1_000_000)?;
    Timestamp::checked(
        unix.div_euclid(1_000_000),
        unix.rem_euclid(1_000_000) as u32 * 1000,
        Precision::Micros,
        Basis::Recorded,
    )
}

/// A column holding a webkit time; 0 and NULL mean unset.
fn webkit_at(sink: &mut Sink, row: &Row, i: usize, what: &str) -> Option<Timestamp> {
    or_warn(sink, what, int_at(row, i).filter(|&m| m > 0), webkit_time)
}

fn transition_name(transition: Option<i64>) -> Option<Cow<'static, str>> {
    let core = transition? & 0xff;
    Some(Cow::Borrowed(match core {
        0 => "link",
        1 => "typed",
        2 => "auto_bookmark",
        3 => "auto_subframe",
        4 => "manual_subframe",
        5 => "generated",
        6 => "auto_toplevel",
        7 => "form_submit",
        8 => "reload",
        9 => "keyword",
        10 => "keyword_generated",
        n => return Some(Cow::Owned(format!("unknown({n})"))),
    }))
}

#[derive(Serialize)]
struct Visit<'a> {
    time: Option<Timestamp>,
    user: &'a str,
    browser: &'static str,
    profile: &'a str,
    url: Option<String>,
    title: Option<String>,
    visit_count: Option<i64>,
    typed_count: Option<i64>,
    transition: Option<Cow<'static, str>>,
    /// The whole transition value: the low byte is the type, the rest are qualifier bits.
    transition_raw: Option<i64>,
    from_visit: Option<i64>,
    visit_duration_secs: Option<f64>,
}

impl Record for Visit<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        self.time
            .map(|t| Event::new(t, "url_visited", visit_message(self.user, self.url.as_deref(), self.title.as_deref())))
            .into_iter()
    }
}

fn parse_history(input: &Input, sink: &mut Sink) -> Result<()> {
    let db = open_with_tables(input, &["urls", "visits"])?;
    let (user, browser, profile) = (user_from_path(input.path), browser_of(input.path), profile_of(input.path));
    let mut stmt = db
        .conn
        .prepare(&format!(
            "SELECT v.visit_time, u.url, u.title, u.visit_count, u.typed_count, v.transition, v.from_visit, \
             v.visit_duration FROM visits v LEFT JOIN {} u ON u.id = v.url ORDER BY v.visit_time, v.id",
            unique_rows("urls", "id")
        ))
        .map_err(sql_error)?;
    let mut rows = stmt.query([]).map_err(sql_error)?;
    while let Some(row) = rows.next().map_err(sql_error)? {
        let time = webkit_at(sink, row, 0, "visit_time");
        sink.emit(
            Loc::None,
            &Visit {
                time,
                user,
                browser,
                profile,
                url: text_at(row, 1),
                title: text_at(row, 2),
                visit_count: int_at(row, 3),
                typed_count: int_at(row, 4),
                transition: transition_name(int_at(row, 5)),
                transition_raw: int_at(row, 5),
                from_visit: int_at(row, 6),
                visit_duration_secs: int_at(row, 7).map(|us| us as f64 / 1e6),
            },
        )?;
    }
    Ok(())
}

#[derive(Serialize)]
struct Download<'a> {
    time: Option<Timestamp>,
    end_time: Option<Timestamp>,
    user: &'a str,
    browser: &'static str,
    profile: &'a str,
    target_path: Option<String>,
    url: Option<String>,
    referrer: Option<String>,
    tab_url: Option<String>,
    received_bytes: Option<i64>,
    total_bytes: Option<i64>,
    state: Option<Cow<'static, str>>,
    danger_type: Option<i64>,
    opened: Option<bool>,
    mime_type: Option<String>,
}

impl Record for Download<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        self.time
            .map(|t| {
                Event::new(
                    t,
                    "file_downloaded",
                    download_message(self.user, self.url.as_deref(), self.target_path.as_deref()),
                )
            })
            .into_iter()
    }
}

fn download_state(state: Option<i64>) -> Option<Cow<'static, str>> {
    Some(Cow::Borrowed(match state? {
        0 => "in_progress",
        1 => "complete",
        2 => "cancelled",
        // Chromium's `DownloadState::BUG_140687`: a retired value that old databases still hold.
        3 => "bug_140687",
        4 => "interrupted",
        n => return Some(Cow::Owned(format!("unknown({n})"))),
    }))
}

fn parse_downloads(input: &Input, sink: &mut Sink) -> Result<()> {
    let db = open_with_tables(input, &["downloads", "downloads_url_chains"])?;
    let (user, browser, profile) = (user_from_path(input.path), browser_of(input.path), profile_of(input.path));
    let mut stmt = db
        .conn
        .prepare(
            "SELECT d.start_time, d.end_time, d.target_path, \
             (SELECT c.url FROM downloads_url_chains c WHERE c.id = d.id ORDER BY c.chain_index DESC LIMIT 1), \
             d.referrer, d.tab_url, d.received_bytes, d.total_bytes, d.state, d.danger_type, d.opened, d.mime_type \
             FROM downloads d ORDER BY d.start_time, d.id",
        )
        .map_err(sql_error)?;
    let mut rows = stmt.query([]).map_err(sql_error)?;
    while let Some(row) = rows.next().map_err(sql_error)? {
        let (time, end_time) = (webkit_at(sink, row, 0, "start_time"), webkit_at(sink, row, 1, "end_time"));
        sink.emit(
            Loc::None,
            &Download {
                time,
                end_time,
                user,
                browser,
                profile,
                target_path: text_at(row, 2),
                url: text_at(row, 3),
                referrer: text_at(row, 4),
                tab_url: text_at(row, 5),
                received_bytes: int_at(row, 6),
                total_bytes: int_at(row, 7),
                state: download_state(int_at(row, 8)),
                danger_type: int_at(row, 9),
                opened: int_at(row, 10).map(|n| n != 0),
                mime_type: text_at(row, 11),
            },
        )?;
    }
    Ok(())
}

// ---- profile files besides History ----

/// Every browser's profile directory pattern joined with a profile file name.
macro_rules! profile_files {
    ($file:literal) => {
        &[
            concat!("home/*/.config/google-chrome/*/", $file),
            concat!("home/*/.config/chromium/*/", $file),
            concat!("home/*/.config/BraveSoftware/Brave-Browser/*/", $file),
            concat!("home/*/.config/microsoft-edge/*/", $file),
            concat!("root/.config/google-chrome/*/", $file),
            concat!("root/.config/chromium/*/", $file),
            concat!("root/.config/BraveSoftware/Brave-Browser/*/", $file),
            concat!("root/.config/microsoft-edge/*/", $file),
            concat!("home/*/snap/chromium/common/chromium/*/", $file),
            concat!("Users/*/Library/Application Support/Google/Chrome/*/", $file),
            concat!("Users/*/Library/Application Support/Chromium/*/", $file),
            concat!("Users/*/Library/Application Support/BraveSoftware/Brave-Browser/*/", $file),
            concat!("Users/*/Library/Application Support/Microsoft Edge/*/", $file),
            concat!("home/*/.var/app/com.google.Chrome/config/google-chrome/*/", $file),
            concat!("home/*/.var/app/org.chromium.Chromium/config/chromium/*/", $file),
            concat!("home/*/.var/app/com.brave.Browser/config/BraveSoftware/Brave-Browser/*/", $file),
            concat!("home/*/.var/app/com.microsoft.Edge/config/microsoft-edge/*/", $file),
            concat!("home/*/snap/brave/common/.config/BraveSoftware/Brave-Browser/*/", $file),
        ]
    };
}

pub const COOKIES: Artifact = Artifact::new(
    "chromium-cookies",
    "Chrome, Chromium, Brave and Edge cookies: host, name and times (never the value)",
    Category::Activity,
    ANY_OS,
    profile_files!("Cookies"),
    parse_cookies,
);

pub const LOGINS: Artifact = Artifact::new(
    "chromium-logins",
    "Chrome, Chromium, Brave and Edge saved logins: site, user name and times (never the password)",
    Category::Activity,
    ANY_OS,
    profile_files!("Login Data"),
    parse_logins,
);

pub const EXTENSION_SETTINGS: Artifact = Artifact::new(
    "chromium-extension-settings",
    "Chrome, Chromium, Brave and Edge extensions as the profile records them (install time, source, path, permissions)",
    Category::Persistence,
    ANY_OS,
    profile_files!("Preferences"),
    parse_extension_settings,
)
.companions(profile_files!("Secure Preferences"));

pub const EXTENSIONS: Artifact = Artifact::new(
    "chromium-extensions",
    "Chrome, Chromium, Brave and Edge installed extension manifests: name, version, permissions, update URL",
    Category::Persistence,
    ANY_OS,
    profile_files!("Extensions/*/*/manifest.json"),
    parse_extensions,
)
.companions(profile_files!("Extensions/*/*/_locales/*/messages.json"));

/// The names of the columns of `table`.
fn columns(db: &crate::sqlite::Database, table: &str) -> Vec<String> {
    let Ok(mut stmt) = db.conn.prepare(&format!("PRAGMA table_info({table})")) else { return Vec::new() };
    let Ok(rows) = stmt.query_map([], |row| row.get::<_, String>(1)) else { return Vec::new() };
    rows.flatten().collect()
}

#[derive(Serialize)]
struct CookieRow<'a> {
    user: &'a str,
    browser: &'static str,
    profile: &'a str,
    /// `host_key`: the domain the cookie belongs to (a leading dot means subdomains too).
    domain: Option<String>,
    name: Option<String>,
    path: Option<String>,
    created: Option<Timestamp>,
    last_access: Option<Timestamp>,
    /// Empty for a session cookie.
    expires: Option<Timestamp>,
    secure: Option<bool>,
    http_only: Option<bool>,
    /// `-1` unspecified, `0` none, `1` lax, `2` strict.
    same_site: Option<i64>,
    /// 0 unset, 1 set over HTTP, 2 over HTTPS.
    source_scheme: Option<i64>,
    /// Whether the database holds a value (it is not read).
    has_value: bool,
}

impl Record for CookieRow<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let message = format!(
            "{} cookie {} set for {}",
            self.user,
            self.name.as_deref().unwrap_or("?"),
            self.domain.as_deref().unwrap_or("?")
        );
        self.created.map(|t| Event::new(t, "cookie_created", cap(message))).into_iter()
    }
}

fn parse_cookies(input: &Input, sink: &mut Sink) -> Result<()> {
    let db = open_with_tables(input, &["cookies"])?;
    let (user, browser, profile) = (user_from_path(input.path), browser_of(input.path), profile_of(input.path));
    // The profile directory of `Default/Network/Cookies` is one level up.
    let profile = if profile == "Network" { input.path.rsplit('/').nth(2).unwrap_or(profile) } else { profile };
    let have = columns(&db, "cookies");
    // Only columns that exist in this version; the value columns are never selected, only measured.
    let col = |name: &str, fallback: &str| {
        if have.iter().any(|c| c == name) {
            name.to_string()
        } else {
            fallback.to_string()
        }
    };
    let sql = format!(
        "SELECT creation_utc, host_key, name, path, {}, {}, {}, {}, {}, {}, {}, \
         (length(value) > 0 OR length(encrypted_value) > 0) FROM cookies ORDER BY creation_utc, rowid",
        col("expires_utc", "0"),
        col("last_access_utc", "0"),
        col("is_secure", "NULL"),
        col("is_httponly", "NULL"),
        col("samesite", "NULL"),
        col("source_scheme", "NULL"),
        col("has_expires", "1")
    );
    let mut stmt = db.conn.prepare(&sql).map_err(sql_error)?;
    let mut rows = stmt.query([]).map_err(sql_error)?;
    while let Some(row) = rows.next().map_err(sql_error)? {
        let created = webkit_at(sink, row, 0, "creation_utc");
        let has_expires = int_at(row, 11) != Some(0);
        let expires = if has_expires { webkit_at(sink, row, 4, "expires_utc") } else { None };
        let last_access = webkit_at(sink, row, 5, "last_access_utc");
        sink.emit(
            Loc::None,
            &CookieRow {
                user,
                browser,
                profile,
                domain: text_at(row, 1),
                name: text_at(row, 2),
                path: text_at(row, 3),
                created,
                last_access,
                expires,
                secure: int_at(row, 6).map(|v| v != 0),
                http_only: int_at(row, 7).map(|v| v != 0),
                same_site: int_at(row, 8),
                source_scheme: int_at(row, 9),
                has_value: int_at(row, 10) == Some(1),
            },
        )?;
    }
    Ok(())
}

#[derive(Serialize)]
struct LoginRow<'a> {
    user: &'a str,
    browser: &'static str,
    profile: &'a str,
    origin_url: Option<String>,
    signon_realm: Option<String>,
    username: Option<String>,
    created: Option<Timestamp>,
    last_used: Option<Timestamp>,
    password_modified: Option<Timestamp>,
    times_used: Option<i64>,
    /// The user told the browser never to save a password for this site.
    never_save: bool,
    /// Whether a password is stored (the blob is not read).
    password_saved: bool,
}

impl Record for LoginRow<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let who =
            format!("{} on {}", self.username.as_deref().unwrap_or("?"), self.origin_url.as_deref().unwrap_or("?"));
        let mut events = Vec::new();
        if let Some(t) = self.created {
            events.push(Event::new(t, "login_saved", cap(format!("{} saved a login for {who}", self.user))));
        }
        if let Some(t) = self.last_used.filter(|t| Some(*t) != self.created) {
            events.push(Event::new(t, "login_used", cap(format!("{} used the saved login for {who}", self.user))));
        }
        events.into_iter()
    }
}

fn parse_logins(input: &Input, sink: &mut Sink) -> Result<()> {
    let db = open_with_tables(input, &["logins"])?;
    let (user, browser, profile) = (user_from_path(input.path), browser_of(input.path), profile_of(input.path));
    let have = columns(&db, "logins");
    let col = |name: &str, fallback: &str| {
        if have.iter().any(|c| c == name) {
            name.to_string()
        } else {
            fallback.to_string()
        }
    };
    // `password_value`, `form_data`, `possible_username_pairs` and the notes are never read.
    let sql = format!(
        "SELECT origin_url, signon_realm, username_value, date_created, {}, {}, {}, {}, (length(password_value) > 0) \
         FROM logins ORDER BY date_created, rowid",
        col("date_last_used", "0"),
        col("date_password_modified", "0"),
        col("times_used", "NULL"),
        col("blacklisted_by_user", "0")
    );
    let mut stmt = db.conn.prepare(&sql).map_err(sql_error)?;
    let mut rows = stmt.query([]).map_err(sql_error)?;
    while let Some(row) = rows.next().map_err(sql_error)? {
        let created = webkit_at(sink, row, 3, "date_created");
        let last_used = webkit_at(sink, row, 4, "date_last_used");
        let password_modified = webkit_at(sink, row, 5, "date_password_modified");
        sink.emit(
            Loc::None,
            &LoginRow {
                user,
                browser,
                profile,
                origin_url: text_at(row, 0),
                signon_realm: text_at(row, 1),
                username: text_at(row, 2).filter(|u| !u.is_empty()),
                created,
                last_used,
                password_modified,
                times_used: int_at(row, 6),
                never_save: int_at(row, 7).is_some_and(|v| v != 0),
                password_saved: int_at(row, 8) == Some(1),
            },
        )?;
    }
    Ok(())
}

/// Chromium's `ManifestLocation`, from `extensions/common/manifest.h`.
fn extension_location(value: i64) -> Cow<'static, str> {
    Cow::Borrowed(match value {
        1 => "internal",
        2 => "external_pref",
        3 => "external_registry",
        4 => "unpacked",
        5 => "component",
        6 => "external_pref_download",
        7 => "external_policy_download",
        8 => "command_line",
        9 => "external_policy",
        10 => "external_component",
        n => return Cow::Owned(format!("unknown({n})")),
    })
}

#[derive(Serialize)]
struct ExtensionSetting<'a> {
    time: Option<Timestamp>,
    user: &'a str,
    browser: &'static str,
    profile: &'a str,
    id: String,
    name: Option<String>,
    version: Option<String>,
    from_webstore: Option<bool>,
    /// `unpacked` and `command_line` extensions were loaded from a folder: a developer-mode
    /// extension is how malicious extensions are installed by hand.
    location: Option<Cow<'static, str>>,
    /// The folder of an unpacked extension.
    path: Option<String>,
    enabled: bool,
    disable_reasons: Vec<i64>,
    last_update: Option<Timestamp>,
    api_permissions: Vec<String>,
    host_permissions: Vec<String>,
    /// The `Preferences` file the entry came from (`Secure Preferences` is read beside it).
    source: &'static str,
}

impl Record for ExtensionSetting<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let message = format!(
            "{} installed extension {} {} ({}){}",
            self.user,
            self.name.as_deref().unwrap_or(&self.id),
            self.version.as_deref().unwrap_or(""),
            self.location.as_deref().unwrap_or("?"),
            self.path.as_deref().map(|p| format!(" from {p}")).unwrap_or_default()
        );
        self.time.map(|t| Event::new(t, "extension_installed", cap(message))).into_iter()
    }
}

fn json_strings(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect())
        .unwrap_or_default()
}

/// A time that Chromium stores as a decimal string of webkit microseconds.
fn json_webkit(value: Option<&Value>) -> Option<Timestamp> {
    let micros = match value? {
        Value::String(s) => s.parse::<i64>().ok()?,
        Value::Number(n) => n.as_i64()?,
        _ => return None,
    };
    Some(micros).filter(|m| *m > 0).and_then(webkit_time)
}

fn parse_extension_settings(input: &Input, sink: &mut Sink) -> Result<()> {
    use serde_json::Value;
    let (user, browser, profile) = (user_from_path(input.path), browser_of(input.path), profile_of(input.path));
    let mut seen_any = false;
    // The entries are in `Preferences`, and in `Secure Preferences` on Windows and macOS builds;
    // read both when both are there. Each extension id is reported once, the second file filling in.
    let secure_path = input.path.replace("/Preferences", "/Secure Preferences");
    let secure = input.host.read(&secure_path);
    let mut documents: Vec<(&'static str, Vec<u8>)> = vec![("Preferences", input.data.to_vec())];
    if let Some(secure) = secure {
        documents.push(("Secure Preferences", secure.to_vec()));
    }
    let mut reported = std::collections::HashSet::new();
    for (source, bytes) in documents {
        let Ok(doc) = serde_json::from_slice::<Value>(&bytes) else {
            if source == "Preferences" {
                return Err(Error::format("Preferences is not JSON"));
            }
            sink.warn("Secure Preferences is not JSON");
            continue;
        };
        let Some(settings) = doc.pointer("/extensions/settings").and_then(Value::as_object) else { continue };
        for (id, entry) in settings {
            if !reported.insert(id.clone()) {
                continue;
            }
            seen_any = true;
            let manifest = entry.get("manifest");
            let permissions = entry.get("active_permissions").or_else(|| entry.get("granted_permissions"));
            let location = entry.get("location").and_then(Value::as_i64);
            let reasons: Vec<i64> = entry
                .get("disable_reasons")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_i64).collect())
                .unwrap_or_default();
            // An older profile keeps a `state` (0 disabled, 1 enabled) instead of disable reasons.
            let enabled = reasons.is_empty() && entry.get("state").and_then(Value::as_i64) != Some(0);
            sink.emit(
                Loc::None,
                &ExtensionSetting {
                    time: json_webkit(entry.get("first_install_time")),
                    user,
                    browser,
                    profile,
                    id: id.clone(),
                    name: manifest.and_then(|m| m.get("name")).and_then(Value::as_str).map(str::to_string),
                    version: manifest.and_then(|m| m.get("version")).and_then(Value::as_str).map(str::to_string),
                    from_webstore: entry.get("from_webstore").and_then(Value::as_bool),
                    location: location.map(extension_location),
                    path: entry.get("path").and_then(Value::as_str).map(str::to_string),
                    enabled,
                    disable_reasons: reasons,
                    last_update: json_webkit(entry.get("last_update_time")),
                    api_permissions: json_strings(permissions.and_then(|p| p.get("api"))),
                    host_permissions: json_strings(permissions.and_then(|p| p.get("explicit_host"))),
                    source,
                },
            )?;
        }
    }
    if seen_any {
        Ok(())
    } else {
        Err(Error::skipped("no extensions in this profile"))
    }
}

#[derive(Serialize)]
struct ExtensionManifest<'a> {
    user: &'a str,
    browser: &'static str,
    profile: &'a str,
    /// The extension id: the folder name under `Extensions/`.
    id: &'a str,
    /// The folder name under the id: version and install counter (`1.2.3_0`).
    folder: &'a str,
    name: Option<String>,
    version: Option<String>,
    description: Option<String>,
    manifest_version: Option<i64>,
    permissions: Vec<String>,
    host_permissions: Vec<String>,
    update_url: Option<String>,
    /// Whether the manifest carries a `key` (a fixed id, as unpacked and store extensions have).
    has_key: bool,
    /// Background scripts or service worker, content script match patterns: what runs by itself.
    background: Vec<String>,
    content_script_matches: Vec<String>,
}

impl Record for ExtensionManifest<'_> {}

/// `__MSG_name__` resolved against `_locales/<default_locale>/messages.json` (then `en`).
fn localized(input: &Input, dir: &str, default_locale: Option<&str>, text: &str) -> String {
    let Some(key) = text.strip_prefix("__MSG_").and_then(|k| k.strip_suffix("__")) else { return text.to_string() };
    for locale in default_locale.into_iter().chain(["en", "en_US"]) {
        let Some(bytes) = input.host.read(&format!("{dir}/_locales/{locale}/messages.json")) else { continue };
        let Ok(messages) = serde_json::from_slice::<Value>(&bytes) else { continue };
        // Message keys are case-insensitive.
        let found = messages.as_object().and_then(|m| m.iter().find(|(k, _)| k.eq_ignore_ascii_case(key)));
        if let Some(message) = found.and_then(|(_, v)| v.get("message")).and_then(Value::as_str) {
            return message.to_string();
        }
    }
    text.to_string()
}

fn parse_extensions(input: &Input, sink: &mut Sink) -> Result<()> {
    let manifest: Value =
        serde_json::from_slice(input.data).map_err(|e| Error::format(format!("manifest.json is not JSON: {e}")))?;
    let (user, browser, profile) = (user_from_path(input.path), browser_of(input.path), "");
    // `<profile>/Extensions/<id>/<version>/manifest.json`
    let mut parts = input.path.rsplit('/');
    parts.next();
    let (folder, id) = (parts.next().unwrap_or_default(), parts.next().unwrap_or_default());
    let dir = input.path.rsplit_once('/').map_or("", |(dir, _)| dir);
    let profile_dir = input.path.rsplit('/').nth(4).unwrap_or(profile);
    let default_locale = manifest.get("default_locale").and_then(Value::as_str);
    let text = |key: &str| manifest.get(key).and_then(Value::as_str).map(|t| localized(input, dir, default_locale, t));
    let mut background = json_strings(manifest.pointer("/background/scripts"));
    if let Some(worker) = manifest.pointer("/background/service_worker").and_then(Value::as_str) {
        background.push(worker.to_string());
    }
    if let Some(page) = manifest.pointer("/background/page").and_then(Value::as_str) {
        background.push(page.to_string());
    }
    let mut matches = Vec::new();
    for script in manifest.get("content_scripts").and_then(Value::as_array).into_iter().flatten().take(64) {
        matches.extend(json_strings(script.get("matches")));
    }
    sink.emit(
        Loc::None,
        &ExtensionManifest {
            user,
            browser,
            profile: profile_dir,
            id,
            folder,
            name: text("name"),
            version: manifest.get("version").and_then(Value::as_str).map(str::to_string),
            description: text("description"),
            manifest_version: manifest.get("manifest_version").and_then(Value::as_i64),
            permissions: json_strings(manifest.get("permissions")),
            host_permissions: json_strings(manifest.get("host_permissions")),
            update_url: manifest.get("update_url").and_then(Value::as_str).map(str::to_string),
            has_key: manifest.get("key").is_some(),
            background,
            content_script_matches: matches,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run, run_on_host};

    const PATH: &str = "home/alice/.config/google-chrome/Default/History";

    #[test]
    fn parses_history() {
        insta::assert_snapshot!(run(&HISTORY, PATH, &fixture("chromium-history/History"), 0));
    }

    /// `n` visits of one URL, and a `urls` table that lists that URL's id `n` times.
    fn duplicate_ids(n: usize) -> Vec<u8> {
        crate::sqlite::database_bytes(&format!(
            "CREATE TABLE urls(id INTEGER, url TEXT, title TEXT, visit_count, typed_count);
             CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, from_visit, transition, visit_duration);
             WITH RECURSIVE c(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM c WHERE i < {n})
             INSERT INTO urls SELECT 1, 'http://x/', 't', 1, 0 FROM c;
             WITH RECURSIVE c(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM c WHERE i < {n})
             INSERT INTO visits(url, visit_time, transition) SELECT 1, 13300000000000000, 0 FROM c;"
        ))
    }

    #[test]
    fn duplicate_url_ids_do_not_multiply_rows() {
        let out = run(&HISTORY, PATH, &duplicate_ids(300), 0);
        assert_eq!(out.matches("\"url\":").count(), 300, "one row per visit");
    }

    #[test]
    fn generated_columns_are_refused() {
        // A virtual generated column is evaluated on every read: 20 MB of text per row.
        let db = crate::sqlite::database_bytes(
            "CREATE TABLE urls(id INTEGER PRIMARY KEY, title TEXT, visit_count, typed_count,
               url TEXT GENERATED ALWAYS AS (printf('%.*c', 20000000, 'x')) VIRTUAL);
             CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, from_visit, transition, visit_duration);
             INSERT INTO urls(id,title) VALUES (1,'t');
             INSERT INTO visits(url, visit_time) VALUES (1,13300000000000000),(1,13300000000000001),(1,13300000000000002);",
        );
        let out = run(&HISTORY, PATH, &db, 0);
        assert!(out.contains("--- failed") && out.len() < 10_000, "{}", out.len());
    }

    #[test]
    fn parses_downloads() {
        insta::assert_snapshot!(run(
            &DOWNLOADS,
            "Users/sam/Library/Application Support/Microsoft Edge/Profile 1/History",
            &fixture("chromium-history/History"),
            0
        ));
    }

    #[test]
    fn download_states_and_transition_bits() {
        let name = |n| download_state(Some(n)).unwrap().into_owned();
        assert_eq!([name(1), name(3), name(4), name(9)], ["complete", "bug_140687", "interrupted", "unknown(9)"]);
        // The qualifier bits above the low byte survive in transition_raw.
        let out = run(&HISTORY, PATH, &fixture("chromium-history/History"), 0);
        assert!(out.contains("\"transition_raw\":"), "{out}");
        assert_eq!(transition_name(Some(0x8000_0001)).as_deref(), Some("typed"));
    }

    #[test]
    fn reads_the_wal() {
        let main = fixture("chromium-history/wal/History");
        let wal = fixture("chromium-history/wal/History-wal");
        let without = run(&HISTORY, PATH, &main, 0);
        assert!(!without.contains("wal-only"), "the main file must not hold the WAL visit");
        let wal_path = format!("{PATH}-wal");
        let with = run_on_host(&HISTORY, &[(PATH, &main), (&wal_path, &wal)], PATH, 0);
        assert!(with.contains("Only In WAL"), "{with}");
    }

    #[test]
    fn skips_non_databases_and_other_databases() {
        for artifact in [&HISTORY, &DOWNLOADS] {
            assert!(run(artifact, PATH, b"just some text\n", 0).contains("--- skipped"));
            assert!(run(artifact, PATH, b"", 0).contains("--- skipped"));
            let places = fixture("firefox-history/places.sqlite");
            assert!(run(artifact, PATH, &places, 0).contains("--- skipped: no "));
        }
    }

    #[test]
    fn damaged_databases_do_not_panic() {
        let data = fixture("chromium-history/History");
        for artifact in [&HISTORY, &DOWNLOADS] {
            for len in (0..data.len()).step_by(8192) {
                run(artifact, PATH, &data[..len], 0);
            }
            let mut seed = 12345u32;
            for _ in 0..8 {
                let mut copy = data.clone();
                for _ in 0..16 {
                    seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
                    let at = (seed as usize >> 4) % copy.len().min(32768);
                    copy[at] ^= 0xff;
                }
                run(artifact, PATH, &copy, 0);
            }
        }
    }

    // ---- real Chromium 156 (Debian 12, headless, driven over the DevTools protocol) ----

    const BASE: &str = "home/alice/.config/chromium/Default";

    fn clean(out: &str) {
        assert!(!out.contains("--- warning") && !out.contains("--- failed"), "{out}");
    }

    /// One download of a 30000-byte file served with `Content-Disposition: attachment`, started
    /// from `index.html`. The expected values were read from the browser's own database
    /// (`SELECT ... FROM downloads` with sqlite3): state 1 (complete), danger type 4, 30000 of
    /// 30000 bytes, start 13439008425758632 and end 13439008425762002 (webkit microseconds), no
    /// interrupt reason.
    #[test]
    fn real_download_row_matches_the_browsers_own_database() {
        let out = run(&DOWNLOADS, &format!("{BASE}/History"), &fixture("chromium-downloads/History-real"), 0);
        clean(&out);
        let rows: Vec<&str> = out.lines().take_while(|l| !l.starts_with("---")).collect();
        assert_eq!(rows.len(), 1, "{out}");
        let row = rows[0];
        // 13439008425758632 - 11644473600 * 10^6 = 1794534825758632 us = 2026-11-13T01:53:45.758632Z
        assert!(
            row.contains("\"time\":\"2026-11-13T01:53:45.758632Z\"")
                && row.contains("\"end_time\":\"2026-11-13T01:53:45.762002Z\""),
            "{row}"
        );
        assert!(
            row.contains("\"target_path\":\"/tmp/dl/payload.bin\"")
                && row.contains("\"url\":\"http://127.0.0.1:8123/payload.bin\""),
            "{row}"
        );
        assert!(
            row.contains("\"referrer\":\"\"") && row.contains("\"tab_url\":\"http://127.0.0.1:8123/index.html\""),
            "{row}"
        );
        assert!(row.contains("\"received_bytes\":30000,\"total_bytes\":30000,\"state\":\"complete\",\"danger_type\":4,\"opened\":false,\"mime_type\":\"application/octet-stream\""), "{row}");
        let history = run(&HISTORY, &format!("{BASE}/History"), &fixture("chromium-downloads/History-real"), 0);
        assert!(history.contains("\"title\":\"Nx test page\""), "{history}");
    }

    /// The two cookies the page set: `sid` (HttpOnly, one day) and `pref` (one hour). Values are
    /// encrypted in the database and are not read at all.
    #[test]
    fn real_cookies_have_metadata_and_no_value() {
        let out = run(&COOKIES, &format!("{BASE}/Cookies"), &fixture("chromium-cookies/Cookies"), 0);
        clean(&out);
        assert_eq!(out.lines().take_while(|l| !l.starts_with("---")).count(), 2);
        let sid = out.lines().find(|l| l.contains("\"name\":\"sid\"")).unwrap_or_default();
        assert!(
            sid.contains("\"domain\":\"127.0.0.1\",\"name\":\"sid\",\"path\":\"/\"")
                && sid.contains("\"http_only\":true,\"same_site\":-1,\"source_scheme\":1,\"has_value\":true"),
            "{sid}"
        );
        // 13439094823751559 - 13439008423741090 = 86400010469 us: a Max-Age of one day.
        assert!(
            sid.contains("\"created\":\"2026-11-13T01:53:43.741090Z\"")
                && sid.contains("\"expires\":\"2026-11-14T01:53:43.751559Z\""),
            "{sid}"
        );
        assert!(!out.contains("SECRETCOOKIEVALUE123"));
        assert!(out.contains("cookie_created"));
        insta::assert_snapshot!(out);
    }

    /// The `logins` table is the real schema of Chromium 156 with two rows inserted by sqlite (a
    /// login is saved only through the browser's UI). The password blobs carry planted secrets.
    #[test]
    fn logins_never_expose_the_password_blob() {
        let out = run(&LOGINS, &format!("{BASE}/Login Data"), &fixture("chromium-logins/Login Data"), 0);
        clean(&out);
        assert!(!out.contains("PLANTED") && !out.contains("password_value"), "a secret leaked: {out}");
        assert_eq!(out.lines().take_while(|l| !l.starts_with("---")).count(), 2);
        assert!(
            out.contains("\"username\":\"alice@example.test\"")
                && out.contains("\"times_used\":7")
                && out.contains("\"password_saved\":true"),
            "{out}"
        );
        assert!(
            out.contains("\"never_save\":true") && out.contains("login_saved") && out.contains("login_used"),
            "{out}"
        );
        insta::assert_snapshot!(out);
    }

    /// Real `Preferences`: a command-line (`--load-extension`) extension with its folder and the built-in PDF viewer.
    #[test]
    fn extension_settings_show_an_unpacked_extension_and_its_folder() {
        let prefs = fixture("chromium-extension-settings/Preferences");
        let secure = fixture("chromium-extension-settings/Secure Preferences");
        let path = format!("{BASE}/Preferences");
        let out = run_on_host(
            &EXTENSION_SETTINGS,
            &[(&path, &prefs), (&format!("{BASE}/Secure Preferences"), &secure)],
            &path,
            0,
        );
        clean(&out);
        let ours = out.lines().find(|l| l.contains("klofmejghlpmlnjbaladlgfficdlemji")).unwrap_or_default();
        assert!(
            ours.contains("\"from_webstore\":false,\"location\":\"command_line\",\"path\":\"/ext\",\"enabled\":true"),
            "{ours}"
        );
        assert!(
            ours.contains("\"api_permissions\":[\"cookies\",\"tabs\",\"webRequest\"]")
                && ours.contains("\"host_permissions\":[\"<all_urls>\"]"),
            "{ours}"
        );
        assert!(ours.contains("\"time\":\"2026-11-13T01:53:37.8"), "{ours}");
        assert!(out.contains("\"location\":\"component\"") && out.contains("extension_installed"), "{out}");
        assert!(run(&EXTENSION_SETTINGS, &path, b"{}", 0).contains("skipped"));
        assert!(run(&EXTENSION_SETTINGS, &path, b"not json", 0).contains("not JSON"));
    }

    /// The manifest and `_locales` of the extension that was loaded: `__MSG_extName__` is resolved.
    #[test]
    fn extension_manifest_resolves_localised_names() {
        let manifest = fixture("chromium-extensions/manifest.json");
        let messages = fixture("chromium-extensions/_locales/en/messages.json");
        let dir = format!("{BASE}/Extensions/klofmejghlpmlnjbaladlgfficdlemji/1.2.3_0");
        let path = format!("{dir}/manifest.json");
        let out = run_on_host(
            &EXTENSIONS,
            &[(&path, &manifest), (&format!("{dir}/_locales/en/messages.json"), &messages)],
            &path,
            0,
        );
        clean(&out);
        assert!(out.contains("\"id\":\"klofmejghlpmlnjbaladlgfficdlemji\",\"folder\":\"1.2.3_0\",\"name\":\"Nx Test Extension\",\"version\":\"1.2.3\",\"description\":\"Reads everything\""), "{out}");
        assert!(
            out.contains("\"permissions\":[\"tabs\",\"cookies\",\"webRequest\"]")
                && out.contains("\"update_url\":\"https://clients2.google.com/service/update2/crx\""),
            "{out}"
        );
        assert!(out.contains("\"background\":[\"bg.js\"]") && out.contains("\"profile\":\"Default\""), "{out}");
        // Without the locale file the placeholder is kept, not invented.
        assert!(run(&EXTENSIONS, &path, &manifest, 0).contains("\"name\":\"__MSG_extName__\""));
        assert!(run(&EXTENSIONS, &path, b"{\"name\": ", 0).contains("not JSON"));
    }

    #[test]
    fn flatpak_and_snap_profiles_are_covered() {
        use nixcavate_source::glob::Pattern;
        for (artifact, file) in [
            (&HISTORY, "History"),
            (&COOKIES, "Cookies"),
            (&LOGINS, "Login Data"),
            (&EXTENSION_SETTINGS, "Preferences"),
        ] {
            for root in [
                "home/a/.var/app/com.google.Chrome/config/google-chrome/Default",
                "home/a/.var/app/org.chromium.Chromium/config/chromium/Profile 1",
                "home/a/snap/chromium/common/chromium/Default",
                "home/a/.var/app/com.brave.Browser/config/BraveSoftware/Brave-Browser/Default",
            ] {
                let path = format!("{root}/{file}");
                assert!(artifact.paths.iter().any(|p| Pattern::new(p).matches(&path)), "{} misses {path}", artifact.id);
            }
        }
    }

    #[test]
    fn mutated_profile_files_never_panic() {
        let mut seed = 17u64;
        let prefs = fixture("chromium-extension-settings/Preferences");
        for cut in (0..prefs.len()).step_by(11) {
            run(&EXTENSION_SETTINGS, &format!("{BASE}/Preferences"), &prefs[..cut], 0);
        }
        for (artifact, name, file) in
            [(&COOKIES, "chromium-cookies/Cookies", "Cookies"), (&LOGINS, "chromium-logins/Login Data", "Login Data")]
        {
            let db = fixture(name);
            for _ in 0..40 {
                let mut copy = db.clone();
                for _ in 0..8 {
                    seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                    let at = (seed >> 33) as usize % copy.len();
                    copy[at] = (seed >> 20) as u8;
                }
                run(artifact, &format!("{BASE}/{file}"), &copy, 0);
            }
        }
    }
}
