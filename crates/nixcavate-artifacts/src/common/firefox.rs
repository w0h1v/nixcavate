//! Firefox browsing history and downloads: `places.sqlite`. Format reference: Mozilla's Places
//! database documentation (`toolkit/components/places`: `moz_places`, `moz_historyvisits`,
//! `moz_annos`) and `nsINavHistoryService` for the visit types. Modern Firefox keeps downloads
//! as annotations on the downloaded URL's place: the destination file and a JSON `metaData`.

use super::chromium::{cap, download_message, profile_of, visit_message};
use crate::common::home::user_from_path;
use crate::macos::plist_util::or_warn;
use crate::sqlite::{int_at, open_with_tables, sql_error, text_at, unique_rows};
use crate::{Artifact, Category, Input, ANY_OS};
use nixcavate_core::{Basis, Error, Event, Loc, Precision, Record, Result, Sink, Timestamp};
use serde::Serialize;
use serde_json::Value;
use std::borrow::Cow;

pub const HISTORY: Artifact = Artifact::new(
    "firefox-history",
    "Firefox browsing history",
    Category::Activity,
    ANY_OS,
    &[
        "home/*/.mozilla/firefox/*/places.sqlite",
        "home/*/snap/firefox/common/.mozilla/firefox/*/places.sqlite",
        "root/.mozilla/firefox/*/places.sqlite",
        "Users/*/Library/Application Support/Firefox/Profiles/*/places.sqlite",
        "home/*/.var/app/org.mozilla.firefox/.mozilla/firefox/*/places.sqlite",
    ],
    parse_history,
)
.companions(WAL);

pub const DOWNLOADS: Artifact =
    Artifact::new("firefox-downloads", "Firefox downloads", Category::Activity, ANY_OS, HISTORY.paths, parse_downloads)
        .companions(WAL);

const WAL: &[&str] = &[
    "home/*/.mozilla/firefox/*/places.sqlite-wal",
    "home/*/snap/firefox/common/.mozilla/firefox/*/places.sqlite-wal",
    "root/.mozilla/firefox/*/places.sqlite-wal",
    "Users/*/Library/Application Support/Firefox/Profiles/*/places.sqlite-wal",
    "home/*/.var/app/org.mozilla.firefox/.mozilla/firefox/*/places.sqlite-wal",
];

/// PRTime: microseconds since the Unix epoch; `None` when it does not fit 1677-2262.
fn prtime(micros: i64) -> Option<Timestamp> {
    Timestamp::checked(
        micros.div_euclid(1_000_000),
        micros.rem_euclid(1_000_000) as u32 * 1000,
        Precision::Micros,
        Basis::Recorded,
    )
}

/// A PRTime read from a row or JSON value; 0 and NULL mean unset.
fn prtime_of(sink: &mut Sink, what: &str, micros: Option<i64>) -> Option<Timestamp> {
    or_warn(sink, what, micros.filter(|&m| m > 0), prtime)
}

fn visit_type(value: Option<i64>) -> Option<Cow<'static, str>> {
    Some(Cow::Borrowed(match value? {
        1 => "link",
        2 => "typed",
        3 => "bookmark",
        4 => "embed",
        5 => "redirect_permanent",
        6 => "redirect_temporary",
        7 => "download",
        8 => "framed_link",
        9 => "reload",
        n => return Some(Cow::Owned(format!("unknown({n})"))),
    }))
}

#[derive(Serialize)]
struct Visit<'a> {
    time: Option<Timestamp>,
    user: &'a str,
    profile: &'a str,
    url: Option<String>,
    title: Option<String>,
    visit_count: Option<i64>,
    visit_type: Option<Cow<'static, str>>,
    from_visit: Option<i64>,
    typed: Option<bool>,
    frecency: Option<i64>,
}

impl Record for Visit<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        self.time
            .map(|t| Event::new(t, "url_visited", visit_message(self.user, self.url.as_deref(), self.title.as_deref())))
            .into_iter()
    }
}

fn parse_history(input: &Input, sink: &mut Sink) -> Result<()> {
    let db = open_with_tables(input, &["moz_places", "moz_historyvisits"])?;
    let (user, profile) = (user_from_path(input.path), profile_of(input.path));
    let mut stmt = db
        .conn
        .prepare(&format!(
            "SELECT v.visit_date, p.url, p.title, p.visit_count, v.visit_type, v.from_visit, p.typed, p.frecency \
                 FROM moz_historyvisits v LEFT JOIN {} p ON p.id = v.place_id ORDER BY v.visit_date, v.id",
            unique_rows("moz_places", "id")
        ))
        .map_err(sql_error)?;
    let mut rows = stmt.query([]).map_err(sql_error)?;
    while let Some(row) = rows.next().map_err(sql_error)? {
        let time = prtime_of(sink, "visit_date", int_at(row, 0));
        sink.emit(
            Loc::None,
            &Visit {
                time,
                user,
                profile,
                url: text_at(row, 1),
                title: text_at(row, 2),
                visit_count: int_at(row, 3),
                visit_type: visit_type(int_at(row, 4)),
                from_visit: int_at(row, 5),
                typed: int_at(row, 6).map(|n| n != 0),
                frecency: int_at(row, 7),
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
    profile: &'a str,
    url: Option<String>,
    target_path: Option<String>,
    state: Option<Cow<'static, str>>,
    size_bytes: Option<i64>,
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

/// `file:///home/alice/a%20b` to `/home/alice/a b`.
fn path_of_file_uri(uri: &str) -> String {
    let path = uri.strip_prefix("file://").unwrap_or(uri);
    let bytes = path.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while let Some(&b) = bytes.get(i) {
        let hex = |d: Option<&u8>| d.and_then(|&d| (d as char).to_digit(16));
        match (b, hex(bytes.get(i + 1)), hex(bytes.get(i + 2))) {
            (b'%', Some(hi), Some(lo)) => {
                out.push((hi * 16 + lo) as u8);
                i += 3;
            }
            _ => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `nsIDownloadManager` / `DownloadsCommon` state numbers.
fn download_state(value: i64) -> Cow<'static, str> {
    Cow::Borrowed(match value {
        -1 => "not_started",
        0 => "downloading",
        1 => "finished",
        2 => "failed",
        3 => "canceled",
        4 => "paused",
        5 => "queued",
        6 => "blocked_parental",
        7 => "scanning",
        8 => "dirty",
        9 => "blocked_policy",
        n => return Cow::Owned(format!("unknown({n})")),
    })
}

fn parse_downloads(input: &Input, sink: &mut Sink) -> Result<()> {
    let db = open_with_tables(input, &["moz_places", "moz_annos", "moz_anno_attributes"])?;
    let (user, profile) = (user_from_path(input.path), profile_of(input.path));
    let mut stmt = db
        .conn
        .prepare(&format!(
            "SELECT p.url, a.dateAdded, a.content, \
                 (SELECT m.content FROM moz_annos m JOIN moz_anno_attributes t ON t.id = m.anno_attribute_id \
                  WHERE m.place_id = a.place_id AND t.name = 'downloads/metaData' LIMIT 1) \
                 FROM moz_annos a JOIN {} n ON n.id = a.anno_attribute_id \
                 AND n.name = 'downloads/destinationFileURI' LEFT JOIN {} p ON p.id = a.place_id \
                 ORDER BY a.dateAdded, a.id",
            unique_rows("moz_anno_attributes", "id"),
            unique_rows("moz_places", "id")
        ))
        .map_err(sql_error)?;
    let mut rows = stmt.query([]).map_err(sql_error)?;
    while let Some(row) = rows.next().map_err(sql_error)? {
        let meta: Option<Value> = text_at(row, 3).and_then(|t| serde_json::from_str(&t).ok());
        let meta_int = |key: &str| meta.as_ref().and_then(|m| m.get(key)).and_then(Value::as_i64);
        let time = prtime_of(sink, "dateAdded", int_at(row, 1));
        let end = meta_int("endTime").map(|ms| ms.saturating_mul(1000));
        let end_time = prtime_of(sink, "endTime", end);
        sink.emit(
            Loc::None,
            &Download {
                time,
                end_time,
                user,
                profile,
                url: text_at(row, 0),
                target_path: text_at(row, 2).map(|u| path_of_file_uri(&u)),
                state: meta_int("state").map(download_state),
                size_bytes: meta_int("fileSize"),
            },
        )?;
    }
    Ok(())
}

// ---- profile files besides places.sqlite ----

/// Every Firefox profile directory pattern joined with a profile file name.
macro_rules! profile_files {
    ($file:literal) => {
        &[
            concat!("home/*/.mozilla/firefox/*/", $file),
            concat!("home/*/snap/firefox/common/.mozilla/firefox/*/", $file),
            concat!("root/.mozilla/firefox/*/", $file),
            concat!("Users/*/Library/Application Support/Firefox/Profiles/*/", $file),
            concat!("home/*/.var/app/org.mozilla.firefox/.mozilla/firefox/*/", $file),
        ]
    };
}

pub const EXTENSIONS: Artifact = Artifact::new(
    "firefox-extensions",
    "Firefox add-ons: id, version, install time, source URL, signed state, temporary installs",
    Category::Persistence,
    ANY_OS,
    profile_files!("extensions.json"),
    parse_extensions,
);

pub const LOGINS: Artifact = Artifact::new(
    "firefox-logins",
    "Firefox saved logins: site and times (never the user name or password)",
    Category::Activity,
    ANY_OS,
    profile_files!("logins.json"),
    parse_logins,
);

pub const COOKIES: Artifact = Artifact::new(
    "firefox-cookies",
    "Firefox cookies: host, name and times (never the value)",
    Category::Activity,
    ANY_OS,
    profile_files!("cookies.sqlite"),
    parse_cookies,
)
.companions(profile_files!("cookies.sqlite-wal"));

pub const PREFS: Artifact = Artifact::new(
    "firefox-prefs",
    "Firefox preferences a user or a program set that change security: proxy, DNS over HTTPS, signature checks",
    Category::Persistence,
    ANY_OS,
    profile_files!("prefs.js"),
    parse_prefs,
);

pub const USER_JS: Artifact = Artifact::new(
    "firefox-user-js",
    "Firefox user.js: preferences applied at every start (a persistence place)",
    Category::Persistence,
    ANY_OS,
    profile_files!("user.js"),
    parse_prefs,
);

pub const SESSION: Artifact = Artifact::new(
    "firefox-session",
    "Firefox session store: open and closed tabs with their history",
    Category::Activity,
    ANY_OS,
    &[
        "home/*/.mozilla/firefox/*/sessionstore-backups/*.jsonlz4",
        "home/*/.mozilla/firefox/*/sessionstore.jsonlz4",
        "home/*/snap/firefox/common/.mozilla/firefox/*/sessionstore-backups/*.jsonlz4",
        "home/*/snap/firefox/common/.mozilla/firefox/*/sessionstore.jsonlz4",
        "root/.mozilla/firefox/*/sessionstore-backups/*.jsonlz4",
        "Users/*/Library/Application Support/Firefox/Profiles/*/sessionstore-backups/*.jsonlz4",
        "Users/*/Library/Application Support/Firefox/Profiles/*/sessionstore.jsonlz4",
        "home/*/.var/app/org.mozilla.firefox/.mozilla/firefox/*/sessionstore-backups/*.jsonlz4",
    ],
    parse_session,
);

/// Milliseconds since the epoch (`installDate`, `timeCreated`).
fn millis_time(value: Option<&Value>) -> Option<Timestamp> {
    let ms = value?.as_i64().filter(|m| *m > 0)?;
    Timestamp::checked(
        ms.div_euclid(1000),
        (ms.rem_euclid(1000) as u32) * 1_000_000,
        Precision::Millis,
        Basis::Recorded,
    )
}

fn strings(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect())
        .unwrap_or_default()
}

#[derive(Serialize)]
struct Addon<'a> {
    time: Option<Timestamp>,
    user: &'a str,
    profile: &'a str,
    id: Option<String>,
    name: Option<String>,
    version: Option<String>,
    /// `extension`, `theme`, `locale`, `dictionary`...
    addon_type: Option<String>,
    /// `app-profile` (installed by the user), `app-temporary` (loaded from `about:debugging`),
    /// `app-system-addons`, `app-builtin`, `app-system-defaults`...
    location: Option<String>,
    /// Loaded for this session only from a folder or file: the developer's way in.
    temporarily_installed: bool,
    active: Option<bool>,
    user_disabled: Option<bool>,
    update_date: Option<Timestamp>,
    /// Where the `.xpi` came from (`https://addons.mozilla.org/...`).
    source_uri: Option<String>,
    /// How the install was triggered (`amo`, `about:addons`, `sideload`, ...).
    install_source: Option<String>,
    /// 2 is signed by Mozilla, 0 missing, 1 preliminary, 3 system, 4 privileged, negative values: broken or unknown.
    signed_state: Option<i64>,
    foreign_install: Option<bool>,
    path: Option<String>,
    permissions: Vec<String>,
    origins: Vec<String>,
}

impl Record for Addon<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let message = format!(
            "{} installed add-on {} {} ({}){}",
            self.user,
            self.name.as_deref().or(self.id.as_deref()).unwrap_or("?"),
            self.version.as_deref().unwrap_or(""),
            self.location.as_deref().unwrap_or("?"),
            if self.temporarily_installed { ", temporarily" } else { "" }
        );
        self.time.map(|t| Event::new(t, "extension_installed", cap(message))).into_iter()
    }
}

fn parse_extensions(input: &Input, sink: &mut Sink) -> Result<()> {
    let doc: Value =
        serde_json::from_slice(input.data).map_err(|e| Error::format(format!("extensions.json is not JSON: {e}")))?;
    let Some(addons) = doc.get("addons").and_then(Value::as_array) else {
        return Err(Error::format("extensions.json has no addons list"));
    };
    let (user, profile) = (user_from_path(input.path), profile_of(input.path));
    for addon in addons.iter().take(100_000) {
        let location = addon.get("location").and_then(Value::as_str).map(str::to_string);
        let text = |key: &str| addon.get(key).and_then(Value::as_str).map(str::to_string);
        let name = addon
            .pointer("/defaultLocale/name")
            .or_else(|| addon.pointer("/locales/0/name"))
            .and_then(Value::as_str)
            .map(str::to_string);
        sink.emit(
            Loc::None,
            &Addon {
                time: millis_time(addon.get("installDate")),
                user,
                profile,
                id: text("id"),
                name,
                version: text("version"),
                addon_type: text("type"),
                temporarily_installed: addon.get("temporarilyInstalled").and_then(Value::as_bool).unwrap_or(false)
                    || location.as_deref() == Some("app-temporary"),
                location,
                active: addon.get("active").and_then(Value::as_bool),
                user_disabled: addon.get("userDisabled").and_then(Value::as_bool),
                update_date: millis_time(addon.get("updateDate")),
                source_uri: text("sourceURI"),
                install_source: addon
                    .pointer("/installTelemetryInfo/source")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                signed_state: addon.get("signedState").and_then(Value::as_i64),
                foreign_install: addon.get("foreignInstall").and_then(Value::as_bool),
                path: text("path"),
                permissions: strings(addon.pointer("/userPermissions/permissions")),
                origins: strings(addon.pointer("/userPermissions/origins")),
            },
        )?;
    }
    Ok(())
}

#[derive(Serialize)]
struct LoginEntry<'a> {
    user: &'a str,
    profile: &'a str,
    /// `hostname`: the site the login was saved for.
    site: Option<String>,
    form_submit_url: Option<String>,
    http_realm: Option<String>,
    username_field: Option<String>,
    password_field: Option<String>,
    guid: Option<String>,
    created: Option<Timestamp>,
    last_used: Option<Timestamp>,
    password_changed: Option<Timestamp>,
    times_used: Option<i64>,
}

impl Record for LoginEntry<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let site = self.site.as_deref().unwrap_or("?");
        let mut events = Vec::new();
        if let Some(t) = self.created {
            events.push(Event::new(t, "login_saved", cap(format!("{} saved a login for {site}", self.user))));
        }
        if let Some(t) = self.last_used.filter(|t| Some(*t) != self.created) {
            events.push(Event::new(t, "login_used", cap(format!("{} used the saved login for {site}", self.user))));
        }
        events.into_iter()
    }
}

fn parse_logins(input: &Input, sink: &mut Sink) -> Result<()> {
    let doc: Value =
        serde_json::from_slice(input.data).map_err(|e| Error::format(format!("logins.json is not JSON: {e}")))?;
    let Some(logins) = doc.get("logins").and_then(Value::as_array) else {
        return Err(Error::format("logins.json has no logins list"));
    };
    let (user, profile) = (user_from_path(input.path), profile_of(input.path));
    for login in logins.iter().take(1_000_000) {
        // `encryptedUsername`, `encryptedPassword`, `encType` and the rest are never looked at.
        let text = |key: &str| login.get(key).and_then(Value::as_str).map(str::to_string).filter(|s| !s.is_empty());
        sink.emit(
            Loc::None,
            &LoginEntry {
                user,
                profile,
                site: text("hostname"),
                form_submit_url: text("formSubmitURL"),
                http_realm: text("httpRealm"),
                username_field: text("usernameField"),
                password_field: text("passwordField"),
                guid: text("guid"),
                created: millis_time(login.get("timeCreated")),
                last_used: millis_time(login.get("timeLastUsed")),
                password_changed: millis_time(login.get("timePasswordChanged")),
                times_used: login.get("timesUsed").and_then(Value::as_i64),
            },
        )?;
    }
    Ok(())
}

#[derive(Serialize)]
struct CookieEntry<'a> {
    user: &'a str,
    profile: &'a str,
    domain: Option<String>,
    name: Option<String>,
    path: Option<String>,
    created: Option<Timestamp>,
    last_access: Option<Timestamp>,
    /// Empty for a session cookie.
    expires: Option<Timestamp>,
    secure: Option<bool>,
    http_only: Option<bool>,
    /// 0 none, 1 lax, 2 strict.
    same_site: Option<i64>,
    /// Container tab or private-browsing marker (`^userContextId=2`), empty for the default.
    origin_attributes: Option<String>,
    has_value: bool,
}

impl Record for CookieEntry<'_> {
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
    let db = open_with_tables(input, &["moz_cookies"])?;
    let (user, profile) = (user_from_path(input.path), profile_of(input.path));
    let have: Vec<String> = db
        .conn
        .prepare("PRAGMA table_info(moz_cookies)")
        .and_then(|mut s| s.query_map([], |r| r.get::<_, String>(1)).map(|rows| rows.flatten().collect()))
        .unwrap_or_default();
    let col = |name: &str, fallback: &str| {
        if have.iter().any(|c| c == name) {
            name.to_string()
        } else {
            fallback.to_string()
        }
    };
    // `value` is only measured.
    let sql = format!(
        "SELECT {}, host, name, path, expiry, {}, {}, {}, {}, {}, (length(value) > 0) FROM moz_cookies ORDER BY {}, id",
        col("creationTime", "0"),
        col("lastAccessed", "0"),
        col("isSecure", "NULL"),
        col("isHttpOnly", "NULL"),
        col("sameSite", "NULL"),
        col("originAttributes", "NULL"),
        col("creationTime", "id")
    );
    let mut stmt = db.conn.prepare(&sql).map_err(sql_error)?;
    let mut rows = stmt.query([]).map_err(sql_error)?;
    while let Some(row) = rows.next().map_err(sql_error)? {
        let created = prtime_of(sink, "creationTime", int_at(row, 0));
        let last_access = prtime_of(sink, "lastAccessed", int_at(row, 5));
        // `expiry` is milliseconds in current Firefox and seconds in old profiles (read from a real
        // profile: 1794621369545 for a cookie that lives one day). No cookie expires before 1973 in
        // milliseconds or after year 5138 in seconds, so the size of the number tells the unit.
        let expires = int_at(row, 4).filter(|e| *e > 1).and_then(|e| {
            if e >= 100_000_000_000 {
                Timestamp::checked(
                    e.div_euclid(1000),
                    (e.rem_euclid(1000) as u32) * 1_000_000,
                    Precision::Millis,
                    Basis::Recorded,
                )
            } else {
                Timestamp::checked(e, 0, Precision::Seconds, Basis::Recorded)
            }
        });
        sink.emit(
            Loc::None,
            &CookieEntry {
                user,
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
                origin_attributes: text_at(row, 9).filter(|o| !o.is_empty()),
                has_value: int_at(row, 10) == Some(1),
            },
        )?;
    }
    Ok(())
}

// ---- prefs.js and user.js ----

/// The preferences that change what the browser trusts or where its traffic goes. A name ending
/// in `.` is a prefix, any other is exact. Everything else in `prefs.js` is interface state and
/// timestamps, and is not listed.
const SECURITY_PREFS: &[&str] = &[
    "network.proxy.",
    "network.trr.",
    "network.dns.",
    "network.cookie.cookieBehavior",
    "network.captive-portal-service.enabled",
    "xpinstall.",
    "extensions.autoDisableScopes",
    "extensions.enabledScopes",
    "extensions.webextensions.restrictedDomains",
    "extensions.langpacks.signatures.required",
    "security.enterprise_roots.enabled",
    "security.ssl.",
    "security.tls.",
    "security.cert_pinning.",
    "security.OCSP.",
    "security.mixed_content.",
    "security.sandbox.",
    "signon.rememberSignons",
    "signon.autofillForms",
    "browser.safebrowsing.malware.enabled",
    "browser.safebrowsing.phishing.enabled",
    "browser.safebrowsing.downloads.enabled",
    "privacy.trackingprotection.enabled",
    "privacy.firstparty.isolate",
    "app.update.auto",
    "app.update.enabled",
    "app.update.url",
    "dom.security.https_only_mode",
    "general.config.filename",
    "general.config.obscure_value",
    "general.config.sandbox_enabled",
    "browser.startup.homepage",
    "browser.newtab.url",
    "media.peerconnection.ice.proxy_only",
    "toolkit.telemetry.enabled",
];

fn security_pref(name: &str) -> bool {
    SECURITY_PREFS.iter().any(|p| if p.ends_with('.') { name.starts_with(p) } else { name == *p })
}

#[derive(Serialize)]
struct Pref<'a> {
    user: &'a str,
    profile: &'a str,
    /// `prefs.js` or `user.js`.
    file: &'a str,
    name: String,
    /// The value as the file writes it: a JSON string, number or `true`/`false`.
    value: String,
}

impl Record for Pref<'_> {}

fn parse_prefs(input: &Input, sink: &mut Sink) -> Result<()> {
    let (user, profile) = (user_from_path(input.path), profile_of(input.path));
    let file = input.path.rsplit('/').next().unwrap_or_default();
    let mut seen = false;
    crate::text::for_each_line(input, |line| {
        let text = crate::text::lossy(line.bytes);
        let text = text.trim();
        let Some(call) = text.strip_prefix("user_pref(").or_else(|| text.strip_prefix("pref(")) else { return Ok(()) };
        seen = true;
        let Some(body) = call.strip_suffix(");") else { return Ok(()) };
        // `"name", value`: the name is a JSON string with no comma in the interesting ones.
        let Some((name, value)) = body.split_once(", ") else { return Ok(()) };
        let name = name.trim().trim_matches('"');
        if security_pref(name) {
            sink.emit(
                Loc::Line(line.number),
                &Pref { user, profile, file, name: name.to_string(), value: value.trim().to_string() },
            )?;
        }
        Ok(())
    })?;
    if seen {
        Ok(())
    } else {
        Err(Error::skipped("no preferences"))
    }
}

// ---- session store ----

/// The decompressed size a session file may claim; a tab history of this size is far beyond real use.
const MAX_SESSION: usize = 256 << 20;

#[derive(Serialize)]
struct SessionTab<'a> {
    user: &'a str,
    profile: &'a str,
    /// `open` or `closed`.
    state: &'static str,
    window: usize,
    /// The last time the tab was used.
    time: Option<Timestamp>,
    /// The URL shown now (the history entry at `index`).
    url: Option<String>,
    title: Option<String>,
    history_entries: usize,
    /// Every URL of the tab's history, oldest first.
    history: Vec<String>,
    pinned: bool,
}

impl Record for SessionTab<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let message = format!(
            "{} had {} {} tab on {}",
            self.user,
            self.state,
            if self.pinned { "a pinned" } else { "a" },
            self.url.as_deref().unwrap_or("(unknown URL)")
        );
        self.time.map(|t| Event::new(t, "tab_used", cap(message))).into_iter()
    }
}

/// Decompresses a `mozLz40\0` file: the 8-byte magic, a little-endian 32-bit size, one LZ4 block.
fn mozlz4(data: &[u8]) -> Result<Vec<u8>> {
    let body = data.strip_prefix(b"mozLz40\0").ok_or_else(|| Error::format("not a mozlz4 file: no mozLz40 magic"))?;
    let size = body
        .get(..4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize)
        .ok_or_else(|| Error::format("mozlz4 file ends inside its header"))?;
    if size > MAX_SESSION {
        return Err(Error::format(format!(
            "mozlz4 declares {size} decompressed bytes, more than the {MAX_SESSION} this reader accepts"
        )));
    }
    // `decompress` never writes past `size` and fails on a stream that would.
    lz4_flex::block::decompress(body.get(4..).unwrap_or_default(), size)
        .map_err(|e| Error::format(format!("mozlz4: damaged LZ4 block: {e}")))
}

fn parse_session(input: &Input, sink: &mut Sink) -> Result<()> {
    let json = mozlz4(input.data)?;
    let doc: Value =
        serde_json::from_slice(&json).map_err(|e| Error::format(format!("the session is not JSON: {e}")))?;
    // `<profile>/sessionstore-backups/recovery.jsonlz4`: the profile is one level further up.
    let profile = if input.path.contains("/sessionstore-backups/") {
        input.path.rsplit('/').nth(2).unwrap_or_default()
    } else {
        profile_of(input.path)
    };
    let user = user_from_path(input.path);
    let emit_tabs = |sink: &mut Sink, window: usize, tabs: &[Value], state: &'static str| -> Result<()> {
        for tab in tabs.iter().take(100_000) {
            // Closed tabs keep their data under `state`.
            let tab = tab.get("state").unwrap_or(tab);
            let entries: &[Value] = tab.get("entries").and_then(Value::as_array).map_or(&[], Vec::as_slice);
            let index =
                tab.get("index").and_then(Value::as_u64).and_then(|i| usize::try_from(i).ok()).unwrap_or(entries.len());
            let current = index.checked_sub(1).and_then(|i| entries.get(i));
            sink.emit(
                Loc::None,
                &SessionTab {
                    user,
                    profile,
                    state,
                    window,
                    time: millis_time(tab.get("lastAccessed")),
                    url: current.and_then(|e| e.get("url")).and_then(Value::as_str).map(str::to_string),
                    title: current.and_then(|e| e.get("title")).and_then(Value::as_str).map(str::to_string),
                    history_entries: entries.len(),
                    history: entries
                        .iter()
                        .take(1000)
                        .filter_map(|e| e.get("url").and_then(Value::as_str))
                        .map(str::to_string)
                        .collect(),
                    pinned: tab.get("pinned").and_then(Value::as_bool).unwrap_or(false),
                },
            )?;
        }
        Ok(())
    };
    for (i, window) in doc.get("windows").and_then(Value::as_array).into_iter().flatten().take(1000).enumerate() {
        emit_tabs(sink, i, window.get("tabs").and_then(Value::as_array).map_or(&[], Vec::as_slice), "open")?;
        emit_tabs(sink, i, window.get("_closedTabs").and_then(Value::as_array).map_or(&[], Vec::as_slice), "closed")?;
    }
    for (i, window) in doc.get("_closedWindows").and_then(Value::as_array).into_iter().flatten().take(1000).enumerate()
    {
        emit_tabs(sink, i, window.get("tabs").and_then(Value::as_array).map_or(&[], Vec::as_slice), "closed")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run, run_on_host};

    const PATH: &str = "home/alice/.mozilla/firefox/abcd1234.default-release/places.sqlite";

    #[test]
    fn parses_history() {
        insta::assert_snapshot!(run(&HISTORY, PATH, &fixture("firefox-history/places.sqlite"), 0));
    }

    #[test]
    fn parses_downloads() {
        insta::assert_snapshot!(run(&DOWNLOADS, PATH, &fixture("firefox-history/places.sqlite"), 0));
    }

    #[test]
    fn duplicate_place_ids_do_not_multiply_rows() {
        let db = crate::sqlite::database_bytes(
            "CREATE TABLE moz_places(id INTEGER, url TEXT, title TEXT, visit_count, typed, frecency);
             CREATE TABLE moz_historyvisits(id INTEGER PRIMARY KEY, place_id INTEGER, visit_date INTEGER, visit_type, from_visit);
             CREATE TABLE moz_annos(id INTEGER PRIMARY KEY, place_id INTEGER, anno_attribute_id INTEGER, content, dateAdded);
             CREATE TABLE moz_anno_attributes(id INTEGER, name TEXT);
             WITH RECURSIVE c(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM c WHERE i < 200)
             INSERT INTO moz_places SELECT 1, 'http://x/', 't', 1, 0, 0 FROM c;
             WITH RECURSIVE c(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM c WHERE i < 200)
             INSERT INTO moz_anno_attributes SELECT 1, 'downloads/destinationFileURI' FROM c;
             WITH RECURSIVE c(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM c WHERE i < 200)
             INSERT INTO moz_historyvisits(place_id, visit_date, visit_type) SELECT 1, 1700000000000000, 1 FROM c;
             WITH RECURSIVE c(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM c WHERE i < 200)
             INSERT INTO moz_annos(place_id, anno_attribute_id, content, dateAdded) SELECT 1, 1, 'file:///a', 1700000000000000 FROM c;",
        );
        assert_eq!(run(&HISTORY, PATH, &db, 0).matches("\"visit_type\":").count(), 200);
        assert_eq!(run(&DOWNLOADS, PATH, &db, 0).matches("\"target_path\":").count(), 200);
    }

    #[test]
    fn out_of_range_prtime_is_dropped() {
        assert!(prtime(1_700_000_000_000_000).is_some());
        assert!(prtime(i64::MAX).is_none());
        assert_eq!(download_state(5), "queued");
        assert_eq!(download_state(7), "scanning");
    }

    #[test]
    fn decodes_file_uris() {
        assert_eq!(path_of_file_uri("file:///home/a%20b/%e2%82%ac%zz%4"), "/home/a b/\u{20ac}%zz%4");
    }

    #[test]
    fn skips_non_databases_and_other_databases() {
        for artifact in [&HISTORY, &DOWNLOADS] {
            assert!(run(artifact, PATH, b"just some text\n", 0).contains("--- skipped"));
            assert!(run(artifact, PATH, b"", 0).contains("--- skipped"));
            let chromium = fixture("chromium-history/History");
            assert!(run(artifact, PATH, &chromium, 0).contains("--- skipped: no "));
        }
    }

    #[test]
    fn damaged_databases_do_not_panic() {
        let data = fixture("firefox-history/places.sqlite");
        for artifact in [&HISTORY, &DOWNLOADS] {
            for len in (0..data.len()).step_by(8192) {
                run(artifact, PATH, &data[..len], 0);
            }
            let mut seed = 99u32;
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

    // ---- real Firefox ESR 153 (Debian 12, headless, fresh profile) ----

    const PROFILE: &str = "home/alice/.mozilla/firefox/abcd1234.default-esr";

    fn clean(out: &str) {
        assert!(!out.contains("--- warning") && !out.contains("--- failed"), "{out}");
    }

    fn rows(out: &str) -> Vec<&str> {
        out.lines().take_while(|l| !l.starts_with("---")).collect()
    }

    /// The page set `sid` (HttpOnly, one day) and `pref` (one hour). Expected values were read from
    /// the profile with sqlite3 (the rows are in the write-ahead log): creationTime 1794534969405343
    /// for `sid`, expiry 1794621369545 (milliseconds), sameSite 256 (unset).
    #[test]
    fn real_cookies_from_the_database_and_its_wal() {
        let db = fixture("firefox-cookies/cookies.sqlite");
        let wal = fixture("firefox-cookies/cookies.sqlite-wal");
        let path = format!("{PROFILE}/cookies.sqlite");
        let out = run_on_host(&COOKIES, &[(&path, &db), (&format!("{path}-wal"), &wal)], &path, 0);
        clean(&out);
        assert_eq!(rows(&out).len(), 2, "{out}");
        let sid = rows(&out).into_iter().find(|l| l.contains("\"name\":\"sid\"")).unwrap_or_default();
        assert!(
            sid.contains("\"created\":\"2026-11-13T01:56:09.405343Z\"")
                && sid.contains("\"expires\":\"2026-11-14T01:56:09.545Z\""),
            "{sid}"
        );
        assert!(sid.contains("\"http_only\":true,\"same_site\":256") && sid.contains("\"has_value\":true"), "{sid}");
        assert!(!out.contains("SECRETCOOKIEVALUE123"));
        // Without the WAL the rows are not there: the companion matters.
        assert_eq!(rows(&run(&COOKIES, &path, &db, 0)).len(), 0);
        insta::assert_snapshot!(out);
    }

    /// The profile's own `extensions.json`: ten built-in add-ons and themes (none installed by the user).
    #[test]
    fn real_extensions_json() {
        let out =
            run(&EXTENSIONS, &format!("{PROFILE}/extensions.json"), &fixture("firefox-extensions/extensions.json"), 0);
        clean(&out);
        assert_eq!(rows(&out).len(), 10, "{out}");
        assert!(
            out.contains("\"id\":\"formautofill@mozilla.org\"")
                && out.contains("\"name\":\"Form Autofill\"")
                && out.contains("\"location\":\"app-builtin-addons\""),
            "{out}"
        );
        assert!(
            out.contains("\"time\":\"2026-11-13T01:56:09.075Z\"") && out.contains("\"addon_type\":\"theme\""),
            "{out}"
        );
        assert!(out.contains("\"temporarily_installed\":false"));
    }

    #[test]
    fn temporary_and_sideloaded_addons_are_marked() {
        let json = br#"{"schemaVersion":36,"addons":[{"id":"dev@example.test","version":"0.1","type":"extension","location":"app-temporary","active":true,"userDisabled":false,"installDate":1794534000000,"path":"/home/alice/dev/addon","signedState":0,"foreignInstall":false,"defaultLocale":{"name":"Dev tool"},"userPermissions":{"permissions":["tabs","webRequest"],"origins":["<all_urls>"]}},{"id":"side@example.test","version":"2","type":"extension","location":"app-system-share","foreignInstall":true,"signedState":-1,"sourceURI":"https://evil.example.test/x.xpi","installTelemetryInfo":{"source":"sideload"}}]}"#;
        let out = run(&EXTENSIONS, &format!("{PROFILE}/extensions.json"), json, 0);
        clean(&out);
        assert!(
            out.contains("\"temporarily_installed\":true")
                && out.contains("\"path\":\"/home/alice/dev/addon\"")
                && out.contains("\"origins\":[\"<all_urls>\"]"),
            "{out}"
        );
        assert!(
            out.contains("\"source_uri\":\"https://evil.example.test/x.xpi\"")
                && out.contains("\"install_source\":\"sideload\"")
                && out.contains("\"foreign_install\":true,\"path\":null"),
            "{out}"
        );
        assert!(run(&EXTENSIONS, &format!("{PROFILE}/extensions.json"), b"{}", 0).contains("no addons list"));
    }

    /// `logins.json` in the format Firefox writes (synthetic: a login is saved only through the UI); the encrypted fields carry planted secrets.
    #[test]
    fn logins_json_has_metadata_and_never_the_secrets() {
        let out = run(&LOGINS, &format!("{PROFILE}/logins.json"), &fixture("firefox-logins/logins.json"), 0);
        clean(&out);
        assert!(!out.contains("PLANTED") && !out.contains("encrypted"), "a secret leaked: {out}");
        assert_eq!(rows(&out).len(), 2);
        assert!(
            out.contains("\"site\":\"https://shop.example.test\"")
                && out.contains("\"times_used\":5")
                && out.contains("\"http_realm\":\"Staff area\""),
            "{out}"
        );
        assert!(out.contains("\"last_used\":\"2026-11-13T02:40:00.123Z\"") && out.contains("login_used"), "{out}");
        insta::assert_snapshot!(out);
    }

    /// The proxy and DNS-over-HTTPS settings the script put in `user.js` reach `prefs.js` when Firefox starts.
    #[test]
    fn prefs_report_only_security_relevant_settings() {
        let out = run(&PREFS, &format!("{PROFILE}/prefs.js"), &fixture("firefox-prefs/prefs.js"), 0);
        clean(&out);
        for (name, value) in [
            ("network.proxy.http", "\\\"proxy.example.test\\\""),
            ("network.proxy.type", "1"),
            ("network.trr.mode", "2"),
            ("network.trr.uri", "\\\"https://dns.example.test/dns-query\\\""),
            ("xpinstall.signatures.required", "false"),
        ] {
            assert!(out.contains(&format!("\"name\":\"{name}\",\"value\":\"{value}\"")), "{name}: {out}");
        }
        assert!(
            !out.contains("browser.startup.homepage_override") || out.contains("browser.startup.homepage"),
            "{out}"
        );
        let user_js = run(&USER_JS, &format!("{PROFILE}/user.js"), &fixture("firefox-prefs/user.js"), 0);
        assert!(user_js.contains("\"file\":\"user.js\"") && rows(&user_js).len() >= 6, "{user_js}");
        insta::assert_snapshot!(out);
    }

    /// A real `recovery.jsonlz4` of a headless session that visited one page.
    #[test]
    fn real_session_store_is_decompressed_with_bounds() {
        let data = fixture("firefox-session/recovery.jsonlz4");
        let path = format!("{PROFILE}/sessionstore-backups/recovery.jsonlz4");
        let out = run(&SESSION, &path, &data, 0);
        clean(&out);
        assert!(
            out.contains("http://127.0.0.1:8124/index.html")
                && out.contains("\"state\":\"open\"")
                && out.contains("\"profile\":\"abcd1234.default-esr\""),
            "{out}"
        );
        assert!(run(&SESSION, &path, b"mozLz40\0", 0).contains("ends inside its header"));
        assert!(run(&SESSION, &path, b"not mozlz4 at all", 0).contains("no mozLz40 magic"));
        // A header that declares 4 GiB must not allocate it.
        let mut bomb = b"mozLz40\0".to_vec();
        bomb.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0x10, b'a']);
        assert!(run(&SESSION, &path, &bomb, 0).contains("more than the"));
        // A declared size larger than the block really holds.
        let mut lying = b"mozLz40\0".to_vec();
        lying.extend_from_slice(&[0x10, 0, 0, 0, 0x10, b'a']);
        run(&SESSION, &path, &lying, 0);
        insta::assert_snapshot!(out);
    }

    #[test]
    fn session_and_prefs_mutations_never_panic() {
        let mut seed = 5u64;
        let data = fixture("firefox-session/recovery.jsonlz4");
        let path = format!("{PROFILE}/sessionstore-backups/recovery.jsonlz4");
        for cut in 0..data.len() {
            run(&SESSION, &path, &data[..cut], 0);
        }
        for _ in 0..3000 {
            let mut copy = data.clone();
            for _ in 0..3 {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                let at = (seed as usize >> 33) % copy.len();
                copy[at] = (seed >> 20) as u8;
            }
            run(&SESSION, &path, &copy, 0);
        }
        for name in ["firefox-extensions/extensions.json", "firefox-logins/logins.json"] {
            let json = fixture(name);
            for cut in (0..json.len()).step_by(13) {
                run(&EXTENSIONS, &format!("{PROFILE}/extensions.json"), &json[..cut], 0);
                run(&LOGINS, &format!("{PROFILE}/logins.json"), &json[..cut], 0);
            }
        }
        let db = fixture("firefox-cookies/cookies.sqlite");
        for _ in 0..30 {
            let mut copy = db.clone();
            for _ in 0..8 {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                let at = (seed as usize >> 33) % copy.len();
                copy[at] = (seed >> 20) as u8;
            }
            run(&COOKIES, &format!("{PROFILE}/cookies.sqlite"), &copy, 0);
        }
    }

    #[test]
    fn flatpak_firefox_is_covered() {
        use nixcavate_source::glob::Pattern;
        for artifact in [&HISTORY, &EXTENSIONS, &LOGINS, &COOKIES, &PREFS, &SESSION] {
            let file = if artifact.id == "firefox-session" {
                "sessionstore-backups/recovery.jsonlz4"
            } else {
                artifact.paths[0].rsplit('/').next().unwrap_or_default()
            };
            let path = format!("home/a/.var/app/org.mozilla.firefox/.mozilla/firefox/x.default/{file}");
            assert!(artifact.paths.iter().any(|p| Pattern::new(p).matches(&path)), "{} misses {path}", artifact.id);
        }
    }
}
