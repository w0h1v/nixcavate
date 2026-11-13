//! User-activity and login settings kept in property lists: Finder (`com.apple.finder.plist`:
//! recent folders, Go To Folder history, volumes ever mounted on the desktop, last server),
//! the Dock (`com.apple.dock.plist`: pinned and recent applications), the login window
//! (`com.apple.loginwindow.plist`: last user, auto-login user, `LoginHook` and `LogoutHook`,
//! and the ByHost `TALAppsToRelaunchAtLogin` list) and the Spotlight typed-shortcut store.
//!
//! Key names are those observed in public descriptions of the files: Apple's `defaults`
//! domains, Sarah Edwards' mac4n6 write-ups, and the `com.apple.loginwindow` man page entries
//! for `LoginHook`/`LogoutHook`. Synthetic only: no real preference file was read; the doubts
//! are key spelling on macOS releases newer than 13 and the Spotlight shortcuts file name and
//! layout (`LAST_USED` date, `DISPLAY_NAME`, `URL`).

use super::bookmark::decode;
use super::plist_util::{date, parse, string};
use super::util::clip;
use crate::common::home::user_from_path;
use crate::{Artifact, Category, Input, MACOS};
use nixcavate_core::{Error, Event, Loc, Record, Result, Sink, Timestamp};
use plist::{Dictionary, Value};
use serde::Serialize;

pub const FINDER: Artifact = Artifact::new(
    "finder-prefs",
    "Finder recent folders, Go To Folder history and desktop volumes",
    Category::Activity,
    MACOS,
    &["Users/*/Library/Preferences/com.apple.finder.plist"],
    parse_finder,
);

pub const DOCK: Artifact = Artifact::new(
    "dock-items",
    "Dock pinned and recent applications",
    Category::Activity,
    MACOS,
    &["Users/*/Library/Preferences/com.apple.dock.plist"],
    parse_dock,
);

pub const LOGINWINDOW: Artifact = Artifact::new(
    "login-window",
    "Login window settings, login/logout hooks and apps reopened at login",
    Category::Persistence,
    MACOS,
    &[
        "Library/Preferences/com.apple.loginwindow.plist",
        "private/var/root/Library/Preferences/com.apple.loginwindow.plist",
        "Users/*/Library/Preferences/com.apple.loginwindow.plist",
        "Users/*/Library/Preferences/ByHost/com.apple.loginwindow.*.plist",
    ],
    parse_loginwindow,
);

pub const SPOTLIGHT_SHORTCUTS: Artifact = Artifact::new(
    "spotlight-shortcuts",
    "Spotlight typed searches and what the user opened from them",
    Category::Activity,
    MACOS,
    &[
        "Users/*/Library/Application Support/com.apple.spotlight.Shortcuts",
        "Users/*/Library/Application Support/com.apple.spotlight/com.apple.spotlight.Shortcuts*",
    ],
    parse_shortcuts,
);

const MAX_ITEMS: usize = 20_000;

#[derive(Serialize)]
struct Item<'a> {
    user: &'a str,
    /// What the row is: `recent_folder`, `go_to_folder`, `desktop_volume`, `connect_to_server`,
    /// `pinned_app`, `pinned_item`, `recent_app`, `setting`, `login_hook`, `logout_hook`,
    /// `relaunch_app` or `shortcut`.
    kind: &'static str,
    order: Option<usize>,
    name: Option<String>,
    path: Option<String>,
    bundle_id: Option<String>,
    value: Option<String>,
    time: Option<Timestamp>,
}

impl Record for Item<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let message = format!(
            "{} {}",
            self.kind,
            self.value.as_deref().or(self.name.as_deref()).or(self.path.as_deref()).unwrap_or("")
        );
        self.time.map(|ts| Event::new(ts, "activity", message)).into_iter()
    }
}

fn item<'a>(user: &'a str, kind: &'static str) -> Item<'a> {
    Item { user, kind, order: None, name: None, path: None, bundle_id: None, value: None, time: None }
}

fn root(input: &Input) -> Result<Dictionary> {
    match parse(input.data)? {
        Value::Dictionary(dict) => Ok(dict),
        _ => Err(Error::format("preference file is not a dictionary")),
    }
}

fn parse_finder(input: &Input, sink: &mut Sink) -> Result<()> {
    let dict = root(input)?;
    let user = user_from_path(input.path);
    if let Some(Value::Array(folders)) = dict.get("FXRecentFolders") {
        for (i, folder) in folders.iter().take(MAX_ITEMS).enumerate() {
            let Some(folder) = folder.as_dictionary() else { continue };
            let target = match folder.get("file-bookmark") {
                Some(Value::Data(bytes)) => decode(bytes),
                _ => None,
            };
            let mut row = item(user, "recent_folder");
            row.order = Some(i);
            row.name = string(folder, "name").map(|n| clip(n, 512));
            row.path = target.and_then(|b| b.full_path());
            sink.emit(Loc::None, &row)?;
        }
    }
    if let Some(Value::Array(history)) = dict.get("GoToFieldHistory") {
        for (i, entry) in history.iter().take(MAX_ITEMS).enumerate() {
            if let Some(text) = entry.as_string() {
                let mut row = item(user, "go_to_folder");
                row.order = Some(i);
                row.path = Some(clip(text, 1024));
                sink.emit(Loc::None, &row)?;
            }
        }
    }
    if let Some(Value::Dictionary(volumes)) = dict.get("FXDesktopVolumePositions") {
        for (key, _) in volumes.iter().take(MAX_ITEMS) {
            // `<volume name>_0x<id>`.
            let name = key.rsplit_once("_0x").map_or(key.as_str(), |(n, _)| n);
            let mut row = item(user, "desktop_volume");
            row.name = Some(clip(name, 256));
            row.value = Some(clip(key, 256));
            sink.emit(Loc::None, &row)?;
        }
    }
    if let Some(url) = string(&dict, "FXConnectToLastURL") {
        let mut row = item(user, "connect_to_server");
        row.path = Some(clip(url, 1024));
        sink.emit(Loc::None, &row)?;
    }
    Ok(())
}

fn parse_dock(input: &Input, sink: &mut Sink) -> Result<()> {
    let dict = root(input)?;
    let user = user_from_path(input.path);
    let lists: [(&str, &'static str); 3] =
        [("persistent-apps", "pinned_app"), ("persistent-others", "pinned_item"), ("recent-apps", "recent_app")];
    for (key, kind) in lists {
        let Some(Value::Array(tiles)) = dict.get(key) else { continue };
        for (i, tile) in tiles.iter().take(MAX_ITEMS).enumerate() {
            let Some(data) = tile.as_dictionary().and_then(|t| t.get("tile-data")).and_then(Value::as_dictionary)
            else {
                continue;
            };
            let url = data
                .get("file-data")
                .and_then(Value::as_dictionary)
                .and_then(|f| string(f, "_CFURLString"))
                .map(|u| clip(u, 1024));
            let mut row = item(user, kind);
            row.order = Some(i);
            row.name = string(data, "file-label").map(|n| clip(n, 256));
            row.bundle_id = string(data, "bundle-identifier").map(|n| clip(n, 256));
            row.path = url;
            sink.emit(Loc::None, &row)?;
        }
    }
    Ok(())
}

/// Settings of the login window worth reading in an investigation.
const LOGIN_SETTINGS: &[&str] = &[
    "lastUser",
    "lastUserName",
    "autoLoginUser",
    "GuestEnabled",
    "SHOWFULLNAME",
    "DisableConsoleAccess",
    "RestartDisabled",
    "ShutDownDisabled",
    "LoginwindowText",
];

fn scalar(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(clip(s, 512)),
        Value::Boolean(b) => Some(b.to_string()),
        Value::Integer(i) => Some(i.to_string()),
        _ => None,
    }
}

fn parse_loginwindow(input: &Input, sink: &mut Sink) -> Result<()> {
    let dict = root(input)?;
    let user = user_from_path(input.path);
    for (key, kind) in [("LoginHook", "login_hook"), ("LogoutHook", "logout_hook")] {
        if let Some(command) = string(&dict, key) {
            let mut row = item(user, kind);
            row.name = Some(key.to_string());
            row.value = Some(clip(command, 1024));
            sink.emit(Loc::None, &row)?;
        }
    }
    for key in LOGIN_SETTINGS {
        if let Some(value) = dict.get(key).and_then(scalar) {
            let mut row = item(user, "setting");
            row.name = Some((*key).to_string());
            row.value = Some(value);
            sink.emit(Loc::None, &row)?;
        }
    }
    if let Some(Value::Array(apps)) = dict.get("TALAppsToRelaunchAtLogin") {
        for (i, app) in apps.iter().take(MAX_ITEMS).enumerate() {
            let Some(app) = app.as_dictionary() else { continue };
            let mut row = item(user, "relaunch_app");
            row.order = Some(i);
            row.bundle_id = string(app, "BundleID").map(|b| clip(b, 256));
            row.path = string(app, "Path").map(|p| clip(p, 1024));
            sink.emit(Loc::None, &row)?;
        }
    }
    Ok(())
}

fn parse_shortcuts(input: &Input, sink: &mut Sink) -> Result<()> {
    let dict = root(input)?;
    let user = user_from_path(input.path);
    let mut any = false;
    for (query, entry) in dict.iter().take(MAX_ITEMS) {
        let Some(entry) = entry.as_dictionary() else { continue };
        any = true;
        let mut row = item(user, "shortcut");
        row.value = Some(clip(query, 512));
        row.name = string(entry, "DISPLAY_NAME").map(|n| clip(n, 512));
        row.path = string(entry, "URL").map(|u| clip(u, 1024));
        row.time = entry.get("LAST_USED").and_then(date);
        sink.emit(Loc::None, &row)?;
    }
    if !any {
        return Err(Error::skipped("no shortcut entries"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    #[test]
    fn finder_dock_and_login_window() {
        let finder = "Users/alice/Library/Preferences/com.apple.finder.plist";
        insta::assert_snapshot!(run(&FINDER, finder, &fixture("user-prefs/com.apple.finder.plist"), 0));
        let dock = "Users/alice/Library/Preferences/com.apple.dock.plist";
        insta::assert_snapshot!(run(&DOCK, dock, &fixture("user-prefs/com.apple.dock.plist"), 0));
        let login = "Library/Preferences/com.apple.loginwindow.plist";
        insta::assert_snapshot!(run(&LOGINWINDOW, login, &fixture("user-prefs/com.apple.loginwindow.plist"), 0));
    }

    #[test]
    fn spotlight_shortcuts() {
        let path = "Users/alice/Library/Application Support/com.apple.spotlight.Shortcuts";
        insta::assert_snapshot!(run(
            &SPOTLIGHT_SHORTCUTS,
            path,
            &fixture("user-prefs/com.apple.spotlight.Shortcuts"),
            0
        ));
    }

    #[test]
    fn wrong_shapes_are_tolerated() {
        let path = "Users/alice/Library/Preferences/com.apple.finder.plist";
        let odd = b"<plist version=\"1.0\"><dict><key>FXRecentFolders</key><string>x</string><key>GoToFieldHistory</key><array><integer>1</integer></array></dict></plist>";
        let out = run(&FINDER, path, odd, 0);
        assert!(!out.contains("failed") && !out.contains("\"kind\""), "{out}");
        assert!(run(&FINDER, path, b"[1]", 0).contains("failed: "));
    }

    #[test]
    fn damaged_plists_do_not_panic() {
        let finder = "Users/alice/Library/Preferences/com.apple.finder.plist";
        crate::macos::plist_util::tests::survives_damage(
            &FINDER,
            finder,
            &fixture("user-prefs/com.apple.finder.plist"),
        );
        let login = "Library/Preferences/com.apple.loginwindow.plist";
        crate::macos::plist_util::tests::survives_damage(
            &LOGINWINDOW,
            login,
            &fixture("user-prefs/com.apple.loginwindow.plist"),
        );
    }
}
