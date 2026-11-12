//! Known Wi-Fi networks. macOS 11+ keeps `com.apple.wifi.known-networks.plist`, a dict keyed
//! `wifi.network.ssid.<SSID>` whose values hold `SSID`, `AddedAt`, `JoinedByUserAt`,
//! `JoinedBySystemAt`, `SupportedSecurityTypes`, `Hidden`, `CaptiveProfile` and, under
//! `__OSSpecific__`, `BSSIDList` and `ChannelHistory`. Older systems keep a `KnownNetworks`
//! dict in `com.apple.airport.preferences.plist` with `SSIDString`, `SecurityType`,
//! `LastConnected`, `AddedAt` and `ChannelHistory`. Format: property list (`plist(5)`); key
//! names as observed in the two generations. Neither file holds passwords (the keychain does).

use super::plist_util::{boolean, date, integer, parse as read_plist, string, strings};
use crate::text::lossy;
use crate::{Artifact, Category, Input, MACOS};
use nixcavate_core::{Error, Event, Loc, Record, Result, Sink, Timestamp};
use plist::{Dictionary, Value};
use serde::Serialize;

pub const ARTIFACT: Artifact = Artifact::new(
    "wifi-networks",
    "Known Wi-Fi networks and when they were joined",
    Category::Network,
    MACOS,
    &[
        "Library/Preferences/com.apple.wifi.known-networks.plist",
        "Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist",
    ],
    parse,
);

const KEY_PREFIX: &str = "wifi.network.ssid.";

#[derive(Serialize)]
struct Network {
    ssid: String,
    security: Option<String>,
    hidden: bool,
    /// The most recent join (user or system), or `LastConnected` on older systems.
    time: Option<Timestamp>,
    added_time: Option<Timestamp>,
    joined_by_user_time: Option<Timestamp>,
    joined_by_system_time: Option<Timestamp>,
    bssids: Vec<String>,
    channels: Vec<i64>,
    captive: bool,
}

impl Record for Network {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let joined = self.time.map(|ts| Event::new(ts, "wifi_joined", format!("joined Wi-Fi network {}", self.ssid)));
        let added =
            self.added_time.map(|ts| Event::new(ts, "wifi_added", format!("added Wi-Fi network {}", self.ssid)));
        joined.into_iter().chain(added)
    }
}

/// A key from the network dict, falling back to the `__OSSpecific__` sub-dict.
fn lookup<'a>(network: &'a Dictionary, key: &str) -> Option<&'a Value> {
    network.get(key).or_else(|| network.get("__OSSpecific__")?.as_dictionary()?.get(key))
}

fn ssid(network: &Dictionary, key: &str) -> String {
    match network.get("SSID") {
        Some(Value::Data(bytes)) => lossy(bytes).into_owned(),
        other => other
            .and_then(Value::as_string)
            .or_else(|| string(network, "SSIDString"))
            .map_or_else(|| key.strip_prefix(KEY_PREFIX).unwrap_or(key).to_string(), str::to_owned),
    }
}

/// A date-valued key; `None` with a warning when it is present but outside 1677-2262.
fn time(sink: &mut Sink, entry: &Dictionary, key: &str) -> Option<Timestamp> {
    let value = entry.get(key)?;
    let time = date(value);
    if time.is_none() && value.as_date().is_some() {
        sink.warn(format!("{key} is not a valid time; left empty"));
    }
    time
}

fn network(sink: &mut Sink, key: &str, entry: &Dictionary) -> Network {
    let user = time(sink, entry, "JoinedByUserAt");
    let system = time(sink, entry, "JoinedBySystemAt");
    let types = lookup(entry, "SupportedSecurityTypes").or_else(|| entry.get("SecurityType"));
    let security = match types {
        Some(array @ Value::Array(_)) => Some(strings(array).join(",")),
        other => other.and_then(Value::as_string).map(str::to_owned),
    };
    let bssids = match lookup(entry, "BSSIDList") {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|item| {
                let named = item.as_dictionary().and_then(|d| d.get("BSSID")).unwrap_or(item);
                named.as_string().map(str::to_owned)
            })
            .collect(),
        _ => Vec::new(),
    };
    let mut channels = Vec::new();
    if let Some(Value::Array(history)) = lookup(entry, "ChannelHistory") {
        for item in history {
            if let Some(channel) = item.as_dictionary().and_then(|d| integer(d, "Channel")) {
                if !channels.contains(&channel) {
                    channels.push(channel);
                }
            }
        }
    }
    let captive = match entry.get("CaptiveProfile") {
        Some(Value::Dictionary(profile)) => boolean(profile, "CaptiveNetwork").unwrap_or(true),
        other => other.and_then(Value::as_boolean).unwrap_or(false),
    };
    let joined = user.into_iter().chain(system).max_by_key(|t| t.utc);
    Network {
        ssid: ssid(entry, key),
        security,
        hidden: boolean(entry, "Hidden").unwrap_or(false),
        time: joined.or_else(|| time(sink, entry, "LastConnected")),
        added_time: time(sink, entry, "AddedAt"),
        joined_by_user_time: user,
        joined_by_system_time: system,
        bssids,
        channels,
        captive,
    }
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    let root = read_plist(input.data)?;
    let Some(root) = root.as_dictionary() else {
        return Err(Error::skipped("not a dictionary"));
    };
    // The older file nests the networks; in the newer one they are the top-level keys.
    let nested = root.get("KnownNetworks").and_then(Value::as_dictionary);
    let networks = nested.unwrap_or(root);
    if nested.is_none() && !root.keys().any(|k| k.starts_with(KEY_PREFIX)) {
        return Err(Error::skipped("no known networks"));
    }
    for (key, entry) in networks {
        if nested.is_none() && !key.starts_with(KEY_PREFIX) {
            continue;
        }
        match entry.as_dictionary() {
            Some(entry) => {
                let record = network(sink, key, entry);
                sink.emit(Loc::None, &record)?;
            }
            None => sink.warn(format!("network {key}: not a dictionary")),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    const NEW: &str = "Library/Preferences/com.apple.wifi.known-networks.plist";
    const OLD: &str = "Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist";

    #[test]
    fn parses_known_networks_plist() {
        insta::assert_snapshot!(run(&ARTIFACT, NEW, &fixture("wifi-networks/com.apple.wifi.known-networks.plist"), 0));
    }

    #[test]
    fn parses_older_airport_preferences() {
        insta::assert_snapshot!(run(&ARTIFACT, OLD, &fixture("wifi-networks/com.apple.airport.preferences.plist"), 0));
    }

    #[test]
    fn other_inputs_are_not_parsed() {
        assert!(run(&ARTIFACT, NEW, b"", 0).contains("skipped: empty file"));
        assert!(run(&ARTIFACT, NEW, b"junk", 0).contains("failed: "));
        let unrelated = fixture("wifi-networks/unrelated.plist");
        assert!(run(&ARTIFACT, NEW, &unrelated, 0).contains("skipped: no known networks"));
    }

    #[test]
    fn absurd_dates_are_dropped_with_a_warning() {
        let xml = b"<plist version=\"1.0\"><dict><key>wifi.network.ssid.X</key><dict>\
                    <key>AddedAt</key><date>9999-12-31T00:00:00Z</date>\
                    <key>JoinedByUserAt</key><date>0001-01-01T00:00:00Z</date></dict></dict></plist>";
        let out = run(&ARTIFACT, NEW, xml, 0);
        assert!(out.contains("\"added_time\":null") && out.contains("\"joined_by_user_time\":null"), "{out}");
        assert!(out.contains("AddedAt is not a valid time") && out.contains("JoinedByUserAt is not a valid"), "{out}");
    }

    #[test]
    fn damaged_files_do_not_panic() {
        for (path, name) in [
            (NEW, "wifi-networks/com.apple.wifi.known-networks.plist"),
            (OLD, "wifi-networks/com.apple.airport.preferences.plist"),
        ] {
            let data = fixture(name);
            for len in 0..data.len() {
                run(&ARTIFACT, path, &data[..len], 0);
            }
            let mut seed = 17u32;
            for _ in 0..300 {
                let mut copy = data.clone();
                seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                let at = (seed >> 8) as usize % copy.len();
                copy[at] ^= (seed & 0xff) as u8 | 1;
                run(&ARTIFACT, path, &copy, 0);
            }
        }
    }
}
