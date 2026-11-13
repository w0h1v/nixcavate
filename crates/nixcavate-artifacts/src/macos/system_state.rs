//! System state kept in property lists: package receipts, installed configuration profiles,
//! the application firewall, Bluetooth devices, Time Machine snapshots and iOS pairing records.
//!
//! References: `pkgutil(1)` and the receipt plist keys it prints (`PackageIdentifier`,
//! `PackageVersion`, `InstallDate`, `InstallPrefixPath`, `InstallProcessName`); Apple's
//! configuration-profile key reference (`ProfileIdentifier`, `ProfileDisplayName`,
//! `ProfileOrganization`, `ProfileInstallDate`, payload `PayloadType`); `defaults` domains
//! `com.apple.alf`, `com.apple.Bluetooth` and `com.apple.TimeMachine` as described in public
//! research. Synthetic only: no real file of these kinds was read.
//!
//! Secrets: lockdown pairing records hold private keys, certificates and escrow bags. Only the
//! host and system identifiers are read; no other key is touched, and the tests plant keys to
//! prove it. Profile payload CONTENT (certificates, passwords) is never output, only payload types.

use super::plist_util::{date, integer, parse, string};
use super::util::clip;
use crate::{Artifact, Category, Input, MACOS};
use nixcavate_core::{Basis, Error, Event, Loc, Record, Result, Sink, Timestamp};
use plist::{Dictionary, Value};
use serde::Serialize;

pub const PKG_RECEIPTS: Artifact = Artifact::new(
    "pkg-receipts",
    "Installed package receipts (identifier, version, install time and process)",
    Category::Software,
    MACOS,
    &["private/var/db/receipts/*.plist", "var/db/receipts/*.plist"],
    parse_receipt,
);

pub const CONFIG_PROFILES: Artifact = Artifact::new(
    "config-profiles",
    "Installed configuration profiles and their payload types",
    Category::Persistence,
    MACOS,
    &[
        "private/var/db/ConfigurationProfiles/Store/ConfigProfiles.binary",
        "private/var/db/ConfigurationProfiles/ConfigProfiles.plist",
    ],
    parse_profiles,
);

pub const APPLICATION_FIREWALL: Artifact = Artifact::new(
    "application-firewall",
    "Application firewall state and per-application rules",
    Category::Security,
    MACOS,
    &["Library/Preferences/com.apple.alf.plist"],
    parse_alf,
);

pub const BLUETOOTH: Artifact = Artifact::new(
    "bluetooth-devices",
    "Bluetooth devices the system has seen",
    Category::Network,
    MACOS,
    &["Library/Preferences/com.apple.Bluetooth.plist"],
    parse_bluetooth,
);

pub const TIME_MACHINE: Artifact = Artifact::new(
    "time-machine",
    "Time Machine destinations and backup snapshot dates",
    Category::Filesystem,
    MACOS,
    &["Library/Preferences/com.apple.TimeMachine.plist"],
    parse_time_machine,
);

pub const LOCKDOWN: Artifact = Artifact::new(
    "lockdown-pairings",
    "Paired iOS devices (identifiers only; no keys)",
    Category::Accounts,
    MACOS,
    &["private/var/db/lockdown/*.plist", "var/db/lockdown/*.plist"],
    parse_lockdown,
);

fn dictionary(input: &Input) -> Result<Dictionary> {
    match parse(input.data)? {
        Value::Dictionary(d) => Ok(d),
        _ => Err(Error::format("not a dictionary")),
    }
}

fn text(dict: &Dictionary, key: &str) -> Option<String> {
    string(dict, key).map(|s| clip(s, 512))
}

fn time(sink: &mut Sink, dict: &Dictionary, key: &str) -> Option<Timestamp> {
    let value = dict.get(key)?;
    let t = date(value);
    if t.is_none() && value.as_date().is_some() {
        sink.warn(format!("{key} is not a valid time; left empty"));
    }
    t
}

#[derive(Serialize)]
struct Receipt {
    package_id: Option<String>,
    version: Option<String>,
    install_time: Option<Timestamp>,
    install_prefix: Option<String>,
    install_process: Option<String>,
}

impl Record for Receipt {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let message = format!(
            "package {} {} installed by {}",
            self.package_id.as_deref().unwrap_or("?"),
            self.version.as_deref().unwrap_or(""),
            self.install_process.as_deref().unwrap_or("?")
        );
        self.install_time.map(|ts| Event::new(ts, "package_installed", message)).into_iter()
    }
}

fn parse_receipt(input: &Input, sink: &mut Sink) -> Result<()> {
    let dict = dictionary(input)?;
    if !dict.contains_key("PackageIdentifier") {
        return Err(Error::skipped("no PackageIdentifier: not a package receipt"));
    }
    let install_time = time(sink, &dict, "InstallDate");
    sink.emit(
        Loc::None,
        &Receipt {
            package_id: text(&dict, "PackageIdentifier"),
            version: text(&dict, "PackageVersion"),
            install_time,
            install_prefix: text(&dict, "InstallPrefixPath"),
            install_process: text(&dict, "InstallProcessName"),
        },
    )
}

#[derive(Serialize)]
struct Profile {
    /// `computer` or the user the profile is installed for.
    level: String,
    identifier: Option<String>,
    name: Option<String>,
    organization: Option<String>,
    uuid: Option<String>,
    install_time: Option<Timestamp>,
    /// The `PayloadType` of every payload: what the profile configures. Content is not read.
    payload_types: Vec<String>,
}

impl Record for Profile {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let message = format!(
            "configuration profile {} ({}) installed",
            self.name.as_deref().or(self.identifier.as_deref()).unwrap_or("?"),
            self.organization.as_deref().unwrap_or("no organization")
        );
        self.install_time.map(|ts| Event::new(ts, "software_installed", message)).into_iter()
    }
}

const MAX_PROFILES: usize = 10_000;

fn parse_profiles(input: &Input, sink: &mut Sink) -> Result<()> {
    let dict = dictionary(input)?;
    let mut any = false;
    for (key, value) in dict.iter() {
        let level = match key.as_str() {
            "_computerLevel" => "computer".to_string(),
            k if k.starts_with('_') => k.trim_start_matches('_').to_string(),
            _ => continue,
        };
        let Value::Array(profiles) = value else { continue };
        for profile in profiles.iter().take(MAX_PROFILES) {
            let Some(profile) = profile.as_dictionary() else { continue };
            any = true;
            let payload_types = match profile.get("ProfileItems") {
                Some(Value::Array(items)) => items
                    .iter()
                    .filter_map(|i| i.as_dictionary().and_then(|d| string(d, "PayloadType")).map(|t| clip(t, 128)))
                    .collect(),
                _ => Vec::new(),
            };
            let install_time = time(sink, profile, "ProfileInstallDate");
            sink.emit(
                Loc::None,
                &Profile {
                    level: level.clone(),
                    identifier: text(profile, "ProfileIdentifier"),
                    name: text(profile, "ProfileDisplayName"),
                    organization: text(profile, "ProfileOrganization"),
                    uuid: text(profile, "ProfileUUID"),
                    install_time,
                    payload_types,
                },
            )?;
        }
    }
    if !any {
        return Err(Error::skipped("no profiles"));
    }
    Ok(())
}

#[derive(Serialize)]
struct Firewall {
    /// `setting` or `application`.
    kind: &'static str,
    name: String,
    value: Option<String>,
}

impl Record for Firewall {}

fn parse_alf(input: &Input, sink: &mut Sink) -> Result<()> {
    let dict = dictionary(input)?;
    for key in [
        "globalstate",
        "stealthenabled",
        "allowsignedenabled",
        "allowdownloadsignedenabled",
        "loggingenabled",
        "firewallunload",
    ] {
        let value = match dict.get(key) {
            Some(Value::Integer(i)) => i.as_signed().map(|n| n.to_string()),
            Some(Value::Boolean(b)) => Some(b.to_string()),
            _ => None,
        };
        if value.is_some() {
            sink.emit(Loc::None, &Firewall { kind: "setting", name: key.to_string(), value })?;
        }
    }
    for list in ["applications", "exceptions", "explicitauths"] {
        let Some(Value::Array(items)) = dict.get(list) else { continue };
        for item in items.iter().take(MAX_PROFILES) {
            let Some(item) = item.as_dictionary() else {
                if let Some(path) = item.as_string() {
                    sink.emit(
                        Loc::None,
                        &Firewall { kind: "application", name: clip(path, 1024), value: Some(list.into()) },
                    )?;
                }
                continue;
            };
            let name = string(item, "path").or_else(|| string(item, "id")).or_else(|| string(item, "bundleid"));
            let state = integer(item, "state").or_else(|| integer(item, "incoming"));
            if let Some(name) = name {
                sink.emit(
                    Loc::None,
                    &Firewall {
                        kind: "application",
                        name: clip(name, 1024),
                        value: state.map(|s| format!("{list}:{s}")),
                    },
                )?;
            }
        }
    }
    Ok(())
}

#[derive(Serialize)]
struct BluetoothDevice {
    /// `DeviceCache` or `CoreBluetoothCache`.
    cache: &'static str,
    address: String,
    name: Option<String>,
    manufacturer: Option<String>,
    /// The latest of the time fields the cache keeps (inquiry, name, services, last seen).
    last_seen: Option<Timestamp>,
}

impl Record for BluetoothDevice {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let message = format!("Bluetooth device {} ({}) last seen", self.name.as_deref().unwrap_or("?"), self.address);
        self.last_seen.map(|ts| Event::new(ts, "activity", message)).into_iter()
    }
}

fn parse_bluetooth(input: &Input, sink: &mut Sink) -> Result<()> {
    let dict = dictionary(input)?;
    for (cache, kind) in [("DeviceCache", "DeviceCache"), ("CoreBluetoothCache", "CoreBluetoothCache")] {
        let Some(Value::Dictionary(devices)) = dict.get(cache) else { continue };
        for (address, device) in devices.iter().take(MAX_PROFILES) {
            let Some(device) = device.as_dictionary() else { continue };
            let last_seen = device
                .iter()
                .filter(|(k, _)| k.starts_with("Last") || k.ends_with("Time"))
                .filter_map(|(_, v)| date(v))
                .max_by_key(|t| t.utc);
            sink.emit(
                Loc::None,
                &BluetoothDevice {
                    cache: kind,
                    address: clip(address, 64),
                    name: text(device, "Name")
                        .or_else(|| text(device, "displayName"))
                        .or_else(|| text(device, "DeviceName")),
                    manufacturer: text(device, "Manufacturer"),
                    last_seen,
                },
            )?;
        }
    }
    Ok(())
}

#[derive(Serialize)]
struct Backup {
    destination_id: Option<String>,
    volume_name: Option<String>,
    snapshot_time: Option<Timestamp>,
}

impl Record for Backup {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let message = format!("Time Machine backup to {}", self.volume_name.as_deref().unwrap_or("?"));
        self.snapshot_time.map(|ts| Event::new(ts, "activity", message)).into_iter()
    }
}

fn parse_time_machine(input: &Input, sink: &mut Sink) -> Result<()> {
    let dict = dictionary(input)?;
    let Some(Value::Array(destinations)) = dict.get("Destinations") else {
        return Err(Error::skipped("no Destinations"));
    };
    for destination in destinations.iter().take(MAX_PROFILES) {
        let Some(destination) = destination.as_dictionary() else { continue };
        let (id, volume) = (text(destination, "DestinationID"), text(destination, "LastKnownVolumeName"));
        let mut dates: Vec<Timestamp> = match destination.get("SnapshotDates") {
            Some(Value::Array(items)) => items.iter().take(100_000).filter_map(date).collect(),
            _ => Vec::new(),
        };
        dates.sort_by_key(|t| t.utc);
        if dates.is_empty() {
            sink.emit(
                Loc::None,
                &Backup { destination_id: id.clone(), volume_name: volume.clone(), snapshot_time: None },
            )?;
        }
        for t in dates {
            sink.emit(
                Loc::None,
                &Backup { destination_id: id.clone(), volume_name: volume.clone(), snapshot_time: Some(t) },
            )?;
        }
    }
    Ok(())
}

#[derive(Serialize)]
struct Pairing<'a> {
    /// The device identifier: the file name without `.plist`.
    device_id: &'a str,
    host_id: Option<String>,
    system_buid: Option<String>,
    wifi_mac_address: Option<String>,
    /// The record file's modification time as collected (when the pairing was made or refreshed).
    modified: Option<Timestamp>,
}

impl Record for Pairing<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let message = format!("iOS device {} pairing record written", self.device_id);
        self.modified.map(|ts| Event::new(ts, "activity", message)).into_iter()
    }
}

fn parse_lockdown(input: &Input, sink: &mut Sink) -> Result<()> {
    let dict = dictionary(input)?;
    let file = input.path.rsplit('/').next().unwrap_or_default();
    let device_id = file.strip_suffix(".plist").unwrap_or(file);
    if device_id == "SystemConfiguration" {
        // The host-level record holds the system's own identity and keys; only the ID is read.
        return sink.emit(
            Loc::None,
            &Pairing {
                device_id,
                host_id: None,
                system_buid: text(&dict, "SystemBUID"),
                wifi_mac_address: None,
                modified: None,
            },
        );
    }
    sink.emit(
        Loc::None,
        &Pairing {
            device_id,
            host_id: text(&dict, "HostID"),
            system_buid: text(&dict, "SystemBUID"),
            wifi_mac_address: text(&dict, "WiFiMACAddress"),
            modified: (input.mtime > 0).then(|| Timestamp::from_secs(input.mtime, Basis::Recorded)),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    fn check(artifact: &Artifact, path: &str, name: &str) -> String {
        run(artifact, path, &fixture(&format!("system-state/{name}")), 1_700_000_000)
    }

    #[test]
    fn receipts_and_profiles() {
        let r = check(&PKG_RECEIPTS, "private/var/db/receipts/com.example.pkg.plist", "receipt.plist");
        insta::assert_snapshot!(r);
        let p = check(
            &CONFIG_PROFILES,
            "private/var/db/ConfigurationProfiles/Store/ConfigProfiles.binary",
            "ConfigProfiles.binary",
        );
        assert!(!p.contains("PLANTED-CERT-CONTENT"), "{p}");
        insta::assert_snapshot!(p);
    }

    #[test]
    fn firewall_bluetooth_and_time_machine() {
        insta::assert_snapshot!(check(
            &APPLICATION_FIREWALL,
            "Library/Preferences/com.apple.alf.plist",
            "com.apple.alf.plist"
        ));
        insta::assert_snapshot!(check(
            &BLUETOOTH,
            "Library/Preferences/com.apple.Bluetooth.plist",
            "com.apple.Bluetooth.plist"
        ));
        insta::assert_snapshot!(check(
            &TIME_MACHINE,
            "Library/Preferences/com.apple.TimeMachine.plist",
            "com.apple.TimeMachine.plist"
        ));
    }

    #[test]
    fn lockdown_records_never_expose_keys() {
        let out = check(&LOCKDOWN, "private/var/db/lockdown/00008030-001234567890802E.plist", "lockdown.plist");
        for secret in ["PLANTED-PRIVATE-KEY", "PLANTED-ESCROW", "PLANTED-CERT"] {
            assert!(!out.contains(secret), "{out}");
        }
        insta::assert_snapshot!(out);
    }

    #[test]
    fn damaged_plists_do_not_panic() {
        let data = fixture("system-state/ConfigProfiles.binary");
        crate::macos::plist_util::tests::survives_damage(
            &CONFIG_PROFILES,
            "private/var/db/ConfigurationProfiles/ConfigProfiles.plist",
            &data,
        );
    }
}
