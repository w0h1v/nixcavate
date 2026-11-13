//! Network use per process (`netusage.sqlite`, from `networkd`), DHCP leases and the network
//! interface list.
//!
//! `netusage.sqlite` is a Core Data store: `ZPROCESS` (process name, bundle name, first and
//! last timestamp), `ZLIVEUSAGE` (bytes in and out over Wi-Fi, wired and cellular per
//! interval, `ZHASPROCESS` pointing at `ZPROCESS.Z_PK`) and `ZNETWORKATTACHMENT` (networks
//! seen). Layout and join as in Sarah Edwards' APOLLO `netusage` module. Times are Mac
//! absolute time. DHCP lease files are property lists named `<interface>-...` with
//! `IPAddress`, `LeaseStartDate`, `LeaseLength`, `RouterIPAddress`, `RouterHardwareAddress` and
//! `SSID` (dhcpclient behaviour as described in public research). `NetworkInterfaces.plist`
//! lists the interfaces the system has known, with MAC addresses.
//!
//! Synthetic only: no real netusage database, lease file or interface list was read.

use super::plist_util::{date, integer, mac_time, or_warn, parse, string};
use super::tcc::select_columns;
use crate::sqlite::{int_at, open_with_tables, real_at, sql_error, text_at, unique_rows};
use crate::{Artifact, Category, Input, MACOS};
use nixcavate_core::{Error, Event, Loc, Record, Result, Sink, Timestamp};
use plist::Value;
use serde::Serialize;

pub const NETUSAGE: Artifact = Artifact::new(
    "netusage",
    "Per-process network usage (netusage.sqlite)",
    Category::Network,
    MACOS,
    &["private/var/networkd/netusage.sqlite", "private/var/networkd/db/netusage.sqlite"],
    parse_netusage,
)
.companions(&["private/var/networkd/netusage.sqlite-wal", "private/var/networkd/db/netusage.sqlite-wal"]);

pub const DHCP_LEASES: Artifact = Artifact::new(
    "dhcp-leases",
    "DHCP leases per interface (router, SSID, lease start)",
    Category::Network,
    MACOS,
    &["private/var/db/dhcpclient/leases/*"],
    parse_lease,
);

pub const NETWORK_INTERFACES: Artifact = Artifact::new(
    "network-interfaces",
    "Network interfaces the system has known",
    Category::Network,
    MACOS,
    &["Library/Preferences/SystemConfiguration/NetworkInterfaces.plist"],
    parse_interfaces,
);

#[derive(Serialize)]
struct Usage {
    /// `usage` (one interval), `process` (first and last time a process was seen) or `network`.
    kind: &'static str,
    time: Option<Timestamp>,
    first_time: Option<Timestamp>,
    process: Option<String>,
    bundle: Option<String>,
    network: Option<String>,
    wifi_in: Option<i64>,
    wifi_out: Option<i64>,
    wired_in: Option<i64>,
    wired_out: Option<i64>,
    cellular_in: Option<i64>,
    cellular_out: Option<i64>,
}

impl Record for Usage {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let what = self.process.as_deref().or(self.network.as_deref()).unwrap_or("?");
        let message = match self.kind {
            "usage" => format!("{what} used the network"),
            "process" => format!("{what} last seen using the network"),
            _ => format!("network {what} seen"),
        };
        self.time.map(|ts| Event::new(ts, "activity", message)).into_iter()
    }
}

fn parse_netusage(input: &Input, sink: &mut Sink) -> Result<()> {
    let db = open_with_tables(input, &["ZPROCESS"])?;
    let process = select_columns(&db, "ZPROCESS", &["ZPROCNAME", "ZBUNDLENAME", "ZFIRSTTIMESTAMP", "ZTIMESTAMP"])?;
    let sql = format!("SELECT {} FROM ZPROCESS ORDER BY rowid", process.join(", "));
    let mut stmt = db.conn.prepare(&sql).map_err(sql_error)?;
    let mut rows = stmt.query([]).map_err(sql_error)?;
    while let Some(row) = rows.next().map_err(sql_error)? {
        let first = or_warn(sink, "ZFIRSTTIMESTAMP", real_at(row, 2), mac_time);
        let last = or_warn(sink, "ZTIMESTAMP", real_at(row, 3), mac_time);
        sink.emit(Loc::None, &blank("process", text_at(row, 0), text_at(row, 1), last, first))?;
    }

    if db.has_table("ZLIVEUSAGE") {
        db.refuse_generated_columns(&["ZLIVEUSAGE"])?;
        let names =
            ["ZTIMESTAMP", "ZWIFIIN", "ZWIFIOUT", "ZWIREDIN", "ZWIREDOUT", "ZWWANIN", "ZWWANOUT", "ZHASPROCESS"];
        let usage = select_columns(&db, "ZLIVEUSAGE", &names)?;
        let qualified = |c: &String, alias: &str| if c == "NULL" { c.clone() } else { format!("{alias}.{c}") };
        let mut cols: Vec<String> = usage.iter().take(7).map(|c| qualified(c, "u")).collect();
        cols.push(qualified(&process[0], "p"));
        cols.push(qualified(&process[1], "p"));
        // Without the foreign key column nothing joins.
        let on = if usage[7] == "NULL" { "0".to_string() } else { "p.Z_PK = u.ZHASPROCESS".to_string() };
        let sql = format!(
            "SELECT {} FROM ZLIVEUSAGE u LEFT JOIN {} p ON {on} ORDER BY u.ZTIMESTAMP, u.rowid",
            cols.join(", "),
            unique_rows("ZPROCESS", "Z_PK"),
        );
        let mut stmt = db.conn.prepare(&sql).map_err(sql_error)?;
        let mut rows = stmt.query([]).map_err(sql_error)?;
        while let Some(row) = rows.next().map_err(sql_error)? {
            let time = or_warn(sink, "ZTIMESTAMP", real_at(row, 0), mac_time);
            let mut record = blank("usage", text_at(row, 7), text_at(row, 8), time, None);
            record.wifi_in = int_at(row, 1);
            record.wifi_out = int_at(row, 2);
            record.wired_in = int_at(row, 3);
            record.wired_out = int_at(row, 4);
            record.cellular_in = int_at(row, 5);
            record.cellular_out = int_at(row, 6);
            sink.emit(Loc::None, &record)?;
        }
    }

    if db.has_table("ZNETWORKATTACHMENT") {
        db.refuse_generated_columns(&["ZNETWORKATTACHMENT"])?;
        let cols = select_columns(&db, "ZNETWORKATTACHMENT", &["ZIDENTIFIER", "ZFIRSTTIMESTAMP", "ZTIMESTAMP"])?;
        let sql = format!("SELECT {} FROM ZNETWORKATTACHMENT ORDER BY rowid", cols.join(", "));
        let mut stmt = db.conn.prepare(&sql).map_err(sql_error)?;
        let mut rows = stmt.query([]).map_err(sql_error)?;
        while let Some(row) = rows.next().map_err(sql_error)? {
            let first = or_warn(sink, "ZFIRSTTIMESTAMP", real_at(row, 1), mac_time);
            let last = or_warn(sink, "ZTIMESTAMP", real_at(row, 2), mac_time);
            let mut record = blank("network", None, None, last, first);
            record.network = text_at(row, 0);
            sink.emit(Loc::None, &record)?;
        }
    }
    Ok(())
}

fn blank(
    kind: &'static str,
    process: Option<String>,
    bundle: Option<String>,
    time: Option<Timestamp>,
    first_time: Option<Timestamp>,
) -> Usage {
    Usage {
        kind,
        time,
        first_time,
        process,
        bundle,
        network: None,
        wifi_in: None,
        wifi_out: None,
        wired_in: None,
        wired_out: None,
        cellular_in: None,
        cellular_out: None,
    }
}

#[derive(Serialize)]
struct Lease {
    interface: String,
    ip_address: Option<String>,
    lease_start: Option<Timestamp>,
    lease_length_secs: Option<i64>,
    router_ip: Option<String>,
    router_mac: Option<String>,
    ssid: Option<String>,
}

impl Record for Lease {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let message = format!(
            "DHCP lease {} on {}{}",
            self.ip_address.as_deref().unwrap_or("?"),
            self.interface,
            self.ssid.as_deref().map(|s| format!(" (SSID {s})")).unwrap_or_default()
        );
        self.lease_start.map(|ts| Event::new(ts, "network_connected", message)).into_iter()
    }
}

fn mac(bytes: &[u8]) -> Option<String> {
    (bytes.len() == 6).then(|| bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":"))
}

fn parse_lease(input: &Input, sink: &mut Sink) -> Result<()> {
    let value = parse(input.data)?;
    let Some(dict) = value.as_dictionary() else { return Err(Error::format("lease is not a dictionary")) };
    let name = input.path.rsplit('/').next().unwrap_or_default();
    let interface = name.split(['-', ',']).next().unwrap_or_default();
    let lease_start = dict.get("LeaseStartDate").and_then(|v| {
        let t = date(v);
        if t.is_none() {
            sink.warn("LeaseStartDate is not a valid time; left empty");
        }
        t
    });
    let ssid = match dict.get("SSID") {
        Some(Value::Data(bytes)) => Some(crate::text::lossy(bytes).into_owned()),
        other => other.and_then(Value::as_string).map(str::to_owned),
    };
    let router_mac = match dict.get("RouterHardwareAddress") {
        Some(Value::Data(bytes)) => mac(bytes),
        other => other.and_then(Value::as_string).map(str::to_owned),
    };
    sink.emit(
        Loc::None,
        &Lease {
            interface: interface.to_string(),
            ip_address: string(dict, "IPAddress").map(str::to_owned),
            lease_start,
            lease_length_secs: integer(dict, "LeaseLength"),
            router_ip: string(dict, "RouterIPAddress").map(str::to_owned),
            router_mac,
            ssid,
        },
    )
}

#[derive(Serialize)]
struct Interface {
    bsd_name: Option<String>,
    mac_address: Option<String>,
    interface_type: Option<String>,
    user_defined_name: Option<String>,
    built_in: Option<bool>,
    primary: bool,
}

impl Record for Interface {}

fn parse_interfaces(input: &Input, sink: &mut Sink) -> Result<()> {
    let value = parse(input.data)?;
    let Some(list) = value.as_dictionary().and_then(|d| d.get("Interfaces")).and_then(Value::as_array) else {
        return Err(Error::skipped("no Interfaces array"));
    };
    for item in list {
        let Some(dict) = item.as_dictionary() else { continue };
        let mac_address = match dict.get("IOMACAddress") {
            Some(Value::Data(bytes)) => mac(bytes),
            _ => None,
        };
        let info = dict.get("SCNetworkInterfaceInfo").and_then(Value::as_dictionary);
        sink.emit(
            Loc::None,
            &Interface {
                bsd_name: string(dict, "BSD Name").map(str::to_owned),
                mac_address,
                interface_type: string(dict, "SCNetworkInterfaceType").map(str::to_owned),
                user_defined_name: info.and_then(|i| string(i, "UserDefinedName")).map(str::to_owned),
                built_in: dict.get("IOBuiltin").and_then(Value::as_boolean),
                primary: dict.get("IOPrimaryInterface").and_then(Value::as_boolean).unwrap_or(false),
            },
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sqlite::database_bytes;
    use crate::testing::{fixture, run};

    const DB: &str = "private/var/networkd/netusage.sqlite";

    #[test]
    fn netusage_joins_usage_to_processes() {
        insta::assert_snapshot!(run(&NETUSAGE, DB, &fixture("netusage/netusage.sqlite"), 0));
    }

    #[test]
    fn lease_and_interfaces() {
        let lease = "private/var/db/dhcpclient/leases/en0-1,aa:bb:cc:dd:ee:ff";
        insta::assert_snapshot!(run(&DHCP_LEASES, lease, &fixture("netusage/lease.plist"), 0));
        let path = "Library/Preferences/SystemConfiguration/NetworkInterfaces.plist";
        insta::assert_snapshot!(run(&NETWORK_INTERFACES, path, &fixture("netusage/NetworkInterfaces.plist"), 0));
    }

    #[test]
    fn a_database_without_the_tables_is_skipped() {
        let db = database_bytes("CREATE TABLE t (a);");
        assert!(run(&NETUSAGE, DB, &db, 0).contains("skipped: no ZPROCESS table"));
        assert!(run(&NETUSAGE, DB, b"", 0).contains("skipped"));
    }

    #[test]
    fn damaged_inputs_do_not_panic() {
        crate::macos::util::survives_sparse(&NETUSAGE, DB, &fixture("netusage/netusage.sqlite"), 997, 20);
        let lease = fixture("netusage/lease.plist");
        crate::macos::plist_util::tests::survives_damage(
            &DHCP_LEASES,
            "private/var/db/dhcpclient/leases/en0-1",
            &lease,
        );
    }
}
