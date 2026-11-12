//! NetworkManager connection profiles. Format: nm-settings-keyfile(5), an INI file with one
//! connection per file. Secrets (PSKs, VPN passwords) are never copied to the output; only
//! whether the profile holds one is reported.

use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, LINUX};
use nixcavate_core::time::parse_uint;
use nixcavate_core::{Basis, Error, Event, Loc, Record, Result, Sink, Timestamp};
use serde::Serialize;

pub const ARTIFACT: Artifact = Artifact::new(
    "networkmanager",
    "NetworkManager connection profiles",
    Category::Network,
    LINUX,
    &["etc/NetworkManager/system-connections/*", "run/NetworkManager/system-connections/*"],
    parse,
);

#[derive(Serialize, Default)]
struct Connection<'a> {
    /// Last successful activation, as NetworkManager records it.
    time: Option<Timestamp>,
    id: &'a str,
    uuid: &'a str,
    connection_type: &'a str,
    interface: &'a str,
    autoconnect: Option<bool>,
    ssid: &'a str,
    /// The `key-mgmt` of the wifi security setting (`wpa-psk`, `wpa-eap`, ...).
    security: &'a str,
    ipv4_method: &'a str,
    ipv4_addresses: Vec<&'a str>,
    ipv4_dns: Vec<&'a str>,
    ipv6_method: &'a str,
    vpn_service: &'a str,
    vpn_gateway: &'a str,
    /// True when a non-empty secret value is stored in the file.
    has_secret: bool,
}

impl Record for Connection<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        self.time
            .map(|t| Event::new(t, "network_connected", format!("connected to {} ({})", self.id, self.connection_type)))
            .into_iter()
    }
}

fn is_secret_key(section: &str, key: &str) -> bool {
    section == "vpn-secrets"
        || matches!(
            key,
            "psk"
                | "password"
                | "private-key-password"
                | "secrets"
                | "private-key"
                | "preshared-key"
                | "leap-password"
                | "password-raw"
                | "pin"
        )
        || key.starts_with("wep-key")
        || key.ends_with("-password")
        || key.ends_with("-passwords")
}

/// The `remote` or `gateway` pair inside an old-style `data=k = v, k = v` value.
fn data_gateway(data: &str) -> Option<&str> {
    data.split(',')
        .filter_map(|pair| pair.split_once('='))
        .find_map(|(k, v)| matches!(k.trim(), "remote" | "gateway").then(|| v.trim()))
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    // Keyfile lines are collected as owned text only until the end of the file, because the
    // record borrows from them and the file may be compressed.
    let mut lines: Vec<String> = Vec::new();
    for_each_line(input, |line| {
        lines.push(lossy(line.bytes).into_owned());
        Ok(())
    })?;

    let mut conn = Connection::default();
    let mut section = "";
    let mut seen_connection = false;
    for line in &lines {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            section = name;
            seen_connection |= name == "connection";
            continue;
        }
        let Some((key, value)) = line.split_once('=') else { continue };
        let (key, value) = (key.trim(), value.trim());
        if is_secret_key(section, key) && !value.is_empty() {
            conn.has_secret = true;
        }
        match (section, key) {
            ("connection", "id") => conn.id = value,
            ("connection", "uuid") => conn.uuid = value,
            ("connection", "type") => conn.connection_type = value,
            ("connection", "interface-name") => conn.interface = value,
            ("connection", "autoconnect") => conn.autoconnect = Some(value.eq_ignore_ascii_case("true")),
            ("connection", "timestamp") => {
                conn.time = parse_uint(value.as_bytes())
                    .and_then(|s| i64::try_from(s).ok())
                    .map(|s| Timestamp::from_secs(s, Basis::Recorded));
            }
            ("wifi" | "802-11-wireless", "ssid") => conn.ssid = value,
            ("wifi-security" | "802-11-wireless-security", "key-mgmt") => conn.security = value,
            ("ipv4", "method") => conn.ipv4_method = value,
            ("ipv4", "dns") => conn.ipv4_dns = value.split(';').filter(|d| !d.is_empty()).collect(),
            ("ipv4", k) if k.starts_with("address") => conn.ipv4_addresses.push(value),
            ("ipv6", "method") => conn.ipv6_method = value,
            ("vpn", "service-type") => conn.vpn_service = value,
            ("vpn", "remote" | "gateway") => conn.vpn_gateway = value,
            ("vpn", "data") => conn.vpn_gateway = data_gateway(value).unwrap_or(conn.vpn_gateway),
            _ => {}
        }
    }
    if !seen_connection {
        return Err(if lines.iter().all(|l| l.trim().is_empty()) {
            Error::skipped("empty file")
        } else {
            Error::format("no [connection] section")
        });
    }
    sink.emit(Loc::Line(1), &conn)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    const DIR: &str = "etc/NetworkManager/system-connections/";

    #[test]
    fn parses_profiles_and_never_prints_secrets() {
        let mut all = String::new();
        for name in ["HomeWifi", "Work", "Wired"] {
            let data = fixture(&format!("networkmanager/{name}.nmconnection"));
            all.push_str(&run(&ARTIFACT, &format!("{DIR}{name}.nmconnection"), &data, 0));
        }
        assert!(!all.contains("hunter2-secret-passphrase"));
        assert!(!all.contains("s3cret-vpn"));
        assert!(all.contains("\"has_secret\":true"));
        insta::assert_snapshot!(all);
    }

    #[test]
    fn more_secret_keys_are_flagged_but_not_printed() {
        let path = format!("{DIR}x.nmconnection");
        for key in
            ["private-key", "preshared-key", "leap-password", "password-raw", "pin", "ca-cert-password", "x-passwords"]
        {
            let data = format!("[connection]\nid=x\n[802-1x]\n{key}=TOPSECRET\n");
            let out = run(&ARTIFACT, &path, data.as_bytes(), 0);
            assert!(out.contains("\"has_secret\":true") && !out.contains("TOPSECRET"), "{key}: {out}");
        }
        let out = run(&ARTIFACT, &path, b"[connection]\nid=x\n[802-1x]\nidentity=bob\n", 0);
        assert!(out.contains("\"has_secret\":false"), "{out}");
    }

    #[test]
    fn empty_and_garbage_do_not_panic() {
        let path = format!("{DIR}x.nmconnection");
        assert!(run(&ARTIFACT, &path, b"", 0).contains("skipped"));
        let junk: Vec<u8> = (0..=255u8).cycle().take(2000).collect();
        assert!(run(&ARTIFACT, &path, &junk, 0).contains("failed"));
    }
}
