//! Remote-access, tunnelling and VPN tools: what is installed and configured, who it connects
//! to, who connected, and what it logged. Attackers use these for persistence and for hands-on
//! access, and administrators forget them; each leaves identifiers an investigation needs (the
//! tool's own ID, a tunnel or network ID, a server) and secrets it must not copy (passwords,
//! tokens, private keys, pre-shared keys), which are never read into a record.
//!
//! Three artifacts, because the files are of three kinds:
//! - `remote-access-config`: configuration and state files, one record per identity, tunnel,
//!   proxy, peer, network, remote server or extension.
//! - `remote-access-log`: the tools' own logs (AnyDesk, TeamViewer, RustDesk, the VS Code
//!   server family, OpenVPN) as timestamped lines.
//! - `remote-sessions`: the connection lists AnyDesk (`connection_trace.txt`) and TeamViewer
//!   (`Connections_incoming.txt`) keep: when, from which remote ID, as which local user.
//!
//! Verified against the real software run in a container: AnyDesk, TeamViewer Host and RustDesk
//! (configuration and start-up logs), WireGuard tools, OpenVPN (client configuration and its
//! log), ZeroTier (joined networks), ngrok, cloudflared and frp (configuration each tool's own
//! checker accepts), Tailscale against a real headscale server, the VS Code server (logs and the
//! extension list). Not producible without an account or a remote peer, and therefore
//! "Synthetic only" in docs/LIMITATIONS.md: the AnyDesk and TeamViewer connection lists, the
//! MeshAgent `.msh`, VS Code's `code_tunnel.json`, cloudflared's credentials JSON, RustDesk's
//! `RustDesk2.toml` and the log lines of an incoming remote session.
//!
//! Not covered: Splashtop, DWService, `chisel`, `gost`, `rathole`, `bore` and reverse-SSH
//! (no standard configuration location); JetBrains Gateway (its logs sit in version-named
//! folders); OpenVPN status files; RustDesk server logs beyond the client's layout.

use super::ini_lite::pairs;
use super::yaml_lite::parse as parse_yaml;
use crate::common::home::user_from_path;
use crate::common::stamped_log::{parse, timestamp, Parsed};
use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, LINUX};
use nixcavate_core::time::{month_from_abbrev, parse_iso8601, parse_uint, secs_from_civil};
use nixcavate_core::{Basis, Error, Event, Loc, Precision, Record, Result, Sink, Timestamp};
use serde::Serialize;
use serde_json::Value;

pub const CONFIG: Artifact = Artifact::new(
    "remote-access-config",
    "Remote-access, tunnel and VPN tool configuration (names and servers, never secrets)",
    Category::Persistence,
    LINUX,
    &[
        "etc/anydesk/*.conf",
        "home/*/.anydesk/*.conf",
        "root/.anydesk/*.conf",
        "etc/teamviewer/global.conf",
        "opt/teamviewer/config/global.conf",
        "home/*/.config/rustdesk/*.toml",
        "root/.config/rustdesk/*.toml",
        "var/lib/rustdesk/.config/rustdesk/*.toml",
        "usr/local/mesh_services/meshagent/*.msh",
        "opt/meshagent/*.msh",
        "home/*/.config/ngrok/ngrok.yml",
        "root/.config/ngrok/ngrok.yml",
        "home/*/.ngrok2/ngrok.yml",
        "root/.ngrok2/ngrok.yml",
        "etc/cloudflared/*.yml",
        "etc/cloudflared/*.yaml",
        "etc/cloudflared/*.json",
        "home/*/.cloudflared/*.yml",
        "home/*/.cloudflared/*.yaml",
        "home/*/.cloudflared/*.json",
        "root/.cloudflared/*.yml",
        "root/.cloudflared/*.yaml",
        "root/.cloudflared/*.json",
        "var/lib/tailscale/tailscaled.state",
        "var/lib/zerotier-one/networks.d/*.conf",
        "var/lib/zerotier-one/identity.public",
        "etc/frp/*.toml",
        "etc/frp/*.ini",
        "etc/wireguard/*.conf",
        "etc/openvpn/*.conf",
        "etc/openvpn/*/*.conf",
        "etc/openvpn/*.ovpn",
        "etc/openvpn/*/*.ovpn",
        "home/*/.vscode/cli/code_tunnel.json",
        "root/.vscode/cli/code_tunnel.json",
        "home/*/.vscode-server/cli/code_tunnel.json",
        "root/.vscode-server/cli/code_tunnel.json",
        "home/*/.vscode-server/extensions/extensions.json",
        "root/.vscode-server/extensions/extensions.json",
        "home/*/.cursor-server/extensions/extensions.json",
        "root/.cursor-server/extensions/extensions.json",
        "home/*/.windsurf-server/extensions/extensions.json",
        "root/.windsurf-server/extensions/extensions.json",
    ],
    parse_config,
);

const MAX_FILE: usize = 4 << 20;
const MAX_ROWS: usize = 1000;

#[derive(Serialize)]
struct Config {
    tool: &'static str,
    /// `identity`, `config`, `tunnel`, `proxy`, `peer`, `interface`, `network`, `remote`,
    /// `server`, `credentials`, `extension`, `node`.
    kind: &'static str,
    user: String,
    name: String,
    /// The tool's own ID, a tunnel, network or node ID, or a peer's public key.
    id: String,
    /// The server, endpoint or control URL this entry reaches.
    server: String,
    /// What it exposes or routes: a local service, `AllowedIPs`, the ingress service.
    target: String,
    detail: Vec<String>,
    time: Option<Timestamp>,
    /// True when the file holds a secret (never output).
    holds_secret: bool,
}

impl Record for Config {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let (event, verb) = if self.kind == "extension" {
            ("extension_installed", "installed")
        } else {
            ("remote_access_configured", "configured")
        };
        let message = format!("{} {} {} {verb}", self.tool, self.kind, self.name);
        self.time.map(|t| Event::new(t, event, message)).into_iter()
    }
}

impl Config {
    fn new(tool: &'static str, kind: &'static str, user: &str) -> Self {
        Self {
            tool,
            kind,
            user: user.into(),
            name: String::new(),
            id: String::new(),
            server: String::new(),
            target: String::new(),
            detail: Vec::new(),
            time: None,
            holds_secret: false,
        }
    }

    fn set(mut self, name: &str, id: &str, server: &str, target: &str) -> Self {
        self.name = cap(name);
        self.id = cap(id);
        self.server = cap(server);
        self.target = cap(target);
        self
    }

    fn note(&mut self, text: String) {
        if self.detail.len() < 64 {
            self.detail.push(cap(&text));
        }
    }
}

fn cap(text: &str) -> String {
    let mut end = text.len().min(1024);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text.get(..end).unwrap_or_default().to_string()
}

fn str_at<'a>(v: &'a Value, path: &[&str]) -> &'a str {
    path.iter().try_fold(v, |v, k| v.get(k)).and_then(Value::as_str).unwrap_or_default()
}

fn scalar(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::Bool(b)) => b.to_string(),
        Some(Value::Array(a)) => a.iter().map(|i| scalar(Some(i))).collect::<Vec<_>>().join(","),
        _ => String::new(),
    }
}

fn file_stem(path: &str) -> &str {
    let name = path.rsplit('/').next().unwrap_or(path);
    name.rsplit_once('.').map_or(name, |(stem, _)| stem)
}

fn secretive(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    ["pwd", "password", "passwd", "secret", "token", "privatekey", "presharedkey", "key_pair", "authtoken"]
        .iter()
        .any(|s| k.contains(s))
}

fn anydesk(text: &str, user: &str) -> Vec<Config> {
    let mut row = Config::new("anydesk", "identity", user);
    for p in pairs(text, false) {
        match p.key {
            "ad.anynet.id" => row.id = cap(p.value),
            "ad.anynet.alias" if !p.value.is_empty() => row.name = cap(p.value),
            "ad.anynet.last_relay" => row.server = cap(p.value),
            "ad.license.name" => row.note(format!("license={}", p.value)),
            "ad.security.interactive_access" => row.note(format!("interactive_access={}", p.value)),
            key if secretive(key) && !p.value.is_empty() => row.holds_secret = true,
            _ => {}
        }
    }
    vec![row]
}

fn teamviewer(text: &str, user: &str) -> Vec<Config> {
    let mut row = Config::new("teamviewer", "identity", user);
    for line in text.lines() {
        // `[int32] ClientID = 1273690974`
        let Some((key, value)) = line.split_once('=') else { continue };
        let key = key.rsplit(']').next().unwrap_or(key).trim();
        match key {
            "ClientID" => row.id = cap(value.trim()),
            "BuddyName" | "ClientName" => row.name = cap(value.trim().trim_matches('"')),
            "LicenseType" => row.note(format!("license_type={}", value.trim())),
            _ if secretive(key) || ["Certificate", "CertificateKey", "PK", "SK"].contains(&key) => {
                row.holds_secret = true
            }
            _ => {}
        }
    }
    vec![row]
}

fn rustdesk(text: &str, user: &str) -> Vec<Config> {
    let mut row = Config::new("rustdesk", "identity", user);
    for p in pairs(text, false) {
        match (p.section, p.key) {
            ("", "id") => row.id = cap(p.value),
            ("", "enc_id") if !p.value.is_empty() => row.note("the ID is stored encrypted (enc_id)".into()),
            ("", "rendezvous_server") => row.server = cap(p.value),
            ("options", "custom-rendezvous-server") if row.server.is_empty() => row.server = cap(p.value),
            ("options", "relay-server" | "api-server") => row.note(format!("{}={}", p.key, p.value)),
            (_, key) if key != "key_pair" && secretive(key) && !p.value.is_empty() => row.holds_secret = true,
            _ => {}
        }
    }
    // `key_pair` is a multi-line array: it holds a key when numbers follow it.
    if let Some(after) = text.split("key_pair").nth(1) {
        let block = after.split("key_confirmed").next().unwrap_or_default();
        row.holds_secret |= block.bytes().any(|b| b.is_ascii_digit());
    }
    vec![row]
}

fn meshagent(text: &str, user: &str) -> Vec<Config> {
    let mut row = Config::new("meshagent", "identity", user);
    for p in pairs(text, false) {
        match p.key {
            "MeshServer" => row.server = cap(p.value),
            "MeshID" => row.id = cap(p.value),
            "MeshName" => row.name = cap(p.value),
            "ServerID" => row.note(format!("server_id={}", p.value)),
            _ => {}
        }
    }
    vec![row]
}

fn ngrok(text: &str, user: &str) -> Vec<Config> {
    let Ok(doc) = parse_yaml(text) else { return Vec::new() };
    if !doc.is_object() {
        return Vec::new();
    }
    let mut rows = Vec::new();
    let mut agent = Config::new("ngrok", "config", user);
    agent.holds_secret = doc.get("authtoken").is_some() || doc.pointer("/agent/authtoken").is_some();
    agent.server = cap(&scalar(doc.pointer("/agent/connect_url").or_else(|| doc.get("connect_url"))));
    let region = scalar(doc.pointer("/agent/region").or_else(|| doc.get("region")));
    if !region.is_empty() {
        agent.note(format!("region={region}"));
    }
    rows.push(agent);
    for (name, tunnel) in doc.get("tunnels").and_then(Value::as_object).into_iter().flatten().take(MAX_ROWS) {
        let mut row = Config::new("ngrok", "tunnel", user).set(name, "", "", &scalar(tunnel.get("addr")));
        for key in ["proto", "domain", "hostname", "subdomain", "remote_addr", "region"] {
            let v = scalar(tunnel.get(key));
            if !v.is_empty() {
                row.note(format!("{key}={v}"));
            }
        }
        rows.push(row);
    }
    rows
}

fn cloudflared(text: &str, path: &str, user: &str) -> Vec<Config> {
    if path.ends_with(".json") {
        let Ok(doc) = serde_json::from_str::<Value>(text) else { return Vec::new() };
        let mut row = Config::new("cloudflared", "credentials", user).set(
            str_at(&doc, &["TunnelName"]),
            str_at(&doc, &["TunnelID"]),
            "",
            "",
        );
        row.note(format!("account={}", str_at(&doc, &["AccountTag"])));
        row.holds_secret = doc.get("TunnelSecret").is_some();
        return vec![row];
    }
    let Ok(doc) = parse_yaml(text) else { return Vec::new() };
    let mut head = Config::new("cloudflared", "config", user).set("", &scalar(doc.get("tunnel")), "", "");
    let creds = scalar(doc.get("credentials-file"));
    if !creds.is_empty() {
        head.note(format!("credentials-file={creds}"));
    }
    let mut rows = vec![head];
    for rule in doc.get("ingress").and_then(Value::as_array).into_iter().flatten().take(MAX_ROWS) {
        let host = scalar(rule.get("hostname"));
        let mut row = Config::new("cloudflared", "tunnel", user).set(
            &host,
            &scalar(doc.get("tunnel")),
            "",
            &scalar(rule.get("service")),
        );
        let path = scalar(rule.get("path"));
        if !path.is_empty() {
            row.note(format!("path={path}"));
        }
        rows.push(row);
    }
    rows
}

fn zerotier(text: &str, path: &str, user: &str) -> Vec<Config> {
    let stem = file_stem(path);
    if path.ends_with("identity.public") {
        // `<10 hex digits>:0:<public key>`: only the node address is kept.
        let address = text.split(':').next().unwrap_or_default().trim();
        return vec![Config::new("zerotier", "node", user).set("", address, "", "")];
    }
    let mut row = Config::new("zerotier", "network", user).set("", stem, "", "");
    if let Ok(doc) = serde_json::from_str::<Value>(text) {
        row.name = cap(str_at(&doc, &["name"]));
        for key in ["type", "status", "mac", "mtu"] {
            let v = scalar(doc.get(key));
            if !v.is_empty() {
                row.note(format!("{key}={v}"));
            }
        }
        let ips = scalar(doc.get("assignedAddresses"));
        if !ips.is_empty() {
            row.target = cap(&ips);
        }
    }
    vec![row]
}

fn frp(text: &str, path: &str, user: &str) -> Vec<Config> {
    let ini = path.ends_with(".ini");
    let (mut server, mut port) = (String::new(), String::new());
    let mut head = Config::new("frp", "config", user).set(file_stem(path), "", "", "");
    let mut rows: Vec<Config> = Vec::new();
    // The proxy being read: its section id, the row and the local address halves.
    let mut proxy: Option<(String, Config, String, String)> = None;
    let flush = |proxy: &mut Option<(String, Config, String, String)>, rows: &mut Vec<Config>| {
        if let Some((_, mut row, ip, port)) = proxy.take() {
            if !ip.is_empty() || !port.is_empty() {
                row.target = format!("{ip}:{port}");
            }
            rows.push(row);
        }
    };
    for p in pairs(text, false) {
        let key = p.key;
        let global = if ini { p.section == "common" } else { p.section.is_empty() };
        if global {
            match key {
                "serverAddr" | "server_addr" => server = p.value.into(),
                "serverPort" | "server_port" => port = p.value.into(),
                "bindPort" | "bind_port" => head.note(format!("listens on {}", p.value)),
                "user" => head.note(format!("user={}", p.value)),
                _ if secretive(key) => head.holds_secret = true,
                _ => {}
            }
            continue;
        }
        if !ini && p.section != "proxies" {
            continue;
        }
        let id = format!("{}#{}", p.section, p.index);
        if proxy.as_ref().is_none_or(|(i, ..)| *i != id) {
            flush(&mut proxy, &mut rows);
            let name = if ini { p.section } else { "" };
            proxy = Some((id, Config::new("frp", "proxy", user).set(name, "", "", ""), String::new(), String::new()));
        }
        let Some((_, row, ip, local_port)) = proxy.as_mut() else { continue };
        match key {
            "name" => row.name = cap(p.value),
            "type" => row.note(format!("type={}", p.value)),
            "localIP" | "local_ip" => *ip = p.value.into(),
            "localPort" | "local_port" => *local_port = p.value.into(),
            "remotePort" | "remote_port" => row.note(format!("remote_port={}", p.value)),
            "customDomains" | "custom_domains" | "subdomain" => row.note(format!("{key}={}", p.value)),
            _ if secretive(key) || key == "sk" => row.holds_secret = true,
            _ => {}
        }
    }
    flush(&mut proxy, &mut rows);
    if !server.is_empty() {
        head.server = cap(&if port.is_empty() { server } else { format!("{server}:{port}") });
    }
    rows.insert(0, head);
    rows.truncate(MAX_ROWS);
    rows
}

fn wireguard(text: &str, path: &str, user: &str) -> Vec<Config> {
    let mut rows: Vec<Config> = Vec::new();
    let stem = file_stem(path);
    let mut current: Option<(String, u32)> = None;
    for p in pairs(text, false) {
        let section = (p.section.to_string(), p.index);
        if current.as_ref() != Some(&section) {
            current = Some(section);
            let row = if p.section.eq_ignore_ascii_case("Peer") {
                Config::new("wireguard", "peer", user)
            } else {
                Config::new("wireguard", "interface", user).set(stem, "", "", "")
            };
            rows.push(row);
        }
        let Some(row) = rows.last_mut() else { continue };
        match p.key.to_ascii_lowercase().as_str() {
            "address" => row.target = cap(p.value),
            "allowedips" => row.target = cap(p.value),
            "publickey" => row.id = cap(p.value),
            "endpoint" => row.server = cap(p.value),
            "listenport" | "dns" | "persistentkeepalive" | "mtu" | "table" => {
                row.note(format!("{}={}", p.key, p.value))
            }
            // Commands run as root when the interface comes up or goes down.
            "preup" | "postup" | "predown" | "postdown" => row.note(format!("{}={}", p.key, p.value)),
            "privatekey" | "presharedkey" => row.holds_secret = true,
            _ => {}
        }
    }
    rows.truncate(MAX_ROWS);
    rows
}

fn openvpn(text: &str, path: &str, user: &str) -> Vec<Config> {
    let mut head = Config::new("openvpn", "config", user).set(file_stem(path), "", "", "");
    let mut remotes = Vec::new();
    for p in pairs(text, true) {
        match p.key {
            "remote" => {
                let mut words = p.value.split_whitespace();
                let (host, port, proto) = (
                    words.next().unwrap_or_default(),
                    words.next().unwrap_or("1194"),
                    words.next().unwrap_or_default(),
                );
                let mut row =
                    Config::new("openvpn", "remote", user).set(file_stem(path), "", &format!("{host}:{port}"), "");
                if !proto.is_empty() {
                    row.note(format!("proto={proto}"));
                }
                remotes.push(row);
            }
            "auth-user-pass" => {
                head.note(if p.value.is_empty() {
                    "auth-user-pass (prompts)".into()
                } else {
                    format!("auth-user-pass file {}", p.value)
                });
                head.holds_secret |= !p.value.is_empty();
            }
            // Commands and files the daemon runs or reads.
            "up"
            | "down"
            | "route-up"
            | "route-pre-down"
            | "ipchange"
            | "tls-verify"
            | "client-connect"
            | "client-disconnect"
            | "learn-address"
            | "auth-user-pass-verify"
            | "plugin"
            | "script-security"
            | "management"
            | "ca"
            | "cert"
            | "key"
            | "tls-auth"
            | "tls-crypt"
            | "askpass"
            | "dev"
            | "proto"
            | "port"
            | "server"
            | "client"
            | "remote-cert-tls"
            | "redirect-gateway" => {
                head.note(if p.value.is_empty() { p.key.to_string() } else { format!("{}={}", p.key, p.value) });
            }
            _ => {}
        }
    }
    // Inline `<key>` blocks are skipped by the line reader; their presence is a secret in the file.
    head.holds_secret |= text.contains("<key>") || text.contains("<tls-crypt>") || text.contains("<tls-auth>");
    if let Some(first) = remotes.first() {
        head.server = first.server.clone();
    }
    let mut rows = vec![head];
    rows.extend(remotes);
    rows.truncate(MAX_ROWS);
    rows
}

/// A Tailscale state file: a JSON object of key to base64 value (real file, written by
/// tailscaled 1.104 against a headscale server). `_profiles` lists the logins (profile name,
/// control URL, user, tailnet, node ID, creation time) and each `profile-<id>` holds the node's
/// preferences, next to its private node key: the preferences that matter here are read, keys
/// are never output. `_machinekey`, disco keys and certificates are secrets and are not read.
fn tailscale(text: &str, user: &str) -> Vec<Config> {
    let Ok(Value::Object(state)) = serde_json::from_str::<Value>(text) else { return Vec::new() };
    let decoded = |key: &str| {
        state
            .get(key)
            .and_then(Value::as_str)
            .and_then(base64_decode)
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
    };
    let mut identity = Config::new("tailscale", "identity", user);
    identity.holds_secret = state.keys().any(|k| k.starts_with('_') && k != "_profiles" && k != "_current-profile");
    let mut rows = Vec::new();
    for (id, profile) in decoded("_profiles").as_ref().and_then(Value::as_object).into_iter().flatten().take(MAX_ROWS) {
        let mut row = Config::new("tailscale", "node", user).set(
            str_at(profile, &["Name"]),
            str_at(profile, &["NodeID"]),
            str_at(profile, &["ControlURL"]),
            str_at(profile, &["NetworkProfile", "MagicDNSName"]),
        );
        row.note(format!("profile={id}"));
        row.note(format!("login={}", str_at(profile, &["UserProfile", "LoginName"])));
        row.note(format!("tailnet={}", str_at(profile, &["NetworkProfile", "DomainName"])));
        row.time = parse_iso8601(str_at(profile, &["Created"]).as_bytes()).and_then(|(t, _)| t.recorded());
        if let Some(prefs) = profile.get("Key").and_then(Value::as_str).and_then(decoded) {
            row.note(format!("hostname={}", str_at(&prefs, &["Hostname"])));
            for flag in ["RunSSH", "RouteAll", "WantRunning", "RunWebClient"] {
                if prefs.get(flag) == Some(&Value::Bool(true)) {
                    row.note(format!("{flag}=true"));
                }
            }
            for list in ["AdvertiseRoutes", "AdvertiseTags"] {
                let v = scalar(prefs.get(list));
                if !v.is_empty() {
                    row.note(format!("{list}={v}"));
                }
            }
            if !str_at(&prefs, &["ExitNodeID"]).is_empty() || !str_at(&prefs, &["ExitNodeIP"]).is_empty() {
                row.note("uses an exit node".into());
            }
        }
        rows.push(row);
    }
    rows.insert(0, identity);
    rows
}

fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let (mut bits, mut count, mut out) = (0u32, 0, Vec::new());
    for b in text.bytes().take(1 << 20) {
        let v = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' => break,
            _ => return None,
        };
        bits = (bits << 6) | u32::from(v);
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count) as u8);
            bits &= (1 << count) - 1;
        }
    }
    Some(out)
}

fn vscode(text: &str, path: &str, user: &str) -> Vec<Config> {
    let server = ["vscode-server", "cursor-server", "windsurf-server"]
        .into_iter()
        .find(|s| path.contains(s))
        .unwrap_or("vscode");
    let tool = match server {
        "cursor-server" => "cursor-server",
        "windsurf-server" => "windsurf-server",
        _ if path.contains("/.vscode/cli/") => "vscode-tunnel",
        _ => "vscode-server",
    };
    let Ok(doc) = serde_json::from_str::<Value>(text) else { return Vec::new() };
    if path.ends_with("code_tunnel.json") {
        let mut row = Config::new(if tool == "vscode-server" { "vscode-tunnel" } else { tool }, "tunnel", user).set(
            str_at(&doc, &["name"]),
            str_at(&doc, &["id"]),
            "",
            "",
        );
        row.note(format!("cluster={}", str_at(&doc, &["cluster"])));
        return vec![row];
    }
    let mut rows = Vec::new();
    for ext in doc.as_array().into_iter().flatten().take(MAX_ROWS) {
        let mut row = Config::new(tool, "extension", user).set(
            str_at(ext, &["identifier", "id"]),
            str_at(ext, &["identifier", "uuid"]),
            "",
            "",
        );
        row.note(format!("version={}", str_at(ext, &["version"])));
        let source = str_at(ext, &["metadata", "source"]);
        if !source.is_empty() {
            row.note(format!("source={source}"));
        }
        row.time =
            ext.pointer("/metadata/installedTimestamp").and_then(Value::as_i64).filter(|ms| *ms > 0).and_then(|ms| {
                Timestamp::checked(ms / 1000, ((ms % 1000) * 1_000_000) as u32, Precision::Millis, Basis::Recorded)
            });
        rows.push(row);
    }
    rows
}

fn parse_config(input: &Input, sink: &mut Sink) -> Result<()> {
    let data = input.data.get(..input.data.len().min(MAX_FILE)).unwrap_or_default();
    let text = lossy(data);
    let (path, user) = (input.path, user_from_path(input.path));
    let name = path.rsplit('/').next().unwrap_or_default();
    if text.trim().is_empty() && !path.contains("zerotier") {
        return Err(Error::skipped("empty file"));
    }
    let rows = if path.contains("anydesk") {
        anydesk(&text, user)
    } else if path.contains("teamviewer") {
        teamviewer(&text, user)
    } else if path.contains("rustdesk") {
        rustdesk(&text, user)
    } else if name.ends_with(".msh") {
        meshagent(&text, user)
    } else if path.contains("ngrok") {
        ngrok(&text, user)
    } else if path.contains("cloudflared") {
        cloudflared(&text, path, user)
    } else if path.contains("tailscale") {
        tailscale(&text, user)
    } else if path.contains("zerotier-one") {
        zerotier(&text, path, user)
    } else if path.contains("etc/frp/") {
        frp(&text, path, user)
    } else if path.contains("etc/wireguard/") {
        wireguard(&text, path, user)
    } else if path.contains("etc/openvpn/") {
        openvpn(&text, path, user)
    } else {
        vscode(&text, path, user)
    };
    if rows.is_empty() {
        return Err(Error::format("no entries found: the file is not in the expected format"));
    }
    for row in &rows {
        sink.emit(Loc::None, row)?;
    }
    Ok(())
}

pub const LOGS: Artifact = Artifact::new(
    "remote-access-log",
    "Remote-access tool logs: AnyDesk, TeamViewer, RustDesk, VS Code server, OpenVPN",
    Category::Logs,
    LINUX,
    &[
        "var/log/anydesk.trace",
        "var/log/anydesk/*.trace",
        "etc/anydesk/*.trace",
        "home/*/.anydesk/*.trace",
        "root/.anydesk/*.trace",
        "var/log/teamviewer*/TeamViewer*_Logfile*.log",
        "opt/teamviewer/logfiles/TeamViewer*_Logfile*.log",
        "home/*/.local/share/logs/RustDesk/*/*.log",
        "root/.local/share/logs/RustDesk/*/*.log",
        "var/log/rustdesk-server/*.log*",
        "home/*/.vscode-server/data/logs/*/*.log",
        "root/.vscode-server/data/logs/*/*.log",
        "home/*/.cursor-server/data/logs/*/*.log",
        "root/.cursor-server/data/logs/*/*.log",
        "home/*/.windsurf-server/data/logs/*/*.log",
        "root/.windsurf-server/data/logs/*/*.log",
        "home/*/.vscode-server/cli/servers/*/log.txt",
        "root/.vscode-server/cli/servers/*/log.txt",
        "home/*/.vscode/cli/tunnel-*.log",
        "root/.vscode/cli/tunnel-*.log",
        "var/log/openvpn.log*",
        "var/log/openvpn/*.log*",
    ],
    |input, sink| parse(input, sink, "a remote-access tool log", "remote_access_log", log_line),
);

fn log_line<'a>(input: &Input, line: &'a str) -> Option<Parsed<'a>> {
    let path = input.path;
    if path.contains("anydesk") {
        anydesk_line(input, line)
    } else if path.contains("teamviewer") {
        teamviewer_line(input, line)
    } else if path.contains("RustDesk") || path.contains("rustdesk") {
        rustdesk_line(input, line)
    } else if path.contains("openvpn") {
        openvpn_line(input, line)
    } else {
        vscode_line(input, line)
    }
}

fn notable(message: &str, words: &[&str]) -> bool {
    let lower = message.to_ascii_lowercase();
    words.iter().any(|w| lower.contains(w))
}

/// `   info 2026-11-13 01:28:09.381         ad   main   4991   4991   component - message`
fn anydesk_line<'a>(input: &Input, line: &'a str) -> Option<Parsed<'a>> {
    let trimmed = line.trim_start();
    let (level, rest) = trimmed.split_once(' ')?;
    if !matches!(level, "info" | "warning" | "error" | "debug" | "fatal") {
        return None;
    }
    let rest = rest.trim_start();
    let (time, used) = parse_iso8601(rest.as_bytes())?;
    let (fields, message) = rest.get(used..)?.split_once(" - ")?;
    let mut tokens = fields.split_whitespace();
    let (_prefix, _thread, pid, _tid, component) =
        (tokens.next()?, tokens.next()?, tokens.next()?, tokens.next()?, tokens.next()?);
    Some(Parsed {
        time: Some(timestamp(input, &time)),
        level: Some(level),
        source: Some(component),
        pid: pid.parse().ok(),
        message,
        timeline: notable(
            message,
            &[
                "startup",
                "accepting connection",
                "incoming",
                "session started",
                "session closed",
                "logged in",
                "connection closed",
            ],
        ),
    })
}

/// `2026/11/13 01:27:18.754  4878  4876 S   message`; `S!` and `S!!` mark warnings and errors.
fn teamviewer_line<'a>(input: &Input, line: &'a str) -> Option<Parsed<'a>> {
    let (date, rest) = line.split_once(' ')?;
    let (clock, rest) = rest.split_once(' ')?;
    let iso = format!("{} {}", date.replace('/', "-"), clock);
    let (time, _) = parse_iso8601(iso.as_bytes())?;
    let mut tokens = rest.split_whitespace();
    let (pid, _tid) = (tokens.next()?, tokens.next()?);
    let after_ids = rest
        .trim_start()
        .split_once(char::is_whitespace)?
        .1
        .trim_start()
        .split_once(char::is_whitespace)?
        .1
        .trim_start();
    let (level, message) = match after_ids.split_once(char::is_whitespace) {
        Some((marker, message)) if marker.starts_with('S') && marker.bytes().skip(1).all(|b| b == b'!') => {
            (Some(marker), message.trim_start())
        }
        _ => (None, after_ids),
    };
    pid.parse::<u32>().ok()?;
    Some(Parsed {
        time: Some(timestamp(input, &time)),
        level,
        source: None,
        pid: pid.parse().ok(),
        message,
        timeline: notable(message, &["logger started", "incoming", "accepted", "remotecontrol", "session"]),
    })
}

/// `[2026-11-13 01:23:11.223191 +00:00] INFO [src/core_main.rs:382] message`
fn rustdesk_line<'a>(input: &Input, line: &'a str) -> Option<Parsed<'a>> {
    let (stamp, rest) = line.strip_prefix('[')?.split_once("] ")?;
    let (clock, zone) = stamp.rsplit_once(' ')?;
    let (time, _) = parse_iso8601(format!("{clock}{zone}").as_bytes())?;
    let (level, rest) = rest.split_once(' ')?;
    let (source, message) = match rest.strip_prefix('[').and_then(|r| r.split_once("] ")) {
        Some((source, message)) => (Some(source), message),
        None => (None, rest),
    };
    Some(Parsed {
        time: Some(timestamp(input, &time)),
        level: Some(level),
        source,
        pid: None,
        message,
        timeline: notable(
            message,
            &["connection opened", "connection closed", "login request", "authorized", "start --service"],
        ),
    })
}

/// `2026-11-13 01:30:29 us=531806 message` (with `--log`), or the classic `Fri Nov 13 01:30:29 2026 message`.
fn openvpn_line<'a>(input: &Input, line: &'a str) -> Option<Parsed<'a>> {
    let keywords = [
        "peer connection initiated",
        "initialization sequence completed",
        "tls error",
        "auth_failed",
        "sigterm",
        "connection reset",
        "connect to",
    ];
    if let Some((time, used)) = parse_iso8601(line.as_bytes()) {
        let rest = line.get(used..)?.trim_start();
        let message = match rest.strip_prefix("us=") {
            Some(after) => after.split_once(' ').map_or("", |(_, m)| m),
            None => rest,
        };
        return Some(Parsed {
            time: Some(timestamp(input, &time)),
            level: None,
            source: None,
            pid: None,
            message,
            timeline: notable(message, &keywords),
        });
    }
    // Www Mmm dd hh:mm:ss yyyy
    let mut parts = line.splitn(6, ' ').filter(|p| !p.is_empty());
    let (_weekday, month, day, clock, year) =
        (parts.next()?, parts.next()?, parts.next()?, parts.next()?, parts.next()?);
    let rest = line.split_once(year)?.1.trim_start();
    let month = month_from_abbrev(month.as_bytes())?;
    let (h, m, s) = {
        let mut c = clock.split(':');
        (parse_uint(c.next()?.as_bytes())?, parse_uint(c.next()?.as_bytes())?, parse_uint(c.next()?.as_bytes())?)
    };
    let secs = secs_from_civil(
        parse_uint(year.as_bytes())? as i64,
        month,
        parse_uint(day.as_bytes())? as u32,
        h as u32,
        m as u32,
        s as u32,
    )?;
    Some(Parsed {
        time: Some(input.local_time(secs, 0, Precision::Seconds)),
        level: None,
        source: None,
        pid: None,
        message: rest,
        timeline: notable(rest, &keywords),
    })
}

/// `2026-11-13 01:18:34.357 [info] message` (the server's logs) or `[2026-11-13 01:19:08] info message`
/// (the CLI's, as `code tunnel` prints it and `cli/servers/*/log.txt` keeps it).
fn vscode_line<'a>(input: &Input, line: &'a str) -> Option<Parsed<'a>> {
    let words = [
        "installing extension",
        "successfully installed",
        "new connection",
        "connection established",
        "reconnect",
        "tunnel",
        "logged in",
    ];
    if let Some(rest) = line.strip_prefix('[') {
        let (stamp, rest) = rest.split_once("] ")?;
        let (time, _) = parse_iso8601(stamp.as_bytes())?;
        let (level, message) = rest.split_once(' ').unwrap_or((rest, ""));
        return Some(Parsed {
            time: Some(timestamp(input, &time)),
            level: Some(level),
            source: None,
            pid: None,
            message,
            timeline: notable(message, &words),
        });
    }
    let (time, used) = parse_iso8601(line.as_bytes())?;
    let rest = line.get(used..)?.trim_start();
    let (level, message) = rest.strip_prefix('[')?.split_once("] ")?;
    Some(Parsed {
        time: Some(timestamp(input, &time)),
        level: Some(level),
        source: None,
        pid: None,
        message,
        timeline: notable(message, &words),
    })
}

pub const SESSIONS: Artifact = Artifact::new(
    "remote-sessions",
    "Remote-desktop connection lists: AnyDesk connection_trace.txt, TeamViewer Connections_incoming.txt",
    Category::Activity,
    LINUX,
    &[
        "etc/anydesk/connection_trace.txt",
        "home/*/.anydesk/connection_trace.txt",
        "root/.anydesk/connection_trace.txt",
        "var/log/teamviewer*/Connections_incoming.txt",
        "var/log/teamviewer*/Connections.txt",
        "opt/teamviewer/logfiles/Connections*.txt",
    ],
    parse_sessions,
);

#[derive(Serialize)]
struct Session<'a> {
    tool: &'static str,
    /// `incoming` or `outgoing`.
    direction: &'a str,
    time: Option<Timestamp>,
    end_time: Option<Timestamp>,
    remote_id: &'a str,
    remote_name: &'a str,
    /// The account on this machine the session ran as (TeamViewer).
    local_user: &'a str,
    /// The connection type (TeamViewer) or the decision (AnyDesk).
    session_type: &'a str,
}

impl Record for Session<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let who = if self.remote_name.is_empty() {
            self.remote_id.to_string()
        } else {
            format!("{} ({})", self.remote_name, self.remote_id)
        };
        self.time
            .map(|t| Event::new(t, "remote_session", format!("{} {} session with {who}", self.tool, self.direction)))
            .into_iter()
    }
}

/// `2026-11-13, 10:12` (AnyDesk) or `13-11-2026 10:12:05` (TeamViewer, day first) as local wall time.
fn wall_time(input: &Input, text: &str, year_first: bool) -> Option<Timestamp> {
    let text = text.trim().replace(',', "");
    let mut parts = text.split_whitespace();
    let (date, clock) = (parts.next()?, parts.next()?);
    let nums: Vec<u64> = date.split(['-', '/']).map(|n| parse_uint(n.as_bytes())).collect::<Option<_>>()?;
    let (year, month, day) = match (year_first, nums.as_slice()) {
        (true, [y, m, d]) => (*y, *m, *d),
        (false, [d, m, y]) => (*y, *m, *d),
        _ => return None,
    };
    let c: Vec<u64> = clock.split(':').map(|n| parse_uint(n.as_bytes())).collect::<Option<_>>()?;
    let (h, m, s) = (*c.first()?, *c.get(1)?, c.get(2).copied().unwrap_or(0));
    let secs = secs_from_civil(
        year as i64,
        u32::try_from(month).ok()?,
        u32::try_from(day).ok()?,
        u32::try_from(h).ok()?,
        u32::try_from(m).ok()?,
        u32::try_from(s).ok()?,
    )?;
    Some(input.local_time(secs, 0, Precision::Seconds))
}

fn parse_sessions(input: &Input, sink: &mut Sink) -> Result<()> {
    let anydesk = input.path.contains("anydesk");
    let mut any = false;
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let text = text.trim_end();
        if text.trim().is_empty() {
            return Ok(());
        }
        any = true;
        let record = if anydesk {
            // `Incoming    2026-11-13, 10:12    User    7283745112    1000000001`
            let fields: Vec<&str> = text.split("  ").map(str::trim).filter(|f| !f.is_empty()).collect();
            let direction = fields.first().map(|d| d.to_ascii_lowercase());
            match (direction.as_deref(), fields.get(1).and_then(|t| wall_time(input, t, true)), fields.get(3)) {
                (Some(d @ ("incoming" | "outgoing")), Some(time), Some(remote_id)) => {
                    Some((d == "incoming", time, None, *remote_id, "", "", fields.get(2).copied().unwrap_or_default()))
                }
                _ => None,
            }
        } else {
            // `ID <tab> name <tab> start <tab> end <tab> local user <tab> type <tab> {guid}`
            let fields: Vec<&str> = text.split('\t').collect();
            match (fields.first(), fields.get(2).and_then(|t| wall_time(input, t, false))) {
                (Some(id), Some(time)) if fields.len() >= 6 => Some((
                    !input.path.ends_with("Connections.txt"),
                    time,
                    fields.get(3).and_then(|t| wall_time(input, t, false)),
                    *id,
                    fields[1],
                    fields[4],
                    fields[5],
                )),
                _ => None,
            }
        };
        let Some((incoming, time, end_time, remote_id, remote_name, local_user, session_type)) = record else {
            sink.warn(format!("line {}: not a connection record", line.number));
            return Ok(());
        };
        let tool = if anydesk { "anydesk" } else { "teamviewer" };
        let direction = if incoming { "incoming" } else { "outgoing" };
        sink.emit(
            Loc::Line(line.number),
            &Session { tool, direction, time: Some(time), end_time, remote_id, remote_name, local_user, session_type },
        )
    })?;
    if any {
        Ok(())
    } else {
        Err(Error::skipped("empty file"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::run;
    use nixcavate_source::glob::Pattern;
    use serde_json::Value;
    use std::collections::BTreeSet;

    fn dir(name: &str) -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test_files/remote-tools").join(name)
    }

    /// Every file under `remote-tools/<folder>` as (path relative to it, bytes).
    fn tree(folder: &str) -> Vec<(String, Vec<u8>)> {
        fn walk(d: &std::path::Path, base: &std::path::Path, out: &mut Vec<(String, Vec<u8>)>) {
            for item in std::fs::read_dir(d).unwrap().flatten() {
                let p = item.path();
                if p.is_dir() {
                    walk(&p, base, out);
                } else {
                    out.push((p.strip_prefix(base).unwrap().to_str().unwrap().to_string(), std::fs::read(&p).unwrap()));
                }
            }
        }
        let base = dir(folder);
        let mut out = Vec::new();
        walk(&base, &base, &mut out);
        out.sort();
        out
    }

    fn truth(name: &str) -> String {
        String::from_utf8_lossy(&std::fs::read(dir("truth").join(name)).unwrap()).into_owned()
    }

    fn matches(a: &Artifact, path: &str) -> bool {
        a.paths.iter().any(|p| Pattern::new(p).matches(path))
    }

    /// Records of one file, asserting that the parser neither warned nor failed.
    fn rows_of(a: &Artifact, files: &[(String, Vec<u8>)], suffix: &str) -> Vec<Value> {
        let (path, data) = files.iter().find(|(p, _)| p.ends_with(suffix)).unwrap_or_else(|| panic!("{suffix}"));
        assert!(matches(a, path), "{path} is not matched by {}", a.id);
        let out = run(a, path, data, 0);
        assert!(!out.contains("--- warning") && !out.contains("--- failed"), "{path}: {out}");
        out.lines().take_while(|l| !l.starts_with("---")).map(|l| serde_json::from_str(l).unwrap()).collect()
    }

    fn real() -> Vec<(String, Vec<u8>)> {
        tree("tree")
    }

    fn details(row: &Value) -> Vec<String> {
        row["detail"].as_array().unwrap().iter().map(|d| d.as_str().unwrap().to_string()).collect()
    }

    fn of_kind<'a>(rows: &'a [Value], kind: &str) -> Vec<&'a Value> {
        rows.iter().filter(|r| r["kind"] == kind).collect()
    }

    #[test]
    fn ngrok_and_cloudflared_and_frp_equal_what_the_tools_checked() {
        let files = real();
        let rows = rows_of(&CONFIG, &files, ".config/ngrok/ngrok.yml");
        assert!(truth("ngrok.truth.txt").contains("Valid configuration file"));
        let tunnels = of_kind(&rows, "tunnel");
        assert_eq!(
            tunnels.iter().map(|t| (t["name"].as_str().unwrap(), t["target"].as_str().unwrap())).collect::<Vec<_>>(),
            [("ssh", "22"), ("web", "8080")]
        );
        assert!(details(tunnels[1]).contains(&"domain=demo.example.ngrok.app".to_string()));
        assert_eq!(of_kind(&rows, "config")[0]["holds_secret"], true);

        // `cloudflared tunnel ingress rule https://ssh.example.com` matched the rule that has this service.
        let rows = rows_of(&CONFIG, &files, "etc/cloudflared/config.yml");
        let ingress = of_kind(&rows, "tunnel");
        assert_eq!(ingress.len(), 3);
        let matched = truth("cloudflared.truth.txt");
        let service = matched.lines().find_map(|l| l.trim().strip_prefix("service: ")).unwrap().to_string();
        let ssh = ingress.iter().find(|r| r["name"] == "ssh.example.com").unwrap();
        assert_eq!(ssh["target"].as_str(), Some(service.as_str()));
        assert_eq!(rows[0]["id"], "6ff42ae2-765d-4adf-8112-31c55c1551ef");
        let creds = rows_of(&CONFIG, &files, ".cloudflared/6ff42ae2-765d-4adf-8112-31c55c1551ef.json");
        assert_eq!(
            (creds[0]["kind"].as_str(), creds[0]["id"].as_str(), creds[0]["holds_secret"].as_bool()),
            (Some("credentials"), Some("6ff42ae2-765d-4adf-8112-31c55c1551ef"), Some(true))
        );

        // `frpc verify` accepted both files.
        assert_eq!(truth("frp.truth.txt").matches("syntax is ok").count(), 2);
        for (file, server) in
            [("etc/frp/frpc.toml", "198.51.100.7:7000"), ("etc/frp/frpc-old.ini", "198.51.100.7:7000")]
        {
            let rows = rows_of(&CONFIG, &files, file);
            assert_eq!(rows[0]["server"], server, "{file}");
            assert_eq!(rows[0]["holds_secret"], true);
            let ssh = rows
                .iter()
                .find(|r| r["kind"] == "proxy" && r["name"] == "ssh")
                .unwrap_or_else(|| panic!("{file}: {rows:?}"));
            assert_eq!(ssh["target"], "127.0.0.1:22", "{file}");
            assert!(details(ssh).contains(&"remote_port=6000".to_string()));
            assert!(details(ssh).contains(&"type=tcp".to_string()));
        }
        let toml = rows_of(&CONFIG, &files, "etc/frp/frpc.toml");
        assert_eq!(of_kind(&toml, "proxy").len(), 2);
        assert!(details(of_kind(&toml, "proxy")[1]).contains(&"customDomains=[\"www.example.com\"]".to_string()));
    }

    #[test]
    fn wireguard_and_openvpn_and_zerotier_equal_the_tools_own_output() {
        let files = real();
        // `wg-quick strip wg0` is what WireGuard itself reads from the file.
        let stripped = truth("wireguard.truth.txt");
        let rows = rows_of(&CONFIG, &files, "etc/wireguard/wg0.conf");
        let peer = of_kind(&rows, "peer")[0];
        for (want, key) in
            [(peer["server"].as_str().unwrap(), "Endpoint"), (peer["target"].as_str().unwrap(), "AllowedIPs")]
        {
            assert!(stripped.contains(&format!("{key} = {want}")), "{key}: {want}");
        }
        assert!(stripped.contains(&format!("PublicKey = {}", peer["id"].as_str().unwrap())));
        let interface = of_kind(&rows, "interface")[0];
        assert_eq!((interface["name"].as_str(), interface["holds_secret"].as_bool()), (Some("wg0"), Some(true)));
        assert!(details(interface).contains(&"ListenPort=51820".to_string()));
        assert!(details(interface).contains(&"PostUp=iptables -A FORWARD -i %i -j ACCEPT".to_string()));
        assert_eq!(peer["holds_secret"], true);

        // OpenVPN's own log lists the connection profiles it parsed from the file.
        let log = String::from_utf8_lossy(&files.iter().find(|(p, _)| p.ends_with("var/log/openvpn.log")).unwrap().1)
            .into_owned();
        let rows = rows_of(&CONFIG, &files, "etc/openvpn/client/office.conf");
        let remotes = of_kind(&rows, "remote");
        assert_eq!(remotes.len(), log.matches("  remote = '").count());
        assert_eq!(remotes.len(), 2);
        for (row, host, port) in [(remotes[0], "vpn.example.com", "1194"), (remotes[1], "backup.example.com", "443")] {
            assert_eq!(row["server"], format!("{host}:{port}"));
            assert!(log.contains(&format!("remote = '{host}'")) && log.contains(&format!("remote_port = '{port}'")));
        }
        assert_eq!(details(remotes[1]), ["proto=tcp"]);
        let config = of_kind(&rows, "config")[0];
        assert!(details(config).contains(&"auth-user-pass file /etc/openvpn/client/creds.txt".to_string()));
        assert_eq!(config["holds_secret"], true);

        // `zerotier-cli listnetworks`
        let nets: BTreeSet<String> = truth("zerotier.truth.txt")
            .lines()
            .filter(|l| l.starts_with("200 listnetworks ") && !l.contains("<nwid>"))
            .map(|l| l.split_whitespace().nth(2).unwrap().to_string())
            .collect();
        let found: BTreeSet<String> = files
            .iter()
            .filter(|(p, _)| p.contains("networks.d/") && p.ends_with(".conf") && !p.ends_with(".local.conf"))
            .flat_map(|(p, _)| rows_of(&CONFIG, &files, p.rsplit('/').next().unwrap()))
            .map(|r| r["id"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(found, nets);
        assert_eq!(nets.len(), 2);
        let info = truth("zerotier.truth.txt")
            .lines()
            .find(|l| l.starts_with("200 info "))
            .unwrap()
            .split_whitespace()
            .nth(2)
            .unwrap()
            .to_string();
        assert_eq!(rows_of(&CONFIG, &files, "identity.public")[0]["id"], info);
    }

    /// Tailscale against a real headscale: the node, login, tailnet and control URL must be those
    /// `tailscale status --json` reports.
    #[test]
    fn tailscale_state_equals_tailscale_status() {
        let files = real();
        let rows = rows_of(&CONFIG, &files, "tailscaled.state");
        let status: Value = serde_json::from_str(&truth("tailscale-status.json")).unwrap();
        let node = of_kind(&rows, "node")[0];
        let d = details(node);
        assert!(d.contains(&format!("hostname={}", status["Self"]["HostName"].as_str().unwrap())), "{d:?}");
        assert!(d.contains(&format!("tailnet={}", status["CurrentTailnet"]["Name"].as_str().unwrap())));
        let user = status["User"].as_object().unwrap().values().next().unwrap();
        assert!(d.contains(&format!("login={}", user["LoginName"].as_str().unwrap())));
        assert_eq!(node["target"], status["CurrentTailnet"]["MagicDNSSuffix"]);
        assert_eq!(node["server"], "http://l8s-headscale:8080");
        assert_eq!(of_kind(&rows, "identity")[0]["holds_secret"], true);
        assert!(run(
            &CONFIG,
            "var/lib/tailscale/tailscaled.state",
            &files.iter().find(|(p, _)| p.ends_with("tailscaled.state")).unwrap().1,
            0
        )
        .contains("remote_access_configured"));
    }

    #[test]
    fn remote_desktop_tools_equal_their_own_listings() {
        let files = real();
        // `anydesk --get-id`
        let anydesk = rows_of(&CONFIG, &files, "etc/anydesk/system.conf");
        assert!(truth("anydesk.truth.txt").contains(anydesk[0]["id"].as_str().unwrap()), "{anydesk:?}");
        assert!(anydesk[0]["server"].as_str().unwrap().contains(".net.anydesk.com"));
        // `teamviewer info`
        let tv = rows_of(&CONFIG, &files, "etc/teamviewer/global.conf");
        assert!(truth("teamviewer.truth.txt").contains(tv[0]["id"].as_str().unwrap()));
        assert_eq!(tv[0]["holds_secret"], true);
        // RustDesk stores its ID encrypted from 1.3 on; the key pair is empty until confirmed.
        let rd = rows_of(&CONFIG, &files, "rustdesk/RustDesk.toml");
        assert_eq!(rd[0]["id"], "");
        assert!(details(&rd[0]).iter().any(|d| d.contains("enc_id")));
        assert_eq!(rd[0]["holds_secret"], false);
        // VS Code server: the extensions its CLI said it installed.
        let installed: BTreeSet<(String, String)> = truth("vscode.truth.txt")
            .lines()
            .filter_map(|l| {
                let rest = l.strip_prefix("Extension '")?;
                let (id, rest) = rest.split_once("' v")?;
                Some((id.to_string(), rest.split(' ').next()?.to_string()))
            })
            .collect();
        let rows = rows_of(&CONFIG, &files, ".vscode-server/extensions/extensions.json");
        let found: BTreeSet<(String, String)> = rows
            .iter()
            .map(|r| {
                (r["name"].as_str().unwrap().to_string(), details(r)[0].strip_prefix("version=").unwrap().to_string())
            })
            .collect();
        // The CLI names the three extensions it was asked for and installed; the fourth is a dependency.
        assert!(installed.is_subset(&found) && installed.len() == 3);
        assert_eq!(found.len(), 4);
        for r in &rows {
            assert!(
                r["tool"] == "vscode-server"
                    && r["time"].is_string()
                    && [0, 36].contains(&r["id"].as_str().unwrap().len()),
                "{r}"
            );
        }
    }

    #[test]
    fn real_logs_parse_line_for_line() {
        let files = real();
        for (suffix, first_time, first_message) in [
            ("var/log/anydesk.trace", "2026-11-13T01:28:09.381", "using neon"),
            ("TeamViewer15_Logfile.log", "2026-11-13T01:27:18.754", "Logger started."),
            ("service/rustdesk_rCURRENT.log", "2026-11-13T01:23:11.223191Z", "start --service"),
            ("20261113T011848/remoteCLI.log", "2026-11-13T01:18:49.077", "Getting Manifest... ms-python.python"),
            ("var/log/openvpn.log", "2026-11-13T01:", "Note: Kernel support for ovpn-dco missing"),
        ] {
            let (path, data) = files.iter().find(|(p, _)| p.ends_with(suffix)).unwrap();
            assert!(matches(&LOGS, path), "{path}");
            let out = run(&LOGS, path, data, 0);
            assert!(
                !out.contains("--- warning") && !out.contains("--- failed"),
                "{path}: {}",
                &out[out.len().saturating_sub(300)..]
            );
            let rows: Vec<Value> =
                out.lines().take_while(|l| !l.starts_with("---")).map(|l| serde_json::from_str(l).unwrap()).collect();
            let physical = String::from_utf8_lossy(data).lines().filter(|l| !l.trim().is_empty()).count();
            assert_eq!(rows.len(), physical, "{path}");
            // Lines that continue an entry (AnyDesk's banner) carry no time of their own.
            let first = rows.iter().find(|r| r["time"].is_string()).unwrap();
            assert!(first["time"].as_str().unwrap().starts_with(first_time), "{path}: {first}");
            assert!(first["message"].as_str().unwrap().contains(first_message), "{path}: {first}");
            let timed = rows.iter().filter(|r| r["time"].is_string()).count();
            assert!(timed * 10 >= rows.len() * 8, "{path}: only {timed} of {} lines have a time", rows.len());
        }
        // AnyDesk's pid and component, TeamViewer's `S!!` error marker, RustDesk's source location.
        let any = run(
            &LOGS,
            "var/log/anydesk.trace",
            &files.iter().find(|(p, _)| p.ends_with("var/log/anydesk.trace")).unwrap().1,
            0,
        );
        assert!(
            any.contains("\"source\":\"main\"") && any.contains("\"pid\":4991") && any.contains("\"level\":\"error\"")
        );
        let tv = run(
            &LOGS,
            "var/log/teamviewer15/TeamViewer15_Logfile.log",
            &files.iter().find(|(p, _)| p.ends_with("TeamViewer15_Logfile.log")).unwrap().1,
            0,
        );
        assert!(tv.contains("\"level\":\"S!!\"") && tv.contains("remote_access_log"));
        let rd = run(
            &LOGS,
            "root/.local/share/logs/RustDesk/service/rustdesk_rCURRENT.log",
            &files.iter().find(|(p, _)| p.ends_with("service/rustdesk_rCURRENT.log")).unwrap().1,
            0,
        );
        assert!(rd.contains("\"source\":\"src/core_main.rs:382\""));
    }

    fn synthetic() -> Vec<(String, Vec<u8>)> {
        tree("synthetic")
    }

    #[test]
    fn connection_lists_and_other_synthetic_formats() {
        let files = synthetic();
        let ad = rows_of(&SESSIONS, &files, "etc/anydesk/connection_trace.txt");
        assert_eq!(ad.len(), 3);
        assert_eq!(
            (ad[0]["direction"].as_str(), ad[0]["remote_id"].as_str(), ad[0]["session_type"].as_str()),
            (Some("incoming"), Some("7283745112"), Some("User"))
        );
        assert_eq!(ad[0]["time"], "2026-11-12T14:03:00Z");
        assert_eq!(ad[1]["direction"], "outgoing");
        let tv = rows_of(&SESSIONS, &files, "Connections_incoming.txt");
        assert_eq!(
            (
                tv[0]["remote_id"].as_str(),
                tv[0]["remote_name"].as_str(),
                tv[0]["local_user"].as_str(),
                tv[0]["session_type"].as_str()
            ),
            (Some("1234567890"), Some("John Doe"), Some("alice"), Some("RemoteControl"))
        );
        assert_eq!(
            (tv[0]["time"].as_str(), tv[0]["end_time"].as_str()),
            (Some("2026-11-12T14:03:11Z"), Some("2026-11-12T14:21:45Z"))
        );
        let out = run(
            &SESSIONS,
            "var/log/teamviewer15/Connections_incoming.txt",
            &files.iter().find(|(p, _)| p.ends_with("Connections_incoming.txt")).unwrap().1,
            0,
        );
        assert!(out.contains("remote_session") && out.contains("John Doe (1234567890)"), "{out}");
        assert!(run(&SESSIONS, "etc/anydesk/connection_trace.txt", b"garbage line\n", 0)
            .contains("not a connection record"));
        assert!(run(&SESSIONS, "etc/anydesk/connection_trace.txt", b"", 0).contains("skipped"));

        let mesh = rows_of(&CONFIG, &files, ".msh");
        assert_eq!(
            (mesh[0]["server"].as_str(), mesh[0]["name"].as_str()),
            (Some("wss://mesh.example.com:443/agent.ashx"), Some("Example Mesh"))
        );
        let tunnel = rows_of(&CONFIG, &files, "code_tunnel.json");
        assert_eq!(
            (tunnel[0]["tool"].as_str(), tunnel[0]["name"].as_str(), tunnel[0]["id"].as_str()),
            (Some("vscode-tunnel"), Some("alice-box"), Some("abcd1234ef"))
        );
        let rd2 = rows_of(&CONFIG, &files, "RustDesk2.toml");
        assert_eq!(rd2[0]["server"], "rd.example.com:21116");
        // `key` there is the server's public key.
        assert_eq!(rd2[0]["holds_secret"], false);
        // The CLI's own log format, as `code tunnel` printed it.
        let cli = run(
            &LOGS,
            "home/alice/.vscode-server/cli/servers/Stable-0123/log.txt",
            &files.iter().find(|(p, _)| p.ends_with("Stable-0123/log.txt")).unwrap().1,
            0,
        );
        assert!(
            cli.contains("\"time\":\"2026-11-13T01:19:08Z\"")
                && cli.contains("\"level\":\"info\"")
                && cli.contains("Using GitHub for authentication"),
            "{cli}"
        );
        // The classic OpenVPN log time format.
        let log = &files.iter().find(|(p, _)| p.ends_with("openvpn-classic.log")).unwrap().1;
        let out = run(&LOGS, "var/log/openvpn.log", log, 0);
        assert!(
            out.contains("\"time\":\"2026-11-13T01:30:31Z\"") && out.contains("Peer Connection Initiated"),
            "{out}"
        );
    }

    /// The file-wide rule: whatever the fixtures hold as a secret must not reach any output.
    #[test]
    fn no_secret_reaches_any_output() {
        let mut secrets = BTreeSet::new();
        for (path, data) in real().iter().chain(synthetic().iter()) {
            let text = String::from_utf8_lossy(data);
            let mut rest = text.as_ref();
            while let Some(at) = rest.find("PLANTED-") {
                let end =
                    rest[at..].find(|c: char| !(c.is_ascii_alphanumeric() || c == '-')).map_or(rest.len(), |e| at + e);
                secrets.insert(rest[at..end].to_string());
                rest = &rest[end..];
            }
            let _ = path;
        }
        // WireGuard's generated keys, and Tailscale's private node key.
        for name in ["wireguard.planted-private", "wireguard.planted-psk"] {
            secrets.insert(truth(name).trim().to_string());
        }
        let state = real().into_iter().find(|(p, _)| p.ends_with("tailscaled.state")).unwrap().1;
        let doc: Value = serde_json::from_slice(&state).unwrap();
        for value in doc.as_object().unwrap().values() {
            secrets.insert(value.as_str().unwrap().to_string());
        }
        assert!(secrets.len() >= 12, "{secrets:?}");
        let mut checked = 0;
        for (path, data) in real().iter().chain(synthetic().iter()) {
            for a in [&CONFIG, &LOGS, &SESSIONS] {
                if matches(a, path) {
                    let out = run(a, path, data, 0);
                    for s in &secrets {
                        assert!(!out.contains(s.as_str()), "{} leaks a secret from {path}: {s}", a.id);
                    }
                    checked += 1;
                }
            }
        }
        assert!(checked >= 28, "{checked}");
    }

    #[test]
    fn odd_input_never_panics_and_names_what_is_wrong() {
        for (path, data) in [
            ("etc/frp/frpc.toml", &b"[[proxies]]\n[[proxies]]\n[proxies\nname"[..]),
            ("etc/wireguard/wg0.conf", b"[Peer]\n[Peer]\nEndpoint\n=\n"),
            ("etc/openvpn/x.conf", b"remote\nremote a b c d\n<key>\n"),
            ("root/.config/ngrok/ngrok.yml", b"tunnels: 5\n"),
            ("var/lib/tailscale/tailscaled.state", b"{\"_profiles\":\"!!!\",\"profile-x\":5}"),
            ("var/lib/zerotier-one/networks.d/abcd.conf", b""),
            (
                "home/a/.vscode-server/extensions/extensions.json",
                b"[1,{\"identifier\":5,\"metadata\":{\"installedTimestamp\":-1}}]",
            ),
        ] {
            let out = run(&CONFIG, path, data, 0);
            assert!(
                out.contains("\"artifact\":\"remote-access-config\"")
                    || out.contains("failed")
                    || out.contains("skipped"),
                "{path}: {out}"
            );
        }
        assert!(run(&CONFIG, "etc/frp/frpc.toml", b"   \n", 0).contains("skipped"));
        assert!(run(&CONFIG, "root/.config/ngrok/ngrok.yml", b"- a\n- b\n", 0).contains("failed"));
        assert!(run(&LOGS, "var/log/anydesk.trace", b"\x01\x02\n", 0).contains("failed"));
    }

    #[test]
    fn mutated_files_never_panic() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let files: Vec<_> = real().into_iter().chain(synthetic()).collect();
        for round in 0..150 {
            for (path, original) in &files {
                if original.is_empty() {
                    continue;
                }
                for a in [&CONFIG, &LOGS, &SESSIONS] {
                    if !matches(a, path) {
                        continue;
                    }
                    let mut data = original.clone();
                    data.truncate(20_000);
                    for _ in 0..=(round % 6) {
                        let at = (next() as usize) % data.len();
                        data[at] = b" \t\n=[]{}\"'#:<>%-\xff"[(next() as usize) % 17];
                    }
                    if round % 4 == 0 {
                        data.truncate((next() as usize) % data.len());
                    }
                    run(a, path, &data, 0);
                }
            }
        }
    }
}
