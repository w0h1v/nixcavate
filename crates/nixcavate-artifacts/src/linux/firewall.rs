//! Firewall rule files: `iptables` (iptables-save(8) format, as restored at boot by
//! iptables-persistent or the sysconfig scripts) and `nftables` (nft(8) syntax). Rule changes
//! are a common way to open a path in or out of a host.

use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, LINUX};
use nixcavate_core::{Loc, Record, Result, Sink};
use serde::Serialize;

pub const IPTABLES: Artifact = Artifact::new(
    "iptables",
    "iptables saved rules",
    Category::Network,
    LINUX,
    &[
        "etc/iptables/rules.v4",
        "etc/iptables/rules.v6",
        "etc/sysconfig/iptables",
        "etc/sysconfig/ip6tables",
        "etc/iptables.rules",
        "etc/iptables/*.rules",
    ],
    parse_iptables,
);

pub const NFTABLES: Artifact = Artifact::new(
    "nftables",
    "nftables ruleset statements",
    Category::Network,
    LINUX,
    &["etc/nftables.conf", "etc/nftables/*.nft", "etc/nftables/*.conf", "etc/sysconfig/nftables.conf"],
    parse_nftables,
);

#[derive(Serialize)]
struct IptablesLine<'a> {
    table: &'a str,
    chain: &'a str,
    /// `policy` for a `:CHAIN POLICY` line, `rule` for `-A` and `-I`.
    kind: &'static str,
    policy: Option<&'a str>,
    protocol: Option<String>,
    source: Option<String>,
    destination: Option<String>,
    destination_port: Option<String>,
    target: Option<&'a str>,
    rule: &'a str,
}

impl Record for IptablesLine<'_> {}

/// Splits on whitespace, keeping a double-quoted argument (`--comment "a b"`) in one token.
fn tokens(line: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = line.trim_start();
    while !rest.is_empty() {
        let (token, tail) = if let Some(quoted) = rest.strip_prefix('"') {
            quoted.split_once('"').unwrap_or((quoted, ""))
        } else {
            rest.split_once(char::is_whitespace).unwrap_or((rest, ""))
        };
        out.push(token);
        rest = tail.trim_start();
    }
    out
}

fn parse_iptables(input: &Input, sink: &mut Sink) -> Result<()> {
    let mut table = String::new();
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let text = text.trim();
        let loc = Loc::Line(line.number);
        // A saved ruleset with counters (`iptables-save -c`) prefixes rules with `[packets:bytes]`.
        let body = match text.strip_prefix('[').and_then(|r| r.split_once("] ")) {
            Some((counters, rest)) if counters.bytes().all(|b| b.is_ascii_digit() || b == b':') => rest.trim_start(),
            _ => text,
        };
        let blank = IptablesLine {
            table: "",
            chain: "",
            kind: "rule",
            policy: None,
            protocol: None,
            source: None,
            destination: None,
            destination_port: None,
            target: None,
            rule: text,
        };
        if let Some(name) = text.strip_prefix('*') {
            table = name.trim().to_string();
        } else if text == "COMMIT" {
            table.clear();
        } else if let Some(decl) = text.strip_prefix(':') {
            let mut parts = decl.split_whitespace();
            let (chain, policy) = (parts.next().unwrap_or(""), parts.next());
            sink.emit(loc, &IptablesLine { table: &table, chain, kind: "policy", policy, ..blank })?;
        } else if text.is_empty() || text.starts_with('#') {
        } else if let Some(rule) = body.strip_prefix("-A ").or_else(|| body.strip_prefix("-I ")) {
            let args = tokens(rule);
            let chain = args.first().copied().unwrap_or("");
            let mut record = IptablesLine { table: &table, chain, ..blank };
            // `!` negates the option that follows it; keep that visible in the value.
            let mut negate = false;
            let mut i = 1;
            while i < args.len() {
                let (option, value) = (args[i], args.get(i + 1).copied());
                if option == "!" {
                    negate = true;
                    i += 1;
                    continue;
                }
                let slot = match option {
                    "-p" | "--protocol" => Some(&mut record.protocol),
                    "-s" | "--source" => Some(&mut record.source),
                    "-d" | "--destination" => Some(&mut record.destination),
                    "--dport" | "--dports" | "--destination-port" | "--destination-ports" => {
                        Some(&mut record.destination_port)
                    }
                    "-j" | "--jump" | "-g" | "--goto" => {
                        record.target = value;
                        None
                    }
                    _ => None,
                };
                if let (Some(slot), Some(value)) = (slot, value) {
                    *slot = Some(if negate { format!("!{value}") } else { value.to_string() });
                }
                negate = false;
                i += 1;
            }
            sink.emit(loc, &record)?;
        } else {
            sink.warn(format!("line {}: not an iptables-save line", line.number));
        }
        Ok(())
    })
}

#[derive(Serialize)]
struct NftStatement<'a> {
    /// The enclosing table, e.g. `inet filter`.
    table: &'a str,
    /// The enclosing chain; for sets, maps and other objects the object's header (`set blocked`).
    chain: &'a str,
    text: &'a str,
}

impl Record for NftStatement<'_> {}

/// The line without its `#` comment, and the net number of braces it opens. Quoted text
/// is skipped for both.
fn nft_scan(line: &str) -> (&str, i32) {
    let (mut quoted, mut net) = (false, 0);
    for (i, b) in line.bytes().enumerate() {
        match b {
            b'"' => quoted = !quoted,
            b'#' if !quoted => return (&line[..i], net),
            b'{' if !quoted => net += 1,
            b'}' if !quoted => net -= 1,
            _ => {}
        }
    }
    (line, net)
}

/// A statement that opened a brace on one line and closes it on a later one.
struct Pending {
    line: u64,
    text: String,
    depth: i32,
}

fn parse_nftables(input: &Input, sink: &mut Sink) -> Result<()> {
    // Depth 0 is the top level, 1 is inside a table, 2 is inside a chain or other object.
    let (mut depth, mut table, mut chain) = (0, String::new(), String::new());
    let mut pending: Option<Pending> = None;
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let (code, net) = nft_scan(&text);
        let code = code.trim();
        if code.is_empty() {
            return Ok(());
        }
        // Multi-line values such as `elements = { a,\n b }` are joined into one statement.
        if let Some(p) = pending.as_mut() {
            p.text.push(' ');
            p.text.push_str(code);
            p.depth += net;
            if p.depth <= 0 {
                if let Some(p) = pending.take() {
                    sink.emit(Loc::Line(p.line), &NftStatement { table: &table, chain: &chain, text: &p.text })?;
                }
            }
            return Ok(());
        }
        let loc = Loc::Line(line.number);
        // A statement may close its block on the same line (`counter drop }`).
        let (code, mut close, net) = match code.strip_suffix('}') {
            Some(head) if depth >= 1 && net == -1 && !head.trim().is_empty() => (head.trim_end(), true, 0),
            _ => (code, false, net),
        };
        let opens = code.ends_with('{') && net == 1;
        match (depth, code) {
            (0, _) if opens && code.starts_with("table ") => {
                table = code["table ".len()..code.len() - 1].trim().to_string();
                depth = 1;
            }
            (1, _) if opens => {
                let header = code[..code.len() - 1].trim();
                chain = header.strip_prefix("chain ").unwrap_or(header).to_string();
                depth = 2;
            }
            (1 | 2, "}") => close = true,
            _ if net > 0 => pending = Some(Pending { line: line.number, text: code.to_string(), depth: net }),
            _ => sink.emit(loc, &NftStatement { table: &table, chain: &chain, text: code })?,
        }
        if close {
            if depth == 2 {
                chain.clear();
            } else {
                table.clear();
            }
            depth -= 1;
        }
        Ok(())
    })?;
    if let Some(p) = pending {
        sink.warn(format!("line {}: unterminated statement", p.line));
        sink.emit(Loc::Line(p.line), &NftStatement { table: &table, chain: &chain, text: &p.text })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    #[test]
    fn parses_iptables_v4_and_v6() {
        let mut all = run(&IPTABLES, "etc/iptables/rules.v4", &fixture("iptables/rules.v4"), 0);
        all.push_str(&run(&IPTABLES, "etc/iptables/rules.v6", &fixture("iptables/rules.v6"), 0));
        insta::assert_snapshot!(all);
    }

    #[test]
    fn parses_nftables() {
        insta::assert_snapshot!(run(&NFTABLES, "etc/nftables.conf", &fixture("nftables/nftables.conf"), 0));
    }

    #[test]
    fn nftables_script_forms() {
        let script = b"#!/usr/sbin/nft -f\nflush ruleset\ntable inet t {\n  chain c { # inline\n";
        let out = run(&NFTABLES, "etc/nftables.conf", script, 0);
        assert!(out.contains("flush ruleset"));
        assert!(!out.contains("nft -f"));
    }

    #[test]
    fn nftables_multi_line_values_are_joined() {
        let conf = b"table inet t {\n set s {\n  elements = { 192.0.2.1,\n   192.0.2.2 }\n }\n chain c {\n  ip saddr vmap {\n   192.0.2.3 : drop }\n  accept\n }\n}\n";
        let out = run(&NFTABLES, "etc/nftables.conf", conf, 0);
        assert!(out.contains("\"text\":\"elements = { 192.0.2.1, 192.0.2.2 }\""), "{out}");
        assert!(out.contains("\"chain\":\"c\",\"text\":\"ip saddr vmap { 192.0.2.3 : drop }\""), "{out}");
        assert!(out.contains("\"text\":\"accept\""));
    }

    #[test]
    fn iptables_counters_and_insert_rules_are_kept() {
        let data = b"*filter\n:INPUT DROP [0:0]\n[12:345] -A INPUT -p tcp --dport 4444 -j ACCEPT\n-I INPUT 1 -s 6.6.6.6 -j ACCEPT\nCOMMIT\n";
        let out = run(&IPTABLES, "etc/sysconfig/iptables", data, 0);
        assert_eq!(out.lines().filter(|l| l.contains("\"kind\":\"rule\"")).count(), 2, "{out}");
        assert!(out.contains("\"destination_port\":\"4444\"") && out.contains("\"source\":\"6.6.6.6\""), "{out}");
        assert!(!out.contains("warning"), "{out}");
    }

    #[test]
    fn iptables_unrecognized_lines_warn() {
        let out = run(&IPTABLES, "etc/sysconfig/iptables", b"*filter\n-P INPUT DROP\n# c\n\nCOMMIT\n", 0);
        assert!(out.contains("warning: line 2: not an iptables-save line"), "{out}");
        assert_eq!(out.matches("warning").count(), 1, "{out}");
    }

    #[test]
    fn nftables_closing_brace_on_a_statement_line_reduces_depth() {
        let conf = b"table inet t {\n chain c {\n  accept }\n chain d {\n  drop\n }\n}\ntable ip u {\n}\n";
        let out = run(&NFTABLES, "etc/nftables.conf", conf, 0);
        assert!(out.contains("\"table\":\"inet t\",\"chain\":\"c\",\"text\":\"accept\""), "{out}");
        assert!(out.contains("\"table\":\"inet t\",\"chain\":\"d\",\"text\":\"drop\""), "{out}");
    }

    #[test]
    fn empty_and_garbage_do_not_panic() {
        for (artifact, path) in [(&IPTABLES, "etc/iptables/rules.v4"), (&NFTABLES, "etc/nftables.conf")] {
            assert_eq!(run(artifact, path, b"", 0), "");
            let junk: Vec<u8> = (0..=255u8).cycle().take(2000).collect();
            run(artifact, path, &junk, 0);
            run(artifact, path, b"}\n}\n{ {\ntable x {\nchain {\n-A\n:\n*\nCOMMIT\n-A INPUT -p\n! ! -s\n", 0);
        }
    }
}
