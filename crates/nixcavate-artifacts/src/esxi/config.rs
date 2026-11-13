//! ESXi configuration and state files. ESXi keeps its settings in `etc/vmware`: `esx.conf`
//! (one `/path/to/key = "value"` per line) and XML files written by `hostd`. Because the
//! system runs from memory, a file here that is not part of the image either survives in the
//! `local.tgz` state backup or was written since boot. Formats were checked against the files
//! of a public ESXi 6.7 `vm-support` bundle (see `docs/LIMITATIONS.md`).

use super::xml::{self, Node};
use crate::common::script;
use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, ESXI};
use nixcavate_core::{Error, Loc, Record, Result, Sink};
use serde::Serialize;

pub const ESX_CONF: Artifact = Artifact::new(
    "esxi-config",
    "ESXi host settings (esx.conf, etc/vmware/config and settings)",
    Category::System,
    ESXI,
    &["etc/vmware/esx.conf", "etc/vmware/config", "etc/vmware/settings"],
    parse_conf,
);

pub const HOST_CONFIG: Artifact = Artifact::new(
    "esxi-host-config",
    "ESXi service switches and vCenter link (hostsvc.xml, vpxa.cfg, snmp.xml)",
    Category::System,
    ESXI,
    &["etc/vmware/hostd/hostsvc.xml", "etc/vmware/vpxa/vpxa.cfg", "etc/vmware/snmp.xml"],
    parse_host_config,
);

pub const VM_INVENTORY: Artifact = Artifact::new(
    "esxi-vm-inventory",
    "Virtual machines registered on the host (vmInventory.xml)",
    Category::System,
    ESXI,
    &["etc/vmware/hostd/vmInventory.xml"],
    parse_inventory,
);

pub const PERMISSIONS: Artifact = Artifact::new(
    "esxi-permissions",
    "Local permissions on the host (authorization.xml)",
    Category::Accounts,
    ESXI,
    &["etc/vmware/hostd/authorization.xml"],
    parse_permissions,
);

pub const FIREWALL_RULES: Artifact = Artifact::new(
    "esxi-firewall-rules",
    "ESXi firewall rule sets (etc/vmware/firewall/*.xml)",
    Category::Network,
    ESXI,
    &["etc/vmware/firewall/*.xml"],
    parse_firewall,
);

pub const RC_LOCAL: Artifact = Artifact::new(
    "esxi-rc-local",
    "Commands in the shell scripts of /etc/rc.local.d (run at every boot)",
    Category::Persistence,
    ESXI,
    &["etc/rc.local.d/*.sh"],
    script::content_lines,
);

pub const RC_LOCAL_FILES: Artifact = Artifact::new(
    "esxi-rc-local-files",
    "Files in /etc/rc.local.d: /etc/rc.local runs every executable one at boot",
    Category::Persistence,
    ESXI,
    &["etc/rc.local.d/**"],
    script::file_info,
);

// ---------------------------------------------------------------- esx.conf

#[derive(Serialize)]
struct Setting<'a> {
    /// The first segment of an `esx.conf` path (`adv`, `firewall`, `system`, `vmkernel`...).
    section: &'a str,
    key: &'a str,
    value: &'a str,
    /// True when the value was withheld because the key names a secret.
    redacted: bool,
}

impl Record for Setting<'_> {}

/// Words in a key that say its value is a credential. The value is never output.
const SECRET_WORDS: [&str; 8] = ["password", "passwd", "secret", "chap", "credential", "communit", "token", "private"];

fn names_a_secret(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    SECRET_WORDS.iter().any(|w| lower.contains(w))
}

fn parse_conf(input: &Input, sink: &mut Sink) -> Result<()> {
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let text = text.trim();
        if text.is_empty() || text.starts_with('#') {
            return Ok(());
        }
        let Some((key, value)) = text.split_once(" = ").or_else(|| text.split_once('=')) else {
            sink.warn(format!("line {}: not a `key = value` setting", line.number));
            return Ok(());
        };
        let (key, value) = (key.trim(), value.trim());
        let value = value.strip_prefix('"').and_then(|v| v.strip_suffix('"')).unwrap_or(value);
        let section = key.strip_prefix('/').and_then(|k| k.split('/').next()).unwrap_or_default();
        let redacted = names_a_secret(key);
        sink.emit(Loc::Line(line.number), &Setting { section, key, value: if redacted { "" } else { value }, redacted })
    })
}

// ---------------------------------------------------------------- generic XML leaves

#[derive(Serialize)]
struct Leaf<'a> {
    /// The element path, with `[id]` where an element carries an `id`.
    key: String,
    value: &'a str,
    /// True when the value was withheld because the key names a secret.
    redacted: bool,
}

impl Record for Leaf<'_> {}

/// The most leaves one file may produce.
const MAX_LEAVES: usize = 20_000;

fn walk<'a>(node: &'a Node<'a>, path: &mut Vec<String>, out: &mut Vec<(String, &'a str)>) {
    if out.len() >= MAX_LEAVES {
        return;
    }
    let mut name = node.name.to_string();
    if let Some(id) = node.attr("id") {
        name = format!("{name}[{id}]");
    }
    path.push(name);
    if node.children.is_empty() {
        if !node.text.is_empty() {
            out.push((path.join("/"), &node.text));
        }
    } else {
        for child in &node.children {
            walk(child, path, out);
        }
    }
    path.pop();
}

fn parse_host_config(input: &Input, sink: &mut Sink) -> Result<()> {
    let text = lossy(input.data);
    let doc = xml::parse(&text);
    if doc.root.children.is_empty() {
        return Err(Error::skipped("no XML elements"));
    }
    if doc.incomplete {
        sink.warn("the file is cut or too large; the elements read are shown");
    }
    let mut leaves = Vec::new();
    for root in &doc.root.children {
        walk(root, &mut Vec::new(), &mut leaves);
    }
    for (key, value) in leaves {
        let redacted = names_a_secret(&key);
        sink.emit(Loc::None, &Leaf { key, value: if redacted { "" } else { value }, redacted })?;
    }
    Ok(())
}

// ---------------------------------------------------------------- vmInventory.xml

#[derive(Serialize)]
struct Registered<'a> {
    entry_id: &'a str,
    /// hostd's number for the VM (`vim.VirtualMachine:<id>`).
    object_id: &'a str,
    vmx_path: &'a str,
    /// The datastore folder name or UUID in `vmx_path`.
    datastore: &'a str,
    vm_folder: &'a str,
}

impl Record for Registered<'_> {}

/// The root element of a document, or the error for a file that is not one.
fn config_root<'a>(doc: &'a xml::Document<'a>, sink: &mut Sink) -> Result<&'a Node<'a>> {
    let root = doc.root.child("ConfigRoot").ok_or_else(|| Error::format("no <ConfigRoot> element"))?;
    if doc.incomplete {
        sink.warn("the file is cut or too large; the entries read are shown");
    }
    Ok(root)
}

fn parse_inventory(input: &Input, sink: &mut Sink) -> Result<()> {
    let text = lossy(input.data);
    let doc = xml::parse(&text);
    let root = config_root(&doc, sink)?;
    for entry in root.children_named("ConfigEntry") {
        let path = entry.child_text("vmxCfgPath");
        let mut parts = path.strip_prefix("/vmfs/volumes/").unwrap_or_default().split('/');
        let (datastore, folder) = (parts.next().unwrap_or_default(), parts.next().unwrap_or_default());
        let id = entry.attr("id");
        sink.emit(
            Loc::None,
            &Registered {
                entry_id: id.as_deref().unwrap_or_default(),
                object_id: entry.child_text("objID"),
                vmx_path: path,
                datastore,
                // A path with no folder (`.../x.vmx` directly in the datastore) names none.
                vm_folder: if parts.next().is_some() { folder } else { "" },
            },
        )?;
    }
    Ok(())
}

// ---------------------------------------------------------------- authorization.xml

#[derive(Serialize)]
struct Permission<'a> {
    id: &'a str,
    /// The inventory object the permission applies to (`ha-folder-root` is the whole host).
    entity: &'a str,
    user: &'a str,
    is_group: bool,
    /// `-1` is the built-in Administrator role, `-2` No Access, `-3` Read-only.
    role_id: Option<i64>,
    propagate: bool,
}

impl Record for Permission<'_> {}

fn parse_permissions(input: &Input, sink: &mut Sink) -> Result<()> {
    let text = lossy(input.data);
    let doc = xml::parse(&text);
    let root = config_root(&doc, sink)?;
    for ace in root.children_named("ACEData") {
        let id = ace.attr("id");
        sink.emit(
            Loc::None,
            &Permission {
                id: id.as_deref().unwrap_or_default(),
                entity: ace.child_text("ACEDataEntity"),
                user: ace.child_text("ACEDataUser"),
                is_group: ace.child_text("ACEDataIsGroup") == "true",
                role_id: ace.child_text("ACEDataRoleId").parse().ok(),
                propagate: ace.child_text("ACEDataPropagate") == "true",
            },
        )?;
    }
    Ok(())
}

// ---------------------------------------------------------------- firewall rule sets

#[derive(Serialize)]
struct Rule<'a> {
    /// The rule set (`sshServer`, `vsanhealth-unicasttest`).
    ruleset: &'a str,
    rule_id: &'a str,
    direction: &'a str,
    protocol: &'a str,
    /// `src` or `dst`.
    port_type: &'a str,
    /// A port, or `from-to` for a range.
    port: String,
    enabled: &'a str,
}

impl Record for Rule<'_> {}

fn parse_firewall(input: &Input, sink: &mut Sink) -> Result<()> {
    let text = lossy(input.data);
    let doc = xml::parse(&text);
    let root = config_root(&doc, sink)?;
    for service in root.children_named("service") {
        for rule in service.children_named("rule") {
            let port = rule.child("port");
            let range = port.and_then(|p| Some(format!("{}-{}", p.child("begin")?.text, p.child("end")?.text)));
            let rule_id = rule.attr("id");
            let port_type = port.and_then(|p| p.attr("type"));
            sink.emit(
                Loc::None,
                &Rule {
                    ruleset: service.child_text("id"),
                    rule_id: rule_id.as_deref().unwrap_or_default(),
                    direction: rule.child_text("direction"),
                    protocol: rule.child_text("protocol"),
                    port_type: port_type.as_deref().unwrap_or_default(),
                    port: range.unwrap_or_else(|| port.map(|p| p.text.to_string()).unwrap_or_default()),
                    enabled: service.child_text("enabled"),
                },
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    #[test]
    fn esx_conf_keys_sections_and_secrets() {
        let out = run(&ESX_CONF, "etc/vmware/esx.conf", &fixture("esxi-config/esx.conf"), 0);
        insta::assert_snapshot!(out);
        assert!(!out.contains("S3cretChap") && !out.contains("hunter2"), "{out}");
    }

    #[test]
    fn host_config_leaves() {
        let out = run(&HOST_CONFIG, "etc/vmware/hostd/hostsvc.xml", &fixture("esxi-config/hostsvc.xml"), 0);
        insta::assert_snapshot!(out);
        let vpxa = run(&HOST_CONFIG, "etc/vmware/vpxa/vpxa.cfg", &fixture("esxi-config/vpxa.cfg"), 0);
        assert!(vpxa.contains("\"key\":\"config/vpxa/serverIp\",\"value\":\"192.0.2.2\""), "{vpxa}");
        let snmp = run(&HOST_CONFIG, "etc/vmware/snmp.xml", &fixture("esxi-config/snmp.xml"), 0);
        assert!(!snmp.contains("publicc0mmunity"), "{snmp}");
        assert!(snmp.contains("\"redacted\":true"), "{snmp}");
    }

    #[test]
    fn inventory_permissions_and_firewall() {
        let out = run(&VM_INVENTORY, "etc/vmware/hostd/vmInventory.xml", &fixture("esxi-config/vmInventory.xml"), 0);
        insta::assert_snapshot!(out);
        let out = run(&PERMISSIONS, "etc/vmware/hostd/authorization.xml", &fixture("esxi-config/authorization.xml"), 0);
        insta::assert_snapshot!(out);
        let out = run(&FIREWALL_RULES, "etc/vmware/firewall/custom.xml", &fixture("esxi-config/firewall.xml"), 0);
        insta::assert_snapshot!(out);
    }

    #[test]
    fn rc_local_content_and_files() {
        let out = run(&RC_LOCAL, "etc/rc.local.d/local.sh", &fixture("esxi-config/local.sh"), 0);
        insta::assert_snapshot!(out);
        let out = run(&RC_LOCAL_FILES, "etc/rc.local.d/backdoor.sh", &fixture("esxi-config/local.sh"), 1_700_000_000);
        assert!(out.contains("\"size\":") && out.contains("\"mode\":\"100644\""), "{out}");
    }

    #[test]
    fn wrong_format_and_damaged_inputs_do_not_panic() {
        assert!(run(&VM_INVENTORY, "etc/vmware/hostd/vmInventory.xml", b"<x/>", 0).contains("failed"));
        assert!(run(&HOST_CONFIG, "etc/vmware/snmp.xml", b"no xml", 0).contains("skipped"));
        for (artifact, path, name) in [
            (&ESX_CONF, "etc/vmware/esx.conf", "esxi-config/esx.conf"),
            (&HOST_CONFIG, "etc/vmware/vpxa/vpxa.cfg", "esxi-config/vpxa.cfg"),
            (&VM_INVENTORY, "etc/vmware/hostd/vmInventory.xml", "esxi-config/vmInventory.xml"),
            (&PERMISSIONS, "etc/vmware/hostd/authorization.xml", "esxi-config/authorization.xml"),
            (&FIREWALL_RULES, "etc/vmware/firewall/x.xml", "esxi-config/firewall.xml"),
        ] {
            let data = fixture(name);
            run(artifact, path, b"", 0);
            for n in 0..=data.len() {
                run(artifact, path, &data[..n], 0);
            }
            for i in (0..data.len()).step_by(5) {
                let mut flipped = data.clone();
                flipped[i] ^= 0xff;
                run(artifact, path, &flipped, 0);
            }
        }
    }
}
