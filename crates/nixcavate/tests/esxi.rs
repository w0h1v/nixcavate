//! End-to-end test of VMware ESXi evidence: a `vm-support` bundle (a folder that mirrors the
//! host, with its large files in `.FRAG-` pieces) and a UAC collection made on ESXi. Both must be
//! recognised as ESXi, named from the host's own files, and give one ordered timeline in which
//! shell commands, logins and a VIB install appear.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Scratch {
        let dir = std::env::temp_dir().join(format!("nixcavate-esxi-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn nixcavate(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_nixcavate")).args(args).output().unwrap()
}

fn write(base: &Path, files: &[(&str, &str)]) {
    for (path, content) in files {
        let full = base.join(path);
        fs::create_dir_all(full.parent().unwrap()).unwrap();
        fs::write(full, content).unwrap();
    }
}

const SHELL_LOG: &str = "\
2025-01-10T01:30:36Z SSH: SSH login enabled
2025-01-10T01:37:05Z shell[2100700]: Interactive shell session started
2025-01-10T01:37:20Z shell[2100700]: [root]: esxcli software vib install -v /tmp/agent.vib --force
";

const HOSTD_LOG: &str = "\
2025-01-10T01:36:00.000Z info hostd[2099437] [Originator@6876 sub=Vimsvc.ha-eventmgr opID=a] Event 1 : User root@203.0.113.50 logged in as Mozilla/5.0
2025-01-10T01:50:00.000Z info hostd[2099437] [Originator@6876 sub=Vimsvc.ha-eventmgr opID=b] Event 2 : db01 on  esx01 in ha-datacenter is powered off
";

const VIB: &str =
    "<vib version=\"5.0\"><type>bootbank</type><name>agent</name><version>1.0</version><vendor>example</vendor>\
<installdate>2025-01-10T01:40:00.000000+00:00</installdate><acceptance-level>community</acceptance-level>\
<file-list><file>bin/agent</file></file-list></vib>";

const HOSTS: &str = "127.0.0.1\tlocalhost.localdomain localhost\n::1\t\tlocalhost.localdomain localhost\n192.0.2.10\tesx01.example.com esx01\n";

fn timeline_rows(out: &Path) -> Vec<(String, String, String)> {
    let run = nixcavate(&["super-timeline", "-d", out.to_str().unwrap()]);
    assert!(run.status.success(), "{}", String::from_utf8_lossy(&run.stderr));
    let csv = fs::read_to_string(out.join("timeline.csv")).unwrap();
    let mut lines = csv.lines();
    let header: Vec<&str> = lines.next().unwrap().split(',').collect();
    let at = |name: &str| header.iter().position(|h| *h == name).unwrap();
    let (time, event, message) = (at("timestamp"), at("event"), at("message"));
    let rows: Vec<(String, String, String)> = lines
        .map(|l| {
            let cells: Vec<&str> = l.splitn(header.len(), ',').collect();
            (cells[time].to_string(), cells[event].to_string(), cells[message].to_string())
        })
        .collect();
    let times: Vec<&String> = rows.iter().map(|r| &r.0).collect();
    let mut sorted = times.clone();
    sorted.sort();
    assert_eq!(times, sorted, "ordered by time");
    rows
}

/// The kinds of the rows, in order, with the logs' own events only.
fn kinds(rows: &[(String, String, String)]) -> Vec<&str> {
    rows.iter().map(|r| r.1.as_str()).collect()
}

fn check(out: &Path, name: &str) {
    let manifest: serde_json::Value = serde_json::from_slice(&fs::read(out.join("manifest.json")).unwrap()).unwrap();
    let hosts = manifest["hosts"].as_array().unwrap();
    assert_eq!(hosts.len(), 1, "{manifest}");
    assert_eq!((hosts[0]["os"].as_str(), hosts[0]["name"].as_str()), (Some("esxi"), Some(name)), "{manifest}");
    let rows = timeline_rows(out);
    let wanted = ["ssh_enabled", "shell_session", "executed", "package_installed", "login", "vm_power_off"];
    let found: Vec<&str> = kinds(&rows).into_iter().filter(|k| wanted.contains(k)).collect();
    assert_eq!(
        found,
        ["ssh_enabled", "login", "shell_session", "executed", "package_installed", "vm_power_off"],
        "{rows:#?}"
    );
    let executed = rows.iter().find(|r| r.1 == "executed").unwrap();
    assert!(executed.2.contains("esxcli software vib install"), "{executed:?}");
    let install = rows.iter().find(|r| r.1 == "package_installed").unwrap();
    assert!(install.2.contains("agent") && install.2.contains("community"), "{install:?}");
}

#[test]
fn a_vm_support_bundle_is_an_esxi_host_with_one_timeline() {
    let scratch = Scratch::new("bundle");
    let case = scratch.0.join("case");
    let bundle = "esx-esx01.example.com-2025-01-10--02.00-1234";
    let (first, second) = HOSTD_LOG.split_at(HOSTD_LOG.len() / 2);
    write(
        &case,
        &[
            (&format!("{bundle}/etc/hosts"), HOSTS),
            (&format!("{bundle}/etc/vmware/hostd/hostsvc.xml"), "<ConfigRoot><mode>normal</mode></ConfigRoot>"),
            (&format!("{bundle}/var/run/log/shell.log"), SHELL_LOG),
            // A large log arrives in pieces cut anywhere, including inside a line.
            (&format!("{bundle}/var/run/log/hostd.log.FRAG-00000"), first),
            (&format!("{bundle}/var/run/log/hostd.log.FRAG-00001"), second),
            (&format!("{bundle}/var/db/esximg/vibs/agent.xml"), VIB),
            (
                &format!("{bundle}/commands/localcli_vm-process-list.txt"),
                "db01:\n   World ID: 1\n   Display Name: db01\n",
            ),
        ],
    );
    let out = scratch.0.join("out");
    let run = nixcavate(&["auto-parse", "-d", case.to_str().unwrap(), "-o", out.to_str().unwrap()]);
    assert!(run.status.success(), "{}", String::from_utf8_lossy(&run.stderr));
    // The folder has no esx.conf, so the name comes from /etc/hosts.
    check(&out, "esx01.example.com");
    assert!(out.join("esx01.example.com/Live/esxi-live-vm-processes").exists());
}

#[test]
fn a_uac_collection_made_on_esxi_is_an_esxi_host_named_from_esx_conf() {
    let scratch = Scratch::new("uac");
    let case = scratch.0.join("case");
    let root = "uac-esx01-esxi-20250110020000/[root]";
    write(
        &case,
        &[
            (&format!("{root}/etc/vmware/esx.conf"), "/adv/Misc/HostName = \"esx01\"\n"),
            (&format!("{root}/var/log/shell.log"), SHELL_LOG),
            (&format!("{root}/var/run/log/hostd.log"), HOSTD_LOG),
            (&format!("{root}/var/db/esximg/vibs/agent.xml"), VIB),
            ("uac-esx01-esxi-20250110020000/uac.log", ""),
        ],
    );
    let out = scratch.0.join("out");
    let run = nixcavate(&["auto-parse", "-d", case.to_str().unwrap(), "-o", out.to_str().unwrap()]);
    assert!(run.status.success(), "{}", String::from_utf8_lossy(&run.stderr));
    check(&out, "esx01");
}
