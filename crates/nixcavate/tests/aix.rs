//! End-to-end test of an AIX evidence tree: a synthetic UAC-style collection (see
//! `test_files/aix-utmp/make_fixtures.py` for the binary login files; the text files are written
//! here) must be detected as AIX, named, and yield logins, failed logins, `su`, cron runs, an
//! `inittab` persistence finding and the software, error and network records.
//! Nothing here came from a real AIX host.

use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Scratch {
        let dir = std::env::temp_dir().join(format!("nixcavate-aix-{name}-{}", std::process::id()));
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

fn fixture(name: &str) -> Vec<u8> {
    fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test_files/aix-utmp").join(name)).unwrap()
}

fn write(base: &Path, rel: &str, content: &[u8]) {
    let path = base.join(rel);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, content).unwrap();
}

/// A collection shaped as UAC writes one for AIX: `/etc` and `/var/adm` under `[root]`, command
/// output under `live_response/`.
fn aix_collection(base: &Path) -> PathBuf {
    let top = base.join("uac-aixhost01-aix-20240311010203");
    let root = "[root]";
    let put = |rel: &str, content: &[u8]| write(&top, &format!("{root}/{rel}"), content);
    put("etc/passwd", b"root:!:0:0::/:/usr/bin/ksh\ndaemon:!:1:1::/etc:\nalice:!:200:1::/home/alice:/usr/bin/ksh\n");
    put("etc/group", b"system:!:0:root\nstaff:!:1:alice\n");
    put("etc/objrepos/CuAt", b"\0");
    put("etc/environment", b"# system environment\nPATH=/usr/bin:/etc:/usr/sbin\nTZ=UTC0\nLDR_PRELOAD=/tmp/.hook.so\n");
    put(
        "etc/inittab",
        b"init:2:initdefault:\nbrc::sysinit:/sbin/rc.boot 3 >/dev/console 2>&1\nsrcmstr:23456789:respawn:/usr/sbin/srcmstr\n\
          cron:23456789:respawn:/usr/sbin/cron\nupdchk:2:respawn:/tmp/.upd/agent --connect 203.0.113.50\nmonitor:2:respawn:/data/mon/agent --daemon\n",
    );
    put(
        "etc/security/lastlog",
        b"alice:\n\ttime_last_login = 1710032600\n\ttty_last_login = /dev/pts/1\n\thost_last_login = 203.0.113.9\n\tunsuccessful_login_count = 2\n",
    );
    put("etc/security/user", b"default:\n\tlogin = true\nroot:\n\tadmin = true\n\trlogin = false\n");
    put("etc/security/passwd", b"alice:\n\tpassword = {ssha256}12$aaaaaaaaaaaaaaaaaaaaaa$bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n\tlastupdate = 1709000000\n");
    put("etc/security/failedlogin", &fixture("failedlogin.lp64"));
    put("var/adm/wtmp", &fixture("wtmp.lp64"));
    put("var/adm/sulog", b"SU 03/10 01:30 + pts/1 alice-root\nSU 03/10 01:31 - pts/2 bob-root\n");
    put(
        "var/adm/cron/log",
        b"! *** cron started ***   pid = 6291650 Sun Mar 10 00:00:01 2024\n>  CMD: /usr/lib/ras/dumpcheck >/dev/null 2>&1\n>  root 8126588 c Sun Mar 10 01:00:00 2024\n<  root 8126588 c Sun Mar 10 01:00:01 2024\n",
    );
    put("var/adm/ras/errlog", &[0u8; 64]);
    let live = |rel: &str, content: &[u8]| write(&top, &format!("live_response/{rel}"), content);
    live("system/uname_-a.txt", b"AIX aixhost01 2 7 00F9C5A04C00\n");
    live("system/oslevel_-s.txt", b"7200-05-04-2220\n");
    live(
        "system/errpt_-a.txt",
        b"---------------------------------------------------------------------------\nLABEL:          SSH_ERR\nIDENTIFIER:     1A2B3C4D\n\nDate/Time:       Sun Mar 10 01:02:03 UTC 2024\nSequence Number: 12\nClass:           S\nType:            INFO\nResource Name:   sshd\n\nDescription\nAUTHENTICATION FAILURE\n",
    );
    live(
        "packages/lslpp_-a_-h_-c.txt",
        b"#Path:Fileset:Level:PTF Id:Action:Status:Date:Time\n/usr/lib/objrepos:evil.rte:1.0.0.0::APPLY:COMPLETE:03/09/24:23;59;01\n",
    );
    live(
        "network/netstat_-an.txt",
        b"Active Internet connections (including servers)\nProto Recv-Q Send-Q  Local Address          Foreign Address        (state)\ntcp4       0      0  *.22                   *.*                    LISTEN\ntcp4       0      0  10.0.0.5.22            203.0.113.9.51234      ESTABLISHED\n",
    );
    live("process/ps_-ef.txt", b"     UID    PID   PPID   C    STIME    TTY  TIME CMD\n    root      1      0   0   Mar 10      -  0:12 /etc/init\n");
    write(&top, "uac.log", b"");
    top
}

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_nixcavate")).args(args).output().unwrap()
}

/// The JSON rows of every output file of one artifact below `out`.
fn rows(out: &Path, artifact: &str) -> Vec<Value> {
    fn walk(dir: &Path, artifact: &str, found: &mut Vec<Value>) {
        for entry in fs::read_dir(dir).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, artifact, found);
            } else if path.extension().is_some_and(|e| e == "jsonl")
                && path.parent().and_then(|p| p.file_name()).is_some_and(|n| n == artifact)
            {
                found.extend(fs::read_to_string(&path).unwrap().lines().map(|l| serde_json::from_str(l).unwrap()));
            }
        }
    }
    let mut found = Vec::new();
    walk(out, artifact, &mut found);
    found
}

#[test]
fn a_uac_collection_of_an_aix_host_is_read() {
    let scratch = Scratch::new("collection");
    let tree = aix_collection(&scratch.0);
    let out = scratch.0.join("out");
    let result = run(&["auto-parse", "-d", tree.to_str().unwrap(), "-o", out.to_str().unwrap(), "-t", "jsonl"]);
    assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));

    let manifest: Value = serde_json::from_slice(&fs::read(out.join("manifest.json")).unwrap()).unwrap();
    let host = &manifest["hosts"][0];
    assert_eq!((host["os"].as_str(), host["name"].as_str()), (Some("aix"), Some("aixhost01")));
    assert_eq!(host["os_version"], "AIX 7200-05-04-2220");
    let failed: Vec<&Value> =
        manifest["tasks"].as_array().unwrap().iter().filter(|t| t["status"] == "failed").collect();
    assert!(failed.is_empty(), "{failed:?}");
    let ran = |artifact: &str| {
        manifest["tasks"].as_array().unwrap().iter().any(|t| t["artifact"] == artifact && t["status"] == "succeeded")
    };
    for artifact in [
        "aix-wtmp",
        "aix-failedlogin",
        "aix-lastlog",
        "aix-sulog",
        "aix-cron-log",
        "aix-inittab",
        "aix-security-passwd",
        "aix-errpt",
        "aix-lslpp",
        "aix-live-network",
        "live-processes",
        "passwd",
        "group",
    ] {
        assert!(ran(artifact), "{artifact} did not run: {manifest}");
    }
    // Linux artifacts must not run on this host.
    assert!(!manifest["tasks"].as_array().unwrap().iter().any(|t| t["artifact"] == "wtmp"));

    let wtmp = rows(&out, "aix-wtmp");
    let users: Vec<&str> =
        wtmp.iter().filter(|r| r["type"] == "user_process").map(|r| r["user"].as_str().unwrap()).collect();
    assert_eq!(users, ["alice", "bob"]);
    assert_eq!(rows(&out, "aix-failedlogin").len(), 2);
    let su = rows(&out, "aix-sulog");
    assert_eq!((su.len(), su[0]["success"].clone(), su[1]["success"].clone()), (2, true.into(), false.into()));
    let cron = rows(&out, "aix-cron-log");
    assert!(cron.iter().any(|r| r["kind"] == "start" && r["command"] == "/usr/lib/ras/dumpcheck >/dev/null 2>&1"));
    assert!(rows(&out, "aix-security-passwd")[0].to_string().contains("ssha256"));
    assert!(!rows(&out, "aix-security-passwd")[0].to_string().contains("bbbbbbbb"));

    // One timeline holds logins, failed logins, su, cron runs and the package install.
    let timeline = scratch.0.join("timeline.csv");
    let result = run(&["super-timeline", "-d", out.to_str().unwrap(), "-o", timeline.to_str().unwrap(), "-t", "csv"]);
    assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    let csv = fs::read_to_string(&timeline).unwrap();
    for needle in [
        "aix-wtmp,login",
        "aix-failedlogin,failed_login",
        "aix-sulog,su,",
        "aix-cron-log,executed",
        "aix-lslpp,package_installed",
    ] {
        assert!(csv.contains(needle), "{needle} missing from the timeline:\n{csv}");
    }
}

#[test]
fn the_hunter_flags_the_planted_inittab_entry_and_loader_variable() {
    let scratch = Scratch::new("hunter");
    let tree = aix_collection(&scratch.0);
    let result = run(&["persistence-hunter", "-d", tree.to_str().unwrap(), "-t", "jsonl", "-q"]);
    assert_eq!(result.status.code(), Some(0), "{}", String::from_utf8_lossy(&result.stderr));
    let findings: Vec<Value> =
        String::from_utf8(result.stdout).unwrap().lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    let keys: Vec<(&str, &str)> =
        findings.iter().map(|f| (f["check"].as_str().unwrap(), f["source_path"].as_str().unwrap())).collect();
    assert!(keys.contains(&("aix-inittab-suspicious-command", "etc/inittab")), "{keys:?}");
    assert!(keys.contains(&("aix-inittab-nonsystem-command", "etc/inittab")), "{keys:?}");
    assert!(keys.contains(&("aix-loader-hijack", "etc/environment")), "{keys:?}");
    // The stock-looking entries are not findings.
    assert!(!findings.iter().any(|f| f["detail"].to_string().contains("srcmstr")), "{findings:?}");
}
