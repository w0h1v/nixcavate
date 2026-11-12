//! End-to-end tests of `persistence-hunter` on planted host trees under
//! `test_files/persistence-hunter/{linux,macos}`: each holds a benign baseline and one planted
//! sample per check. Findings must match the planted set exactly, so a false positive on the
//! baseline fails the test.

use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Scratch {
        let dir = std::env::temp_dir().join(format!("nixcavate-hunter-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.0.join(rel)
    }

    fn write(&self, rel: &str, content: &str) -> PathBuf {
        let path = self.path(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, content).unwrap();
        path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn tree(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test_files/persistence-hunter").join(name)
}

fn hunt(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_nixcavate")).arg("persistence-hunter").args(args).output().unwrap()
}

fn s(path: &Path) -> &str {
    path.to_str().unwrap()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// The JSONL findings of a run that must exit 0.
fn findings(args: &[&str]) -> Vec<Value> {
    let mut all = vec!["-t", "jsonl", "-q"];
    all.extend_from_slice(args);
    let out = hunt(&all);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    String::from_utf8(out.stdout).unwrap().lines().map(|l| serde_json::from_str(l).unwrap()).collect()
}

fn field<'a>(finding: &'a Value, key: &str) -> &'a str {
    finding[key].as_str().unwrap()
}

/// `(check, source_path)` of every finding, sorted.
fn keys(findings: &[Value]) -> Vec<(String, String)> {
    let mut keys: Vec<_> =
        findings.iter().map(|f| (field(f, "check").into(), field(f, "source_path").into())).collect();
    keys.sort();
    keys
}

fn expected(list: &[(&str, &str)]) -> Vec<(String, String)> {
    let mut keys: Vec<_> = list.iter().map(|(c, p)| (c.to_string(), p.to_string())).collect();
    keys.sort();
    keys
}

const LINUX_PLANTED: &[(&str, &str)] = &[
    ("anacron-suspicious-command", "etc/anacrontab"),
    ("at-job", "var/spool/cron/atjobs/a0000101c85f22"),
    ("at-job-suspicious", "var/spool/cron/atjobs/a0000201c85f23"),
    ("authorized-key-forced-command", "home/bob/.ssh/authorized_keys"),
    ("authorized-key-root", "root/.ssh/authorized_keys"),
    ("cron-reboot-job", "etc/cron.d/planted"),
    ("cron-suspicious-command", "etc/cron.d/planted"),
    ("ld-library-path-writable", "etc/ld.so.conf.d/planted.conf"),
    ("ld-preload-entry", "etc/ld.so.preload"),
    ("modprobe-install-command", "etc/modprobe.d/planted.conf"),
    ("pam-exec-module", "etc/pam.d/planted"),
    ("pam-module-unusual-path", "etc/pam.d/planted"),
    ("passwd-extra-uid0", "etc/passwd"),
    ("passwd-password-in-passwd", "etc/passwd"),
    ("rc-local-command", "etc/rc.local"),
    ("rc-local-suspicious", "etc/rc.local"),
    ("shadow-passwordless", "etc/shadow"),
    ("shell-profile-suspicious", "home/bob/.bashrc"),
    ("shell-profile-suspicious", "home/bob/.bashrc"),
    ("sudoers-nopasswd-all", "etc/sudoers.d/90-deploy"),
    ("systemd-ld-preload", "etc/systemd/system/preload.service"),
    ("systemd-suspicious-exec", "etc/systemd/system/updater.service"),
    ("systemd-user-unit", "home/alice/.config/systemd/user/sync.service"),
    ("udev-run-suspicious", "etc/udev/rules.d/99-planted.rules"),
    ("xdg-autostart-suspicious", "etc/xdg/autostart/updater.desktop"),
];

const MACOS_PLANTED: &[(&str, &str)] = &[
    ("btm-item-unsigned", "private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v16.btm"),
    ("emond-rule-command", "private/etc/emond.d/rules/planted.plist"),
    ("kext-third-party", "Library/Extensions/Example.kext/Contents/Info.plist"),
    ("launchd-apple-label-outside-system", "Library/LaunchDaemons/com.apple.fake.plist"),
    ("launchd-dyld-insert", "Library/LaunchDaemons/com.example.dyld.plist"),
    ("launchd-suspicious-program", "Library/LaunchAgents/com.example.beacon.plist"),
    ("launchd-suspicious-program", "Library/LaunchDaemons/com.example.fetch.plist"),
    ("launchd-suspicious-program", "Users/alice/Library/LaunchAgents/com.example.tmp.plist"),
    ("launchd-user-agent-persistent", "Users/alice/Library/LaunchAgents/com.example.persist.plist"),
];

/// Files of a tree: `(relative path, executable)`.
fn walk(dir: &Path, base: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            walk(&path, base, out);
        } else {
            out.push(path.strip_prefix(base).unwrap().to_path_buf());
        }
    }
}

/// The planted Linux tree plus three planted cron/init scripts as a tar.gz, with the owner and
/// mode of every entry set explicitly: neither survives a git checkout.
fn linux_archive(scratch: &Scratch) -> PathBuf {
    let root = tree("linux");
    let mut files = Vec::new();
    walk(&root, &root, &mut files);
    let mut entries: Vec<(String, Vec<u8>, u32, u64)> = files
        .iter()
        .map(|rel| {
            let name = rel.to_str().unwrap().to_string();
            let mode = if name.contains("cron.daily") || name.starts_with("etc/init.d") { 0o755 } else { 0o644 };
            (name, fs::read(root.join(rel)).unwrap(), mode, 0)
        })
        .collect();
    let script = b"#!/bin/sh\ntrue\n".to_vec();
    entries.push(("etc/cron.daily/dropper".into(), script.clone(), 0o666, 0));
    entries.push(("etc/cron.weekly/foreign".into(), script.clone(), 0o755, 1000));
    entries.push(("etc/init.d/rogue".into(), script, 0o775 | 0o002, 0));
    let path = scratch.path("linux.tar.gz");
    let gz = flate2::write::GzEncoder::new(fs::File::create(&path).unwrap(), flate2::Compression::fast());
    let mut tar = tar::Builder::new(gz);
    for (name, content, mode, uid) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(mode);
        header.set_uid(uid);
        header.set_mtime(1_700_000_000);
        tar.append_data(&mut header, &name, content.as_slice()).unwrap();
    }
    tar.into_inner().unwrap().finish().unwrap();
    path
}

#[test]
fn linux_archive_yields_exactly_the_planted_findings() {
    let scratch = Scratch::new("linux-archive");
    let archive = linux_archive(&scratch);
    let found = findings(&["-f", s(&archive)]);
    let mut want = LINUX_PLANTED.to_vec();
    want.extend([
        ("cron-script-writable", "etc/cron.daily/dropper"),
        ("cron-script-writable", "etc/cron.weekly/foreign"),
        ("cron-script-writable", "etc/init.d/rogue"),
    ]);
    assert_eq!(keys(&found), expected(&want));
    let by_check = |check: &str| found.iter().find(|f| field(f, "check") == check).unwrap();
    assert_eq!(field(by_check("cron-script-writable"), "technique"), "T1053.003");
    let rogue = found.iter().find(|f| field(f, "source_path") == "etc/init.d/rogue").unwrap();
    assert_eq!((field(rogue, "technique"), field(rogue, "severity")), ("T1037.004", "medium"));
    assert!(field(rogue, "detail").contains("world-writable"));
    let foreign = found.iter().find(|f| field(f, "source_path") == "etc/cron.weekly/foreign").unwrap();
    assert!(field(foreign, "detail").contains("owned by uid 1000"));
    assert!(found.iter().all(|f| field(f, "host") == "plant-linux" && !field(f, "evidence").is_empty()));
}

#[test]
fn linux_directory_yields_the_planted_findings() {
    // Files extracted by a non-root user are not owned by root, so the owner check is excluded.
    let found = findings(&["-d", s(&tree("linux"))]);
    let found: Vec<Value> = found.into_iter().filter(|f| field(f, "check") != "cron-script-writable").collect();
    assert_eq!(keys(&found), expected(LINUX_PLANTED));
}

#[test]
fn macos_directory_yields_exactly_the_planted_findings() {
    let found = findings(&["-d", s(&tree("macos"))]);
    assert_eq!(keys(&found), expected(MACOS_PLANTED));
    let technique = |path: &str| {
        let f = found.iter().find(|f| field(f, "source_path") == path).unwrap();
        (field(f, "technique").to_string(), field(f, "status").to_string())
    };
    assert_eq!(technique("Library/LaunchAgents/com.example.beacon.plist").0, "T1543.001");
    assert_eq!(technique("Library/LaunchDaemons/com.example.fetch.plist").0, "T1543.004");
    assert_eq!(technique("Library/LaunchDaemons/com.apple.fake.plist").0, "T1036.004");
    assert_eq!(technique("private/etc/emond.d/rules/planted.plist").1, "finding");
    assert!(found.iter().all(|f| field(f, "host") == "macos"));
}

#[test]
fn rows_are_sorted_and_min_severity_filters() {
    let found = findings(&["-d", s(&tree("macos"))]);
    let rank = |f: &Value| ["info", "low", "medium", "high"].iter().position(|x| *x == field(f, "severity")).unwrap();
    assert!(found.windows(2).all(|w| rank(&w[0]) >= rank(&w[1])), "high severity first");
    let high = findings(&["-d", s(&tree("macos")), "--min-severity", "high"]);
    assert_eq!(high.len(), 5);
    assert!(high.iter().all(|f| field(f, "severity") == "high"));
}

const PROFILE: &str = "\
allow:
  - check: systemd-*
    path: etc/systemd/system/updater.service
    reason: Corporate agent
  - contains: /usr/local/bin/startup-check
    host: plant-*
  - check: cron-suspicious-command
    host: other-*
    reason: Never matches
";

#[test]
fn allow_rules_suppress_exactly_their_targets() {
    let scratch = Scratch::new("allow");
    let profile = scratch.write("profile.yaml", PROFILE);
    let dir = tree("linux");
    let args = ["-d", s(&dir), "--profile", s(&profile)];
    let found = findings(&args);
    let mut want = LINUX_PLANTED.to_vec();
    want.retain(|k| !matches!(k.0, "systemd-suspicious-exec" | "cron-reboot-job"));
    assert_eq!(
        keys(&found.into_iter().filter(|f| field(f, "check") != "cron-script-writable").collect::<Vec<_>>()),
        expected(&want)
    );

    let all = findings(&[&args[..], &["--show-allowed"]].concat());
    let allowed: Vec<&Value> = all.iter().filter(|f| field(f, "status") == "allowed").collect();
    assert_eq!(allowed.len(), 2);
    let systemd = allowed.iter().find(|f| field(f, "check") == "systemd-suspicious-exec").unwrap();
    assert_eq!(field(systemd, "reason"), "Corporate agent");
    let reboot = allowed.iter().find(|f| field(f, "check") == "cron-reboot-job").unwrap();
    assert_eq!(field(reboot, "reason"), "");
    // The same check on another path is untouched: every key of an entry must match.
    assert!(all.iter().any(|f| field(f, "check") == "systemd-user-unit" && field(f, "status") == "finding"));
}

#[test]
fn block_rules_flag_clean_records() {
    let scratch = Scratch::new("block");
    let profile = scratch.write(
        "profile.yaml",
        "block:\n  - contains: backup.sh --target\n    title: Known bad script\n    technique: T1105\n",
    );
    let dir = tree("linux");
    let found = findings(&["-d", s(&dir), "--profile", s(&profile)]);
    let blocked: Vec<&Value> = found.iter().filter(|f| field(f, "status") == "blocked").collect();
    assert_eq!(blocked.len(), 1);
    let b = blocked[0];
    assert_eq!(field(b, "source_path"), "var/spool/cron/crontabs/alice");
    assert_eq!((field(b, "title"), field(b, "technique"), field(b, "severity")), ("Known bad script", "T1105", "high"));
    assert!(
        found.iter().filter(|f| field(f, "source_path") == "var/spool/cron/crontabs/alice").count() == 1,
        "the record had no check finding"
    );
}

const EVIL_DAEMON: &str = "<?xml version=\"1.0\"?><plist version=\"1.0\"><dict>\
    <key>Label</key><string>com.example.evil</string>\
    <key>ProgramArguments</key><array><string>/tmp/evil</string></array>\
    <key>StandardOutPath</key><string>/var/log/corp-agent.log</string>\
    <key>RunAtLoad</key><true/></dict></plist>";

#[test]
fn allow_contains_does_not_look_at_unrelated_fields() {
    let scratch = Scratch::new("allow-bypass");
    scratch.write("Library/LaunchDaemons/com.example.evil.plist", EVIL_DAEMON);
    let hunt_with = |profile: &str| {
        let path = scratch.write("profile.yaml", profile);
        findings(&["-d", s(&scratch.0), "--profile", s(&path), "--show-allowed"])
    };
    // The allowed text sits in StandardOutPath only: the finding stays.
    let found = hunt_with("allow:\n  - contains: corp-agent\n");
    assert!(found.iter().any(|f| field(f, "check") == "launchd-suspicious-program" && field(f, "status") == "finding"));
    // The text of what is run does allow it.
    let found = hunt_with("allow:\n  - contains: /tmp/evil\n");
    assert!(found.iter().any(|f| field(f, "check") == "launchd-suspicious-program" && field(f, "status") == "allowed"));
}

#[test]
fn empty_selectors_are_usage_errors() {
    let scratch = Scratch::new("empty-selector");
    let dir = tree("macos");
    for content in [
        "allow:\n  - contains: \"\"\n",
        "allow:\n  - check: \"\"\n",
        "allow:\n  - path: \"\"\n    contains: x\n",
        "block:\n  - contains: \"\"\n",
    ] {
        let profile = scratch.write("p.yaml", content);
        let out = hunt(&["-d", s(&dir), "--profile", s(&profile)]);
        assert_eq!(out.status.code(), Some(2), "{content}: {}", stderr(&out));
        assert!(stderr(&out).contains("empty"), "{content}: {}", stderr(&out));
    }
}

#[test]
fn block_rules_match_text_with_quotes_and_backslashes() {
    let scratch = Scratch::new("block-quotes");
    scratch.write("etc/crontab", "SHELL=/bin/sh\n* * * * * root /usr/bin/logger \"say \\hi\"\n");
    let profile = scratch.write("profile.yaml", "block:\n  - contains: 'logger \"say \\hi\"'\n");
    let found = findings(&["-d", s(&scratch.0), "--profile", s(&profile)]);
    assert!(found.iter().any(|f| field(f, "status") == "blocked"), "{found:?}");
}

#[test]
fn control_characters_in_detail_are_escaped_but_evidence_is_faithful() {
    let scratch = Scratch::new("control");
    scratch.write("etc/crontab", "SHELL=/bin/sh\n* * * * * root /tmp/x\x1b[31mred\n");
    let out = hunt(&["-d", s(&scratch.0), "-t", "csv", "-q"]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(!out.stdout.contains(&0x1b), "no raw escape in any cell");
    let rows = parse_csv(&String::from_utf8(out.stdout).unwrap());
    let row = rows.iter().find(|r| r[2] == "cron-suspicious-command").unwrap();
    assert!(row[7].contains("\\u{1b}"), "{}", row[7]);
    assert!(row[12].contains("\\u001b"), "evidence keeps the JSON form: {}", row[12]);
}

#[test]
fn malformed_profiles_are_usage_errors() {
    let scratch = Scratch::new("bad-profile");
    let dir = tree("linux");
    let cases = [
        ("unknown top-level key", "deny:\n  - contains: x\n", "deny"),
        ("unknown entry key", "allow:\n  - check: a\n    colour: red\n", "colour"),
        ("not yaml", "allow: [unclosed\n", "profile"),
        ("wrong shape", "allow: yes\n", "profile"),
        ("allow without selector", "allow:\n  - reason: everything\n", "needs one of"),
        ("block without contains", "block:\n  - title: x\n", "profile"),
    ];
    for (name, content, expect) in cases {
        let profile = scratch.write("p.yaml", content);
        let out = hunt(&["-d", s(&dir), "--profile", s(&profile)]);
        assert_eq!(out.status.code(), Some(2), "{name}: {}", stderr(&out));
        assert!(stderr(&out).contains(expect), "{name}: {}", stderr(&out));
        assert!(out.stdout.is_empty(), "{name}");
    }
    let out = hunt(&["-d", s(&dir), "--profile", s(&scratch.path("missing.yaml"))]);
    assert_eq!(out.status.code(), Some(2));
}

/// Minimal RFC 4180 reader: quoted fields, doubled quotes, newlines inside quotes.
fn parse_csv(text: &str) -> Vec<Vec<String>> {
    let (mut rows, mut row, mut cell, mut quoted) = (vec![], vec![], String::new(), false);
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match (c, quoted) {
            ('"', true) if chars.peek() == Some(&'"') => {
                cell.push('"');
                chars.next();
            }
            ('"', _) => quoted = !quoted,
            (',', false) => row.push(std::mem::take(&mut cell)),
            ('\n', false) => {
                row.push(std::mem::take(&mut cell));
                rows.push(std::mem::take(&mut row));
            }
            _ => cell.push(c),
        }
    }
    assert!(!quoted && cell.is_empty() && row.is_empty(), "csv ends cleanly");
    rows
}

const COLUMNS: [&str; 14] = [
    "host",
    "severity",
    "check",
    "technique",
    "tactic",
    "title",
    "status",
    "detail",
    "artifact",
    "source_path",
    "source_line",
    "source_offset",
    "evidence",
    "reason",
];

#[test]
fn csv_json_and_jsonl_agree() {
    let dir = tree("macos");
    let run = |kind: &str| {
        let out = hunt(&["-d", s(&dir), "-t", kind, "-q"]);
        assert_eq!(out.status.code(), Some(0));
        String::from_utf8(out.stdout).unwrap()
    };
    let raw = run("jsonl");
    assert!(raw.starts_with("{\"host\":\"macos\",\"severity\":"), "columns keep their order in the file");
    let jsonl: Vec<Value> = raw.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    let json: Vec<Value> = serde_json::from_str(&run("json")).unwrap();
    assert_eq!(json, jsonl);
    assert_eq!(jsonl.len(), MACOS_PLANTED.len());
    for row in &jsonl {
        let keys: Vec<&str> = row.as_object().unwrap().keys().map(String::as_str).collect();
        let mut sorted = COLUMNS.to_vec();
        sorted.sort();
        assert_eq!(keys, sorted, "serde_json sorts the keys it parses");
        assert!(serde_json::from_str::<Value>(field(row, "evidence")).is_ok(), "evidence is compact JSON");
    }
    let csv = parse_csv(&run("csv"));
    assert_eq!(csv[0], COLUMNS);
    assert_eq!(csv.len(), jsonl.len() + 1);
    for (cells, row) in csv[1..].iter().zip(&jsonl) {
        assert_eq!(cells.len(), COLUMNS.len());
        for (cell, name) in cells.iter().zip(COLUMNS) {
            match &row[name] {
                Value::String(text) => assert_eq!(cell, text, "{name}"),
                Value::Null => assert_eq!(cell, "", "{name}"),
                other => assert_eq!(cell, &other.to_string(), "{name}"),
            }
        }
    }
}

#[test]
fn output_file_is_not_overwritten_without_clobber() {
    let scratch = Scratch::new("output");
    let (dir, out_path) = (tree("macos"), scratch.write("out.csv", "keep me"));
    let out = hunt(&["-d", s(&dir), "-o", s(&out_path), "-q"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("-C"), "{}", stderr(&out));
    assert_eq!(fs::read_to_string(&out_path).unwrap(), "keep me");

    let out = hunt(&["-d", s(&dir), "-o", s(&out_path), "-q", "-C"]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(out.stdout.is_empty());
    let written = fs::read_to_string(&out_path).unwrap();
    assert_eq!(parse_csv(&written).len(), MACOS_PLANTED.len() + 1);

    let fresh = scratch.path("fresh.csv");
    assert_eq!(hunt(&["-d", s(&dir), "-o", s(&fresh), "-q"]).status.code(), Some(0));
    assert!(fresh.exists());
}

#[test]
fn summary_goes_to_stderr_unless_quiet() {
    let dir = tree("macos");
    let out = hunt(&["-d", s(&dir)]);
    assert!(stderr(&out).contains("9 findings (5 high, 1 medium, 3 low"), "{}", stderr(&out));
    assert!(hunt(&["-d", s(&dir), "-q"]).stderr.is_empty());
}

#[test]
fn a_failed_parser_task_exits_1_and_keeps_the_other_findings() {
    let scratch = Scratch::new("partial");
    let planted = "Library/LaunchDaemons/com.example.fetch.plist";
    scratch.write(planted, &fs::read_to_string(tree("macos").join(planted)).unwrap());
    scratch.write("private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v1.btm", "garbage, not a plist");
    scratch.write("Library/LaunchDaemons/broken.plist", "garbage, not a plist");
    let out = hunt(&["-d", s(&scratch.0), "-t", "jsonl", "-q"]);
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(text.contains("launchd-suspicious-program"), "{text}");
    assert!(stderr(&out).contains("failed:"), "{}", stderr(&out));
}

#[test]
fn missing_evidence_is_a_usage_error() {
    let out = hunt(&["-d", "/nonexistent/evidence"]);
    assert_eq!(out.status.code(), Some(2));
}
