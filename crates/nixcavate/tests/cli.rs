//! End-to-end tests of the command line: every input kind, the output contract, exit codes.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// A fresh directory per test, removed when dropped.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Scratch {
        let dir = std::env::temp_dir().join(format!("nixcavate-cli-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.0.join(rel)
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

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// One utmp(5) record.
fn utmp(kind: i16, user: &str, line: &str, host: &str, secs: i32) -> Vec<u8> {
    let mut r = vec![0u8; 384];
    r[0..2].copy_from_slice(&kind.to_le_bytes());
    r[8..8 + line.len()].copy_from_slice(line.as_bytes());
    r[44..44 + user.len()].copy_from_slice(user.as_bytes());
    r[76..76 + host.len()].copy_from_slice(host.as_bytes());
    r[340..344].copy_from_slice(&secs.to_le_bytes());
    r
}

/// The files of a small UAC-style collection: `(path, content)`.
fn collection(host: &str, first_login: i32) -> Vec<(String, Vec<u8>)> {
    let root = format!("uac-{host}/[root]");
    vec![
        (format!("{root}/etc/hostname"), format!("{host}\n").into_bytes()),
        (
            format!("{root}/etc/passwd"),
            b"root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/zsh\n".to_vec(),
        ),
        (format!("{root}/etc/os-release"), b"PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\n".to_vec()),
        (
            format!("{root}/var/log/wtmp"),
            [utmp(2, "reboot", "~", "", first_login - 60), utmp(7, "alice", "pts/0", "203.0.113.9", first_login)]
                .concat(),
        ),
        (format!("{root}/var/log/btmp"), Vec::new()),
    ]
}

fn write_dir(base: &Path, files: &[(String, Vec<u8>)]) {
    for (path, content) in files {
        let full = base.join(path);
        fs::create_dir_all(full.parent().unwrap()).unwrap();
        fs::write(full, content).unwrap();
    }
}

fn write_tar_gz(path: &Path, files: &[(String, Vec<u8>)]) {
    let gz = flate2::write::GzEncoder::new(fs::File::create(path).unwrap(), flate2::Compression::fast());
    let mut tar = tar::Builder::new(gz);
    for (name, content) in files {
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_mtime(1_700_000_000);
        header.set_cksum();
        tar.append_data(&mut header, name, &content[..]).unwrap();
    }
    tar.into_inner().unwrap().finish().unwrap();
}

fn write_zip(path: &Path, files: &[(String, Vec<u8>)]) {
    let mut zip = zip::ZipWriter::new(fs::File::create(path).unwrap());
    for (name, content) in files {
        zip.start_file(name.as_str(), zip::write::SimpleFileOptions::default()).unwrap();
        zip.write_all(content).unwrap();
    }
    zip.finish().unwrap();
}

fn manifest(out: &Path) -> serde_json::Value {
    serde_json::from_slice(&fs::read(out.join("manifest.json")).unwrap()).unwrap()
}

#[test]
fn every_input_kind_gives_the_same_records() {
    let scratch = Scratch::new("inputs");
    let files = collection("web01", 1_700_000_100);
    write_dir(&scratch.path("dir"), &files);
    write_tar_gz(&scratch.path("uac.tar.gz"), &files);
    write_zip(&scratch.path("uac.zip"), &files);

    let mut outputs = Vec::new();
    for (flag, input, out) in [("-d", "dir", "out-dir"), ("-f", "uac.tar.gz", "out-tar"), ("-f", "uac.zip", "out-zip")]
    {
        let out = scratch.path(out);
        let run = nixcavate(&[
            "auto-parse",
            flag,
            scratch.path(input).to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
            "-t",
            "jsonl",
        ]);
        assert!(run.status.success(), "{input}: {}", text(&run.stderr));
        let m = manifest(&out);
        assert_eq!(m["schema_version"], 1);
        assert_eq!(m["hosts"][0]["name"], "web01", "{input}");
        assert_eq!(m["hosts"][0]["os"], "linux");
        assert_eq!(m["hosts"][0]["os_version"], "Debian GNU/Linux 12 (bookworm)");
        let status = |artifact: &str| {
            let tasks = m["tasks"].as_array().unwrap();
            tasks.iter().find(|t| t["artifact"] == artifact).unwrap()["status"].as_str().unwrap().to_string()
        };
        assert_eq!(
            (status("passwd"), status("wtmp"), status("btmp")),
            ("succeeded".into(), "succeeded".into(), "skipped".into())
        );
        outputs.push((
            fs::read_to_string(out.join("web01/Accounts/passwd/etc_passwd.jsonl")).unwrap(),
            fs::read_to_string(out.join("web01/Accounts/wtmp/var_log_wtmp.jsonl")).unwrap(),
        ));
        assert!(!out.join(".scratch").exists(), "scratch is removed after the run");
    }
    assert_eq!(outputs[0], outputs[1]);
    assert_eq!(outputs[0], outputs[2]);
    assert!(outputs[0].0.contains("\"user\":\"alice\"") && outputs[0].1.contains("\"remote_host\":\"203.0.113.9\""));
}

#[test]
fn csv_and_json_outputs_are_well_formed() {
    let scratch = Scratch::new("formats");
    write_dir(&scratch.path("dir"), &collection("web01", 1_700_000_100));
    for kind in ["csv", "json"] {
        let out = scratch.path(kind);
        let run = nixcavate(&[
            "auto-parse",
            "-d",
            scratch.path("dir").to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
            "-t",
            kind,
            "-q",
        ]);
        assert!(run.status.success() && run.stdout.is_empty(), "-q prints nothing: {}", text(&run.stdout));
        let passwd = fs::read_to_string(out.join(format!("web01/Accounts/passwd/etc_passwd.{kind}"))).unwrap();
        if kind == "csv" {
            let mut lines = passwd.lines();
            assert_eq!(
                lines.next().unwrap(),
                "host,artifact,source_path,source_line,user,password_field,uid,gid,gecos,home,shell"
            );
            assert_eq!(lines.next().unwrap(), "web01,passwd,etc/passwd,1,root,x,0,0,root,/root,/bin/bash");
        } else {
            let rows: Vec<serde_json::Value> = serde_json::from_str(&passwd).unwrap();
            assert_eq!((rows.len(), rows[1]["uid"].as_u64()), (2, Some(1000)));
        }
    }
}

#[test]
fn a_folder_of_collections_is_several_hosts_and_one_timeline() {
    let scratch = Scratch::new("multi");
    write_dir(&scratch.path("case"), &collection("alpha", 1_700_000_500));
    write_tar_gz(&scratch.path("case/beta.tar.gz"), &collection("beta", 1_700_000_100));
    // A second collection of the same host must not overwrite the first.
    write_zip(&scratch.path("case/alpha-again.zip"), &collection("alpha", 1_700_000_300));
    let out = scratch.path("out");
    let run = nixcavate(&["auto-parse", "-d", scratch.path("case").to_str().unwrap(), "-o", out.to_str().unwrap()]);
    assert!(run.status.success(), "{}", text(&run.stderr));
    let m = manifest(&out);
    let dirs: Vec<&str> = m["hosts"].as_array().unwrap().iter().map(|h| h["output_dir"].as_str().unwrap()).collect();
    assert_eq!(dirs, ["alpha", "alpha-2", "beta"]);
    assert!(text(&run.stdout).contains("slowest tasks") || text(&run.stdout).contains("tasks"));

    let timeline = nixcavate(&["super-timeline", "-d", out.to_str().unwrap()]);
    assert!(timeline.status.success(), "{}", text(&timeline.stderr));
    let csv = fs::read_to_string(out.join("timeline.csv")).unwrap();
    let rows: Vec<&str> = csv.lines().skip(1).collect();
    assert_eq!(rows.len(), 6);
    let times: Vec<&str> = rows.iter().map(|r| r.split(',').next().unwrap()).collect();
    let mut sorted = times.clone();
    sorted.sort();
    assert_eq!(times, sorted, "the timeline is ordered by time");
    assert!(rows[1].contains(",beta,wtmp,login,alice logged in on pts/0 from 203.0.113.9,"), "{}", rows[1]);

    // A second timeline needs -C; JSONL is valid line by line.
    assert_eq!(nixcavate(&["super-timeline", "-d", out.to_str().unwrap()]).status.code(), Some(2));
    let jsonl = scratch.path("t.jsonl");
    assert!(nixcavate(&["super-timeline", "-d", out.to_str().unwrap(), "-t", "jsonl", "-o", jsonl.to_str().unwrap()])
        .status
        .success());
    let parsed: Vec<serde_json::Value> =
        fs::read_to_string(&jsonl).unwrap().lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    assert_eq!(parsed.len(), 6);
    assert_eq!(parsed[0]["basis"], "recorded");
}

#[test]
fn exit_codes_distinguish_usage_errors_from_failed_tasks() {
    let scratch = Scratch::new("exit");
    let dir = scratch.path("dir");
    write_dir(&dir, &collection("web01", 1_700_000_100));
    let out = scratch.path("out");
    let (dir_s, out_s) = (dir.to_str().unwrap(), out.to_str().unwrap());

    assert_eq!(
        nixcavate(&["auto-parse", "-d", scratch.path("missing").to_str().unwrap(), "-o", out_s]).status.code(),
        Some(2)
    );
    assert_eq!(
        nixcavate(&["auto-parse", "-d", dir_s, "-o", out_s, "--only", "no-such-artifact"]).status.code(),
        Some(2)
    );
    assert_eq!(nixcavate(&["auto-parse", "-d", dir_s, "-o", out_s]).status.code(), Some(0));
    // An earlier run is never mixed with a new one unless asked.
    let again = nixcavate(&["auto-parse", "-d", dir_s, "-o", out_s]);
    assert_eq!(again.status.code(), Some(2));
    assert!(text(&again.stderr).contains("-C"));

    // --clobber removes the old host folder: a file left from the old run is gone.
    fs::write(out.join("web01/stale.txt"), "old").unwrap();
    assert_eq!(nixcavate(&["auto-parse", "-d", dir_s, "-o", out_s, "-C", "--only", "passwd"]).status.code(), Some(0));
    assert!(!out.join("web01/stale.txt").exists());
    assert!(!out.join("web01/Accounts/wtmp").exists(), "--only passwd ran only passwd");

    // An unreadable input fails its task; the rest of the run still succeeds: exit 1.
    use std::os::unix::fs::PermissionsExt;
    let wtmp = dir.join("uac-web01/[root]/var/log/wtmp");
    fs::set_permissions(&wtmp, fs::Permissions::from_mode(0o000)).unwrap();
    if fs::File::open(&wtmp).is_err() {
        let run = nixcavate(&["auto-parse", "-d", dir_s, "-o", out_s, "-C"]);
        assert_eq!(run.status.code(), Some(1), "{}", text(&run.stdout));
        assert!(text(&run.stdout).contains("failed tasks"));
        let m = manifest(&out);
        let tasks = m["tasks"].as_array().unwrap();
        let failed = tasks.iter().find(|t| t["artifact"] == "wtmp").unwrap();
        assert_eq!(failed["status"], "failed");
        assert!(failed["error"].as_str().unwrap().contains("cannot read input"));
        assert!(tasks.iter().any(|t| t["artifact"] == "passwd" && t["status"] == "succeeded"));
    }
    fs::set_permissions(&wtmp, fs::Permissions::from_mode(0o644)).unwrap();
}

#[test]
fn parse_one_file_to_stdout_or_a_file() {
    let scratch = Scratch::new("parse");
    let file = scratch.path("some-wtmp-copy.bin");
    fs::write(&file, utmp(7, "alice", "pts/0", "203.0.113.9", 1_700_000_100)).unwrap();
    let run = nixcavate(&["parse", "wtmp", "-f", file.to_str().unwrap(), "-t", "jsonl"]);
    assert!(run.status.success());
    let row: serde_json::Value = serde_json::from_str(text(&run.stdout).trim()).unwrap();
    assert_eq!((row["user"].as_str(), row["time"].as_str()), (Some("alice"), Some("2023-11-14T22:15:00.000000Z")));

    let out = scratch.path("wtmp.csv");
    assert!(nixcavate(&["parse", "wtmp", "-f", file.to_str().unwrap(), "-o", out.to_str().unwrap()]).status.success());
    assert!(fs::read_to_string(&out).unwrap().starts_with("host,artifact,source_path,source_offset,time,type,user"));
    assert_eq!(
        nixcavate(&["parse", "wtmp", "-f", file.to_str().unwrap(), "-o", out.to_str().unwrap()]).status.code(),
        Some(2)
    );
    assert_eq!(nixcavate(&["parse", "nope", "-f", file.to_str().unwrap()]).status.code(), Some(2));
}

#[test]
fn list_names_every_artifact() {
    let table = nixcavate(&["list"]);
    assert!(table.status.success());
    assert!(text(&table.stdout).contains("var/log/wtmp*"));
    let json: Vec<serde_json::Value> = serde_json::from_slice(&nixcavate(&["list", "--json"]).stdout).unwrap();
    let passwd = json.iter().find(|a| a["id"] == "passwd").unwrap();
    assert_eq!((passwd["category"].as_str(), passwd["os"][0].as_str()), (Some("Accounts"), Some("linux")));
}

#[test]
fn symlinks_are_never_followed_out_of_the_evidence() {
    let scratch = Scratch::new("links");
    let dir = scratch.path("dir");
    write_dir(&dir, &collection("web01", 1_700_000_100));
    fs::write(scratch.path("outside-passwd"), "leaked:x:0:0::/:/bin/sh\n").unwrap();
    let root = dir.join("uac-web01/[root]");
    fs::remove_file(root.join("etc/passwd")).unwrap();
    std::os::unix::fs::symlink(scratch.path("outside-passwd"), root.join("etc/passwd")).unwrap();
    let out = scratch.path("out");
    assert!(nixcavate(&["auto-parse", "-d", dir.to_str().unwrap(), "-o", out.to_str().unwrap(), "-t", "jsonl"])
        .status
        .success());
    assert!(!out.join("web01/Accounts/passwd").exists(), "a link pointing outside the evidence is not parsed");
}

/// `test_files/image/host/build.sh` made these in Debian 12: a GPT disk with one ext4
/// partition holding a small host, as a raw image and as an E01 of the same disk.
#[test]
fn disk_images_are_parsed_like_collections() {
    let scratch = Scratch::new("image");
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test_files/image/host");
    let raw = zstd::decode_all(&fs::read(fixtures.join("disk.img.zst")).unwrap()[..]).unwrap();
    fs::write(scratch.path("disk.img"), raw).unwrap();
    fs::copy(fixtures.join("disk.E01"), scratch.path("disk.E01")).unwrap();

    let mut outputs = Vec::new();
    for image in ["disk.img", "disk.E01"] {
        let out = scratch.path(&format!("out-{image}"));
        let run = nixcavate(&[
            "auto-parse",
            "-f",
            scratch.path(image).to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
            "-t",
            "jsonl",
        ]);
        assert!(run.status.success(), "{image}: {}", text(&run.stderr));
        let m = manifest(&out);
        assert_eq!(m["hosts"][0]["name"], "imagehost", "{image}");
        assert_eq!(m["hosts"][0]["root"], "p1/[root]");
        let tasks = m["tasks"].as_array().unwrap();
        assert!(tasks.iter().all(|t| t["status"] == "succeeded"), "{tasks:?}");
        let read = |rel: &str| fs::read_to_string(out.join("imagehost").join(rel)).unwrap();
        let auth = read("Logs/auth-log/var_log_auth.log.jsonl");
        assert!(
            auth.contains("\"event\":\"ssh_accepted\"") && auth.contains("\"remote_address\":\"203.0.113.9\""),
            "{auth}"
        );
        // The file timeline comes from the filesystem itself, with ext4 creation times.
        let files = read("Filesystem/bodyfile/bodyfile_bodyfile.txt.jsonl");
        let auth_log = files.lines().find(|l| l.contains("\"path\":\"/var/log/auth.log\"")).unwrap();
        assert!(
            auth_log.contains("\"modified\":\"2024-03-10T01:02:03Z\"") && !auth_log.contains("\"created\":null"),
            "{auth_log}"
        );
        assert!(files.contains("\"path\":\"/etc/hostname.link\",\"link_target\":\"/etc/hostname\""));
        outputs.push((auth, read("Execution/bash-history/home_alice_.bash_history.jsonl")));
    }
    assert_eq!(outputs[0], outputs[1], "raw and E01 give the same records");
}

/// Regressions from the adversarial review of the foundation: names, links and escapes that
/// come from the evidence must not collide, leave the evidence, or reach the terminal raw.
#[test]
fn hostile_names_and_links_are_contained() {
    let scratch = Scratch::new("hostile");

    // Two homes that differ only by case must not share an output file.
    let mut files = collection("web01", 1_700_000_100);
    files.push(("uac-web01/[root]/home/Alice/.bash_history".into(), b"echo FROM_UPPER\n".to_vec()));
    files.push(("uac-web01/[root]/home/alice/.bash_history".into(), b"echo FROM_LOWER\n".to_vec()));
    write_tar_gz(&scratch.path("case.tar.gz"), &files);
    let out = scratch.path("out-case");
    assert!(nixcavate(&[
        "auto-parse",
        "-f",
        scratch.path("case.tar.gz").to_str().unwrap(),
        "-o",
        out.to_str().unwrap(),
        "-q"
    ])
    .status
    .success());
    let histories: Vec<String> = fs::read_dir(out.join("web01/Execution/bash-history"))
        .unwrap()
        .map(|f| fs::read_to_string(f.unwrap().path()).unwrap())
        .collect();
    assert_eq!(histories.len(), 2);
    assert!(histories.iter().any(|h| h.contains("FROM_UPPER")) && histories.iter().any(|h| h.contains("FROM_LOWER")));

    // A host that names itself after a reserved output file, with terminal escapes in its
    // OS name: the manifest is still written and the summary shows no raw control bytes.
    let dir = scratch.path("evil");
    write_dir(
        &dir,
        &[
            ("etc/hostname".to_string(), b"manifest.json\n".to_vec()),
            ("etc/os-release".to_string(), b"PRETTY_NAME=\"\x1b]0;PWNED\x07Linux\"\n".to_vec()),
            ("etc/passwd".to_string(), b"root:x:0:0::/root:/bin/sh\n".to_vec()),
        ],
    );
    let out = scratch.path("out-evil");
    let run = nixcavate(&["auto-parse", "-d", dir.to_str().unwrap(), "-o", out.to_str().unwrap()]);
    assert!(run.status.success(), "{}", text(&run.stderr));
    assert!(!run.stdout.contains(&0x1b) && !run.stdout.contains(&0x07), "raw control bytes in the summary");
    assert_eq!(manifest(&out)["hosts"][0]["output_dir"], "manifest.json-2");

    // An archive beside the evidence that is really a symlink to somewhere else is not opened.
    write_tar_gz(&scratch.path("outside.tar.gz"), &collection("OUTSIDE", 1_700_000_100));
    std::os::unix::fs::symlink(scratch.path("outside.tar.gz"), dir.join("notes.tar.gz")).unwrap();
    let out = scratch.path("out-link");
    assert!(nixcavate(&["auto-parse", "-d", dir.to_str().unwrap(), "-o", out.to_str().unwrap(), "-q"])
        .status
        .success());
    assert!(!fs::read_to_string(out.join("manifest.json")).unwrap().contains("OUTSIDE"));

    // The output may not live inside the evidence, nor the evidence inside the output.
    let inside = dir.join("out");
    let refused = nixcavate(&["auto-parse", "-d", dir.to_str().unwrap(), "-o", inside.to_str().unwrap()]);
    assert_eq!(refused.status.code(), Some(2));
    assert!(!inside.exists());
}

/// A hard link in a tar names another member of the archive, wherever the host root is.
#[test]
fn tar_hard_links_resolve_inside_the_archive() {
    let scratch = Scratch::new("hardlink");
    let path = scratch.path("uac-fallback-linux-20260101.tar");
    let mut tar = tar::Builder::new(fs::File::create(&path).unwrap());
    let mut add = |name: &str, kind: tar::EntryType, link: Option<&str>, content: &[u8]| {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(kind);
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        if let Some(link) = link {
            header.set_link_name(link).unwrap();
        }
        header.set_cksum();
        tar.append_data(&mut header, name, content).unwrap();
    };
    add("[root]/etc/hostname.orig", tar::EntryType::Regular, None, b"realname\n");
    add("[root]/etc/hostname", tar::EntryType::Link, Some("[root]/etc/hostname.orig"), b"");
    add("[root]/etc/passwd", tar::EntryType::Regular, None, b"root:x:0:0::/root:/bin/sh\n");
    tar.into_inner().unwrap();
    let out = scratch.path("out");
    assert!(nixcavate(&["auto-parse", "-f", path.to_str().unwrap(), "-o", out.to_str().unwrap(), "-q"])
        .status
        .success());
    assert_eq!(manifest(&out)["hosts"][0]["name"], "realname");
}

/// A rotation that expands far more than real logs do is cut, and the manifest says what
/// span was parsed and when the file was last written, so an analyst can judge the gap.
/// `--max-expansion 0` reads it whole.
#[test]
fn an_over_expanding_log_reports_what_it_covers() {
    let scratch = Scratch::new("expansion");
    let mut files = collection("web01", 1_700_000_100);
    // 150k long, near-identical lines, one per second from 2024-03-10T00:00:00Z: about
    // 50 MiB that zstd packs more than 100 times over.
    let mut log = Vec::new();
    for n in 0..150_000u64 {
        let (h, m, s) = (n / 3600 % 24, n / 60 % 60, n % 60);
        let day = 10 + n / 86_400;
        log.extend_from_slice(
            format!("2024-03-{day:02}T{h:02}:{m:02}:{s:02}+00:00 web01 app[1]: {}\n", "A".repeat(300)).as_bytes(),
        );
    }
    let packed = zstd::encode_all(&log[..], 19).unwrap();
    assert!(packed.len() * 100 < log.len() && log.len() > 16 << 20, "the fixture must exceed the default limit");
    files.push(("uac-web01/[root]/var/log/syslog.1.zst".into(), packed));
    // bzip2 is not supported: the input is skipped, and reported as holding data.
    files.push(("uac-web01/[root]/var/log/syslog.2.bz2".into(), b"BZh91AY&SY\x00\x01\x02\x03rest".to_vec()));
    write_tar_gz(&scratch.path("uac.tar.gz"), &files);
    let evidence = scratch.path("uac.tar.gz");

    let out = scratch.path("out");
    let run = nixcavate(&[
        "auto-parse",
        "-f",
        evidence.to_str().unwrap(),
        "-o",
        out.to_str().unwrap(),
        "-t",
        "jsonl",
        "--max-expansion",
        "1000000",
    ]);
    // The archive itself also compresses heavily, so it gets a limit that lets it through;
    // the log inside is then judged by the default below.
    assert!(run.status.success(), "{}", text(&run.stdout));
    let whole = manifest(&out);
    let full =
        whole["tasks"].as_array().unwrap().iter().find(|t| t["input"] == "var/log/syslog.1.zst").unwrap().clone();
    assert_eq!((full["status"].as_str(), full["records"].as_u64()), (Some("succeeded"), Some(150_000)));
    assert_eq!(full["first_event"], "2024-03-10T00:00:00Z");
    assert_eq!(full["last_event"], "2024-03-11T17:39:59Z");
    assert_eq!(full["input_modified"], "2023-11-14T22:13:20Z");

    // Lay the same files out as a directory so only the log's own expansion is judged.
    let dir = scratch.path("dir");
    write_dir(&dir, &files);
    let out = scratch.path("out-default");
    let run = nixcavate(&["auto-parse", "-d", dir.to_str().unwrap(), "-o", out.to_str().unwrap(), "-t", "jsonl"]);
    assert_eq!(run.status.code(), Some(1), "{}", text(&run.stdout));
    let summary = text(&run.stdout);
    let m = manifest(&out);
    let tasks = m["tasks"].as_array().unwrap();
    let cut = tasks.iter().find(|t| t["input"] == "var/log/syslog.1.zst").unwrap();
    assert_eq!(cut["status"], "failed");
    assert!(cut["error"].as_str().unwrap().contains("--max-expansion"), "{}", cut["error"]);
    let parsed = cut["records"].as_u64().unwrap();
    assert!(parsed > 20_000 && parsed < 150_000, "partial records are kept: {parsed}");
    assert_eq!(cut["first_event"], "2024-03-10T00:00:00Z");
    let last = cut["last_event"].as_str().unwrap();
    assert!(last > "2024-03-10T05" && last < "2024-03-11T17:39:59Z", "{last}");
    assert!(cut["input_modified"].is_string());
    assert!(
        summary.contains(&format!("parsed 2024-03-10T00:00:00Z to {last}; the file was last written")),
        "{summary}"
    );

    let skipped = tasks.iter().find(|t| t["input"] == "var/log/syslog.2.bz2").unwrap();
    assert_eq!((skipped["status"].as_str(), skipped["first_event"].is_null()), (Some("skipped"), true));
    assert!(
        summary.contains("skipped inputs that hold data")
            && summary.contains("bzip2 compression is not supported (last written"),
        "{summary}"
    );
}
