//! Kubernetes container logs as the kubelet writes them: `var/log/pods/<ns>_<pod>_<uid>/<container>/<n>.log`
//! (`<n>` is the container's restart count; rotations are `<n>.log.<date>` and `.gz`) and the
//! `var/log/containers/<pod>_<ns>_<container>-<id>.log` names that point at them.
//!
//! Format, from the CRI logging contract (kubelet `kuberuntime` and the CRI-O/containerd log
//! writers): `<RFC3339Nano time> <stdout|stderr> <P|F> <message>`. `P` marks a partial line (the
//! runtime splits lines longer than 16 KiB); the fragments up to the next `F` are one message and
//! are joined here. Nodes that still run dockershim (Kubernetes before 1.24) write Docker's
//! json-file lines into the same files; each line is told by its first byte.
//!
//! Not split into chunks (unlike `docker-logs`): joining partial lines needs the lines before
//! them, and the kubelet rotates these files at 10 MiB by default.

use crate::text::for_each_line;
use crate::{Artifact, Category, Input, LINUX};
use nixcavate_core::time::parse_iso8601;
use nixcavate_core::{Error, Event, Loc, Record, Result, Sink, Timestamp};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;

pub const ARTIFACT: Artifact = Artifact::new(
    "k8s-pod-logs",
    "Kubernetes pod and container logs (CRI and Docker json-file formats)",
    Category::Containers,
    LINUX,
    &["var/log/pods/*/*/*.log*", "var/log/containers/*.log*"],
    parse,
);

/// A joined partial line stops growing here; the rest starts a new message.
const MAX_JOINED: usize = 1 << 20;

#[derive(Serialize)]
struct Entry<'a> {
    time: Option<Timestamp>,
    namespace: &'a str,
    pod: &'a str,
    pod_uid: &'a str,
    container: &'a str,
    /// Only in the `var/log/containers` names.
    container_id: &'a str,
    /// The `<n>` of `<n>.log`: how many times the container had restarted.
    restart_count: Option<u32>,
    stream: Cow<'a, str>,
    /// `cri` or `docker-json`.
    format: &'static str,
    /// How many `P` fragments and the final `F` line made this message (1 for a plain line).
    fragments: u32,
    /// False when partial fragments ended without an `F` (end of file, another stream, the cap).
    complete: bool,
    message: Cow<'a, str>,
}

impl Record for Entry<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        self.time.map(|t| Event::new(t, "container_log", self.message.as_ref())).into_iter()
    }
}

/// What the path says about the container.
#[derive(Default)]
struct Origin<'a> {
    namespace: &'a str,
    pod: &'a str,
    pod_uid: &'a str,
    container: &'a str,
    container_id: &'a str,
    restart_count: Option<u32>,
}

fn origin(path: &str) -> Origin<'_> {
    let parts: Vec<&str> = path.rsplit('/').take(3).collect();
    let file = parts.first().copied().unwrap_or_default();
    // var/log/pods/<ns>_<pod>_<uid>/<container>/<n>.log
    if let (Some(container), Some(dir)) = (parts.get(1), parts.get(2)) {
        let mut ids = dir.splitn(3, '_');
        if let (Some(namespace), Some(pod), Some(pod_uid)) = (ids.next(), ids.next(), ids.next()) {
            if path.contains("/pods/") || path.starts_with("pods/") {
                let restart_count = file.split('.').next().and_then(|n| n.parse().ok());
                return Origin { namespace, pod, pod_uid, container, restart_count, ..Origin::default() };
            }
        }
    }
    // var/log/containers/<pod>_<ns>_<container>-<id>.log
    let stem = file.split(".log").next().unwrap_or(file);
    let mut names = stem.splitn(3, '_');
    if let (Some(pod), Some(namespace), Some(rest)) = (names.next(), names.next(), names.next()) {
        return match rest.rsplit_once('-') {
            Some((container, id)) if id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()) => {
                Origin { namespace, pod, container, container_id: id, ..Origin::default() }
            }
            _ => Origin { namespace, pod, container: rest, ..Origin::default() },
        };
    }
    Origin::default()
}

#[allow(clippy::too_many_arguments)]
fn entry<'a>(
    from: &Origin<'a>,
    time: Option<Timestamp>,
    stream: Cow<'a, str>,
    format: &'static str,
    fragments: u32,
    complete: bool,
    message: Cow<'a, str>,
) -> Entry<'a> {
    Entry {
        time,
        namespace: from.namespace,
        pod: from.pod,
        pod_uid: from.pod_uid,
        container: from.container,
        container_id: from.container_id,
        restart_count: from.restart_count,
        stream,
        format,
        fragments,
        complete,
        message,
    }
}

/// A Docker json-file line.
#[derive(Deserialize)]
struct JsonLine<'a> {
    #[serde(borrow, default)]
    log: Cow<'a, str>,
    #[serde(borrow, default)]
    stream: Cow<'a, str>,
    #[serde(borrow, default)]
    time: Cow<'a, str>,
}

struct Pending {
    time: Option<Timestamp>,
    stream: String,
    message: String,
    fragments: u32,
    offset: u64,
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    if input.data.iter().all(u8::is_ascii_whitespace) {
        return Err(Error::skipped("empty file"));
    }
    let from = origin(input.path);
    let mut pending: Option<Pending> = None;
    let result = for_each_line(input, |line| {
        if line.bytes.iter().all(u8::is_ascii_whitespace) {
            return Ok(());
        }
        if line.bytes.first() == Some(&b'{') {
            let parsed: JsonLine = match serde_json::from_slice(line.bytes) {
                Ok(parsed) => parsed,
                Err(e) => {
                    sink.warn(format!("line {}: not a json-file log line: {e}", line.number));
                    return Ok(());
                }
            };
            let message = parsed.log.strip_suffix('\n').unwrap_or(&parsed.log).to_string();
            let time = parse_iso8601(parsed.time.as_bytes()).and_then(|(t, _)| t.recorded());
            let stream = Cow::Owned(parsed.stream.into_owned());
            return sink.emit(
                Loc::Line(line.number),
                &entry(&from, time, stream, "docker-json", 1, true, Cow::Owned(message)),
            );
        }
        // <time> <stream> <tag> <message>
        let text = String::from_utf8_lossy(line.bytes);
        let mut fields = text.splitn(4, ' ');
        let (Some(time_text), Some(stream), Some(tag)) = (fields.next(), fields.next(), fields.next()) else {
            sink.warn(format!("line {}: not a CRI log line", line.number));
            return Ok(());
        };
        let Some((parsed, _)) = parse_iso8601(time_text.as_bytes()) else {
            sink.warn(format!("line {}: not a CRI log line (no timestamp)", line.number));
            return Ok(());
        };
        let message = fields.next().unwrap_or_default();
        let time = parsed.recorded();
        let partial = tag.starts_with('P');
        if let Some(open) = pending.take_if(|p| p.stream != stream || p.message.len() >= MAX_JOINED) {
            let item = entry(
                &from,
                open.time,
                Cow::Owned(open.stream),
                "cri",
                open.fragments,
                false,
                Cow::Owned(open.message),
            );
            sink.emit(Loc::Offset(open.offset), &item)?;
        }
        match (pending.take(), partial) {
            (Some(mut open), true) => {
                open.message.push_str(message);
                open.fragments += 1;
                pending = Some(open);
            }
            (Some(mut open), false) => {
                open.message.push_str(message);
                let item = entry(
                    &from,
                    open.time,
                    Cow::Owned(open.stream),
                    "cri",
                    open.fragments + 1,
                    true,
                    Cow::Owned(open.message),
                );
                sink.emit(Loc::Offset(open.offset), &item)?;
            }
            (None, true) => {
                pending = Some(Pending {
                    time,
                    stream: stream.to_string(),
                    message: message.to_string(),
                    fragments: 1,
                    offset: line.offset,
                });
            }
            (None, false) => {
                let item = entry(&from, time, Cow::Borrowed(stream), "cri", 1, true, Cow::Borrowed(message));
                sink.emit(Loc::Offset(line.offset), &item)?;
            }
        }
        Ok(())
    });
    if let Some(open) = pending {
        sink.warn("the file ends inside a partial (P) line");
        let item =
            entry(&from, open.time, Cow::Owned(open.stream), "cri", open.fragments, false, Cow::Owned(open.message));
        sink.emit(Loc::Offset(open.offset), &item)?;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::super::k8s_testdata::{expected, node, records};
    use super::*;
    use crate::testing::run;

    fn log_files(flavor: &str) -> Vec<(String, Vec<u8>)> {
        node(flavor).into_iter().filter(|(p, _)| p.starts_with("var/log/pods/")).collect()
    }

    /// The pod logs the real nodes wrote: every record's namespace, pod, uid, container and
    /// restart count must be the ones `crictl ps -a` reports for a container with that uid and
    /// name, and there is one record per line of the file.
    #[test]
    fn real_logs_carry_the_identity_crictl_reports() {
        for flavor in ["k3s", "kind"] {
            let truth = expected(flavor);
            let containers = truth["containers"].as_array().unwrap();
            let files = log_files(flavor);
            assert!(files.len() >= 8, "{flavor}: {}", files.len());
            let mut lines = 0;
            for (path, data) in &files {
                let out = run(&ARTIFACT, path, data, 0);
                assert!(!out.contains("--- warning") && !out.contains("--- failed"), "{path}: {out}");
                let rows = records(&out);
                let physical = String::from_utf8_lossy(data).lines().filter(|l| !l.trim().is_empty()).count();
                // Every physical line is exactly one fragment of exactly one record.
                let fragments: usize = rows.iter().map(|r| r["fragments"].as_u64().unwrap() as usize).sum();
                assert_eq!(fragments, physical, "{path}");
                lines += physical;
                for r in &rows {
                    let hit = containers.iter().any(|c| {
                        c["namespace"] == r["namespace"]
                            && c["pod"] == r["pod"]
                            && c["uid"] == r["pod_uid"]
                            && c["container"] == r["container"]
                            && c["attempt"] == r["restart_count"]
                    });
                    assert!(hit, "{flavor} {path}: no such container in crictl's listing: {r}");
                    assert!(r["time"].is_string() && r["format"] == "cri");
                }
            }
            assert!(lines > 20, "{flavor}: {lines}");
        }
    }

    /// The CronJob container writes one line to each stream.
    #[test]
    fn stdout_and_stderr_of_a_real_container() {
        let files = log_files("k3s");
        let (path, data) = files.iter().find(|(p, _)| p.contains("_ticker-") && p.ends_with("tick/0.log")).unwrap();
        insta::assert_snapshot!(run(&ARTIFACT, path, data, 0).replace(path.as_str(), "<path>"));
    }

    #[test]
    fn partial_lines_are_joined_and_an_unfinished_one_is_flagged() {
        let path = "var/log/pods/ns1_web-1_uid-1/app/3.log";
        let data = b"2026-11-12T10:00:00.000000001Z stdout P aaa\n\
2026-11-12T10:00:00.000000002Z stdout P bbb\n\
2026-11-12T10:00:00.000000003Z stdout F ccc\n\
2026-11-12T10:00:01.000000000Z stderr F boom\n\
2026-11-12T10:00:02.000000000Z stdout P tail\n";
        let out = run(&ARTIFACT, path, data, 0);
        let rows = records(&out);
        assert_eq!(rows.len(), 3, "{out}");
        assert_eq!((rows[0]["message"].as_str(), rows[0]["fragments"].as_u64()), (Some("aaabbbccc"), Some(3)));
        assert_eq!(rows[0]["time"], "2026-11-12T10:00:00.000000001Z");
        assert_eq!((rows[1]["stream"].as_str(), rows[1]["complete"].as_bool()), (Some("stderr"), Some(true)));
        assert_eq!((rows[2]["message"].as_str(), rows[2]["complete"].as_bool()), (Some("tail"), Some(false)));
        assert!(out.contains("ends inside a partial (P) line"));
        assert!(rows.iter().all(|r| r["restart_count"] == 3 && r["pod_uid"] == "uid-1" && r["namespace"] == "ns1"));
        assert_eq!(out.matches("container_log").count(), 3);
    }

    #[test]
    fn docker_json_lines_on_a_dockershim_node_and_mixed_files() {
        let path = "var/log/containers/old-pod_default_main-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.log";
        let data = b"{\"log\":\"hello\\n\",\"stream\":\"stdout\",\"time\":\"2026-11-12T10:00:00.5Z\"}\n\
2026-11-12T10:00:01.000000000Z stdout F cri line\n{not json\n";
        let out = run(&ARTIFACT, path, data, 0);
        let rows = records(&out);
        assert_eq!(rows.len(), 2, "{out}");
        assert_eq!((rows[0]["format"].as_str(), rows[0]["message"].as_str()), (Some("docker-json"), Some("hello")));
        assert_eq!(rows[0]["container_id"].as_str().map(str::len), Some(64));
        assert_eq!(
            (rows[0]["pod"].as_str(), rows[0]["namespace"].as_str(), rows[0]["container"].as_str()),
            (Some("old-pod"), Some("default"), Some("main"))
        );
        assert_eq!(rows[1]["format"], "cri");
        assert!(out.contains("--- warning: line 3: not a json-file log line"), "{out}");
    }

    #[test]
    fn rotations_and_garbage_and_empty_files() {
        let plain = b"2026-11-12T10:00:00.000000000Z stdout F x\n";
        let mut gz = Vec::new();
        {
            use std::io::Write;
            let mut w = flate2::write::GzEncoder::new(&mut gz, flate2::Compression::fast());
            w.write_all(plain).unwrap();
            w.finish().unwrap();
        }
        let a = run(&ARTIFACT, "var/log/pods/a_b_c/d/0.log.20261112-100000", plain, 0);
        let b = run(&ARTIFACT, "var/log/pods/a_b_c/d/0.log.gz", &gz, 0);
        assert_eq!(records(&a)[0]["message"], records(&b)[0]["message"]);
        assert_eq!(records(&a)[0]["restart_count"], 0);
        let out = run(&ARTIFACT, "var/log/pods/a_b_c/d/0.log", b"hello\nstdout F x\n", 0);
        assert!(out.matches("--- warning").count() == 2 && !out.contains("\"artifact\""), "{out}");
        assert!(run(&ARTIFACT, "var/log/pods/a_b_c/d/0.log", b"", 0).contains("skipped"));
    }

    #[test]
    fn mutated_logs_never_panic() {
        let files = log_files("kind");
        let (path, real) = files.iter().max_by_key(|(_, d)| d.len()).unwrap();
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for round in 0..1500 {
            let mut data = real.clone();
            for _ in 0..=(round % 6) {
                let at = (next() as usize) % data.len();
                data[at] = next() as u8;
            }
            if round % 4 == 0 {
                data.truncate((next() as usize) % data.len());
            }
            run(&ARTIFACT, path, &data, 0);
        }
    }
}
