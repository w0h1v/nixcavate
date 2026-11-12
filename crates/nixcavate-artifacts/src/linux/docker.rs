//! Docker engine state under `/var/lib/docker`: container definitions (`config.v2.json` plus
//! `hostconfig.json`), the `json-file` logging driver's logs, and the image store.
//! Format reference: Moby `container/` and `image/` packages, Docker "JSON File logging driver".
//! The image store is the classic graph driver layout; hosts using the containerd image store
//! keep their images elsewhere and yield nothing here.

use crate::text::for_each_line;
use crate::{Artifact, Category, Input, LINUX};
use nixcavate_core::time::parse_iso8601;
use nixcavate_core::{Error, Event, Loc, Record, Result, Sink, Timestamp};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::borrow::Cow;
use std::collections::BTreeMap;

pub const CONTAINERS: Artifact = Artifact::new(
    "docker-containers",
    "Docker container definitions and state",
    Category::Containers,
    LINUX,
    &["var/lib/docker/containers/*/config.v2.json", "home/*/.local/share/docker/containers/*/config.v2.json"],
    parse_container,
)
.companions(&[
    "var/lib/docker/containers/*/hostconfig.json",
    "home/*/.local/share/docker/containers/*/hostconfig.json",
]);

pub const LOGS: Artifact = Artifact::new(
    "docker-logs",
    "Docker json-file container logs",
    Category::Containers,
    LINUX,
    &["var/lib/docker/containers/*/*-json.log*", "home/*/.local/share/docker/containers/*/*-json.log*"],
    parse_logs,
)
.split_lines();

pub const IMAGES: Artifact = Artifact::new(
    "docker-images",
    "Docker image references and image configurations",
    Category::Containers,
    LINUX,
    &["var/lib/docker/image/*/repositories.json", "var/lib/docker/image/*/imagedb/content/sha256/*"],
    parse_images,
);

/// RFC 3339 with a zone. Docker writes year 1 for "never happened".
pub(super) fn time_of(text: &str) -> Option<Timestamp> {
    if text.starts_with("0001-01-01") {
        return None;
    }
    parse_iso8601(text.as_bytes())?.0.recorded()
}

fn str_at<'a>(v: &'a Value, path: &[&str]) -> &'a str {
    path.iter().try_fold(v, |v, key| v.get(key)).and_then(Value::as_str).unwrap_or_default()
}

fn time_at(v: &Value, path: &[&str]) -> Option<Timestamp> {
    time_of(str_at(v, path))
}

/// The strings of a JSON array, or of a lone string; other shapes yield nothing.
fn strings_at(v: &Value, path: &[&str]) -> Vec<String> {
    match path.iter().try_fold(v, |v, key| v.get(key)) {
        Some(Value::Array(items)) => items.iter().filter_map(|i| i.as_str().map(str::to_owned)).collect(),
        Some(Value::String(s)) => vec![s.clone()],
        _ => Vec::new(),
    }
}

fn parse_json(input: &Input) -> Result<Value> {
    if input.data.iter().all(u8::is_ascii_whitespace) {
        return Err(Error::skipped("empty file"));
    }
    serde_json::from_slice(input.data).map_err(|e| Error::format(format!("not valid JSON: {e}")))
}

#[derive(Serialize)]
struct Container {
    container_id: String,
    name: String,
    image: String,
    image_id: String,
    command: String,
    entrypoint: String,
    time: Option<Timestamp>,
    started_time: Option<Timestamp>,
    finished_time: Option<Timestamp>,
    running: bool,
    exit_code: Option<i64>,
    pid: Option<i64>,
    restart_policy: String,
    privileged: bool,
    network_mode: String,
    binds: Vec<String>,
    /// `hostip:hostport->containerport/proto`
    port_bindings: Vec<String>,
    /// `source:destination`
    mounts: Vec<String>,
    environment: Vec<String>,
    labels: BTreeMap<String, String>,
    hostname: String,
    user: String,
}

impl Record for Container {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let what = |verb: &str| format!("container {} {verb} (image {})", self.name, self.image);
        [
            self.time.map(|t| Event::new(t, "container_created", what("created"))),
            self.started_time.map(|t| Event::new(t, "container_started", what("started"))),
            self.finished_time.map(|t| Event::new(t, "container_finished", what("finished"))),
        ]
        .into_iter()
        .flatten()
    }
}

fn port_bindings(host_config: &Value) -> Vec<String> {
    let Some(Value::Object(ports)) = host_config.get("PortBindings") else { return Vec::new() };
    let mut out = Vec::new();
    for (container_port, bindings) in ports {
        for binding in bindings.as_array().into_iter().flatten() {
            out.push(format!("{}:{}->{container_port}", str_at(binding, &["HostIp"]), str_at(binding, &["HostPort"])));
        }
    }
    out
}

fn mounts(config: &Value) -> Vec<String> {
    let Some(Value::Object(points)) = config.get("MountPoints") else { return Vec::new() };
    points.values().map(|m| format!("{}:{}", str_at(m, &["Source"]), str_at(m, &["Destination"]))).collect()
}

fn restart_policy(host_config: &Value) -> String {
    let name = str_at(host_config, &["RestartPolicy", "Name"]);
    match host_config.pointer("/RestartPolicy/MaximumRetryCount").and_then(Value::as_i64) {
        Some(max) if max > 0 => format!("{name}:{max}"),
        _ => name.to_owned(),
    }
}

fn parse_container(input: &Input, sink: &mut Sink) -> Result<()> {
    let config = parse_json(input)?;
    if !config.is_object() {
        return Err(Error::format("config.v2.json is not a JSON object"));
    }
    let dir = input.path.rsplit_once('/').map_or("", |(dir, _)| dir);
    let host_config = match input.host.read(&format!("{dir}/hostconfig.json")) {
        Some(data) => serde_json::from_slice(&data).unwrap_or_else(|e| {
            sink.warn(format!("hostconfig.json is not valid JSON: {e}"));
            Value::Null
        }),
        None => {
            sink.warn("hostconfig.json is missing: restart policy, privileged, binds and ports are unknown");
            Value::Null
        }
    };
    let id = str_at(&config, &["ID"]);
    let join = |path: &[&str]| strings_at(&config, path).join(" ");
    let command = [strings_at(&config, &["Path"]), strings_at(&config, &["Args"])].concat().join(" ");
    let labels = match config.pointer("/Config/Labels") {
        Some(Value::Object(map)) => map.iter().filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_owned()))).collect(),
        _ => BTreeMap::new(),
    };
    sink.emit(
        Loc::None,
        &Container {
            container_id: if id.is_empty() { dir.rsplit('/').next().unwrap_or_default().into() } else { id.into() },
            name: str_at(&config, &["Name"]).trim_start_matches('/').into(),
            image: str_at(&config, &["Config", "Image"]).into(),
            image_id: str_at(&config, &["Image"]).into(),
            command,
            entrypoint: join(&["Config", "Entrypoint"]),
            time: time_at(&config, &["Created"]),
            started_time: time_at(&config, &["State", "StartedAt"]),
            finished_time: time_at(&config, &["State", "FinishedAt"]),
            running: config.pointer("/State/Running").and_then(Value::as_bool).unwrap_or(false),
            exit_code: config.pointer("/State/ExitCode").and_then(Value::as_i64),
            pid: config.pointer("/State/Pid").and_then(Value::as_i64),
            restart_policy: restart_policy(&host_config),
            privileged: host_config.get("Privileged").and_then(Value::as_bool).unwrap_or(false),
            network_mode: str_at(&host_config, &["NetworkMode"]).into(),
            binds: strings_at(&host_config, &["Binds"]),
            port_bindings: port_bindings(&host_config),
            mounts: mounts(&config),
            environment: strings_at(&config, &["Config", "Env"]),
            labels,
            hostname: str_at(&config, &["Config", "Hostname"]).into(),
            user: str_at(&config, &["Config", "User"]).into(),
        },
    )
}

/// One log line. Borrowed fields keep the per-line cost at one scan of the text.
#[derive(Deserialize)]
struct LogLine<'a> {
    #[serde(borrow, default)]
    log: Cow<'a, str>,
    #[serde(borrow, default)]
    stream: Cow<'a, str>,
    #[serde(borrow, default)]
    time: Cow<'a, str>,
}

#[derive(Serialize)]
struct LogRecord<'a> {
    time: Option<Timestamp>,
    container_id: &'a str,
    stream: Cow<'a, str>,
    message: Cow<'a, str>,
}

impl Record for LogRecord<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        self.time.map(|t| Event::new(t, "container_log", self.message.as_ref())).into_iter()
    }
}

fn parse_logs(input: &Input, sink: &mut Sink) -> Result<()> {
    // `.../containers/<id>/<id>-json.log[.N[.gz]]`
    let container_id = input.path.rsplit('/').nth(1).unwrap_or_default();
    for_each_line(input, |line| {
        if line.bytes.iter().all(u8::is_ascii_whitespace) {
            return Ok(());
        }
        let parsed: LogLine = match serde_json::from_slice(line.bytes) {
            Ok(parsed) => parsed,
            Err(e) => {
                sink.warn(format!("offset {}: not a json-file log line: {e}", line.offset));
                return Ok(());
            }
        };
        let message = match parsed.log {
            Cow::Borrowed(s) => Cow::Borrowed(s.strip_suffix('\n').unwrap_or(s)),
            Cow::Owned(mut s) => {
                if s.ends_with('\n') {
                    s.pop();
                }
                Cow::Owned(s)
            }
        };
        // Docker writes RFC 3339 with nanoseconds and `Z`.
        let time = parse_iso8601(parsed.time.as_bytes()).and_then(|(t, _)| t.recorded());
        sink.emit(Loc::Offset(line.offset), &LogRecord { time, container_id, stream: parsed.stream, message })
    })
}

#[derive(Serialize)]
struct Image {
    /// `reference` (a tag or digest naming an image) or `image` (an image configuration).
    kind: &'static str,
    repository: String,
    reference: String,
    image_id: String,
    time: Option<Timestamp>,
    architecture: String,
    os: String,
    command: String,
    entrypoint: String,
    /// Number of filesystem layers.
    layers: Option<u64>,
    author: String,
    /// `created_by` of each build step, at most 50.
    history: Vec<String>,
}

impl Image {
    fn new(kind: &'static str) -> Self {
        Self {
            kind,
            repository: String::new(),
            reference: String::new(),
            image_id: String::new(),
            time: None,
            architecture: String::new(),
            os: String::new(),
            command: String::new(),
            entrypoint: String::new(),
            layers: None,
            author: String::new(),
            history: Vec::new(),
        }
    }
}

impl Record for Image {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let time = if self.kind == "image" { self.time } else { None };
        time.map(|t| Event::new(t, "image_created", format!("image {} built", self.image_id))).into_iter()
    }
}

const MAX_HISTORY: usize = 50;

fn parse_images(input: &Input, sink: &mut Sink) -> Result<()> {
    let json = parse_json(input)?;
    let file_name = input.path.rsplit('/').next().unwrap_or_default();
    if file_name == "repositories.json" {
        let Some(Value::Object(repositories)) = json.get("Repositories") else {
            return Err(Error::format("no Repositories object"));
        };
        for (repository, references) in repositories {
            for (reference, id) in references.as_object().into_iter().flatten() {
                let mut record = Image::new("reference");
                record.repository = repository.clone();
                record.reference = reference.clone();
                record.image_id = id.as_str().unwrap_or_default().into();
                sink.emit(Loc::None, &record)?;
            }
        }
        return Ok(());
    }
    if !json.is_object() {
        return Err(Error::format("image configuration is not a JSON object"));
    }
    let mut record = Image::new("image");
    record.image_id = format!("sha256:{file_name}");
    record.time = time_at(&json, &["created"]);
    record.architecture = str_at(&json, &["architecture"]).into();
    record.os = str_at(&json, &["os"]).into();
    record.command = strings_at(&json, &["config", "Cmd"]).join(" ");
    record.entrypoint = strings_at(&json, &["config", "Entrypoint"]).join(" ");
    record.layers = json.pointer("/rootfs/diff_ids").and_then(Value::as_array).map(|a| a.len() as u64);
    record.author = str_at(&json, &["author"]).into();
    if let Some(Value::Array(history)) = json.get("history") {
        record.history =
            history.iter().filter_map(|h| h.get("created_by")?.as_str()).take(MAX_HISTORY).map(str::to_owned).collect();
        if history.len() > MAX_HISTORY {
            sink.warn(format!("history has {} entries; only the first {MAX_HISTORY} are kept", history.len()));
        }
    }
    sink.emit(Loc::None, &record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run, run_on_host};

    const WEB_ID: &str = "691d5a9467661aecea323ac1bdfd5196863eabe7159ba1af42da6701d9b39914";
    const WORKER_ID: &str = "b837a46f5538e44c5f7883ef415c510e21d35c288ce75023bec582dfc8477036";

    fn container(name: &str, id: &str) -> String {
        let dir = format!("var/lib/docker/containers/{id}");
        let (config, host) = (format!("{dir}/config.v2.json"), format!("{dir}/hostconfig.json"));
        let (c, h) = (
            fixture(&format!("docker-containers/{name}.config.v2.json")),
            fixture(&format!("docker-containers/{name}.hostconfig.json")),
        );
        run_on_host(&CONTAINERS, &[(&config, &c), (&host, &h)], &config, 0)
    }

    #[test]
    fn running_container_with_port_mount_and_label() {
        insta::assert_snapshot!(container("web01", WEB_ID));
    }

    #[test]
    fn exited_privileged_container() {
        insta::assert_snapshot!(container("worker", WORKER_ID));
    }

    #[test]
    fn missing_hostconfig_warns() {
        let path = format!("var/lib/docker/containers/{WEB_ID}/config.v2.json");
        let out = run(&CONTAINERS, &path, &fixture("docker-containers/web01.config.v2.json"), 0);
        assert!(out.contains("hostconfig.json is missing") && out.contains("\"name\":\"web01\""), "{out}");
    }

    #[test]
    fn rootless_docker_paths_are_covered() {
        use nixcavate_source::glob::Pattern;
        let matches = |a: &Artifact, path: &str| a.paths.iter().any(|p| Pattern::new(p).matches(path));
        assert!(matches(&CONTAINERS, "home/alice/.local/share/docker/containers/abc/config.v2.json"));
        assert!(matches(&LOGS, "home/alice/.local/share/docker/containers/abc/abc-json.log.1"));
    }

    #[test]
    fn hostile_container_json_never_panics() {
        let path = "var/lib/docker/containers/abc/config.v2.json";
        for data in [
            &b""[..],
            b"[]",
            b"null",
            br#"{"ID":5,"Name":[],"Path":7,"Args":5,"Created":3,"State":{"Running":"yes","Pid":"x","StartedAt":9},"Config":{"Env":5,"Labels":{"a":1,"b":"c"}},"MountPoints":[]}"#,
        ] {
            let out = run(&CONTAINERS, path, data, 0);
            assert!(out.contains("failed") || out.contains("skipped") || out.contains("\"command\":\"\""), "{out}");
        }
        let full = fixture("docker-containers/web01.config.v2.json");
        for cut in (0..full.len()).step_by(37) {
            run(&CONTAINERS, path, &full[..cut], 0);
        }
        assert!(run(&CONTAINERS, path, &full[..full.len() - 5], 0).contains("failed: "));
    }

    #[test]
    fn logs_plain_and_gzip_rotation_agree() {
        let id = WORKER_ID;
        let plain = run(
            &LOGS,
            &format!("var/lib/docker/containers/{id}/{id}-json.log"),
            &fixture("docker-logs/worker-json.log"),
            0,
        );
        insta::assert_snapshot!(plain);
        let gz_path = format!("var/lib/docker/containers/{id}/{id}-json.log.1.gz");
        let gz = run(&LOGS, &gz_path, &fixture("docker-logs/worker-json.log.1.gz"), 0);
        // Only the source path differs between the two files.
        let rows = |s: &str| {
            let records = s.split("--- timeline").next().unwrap_or_default();
            records.lines().map(|l| l.split("\"source_offset\"").nth(1).unwrap_or(l).to_owned()).collect::<Vec<_>>()
        };
        assert_eq!(rows(&plain), rows(&gz));
    }

    #[test]
    fn logs_with_damaged_lines_warn_and_continue() {
        let path = "var/lib/docker/containers/abc/abc-json.log";
        insta::assert_snapshot!(run(&LOGS, path, &fixture("docker-logs/damaged-json.log"), 0));
        assert_eq!(run(&LOGS, path, b"", 0), "");
    }

    #[test]
    fn image_references_and_config() {
        let refs = run(
            &IMAGES,
            "var/lib/docker/image/overlay2/repositories.json",
            &fixture("docker-images/repositories.json"),
            0,
        );
        insta::assert_snapshot!(refs);
        let id = "6cf065f724d522cbb3e1898559cd88f015db8a1a4210d2d048a0853b69b57ba9";
        let path = format!("var/lib/docker/image/overlay2/imagedb/content/sha256/{id}");
        insta::assert_snapshot!(run(&IMAGES, &path, &fixture(&format!("docker-images/{id}")), 0));
    }

    #[test]
    fn hostile_image_json_never_panics() {
        let path = "var/lib/docker/image/overlay2/imagedb/content/sha256/aa";
        let repos = "var/lib/docker/image/overlay2/repositories.json";
        for data in [
            &b""[..],
            b"{",
            br#"{"history":5,"rootfs":[],"config":{"Cmd":5},"created":1}"#,
            br#"{"history":[1,{"created_by":2}]}"#,
        ] {
            run(&IMAGES, path, data, 0);
        }
        for data in [&b""[..], b"{}", br#"{"Repositories":{"a":5,"b":{"c":1}}}"#, br#"{"Repositories":"#] {
            run(&IMAGES, repos, data, 0);
        }
        let full = fixture("docker-images/repositories.json");
        for cut in 0..full.len() {
            run(&IMAGES, repos, &full[..cut], 0);
        }
    }

    #[test]
    fn image_history_is_capped() {
        let history = vec![r#"{"created_by":"step"}"#; 60].join(",");
        let data = format!(r#"{{"created":"2024-01-01T00:00:00Z","history":[{history}]}}"#);
        let out = run(&IMAGES, "var/lib/docker/image/overlay2/imagedb/content/sha256/ab", data.as_bytes(), 0);
        assert_eq!(out.matches("\"step\"").count(), MAX_HISTORY);
        assert!(out.contains("only the first 50"));
    }

    #[test]
    fn log_lines_with_escapes_and_wrong_types() {
        let data =
            b"{\"log\":\"a\\\\b\\n\",\"stream\":\"stdout\",\"time\":\"2024-03-10T01:02:03.123456789Z\"}\n{\"log\":1}\n";
        let out = run(&LOGS, "var/lib/docker/containers/c1/c1-json.log", data, 0);
        assert!(out.contains("\"message\":\"a\\\\b\"") && out.contains("warning"), "{out}");
    }
}
