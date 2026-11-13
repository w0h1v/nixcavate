//! containerd's container and sandbox records, from the same `io.containerd.metadata.v1.bolt/meta.db`
//! BoltDB file as `containerd-images`. This is where Kubernetes nodes (namespace `k8s.io`),
//! Docker with its containerd image store (`moby`) and `nerdctl` (`default`) keep what they
//! created: which image, which runtime, when, and the labels the CRI plugin sets
//! (`io.kubernetes.pod.name`, `.namespace`, `.uid`, `io.kubernetes.container.name`).
//!
//! Schema, from containerd's `metadata/buckets.go`: `v1` / `<namespace>` / `containers` /
//! `<id>` (keys `image`, `snapshotter`, `snapshotKey`, `sandboxid`, `createdat`, `updatedat`,
//! `spec`, and buckets `runtime`, `labels`, `extensions`) and `v1` / `<namespace>` / `sandboxes`
//! / `<id>` (`sandboxer`, the times, `runtime`, `labels`, `spec`). `spec` is a protobuf
//! `google.protobuf.Any` whose value is the OCI runtime spec as JSON. From the spec only the
//! command line and the mount list are kept: the environment holds secrets and is never read
//! into a record.

use super::bolt::{Bolt, Bucket, Value};
use super::containerd::{go_time, labels, text};
use crate::text::decompressed;
use crate::{Artifact, Category, Input, LINUX};
use nixcavate_core::{Error, Event, Loc, Record, Result, Sink, Timestamp};
use serde::Serialize;
use std::borrow::Cow;
use std::collections::BTreeMap;

pub const ARTIFACT: Artifact = Artifact::new(
    "containerd-containers",
    "Containers and sandboxes in containerd's metadata (Kubernetes nodes, Docker 29, nerdctl)",
    Category::Containers,
    LINUX,
    &["**/io.containerd.metadata.v1.bolt/meta.db"],
    parse,
);

/// A spec larger than this is not read; real ones are a few kilobytes.
const MAX_SPEC: usize = 1 << 20;
const MAX_LIST: usize = 256;

#[derive(Serialize)]
struct Item<'a> {
    /// `container` or `sandbox`.
    kind: &'static str,
    namespace: Cow<'a, str>,
    id: Cow<'a, str>,
    image: Cow<'a, str>,
    /// The runtime name, e.g. `io.containerd.runc.v2`.
    runtime: Cow<'a, str>,
    snapshotter: Cow<'a, str>,
    snapshot_key: Cow<'a, str>,
    sandbox_id: Cow<'a, str>,
    time: Option<Timestamp>,
    updated_time: Option<Timestamp>,
    /// `io.cri-containerd.kind`: `container` or `sandbox` for CRI-created records.
    cri_kind: String,
    pod_name: String,
    pod_namespace: String,
    pod_uid: String,
    container_name: String,
    /// The process arguments of the OCI spec.
    command: String,
    /// `source:destination` of the OCI spec's mounts.
    mounts: Vec<String>,
    labels: BTreeMap<String, String>,
}

impl Record for Item<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let who = if self.pod_name.is_empty() {
            self.id.to_string()
        } else {
            format!("{}/{} {}", self.pod_namespace, self.pod_name, self.container_name)
        };
        let message = format!(
            "{} {} created in containerd namespace {} (image {})",
            self.kind,
            who.trim(),
            self.namespace,
            self.image
        );
        self.time.map(|t| Event::new(t, "container_created", message)).into_iter()
    }
}

/// The value of protobuf field 2 (bytes) of an `Any`; the cap and every length are checked.
fn any_value(bytes: &[u8]) -> Option<&[u8]> {
    let mut at = 0usize;
    while at < bytes.len() {
        let (tag, used) = read_varint(bytes.get(at..)?)?;
        at = at.checked_add(used)?;
        match tag & 7 {
            0 => at = at.checked_add(read_varint(bytes.get(at..)?)?.1)?,
            1 => at = at.checked_add(8)?,
            5 => at = at.checked_add(4)?,
            2 => {
                let (len, used) = read_varint(bytes.get(at..)?)?;
                at = at.checked_add(used)?;
                let end = at.checked_add(usize::try_from(len).ok()?)?;
                let body = bytes.get(at..end)?;
                if tag >> 3 == 2 {
                    return Some(body);
                }
                at = end;
            }
            _ => return None,
        }
    }
    None
}

fn read_varint(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut value = 0u64;
    for (i, &b) in bytes.iter().take(10).enumerate() {
        value |= u64::from(b & 0x7f).checked_shl(7 * i as u32)?;
        if b & 0x80 == 0 {
            return Some((value, i + 1));
        }
    }
    None
}

/// The command line and mounts of an OCI spec held in a bucket's `spec` value.
fn spec_facts(spec: &[u8]) -> (String, Vec<String>) {
    let Some(json) = any_value(spec).filter(|j| j.len() <= MAX_SPEC) else { return (String::new(), Vec::new()) };
    let Ok(doc) = serde_json::from_slice::<serde_json::Value>(json) else { return (String::new(), Vec::new()) };
    let command = doc
        .pointer("/process/args")
        .and_then(serde_json::Value::as_array)
        .map(|a| a.iter().filter_map(serde_json::Value::as_str).collect::<Vec<_>>().join(" "))
        .unwrap_or_default();
    let mounts = doc
        .get("mounts")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .take(MAX_LIST)
        .map(|m| {
            let field = |k: &str| m.get(k).and_then(serde_json::Value::as_str).unwrap_or_default();
            format!("{}:{}", field("source"), field("destination"))
        })
        .collect();
    (command, mounts)
}

fn collect<'a>(kind: &'static str, namespace: &'a [u8], bucket: &Bucket<'a>, out: &mut Vec<Item<'a>>) {
    let _ = bucket.for_each(|id, value| {
        let Value::Bucket(body) = value else { return };
        let runtime = body.bucket(b"runtime");
        let labels = labels(&body);
        let label = |k: &str| labels.get(k).cloned().unwrap_or_default();
        let (command, mounts) = body.get(b"spec").map(spec_facts).unwrap_or_default();
        out.push(Item {
            kind,
            namespace: String::from_utf8_lossy(namespace),
            id: String::from_utf8_lossy(id),
            image: text(body.get(b"image")),
            runtime: text(runtime.as_ref().and_then(|r| r.get(b"name"))),
            snapshotter: text(body.get(b"snapshotter")),
            snapshot_key: text(body.get(b"snapshotKey")),
            sandbox_id: text(body.get(b"sandboxid").or_else(|| body.get(b"sandboxer"))),
            time: body.get(b"createdat").and_then(go_time),
            updated_time: body.get(b"updatedat").and_then(go_time),
            cri_kind: label("io.cri-containerd.kind"),
            pod_name: label("io.kubernetes.pod.name"),
            pod_namespace: label("io.kubernetes.pod.namespace"),
            pod_uid: label("io.kubernetes.pod.uid"),
            container_name: label("io.kubernetes.container.name"),
            command,
            mounts,
            labels,
        });
    });
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    let data = decompressed(input.data)?;
    if data.is_empty() {
        return Err(Error::skipped("empty file"));
    }
    let db = Bolt::open(&data)?;
    let v1 = db.root().bucket(b"v1").ok_or_else(|| Error::format("no `v1` bucket: not a containerd metadata file"))?;
    let mut items = Vec::new();
    let walked = v1.for_each(|namespace, value| {
        let Value::Bucket(namespace_bucket) = value else { return };
        if let Some(bucket) = namespace_bucket.bucket(b"containers") {
            collect("container", namespace, &bucket, &mut items);
        }
        if let Some(bucket) = namespace_bucket.bucket(b"sandboxes") {
            collect("sandbox", namespace, &bucket, &mut items);
        }
    });
    for item in &items {
        sink.emit(Loc::None, item)?;
    }
    if let Err(e) = walked {
        sink.warn(format!("the namespace list is damaged, so containers may be missing: {e}"));
    }
    if items.is_empty() {
        sink.warn("the containerd metadata holds no containers or sandboxes");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::k8s_testdata::{expected, file_bytes, meta, records};
    use super::*;
    use crate::testing::run;

    const PATH: &str = "var/lib/containerd/io.containerd.metadata.v1.bolt/meta.db";

    /// The containers `ctr -n k8s.io containers ls` lists (id, image, runtime) must be exactly
    /// the container records of the file, and every container `crictl ps -a` reports must carry
    /// the pod labels and attempt number crictl shows.
    #[test]
    fn records_equal_what_ctr_and_crictl_list() {
        for flavor in ["k3s", "kind"] {
            let out = run(&ARTIFACT, PATH, &meta(flavor), 0);
            assert!(!out.contains("--- warning") && !out.contains("--- failed"), "{flavor}: {out}");
            let rows = records(&out);
            let listing = String::from_utf8(file_bytes(flavor, "ctr-containers.txt")).unwrap();
            let mut want: Vec<(String, String, String)> = listing
                .lines()
                .skip(1)
                .map(|l| {
                    let c: Vec<&str> = l.split_whitespace().collect();
                    (c[0].into(), c[1].into(), c[2].into())
                })
                .collect();
            let mut got: Vec<(String, String, String)> = rows
                .iter()
                .filter(|r| r["namespace"] == "k8s.io" && r["kind"] == "container")
                .map(|r| {
                    (
                        r["id"].as_str().unwrap().into(),
                        r["image"].as_str().unwrap().into(),
                        r["runtime"].as_str().unwrap().into(),
                    )
                })
                .collect();
            want.sort();
            got.sort();
            assert_eq!(got, want, "{flavor}");
            let truth = expected(flavor);
            let mut matched = 0;
            for c in truth["containers"].as_array().unwrap() {
                let row =
                    rows.iter().find(|r| r["id"] == c["id"]).unwrap_or_else(|| panic!("{flavor}: {} missing", c["id"]));
                assert_eq!(row["pod_name"], c["pod"], "{flavor}");
                assert_eq!(row["pod_namespace"], c["namespace"]);
                assert_eq!(row["pod_uid"], c["uid"]);
                assert_eq!(row["container_name"], c["container"]);
                assert_eq!(row["cri_kind"], "container");
                assert!(row["time"].is_string() && !row["snapshot_key"].as_str().unwrap().is_empty(), "{row}");
                matched += 1;
            }
            for s in truth["sandboxes"].as_array().unwrap() {
                let row = rows
                    .iter()
                    .find(|r| r["id"] == s["id"])
                    .unwrap_or_else(|| panic!("{flavor}: sandbox {} missing", s["id"]));
                assert_eq!((row["pod_name"].clone(), row["pod_uid"].clone()), (s["pod"].clone(), s["uid"].clone()));
                assert_eq!(row["cri_kind"], "sandbox");
                matched += 1;
            }
            assert!(matched >= 20, "{flavor}: {matched}");
        }
    }

    #[test]
    fn command_lines_and_mounts_come_from_the_spec_but_the_environment_does_not() {
        let out = run(&ARTIFACT, PATH, &meta("k3s"), 0);
        let rows = records(&out);
        let helper = rows.iter().find(|r| r["container_name"] == "helper").unwrap();
        assert_eq!(helper["command"], "sh -c while true; do echo helper-alive; sleep 20; done");
        assert!(helper["mounts"].as_array().unwrap().iter().any(|m| m == "/:/host"), "{helper}");
        // Pods get KUBERNETES_SERVICE_HOST in their environment: it must not reach the output.
        assert!(!out.contains("KUBERNETES_SERVICE_HOST"), "the environment was read");
        assert!(out.contains("\"event\":\"container_created\"") || out.contains("container_created"));
        let secret_pod = rows.iter().find(|r| r["container_name"] == "c" && r["pod_name"] == "secret-user").unwrap();
        assert!(
            secret_pod["mounts"].as_array().unwrap().iter().any(|m| m
                .as_str()
                .unwrap()
                .contains("kubernetes.io~secret")
                || m.as_str().unwrap().ends_with(":/etc/s")),
            "{secret_pod}"
        );
    }

    #[test]
    fn protobuf_any_values_are_bounded() {
        // type_url "x", value `{}`.
        assert_eq!(any_value(&[0x0a, 1, b'x', 0x12, 2, b'{', b'}']), Some(&b"{}"[..]));
        assert_eq!(any_value(&[0x12, 0xff, 0x7f]), None);
        assert_eq!(any_value(&[0x12, 5, 1]), None);
        assert_eq!(any_value(&[0xff; 12]), None);
        assert_eq!(any_value(&[]), None);
        assert_eq!(read_varint(&[0x80; 11]), None);
    }

    #[test]
    fn not_a_bolt_file_and_empty_files() {
        assert!(run(&ARTIFACT, PATH, b"", 0).contains("skipped"));
        assert!(run(&ARTIFACT, PATH, &[0u8; 8192], 0).contains("not a BoltDB file"));
    }

    #[test]
    fn damaged_files_never_panic_or_hang() {
        let real = meta("kind");
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for round in 0..2000 {
            let mut data = real.clone();
            for _ in 0..=(round % 5) {
                let at = (next() as usize) % data.len();
                data[at] = next() as u8;
            }
            if round % 7 == 0 {
                data.truncate((next() as usize) % data.len());
            }
            if round % 2 == 0 {
                // Keep the meta checksum valid so the walk, not the check, is exercised.
                for meta_at in [0usize, 4096] {
                    if let Some(body) = data.get(meta_at + 16..meta_at + 16 + 56) {
                        let sum = body
                            .iter()
                            .fold(0xcbf2_9ce4_8422_2325u64, |h, &b| (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3));
                        if let Some(slot) = data.get_mut(meta_at + 16 + 56..meta_at + 16 + 64) {
                            slot.copy_from_slice(&sum.to_le_bytes());
                        }
                    }
                }
            }
            run(&ARTIFACT, PATH, &data, 0);
        }
    }
}
