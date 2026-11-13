//! containerd's image records: `io.containerd.metadata.v1.bolt/meta.db`, a BoltDB file (read
//! by [`super::bolt`]). It is where Docker 29 and later (whose default image store is
//! containerd's, under `<data-root>/containerd/daemon/`), Kubernetes nodes and `nerdctl` keep
//! the names, digests and times of their images; the classic `image/overlay2` store that
//! `docker-images` reads does not exist on such hosts.
//!
//! Schema, from containerd's `metadata/buckets.go`: bucket `v1`, then one bucket per
//! namespace (`moby` for Docker, `k8s.io` for Kubernetes), then `images`, then one bucket per
//! image name holding `createdat` and `updatedat` (a Go `time.Time` in its binary form),
//! `target` (a bucket: `digest`, `mediatype`, `size` as a signed varint) and `labels`.

use super::bolt::{Bolt, Bucket, Value};
use crate::text::decompressed;
use crate::{Artifact, Category, Input, LINUX};
use nixcavate_core::{Basis, Error, Event, Loc, Precision, Record, Result, Sink, Timestamp};
use serde::Serialize;
use std::borrow::Cow;
use std::collections::BTreeMap;

pub const ARTIFACT: Artifact = Artifact::new(
    "containerd-images",
    "Images in the containerd image store (Docker 29 default, Kubernetes)",
    Category::Containers,
    LINUX,
    &["**/io.containerd.metadata.v1.bolt/meta.db"],
    parse,
);

/// At most this many labels are kept per image.
const MAX_LABELS: usize = 256;

#[derive(Serialize)]
struct Image<'a> {
    namespace: Cow<'a, str>,
    /// The reference, e.g. `docker.io/library/alpine:3`.
    name: Cow<'a, str>,
    digest: Cow<'a, str>,
    media_type: Cow<'a, str>,
    /// The size of the target descriptor (the image's manifest or index), not of its layers.
    manifest_size_bytes: Option<u64>,
    /// When containerd recorded the image (the pull or tag), not when it was built.
    time: Option<Timestamp>,
    updated_time: Option<Timestamp>,
    labels: BTreeMap<String, String>,
}

impl Record for Image<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let message = format!("image {} added to containerd ({})", self.name, self.digest);
        self.time.map(|t| Event::new(t, "image_added", message)).into_iter()
    }
}

/// Seconds from 0001-01-01 (Go's zero time) to 1970-01-01.
const GO_EPOCH_OFFSET: i64 = 62_135_596_800;

/// A Go `time.Time` as `MarshalBinary` writes it: version 1 or 2, seconds since year 1
/// (big-endian i64), nanoseconds (i32), then the zone offset in minutes (and, in version 2,
/// seconds). The instant is UTC whatever the zone. Go's zero time is "no time".
pub(super) fn go_time(bytes: &[u8]) -> Option<Timestamp> {
    let (version, rest) = bytes.split_first()?;
    if !matches!((*version, bytes.len()), (1, 15) | (2, 16)) {
        return None;
    }
    let secs = i64::from_be_bytes(rest.get(..8)?.try_into().ok()?).checked_sub(GO_EPOCH_OFFSET)?;
    let nanos = u32::try_from(i32::from_be_bytes(rest.get(8..12)?.try_into().ok()?)).ok()?;
    if secs <= 0 || nanos >= 1_000_000_000 {
        return None;
    }
    Timestamp::checked(secs, nanos, Precision::Nanos, Basis::Recorded)
}

/// Go's `binary.Varint`: zig-zag LEB128.
fn varint(bytes: &[u8]) -> Option<i64> {
    let mut value = 0u64;
    for (i, &byte) in bytes.iter().take(10).enumerate() {
        value |= u64::from(byte & 0x7f).checked_shl(7 * i as u32)?;
        if byte & 0x80 == 0 {
            return Some(((value >> 1) as i64) ^ -((value & 1) as i64));
        }
    }
    None
}

pub(super) fn text(bytes: Option<&[u8]>) -> Cow<'_, str> {
    bytes.map_or(Cow::Borrowed(""), String::from_utf8_lossy)
}

pub(super) fn labels(image: &Bucket) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    if let Some(bucket) = image.bucket(b"labels") {
        let _ = bucket.for_each(|key, value| {
            if let (true, Value::Data(value)) = (out.len() < MAX_LABELS, value) {
                out.insert(String::from_utf8_lossy(key).into_owned(), String::from_utf8_lossy(value).into_owned());
            }
        });
    }
    out
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    let data = decompressed(input.data)?;
    if data.is_empty() {
        return Err(Error::skipped("empty file"));
    }
    let db = Bolt::open(&data)?;
    let v1 = db.root().bucket(b"v1").ok_or_else(|| Error::format("no `v1` bucket: not a containerd metadata file"))?;
    let mut images = Vec::new();
    let walked = v1.for_each(|namespace, value| {
        let Value::Bucket(namespace_bucket) = value else { return };
        let Some(bucket) = namespace_bucket.bucket(b"images") else { return };
        let _ = bucket.for_each(|name, value| {
            let Value::Bucket(image) = value else { return };
            let target = image.bucket(b"target");
            let field = |key: &[u8]| target.as_ref().and_then(|t| t.get(key));
            images.push(Image {
                namespace: String::from_utf8_lossy(namespace),
                name: String::from_utf8_lossy(name),
                digest: text(field(b"digest")),
                media_type: text(field(b"mediatype")),
                manifest_size_bytes: field(b"size").and_then(varint).and_then(|s| u64::try_from(s).ok()),
                time: image.get(b"createdat").and_then(go_time),
                updated_time: image.get(b"updatedat").and_then(go_time),
                labels: labels(&image),
            });
        });
    });
    for image in &images {
        sink.emit(Loc::None, image)?;
    }
    if let Err(e) = walked {
        sink.warn(format!("the namespace list is damaged, so images may be missing: {e}"));
    }
    if images.is_empty() {
        sink.warn("the containerd metadata holds no images");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};
    use std::io::Read;

    const PATH: &str = "srv/data/docker/containerd/daemon/io.containerd.metadata.v1.bolt/meta.db";

    /// `test_files/containerd-images/build.sh`: a real Docker 29 daemon with its containerd
    /// image store; `meta.db.gz` is the metadata file, `ctr-images.txt` containerd's own listing.
    fn meta() -> Vec<u8> {
        let mut out = Vec::new();
        flate2::read::GzDecoder::new(&fixture("containerd-images/meta.db.gz")[..]).read_to_end(&mut out).unwrap();
        out
    }

    #[test]
    fn images_equal_what_ctr_lists() {
        let out = run(&ARTIFACT, PATH, &meta(), 0);
        assert!(!out.contains("--- warning") && !out.contains("--- failed"), "{out}");
        let listing = String::from_utf8(fixture("containerd-images/ctr-images.txt")).unwrap();
        let mut expected = Vec::new();
        for row in listing.lines().skip(1) {
            let columns: Vec<&str> = row.split(' ').collect();
            expected.push((columns[0].to_string(), columns[1].to_string(), columns[2].to_string()));
        }
        let mut found = Vec::new();
        for row in out.lines().take_while(|l| !l.starts_with("---")) {
            let json: serde_json::Value = serde_json::from_str(row).unwrap();
            let field = |k: &str| json[k].as_str().unwrap().to_string();
            assert_eq!(field("namespace"), "moby");
            found.push((field("name"), field("media_type"), field("digest")));
            // Added within a few minutes before the file was copied out.
            let taken: i64 =
                String::from_utf8(fixture("containerd-images/taken-at.txt")).unwrap().trim().parse().unwrap();
            let time = json["time"].as_str().unwrap();
            let time = nixcavate_core::time::parse_iso8601(time.as_bytes()).unwrap().0.secs;
            assert!((taken - 900..=taken).contains(&time), "{time} vs {taken}");
            assert!(json["manifest_size_bytes"].as_u64().unwrap() > 1000);
        }
        found.sort();
        expected.sort();
        assert_eq!(found, expected);
        insta::assert_snapshot!(out.lines().take_while(|l| !l.starts_with("---")).collect::<Vec<_>>().join("\n"));
    }

    #[test]
    fn not_a_bolt_file_and_empty_files() {
        assert!(run(&ARTIFACT, PATH, b"", 0).contains("skipped"));
        assert!(run(&ARTIFACT, PATH, &[0u8; 8192], 0).contains("not a BoltDB file"));
        assert!(run(&ARTIFACT, PATH, b"SQLite format 3\0", 0).contains("not a BoltDB file"));
    }

    #[test]
    fn times_and_varints_decode_as_go_writes_them() {
        let secs = 1_794_527_100i64 + GO_EPOCH_OFFSET;
        let mut bytes = vec![1u8];
        bytes.extend(secs.to_be_bytes());
        bytes.extend(500_000_000i32.to_be_bytes());
        bytes.extend((-1i16).to_be_bytes());
        assert_eq!(go_time(&bytes).map(|t| t.to_rfc3339()).as_deref(), Some("2026-11-12T23:45:00.500000000Z"));
        assert!(go_time(&bytes[..14]).is_none());
        // Nanoseconds past a second are rejected.
        let mut bad = bytes.clone();
        bad[9..13].copy_from_slice(&2_000_000_000i32.to_be_bytes());
        assert!(go_time(&bad).is_none());
        // Go's zero time.
        let mut zero = vec![1u8];
        zero.extend(0i64.to_be_bytes());
        zero.extend([0u8; 6]);
        assert!(go_time(&zero).is_none());
        assert_eq!(varint(&[0x00]), Some(0));
        assert_eq!(varint(&[0x02]), Some(1));
        assert_eq!(varint(&[0x01]), Some(-1));
        assert_eq!(varint(&[0xc8, 0x91, 0x02]), Some(17508));
        assert_eq!(varint(&[0x80; 11]), None);
        assert_eq!(varint(&[]), None);
    }

    /// Thousands of deterministic byte flips, truncations and forged page numbers of a real
    /// file: none may panic or hang.
    #[test]
    fn damaged_files_never_panic_or_hang() {
        let real = meta();
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for round in 0..3000 {
            let mut data = real.clone();
            for _ in 0..=(round % 5) {
                let at = (next() as usize) % data.len();
                data[at] = next() as u8;
            }
            if round % 7 == 0 {
                let cut = (next() as usize) % data.len();
                data.truncate(cut);
            }
            // Keep the meta checksum valid half the time so the walk, not the check, is tested.
            if round % 2 == 0 {
                for meta in [0usize, 4096] {
                    if let Some(body) = data.get(meta + 16..meta + 16 + 56) {
                        let sum = body
                            .iter()
                            .fold(0xcbf2_9ce4_8422_2325u64, |h, &b| (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3));
                        if let Some(slot) = data.get_mut(meta + 16 + 56..meta + 16 + 64) {
                            slot.copy_from_slice(&sum.to_le_bytes());
                        }
                    }
                }
            }
            run(&ARTIFACT, PATH, &data, 0);
        }
    }

    /// A branch page whose only child is itself is a loop, not an endless recursion.
    #[test]
    fn a_page_tree_that_loops_ends() {
        let mut data = meta();
        // Find the current root page and rewrite it as a branch whose child is itself.
        let (a, b) = (
            u64::from_le_bytes(data[16 + 16..16 + 24].try_into().unwrap()),
            u64::from_le_bytes(data[4096 + 32..4096 + 40].try_into().unwrap()),
        );
        for root in [a, b] {
            let at = root as usize * 4096;
            data[at + 8..at + 10].copy_from_slice(&1u16.to_le_bytes());
            data[at + 10..at + 12].copy_from_slice(&1u16.to_le_bytes());
            data[at + 16..at + 20].copy_from_slice(&16u32.to_le_bytes());
            data[at + 20..at + 24].copy_from_slice(&0u32.to_le_bytes());
            data[at + 24..at + 32].copy_from_slice(&root.to_le_bytes());
        }
        let out = run(&ARTIFACT, PATH, &data, 0);
        assert!(out.contains("no `v1` bucket") || out.contains("loops") || out.contains("--- failed"), "{out}");
    }
}
