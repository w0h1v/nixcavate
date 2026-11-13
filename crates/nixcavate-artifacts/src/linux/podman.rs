//! Podman (containers/storage) metadata: the container and image indexes
//! `containers.json` and `images.json`, for the rootful store and for rootless users.
//! Format reference: containers/storage `containers.go` and `images.go` (JSON arrays).
//! The graph root is configurable (`graphroot` in storage.conf, `--root`) and its folders are
//! named after the storage driver (`overlay-containers`, `vfs-containers`), so the patterns
//! anchor on those names under any prefix.

use super::docker::time_of;
use crate::common::home::user_from_path;
use crate::{Artifact, Category, Input, LINUX};
use nixcavate_core::{Basis, Error, Event, Loc, Record, Result, Sink, Timestamp};
use serde::Serialize;
use serde_json::Value;

pub const CONTAINERS: Artifact = Artifact::new(
    "podman-containers",
    "Podman container index",
    Category::Containers,
    LINUX,
    &["**/*-containers/containers.json"],
    parse_containers,
);

pub const IMAGES: Artifact = Artifact::new(
    "podman-images",
    "Podman image index",
    Category::Containers,
    LINUX,
    &["**/*-images/images.json"],
    parse_images,
);

#[derive(Serialize)]
struct Container {
    user: String,
    container_id: String,
    names: Vec<String>,
    image_id: String,
    image_name: String,
    time: Option<Timestamp>,
}

impl Record for Container {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let name = self.names.first().map_or(self.container_id.as_str(), String::as_str);
        self.time
            .map(|t| Event::new(t, "container_created", format!("container {name} created from {}", self.image_name)))
            .into_iter()
    }
}

#[derive(Serialize)]
struct Image {
    user: String,
    image_id: String,
    names: Vec<String>,
    time: Option<Timestamp>,
    digest: String,
}

impl Record for Image {}

fn text(v: &Value, key: &str) -> String {
    v.get(key).and_then(Value::as_str).unwrap_or_default().to_owned()
}

fn names(v: &Value) -> Vec<String> {
    v.get("names")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|n| n.as_str().map(str::to_owned))
        .collect()
}

/// The entries of the top-level array; `None` entries are reported by the callers.
fn entries(input: &Input) -> Result<Vec<Value>> {
    if input.data.iter().all(u8::is_ascii_whitespace) {
        return Err(Error::skipped("empty file"));
    }
    match serde_json::from_slice(input.data) {
        Ok(Value::Array(items)) => Ok(items),
        Ok(Value::Null) => Ok(Vec::new()),
        Ok(_) => Err(Error::format("expected a JSON array")),
        Err(e) => Err(Error::format(format!("not valid JSON: {e}"))),
    }
}

fn parse_containers(input: &Input, sink: &mut Sink) -> Result<()> {
    let user = user_from_path(input.path);
    for (index, entry) in entries(input)?.iter().enumerate() {
        if !entry.is_object() {
            sink.warn(format!("entry {index} is not an object"));
            continue;
        }
        // Podman keeps its own fields in `metadata`, a JSON document stored as a string.
        let metadata: Value = entry
            .get("metadata")
            .and_then(Value::as_str)
            .and_then(|m| serde_json::from_str(m).ok())
            .unwrap_or_default();
        let time = time_of(&text(entry, "created")).or_else(|| {
            metadata.get("created-at").and_then(Value::as_i64).map(|secs| Timestamp::from_secs(secs, Basis::Recorded))
        });
        sink.emit(
            Loc::None,
            &Container {
                user: user.into(),
                container_id: text(entry, "id"),
                names: names(entry),
                image_id: text(entry, "image"),
                image_name: text(&metadata, "image-name"),
                time,
            },
        )?;
    }
    Ok(())
}

fn parse_images(input: &Input, sink: &mut Sink) -> Result<()> {
    let user = user_from_path(input.path);
    for (index, entry) in entries(input)?.iter().enumerate() {
        if !entry.is_object() {
            sink.warn(format!("entry {index} is not an object"));
            continue;
        }
        sink.emit(
            Loc::None,
            &Image {
                user: user.into(),
                image_id: text(entry, "id"),
                names: names(entry),
                time: time_of(&text(entry, "created")),
                digest: text(entry, "digest"),
            },
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    #[test]
    fn system_containers() {
        let path = "var/lib/containers/storage/vfs-containers/containers.json";
        insta::assert_snapshot!(run(&CONTAINERS, path, &fixture("podman-containers/containers.json"), 0));
    }

    #[test]
    fn rootless_images() {
        let path = "home/alice/.local/share/containers/storage/vfs-images/images.json";
        insta::assert_snapshot!(run(&IMAGES, path, &fixture("podman-images/images.json"), 0));
    }

    /// `test_files/podman-real/build.sh` ran the real podman: a rootful store, a rootless one
    /// and a graph root moved with `--root`. `expected.txt` holds podman's own counts.
    #[test]
    fn real_podman_stores_give_podmans_own_counts() {
        use nixcavate_source::glob::Pattern;
        let expected = String::from_utf8(fixture("podman-real/expected.txt")).unwrap();
        let stores = [
            ("root", "var/lib/containers/storage", ""),
            ("podman", "home/podman/.local/share/containers/storage", "podman"),
            ("moved", "srv/data/containers", ""),
        ];
        for (label, root, user) in stores {
            let row: Vec<&str> = expected.lines().find(|l| l.starts_with(label)).unwrap().split(' ').collect();
            let (containers, images) = (row[2].parse::<usize>().unwrap(), row[4].parse::<usize>().unwrap());
            let (cpath, ipath) =
                (format!("{root}/vfs-containers/containers.json"), format!("{root}/vfs-images/images.json"));
            assert!(CONTAINERS.paths.iter().any(|p| Pattern::new(p).matches(&cpath)), "{cpath}");
            assert!(IMAGES.paths.iter().any(|p| Pattern::new(p).matches(&ipath)), "{ipath}");
            let out = run(&CONTAINERS, &cpath, &fixture(&format!("podman-real/{cpath}")), 0);
            assert_eq!(out.matches("\"artifact\":\"podman-containers\"").count(), containers, "{label}: {out}");
            assert!(out.matches(&format!("\"user\":\"{user}\"")).count() == containers, "{out}");
            let out = run(&IMAGES, &ipath, &fixture(&format!("podman-real/{ipath}")), 0);
            assert_eq!(out.matches("\"artifact\":\"podman-images\"").count(), images, "{label}: {out}");
            assert!(!out.contains("--- warning") && !out.contains("--- failed"), "{out}");
        }
    }

    #[test]
    fn hostile_input_never_panics() {
        let path = "var/lib/containers/storage/vfs-containers/containers.json";
        for data in [
            &b""[..],
            b"{}",
            b"null",
            b"[1,\"x\",null]",
            br#"[{"id":5,"names":"a","metadata":7,"created":[]}]"#,
            br#"[{"metadata":"{not json","created-at":1}]"#,
        ] {
            run(&CONTAINERS, path, data, 0);
            run(&IMAGES, path, data, 0);
        }
        let full = fixture("podman-containers/containers.json");
        for cut in (0..full.len()).step_by(11) {
            let out = run(&CONTAINERS, path, &full[..cut], 0);
            assert!(cut == 0 || out.contains("failed: ") || cut == full.len(), "{cut}");
        }
    }
}
