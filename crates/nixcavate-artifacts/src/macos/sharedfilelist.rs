//! Shared file lists (`*.sfl`, `*.sfl2`, `*.sfl3` in `com.apple.sharedfilelist`): recent
//! applications, documents, servers and hosts, favourite items and volumes, and the per-app
//! recent document lists. An `NSKeyedArchiver` property list whose root has an `items` array;
//! each item has a `Name` and a `Bookmark` (see [`super::bookmark`]) naming the target. Items
//! saved by pre-10.10 systems carry a legacy `Alias` record instead, which is not decoded.
//!
//! References: Sarah Edwards' mac4n6 write-ups on `sfl2` files and the keyed-archive layout
//! above. Synthetic only for the item keys (`Name`, `Bookmark`, `uuid`, `visibility`, `order`):
//! the keyed-archive and bookmark layers were checked against data written by Foundation for
//! a file the checker created, but no real `.sfl2` was read.

use super::bookmark::decode;
use super::keyed_archive::unarchive;
use super::plist_util::{parse, string};
use super::util::clip;
use crate::common::home::user_from_path;
use crate::{Artifact, Category, Input, MACOS};
use nixcavate_core::{Basis, Error, Loc, Record, Result, Sink, Timestamp};
use plist::Value;
use serde::Serialize;

pub const ARTIFACT: Artifact = Artifact::new(
    "shared-file-lists",
    "Recent and favourite items (shared file lists)",
    Category::Activity,
    MACOS,
    &[
        "Users/*/Library/Application Support/com.apple.sharedfilelist/*.sfl*",
        "Users/*/Library/Application Support/com.apple.sharedfilelist/*/*.sfl*",
    ],
    parse_list,
);

const MAX_ITEMS: usize = 10_000;

#[derive(Serialize)]
struct Entry<'a> {
    user: &'a str,
    /// The list's file name without its extension, e.g. `com.apple.LSSharedFileList.RecentApplications`.
    list: &'a str,
    index: usize,
    name: Option<String>,
    path: Option<String>,
    volume_name: Option<String>,
    volume_uuid: Option<String>,
    target_created: Option<Timestamp>,
    uuid: Option<String>,
    visibility: Option<i64>,
    /// The list file's modification time as collected.
    list_modified: Option<Timestamp>,
}

impl Record for Entry<'_> {}

fn parse_list(input: &Input, sink: &mut Sink) -> Result<()> {
    let value = parse(input.data)?;
    let Some(root) = unarchive(&value) else { return Err(Error::skipped("not an NSKeyedArchiver archive")) };
    let Some(items) = root.as_dictionary().and_then(|d| d.get("items")).and_then(Value::as_array) else {
        return Err(Error::skipped("no items array"));
    };
    let file = input.path.rsplit('/').next().unwrap_or_default();
    let list = file.rsplit_once(".sfl").map_or(file, |(stem, _)| stem);
    let modified = (input.mtime > 0).then(|| Timestamp::from_secs(input.mtime, Basis::Recorded));
    let user = user_from_path(input.path);
    if items.len() > MAX_ITEMS {
        sink.warn(format!("{} items; only the first {MAX_ITEMS} are read", items.len()));
    }
    for (index, item) in items.iter().take(MAX_ITEMS).enumerate() {
        let Some(dict) = item.as_dictionary() else { continue };
        let bookmark = match dict.get("Bookmark") {
            Some(Value::Data(bytes)) => decode(bytes),
            _ => None,
        };
        if dict.contains_key("Bookmark") && bookmark.is_none() {
            sink.warn(format!("item {index}: bookmark data is not readable; name only"));
        }
        let uuid = string(dict, "uuid").map(str::to_owned);
        sink.emit(
            Loc::None,
            &Entry {
                user,
                list,
                index,
                name: string(dict, "Name").map(|n| clip(n, 512)),
                path: bookmark.as_ref().and_then(|b| b.full_path()),
                volume_name: bookmark.as_ref().and_then(|b| b.volume_name.clone()),
                volume_uuid: bookmark.as_ref().and_then(|b| b.volume_uuid.clone()),
                target_created: bookmark.as_ref().and_then(|b| b.file_created),
                uuid,
                visibility: dict.get("visibility").and_then(Value::as_signed_integer),
                list_modified: modified,
            },
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    const PATH: &str = "Users/alice/Library/Application Support/com.apple.sharedfilelist/com.apple.LSSharedFileList.RecentDocuments.sfl2";

    #[test]
    fn reads_items_and_their_bookmarks() {
        insta::assert_snapshot!(run(&ARTIFACT, PATH, &fixture("sharedfilelist/Example.sfl2"), 1_700_000_000));
    }

    #[test]
    fn other_plists_are_skipped() {
        let plain = b"<plist version=\"1.0\"><dict/></plist>";
        assert!(run(&ARTIFACT, PATH, plain, 0).contains("skipped: not an NSKeyedArchiver"));
    }

    #[test]
    fn damaged_lists_do_not_panic() {
        let data = fixture("sharedfilelist/Example.sfl2");
        crate::macos::plist_util::tests::survives_damage(&ARTIFACT, PATH, &data);
    }

    /// Foundation's own archive: `NIXCAVATE_ARCHIVE=<file> cargo test ... real_archive -- --ignored --nocapture`.
    #[test]
    #[ignore = "needs an archive file; see docs/LIMITATIONS.md"]
    fn real_archive() {
        let data = std::fs::read(std::env::var("NIXCAVATE_ARCHIVE").unwrap()).unwrap();
        println!("{}", run(&ARTIFACT, PATH, &data, 0));
    }
}
