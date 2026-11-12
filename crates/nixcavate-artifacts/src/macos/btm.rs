//! Background Task Management: what is allowed to run in the background (login items, launch
//! agents and daemons, helper apps). File: `BackgroundItems-v*.btm`, an NSKeyedArchiver
//! archive in a binary property list (`$archiver`, `$objects`, `$top`; Apple's NSKeyedArchiver
//! documentation). Key names come from the layout of a macOS 26 store and are matched
//! tolerantly: `store.itemsByUserIdentifier` maps a user UUID to an array of `ItemRecord`s.

use super::plist_util::{mac_time, parse};
use crate::{Artifact, Category, Input, MACOS};
use nixcavate_core::{Error, Loc, Record, Result, Sink, Timestamp};
use plist::Value;
use serde::Serialize;

pub const ARTIFACT: Artifact = Artifact::new(
    "btm",
    "Background Task Management items (login items, agents, daemons)",
    Category::Persistence,
    MACOS,
    &["private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v*.btm"],
    parse_btm,
);

const MAX_DEPTH: usize = 48;
/// Work budget in bytes-ish units, so shared objects cannot be expanded exponentially.
const MAX_WORK: usize = 8 << 20;

/// An archived object graph with references followed. Binary blobs are dropped: nothing
/// reads them, and keeping them would let a shared blob be copied many times.
#[derive(Debug)]
enum Node {
    Null,
    Bool(bool),
    Int(i64),
    Real(f64),
    Str(String),
    Map(Vec<(String, Node)>),
    List(Vec<Node>),
}

impl Node {
    /// The first of several key spellings (they differ between macOS versions) that is set.
    fn get(&self, keys: &[&str]) -> Option<&Node> {
        let Node::Map(entries) = self else { return None };
        keys.iter()
            .find_map(|key| entries.iter().find(|(k, _)| k == key).map(|(_, v)| v).filter(|v| !matches!(v, Node::Null)))
    }

    fn str(&self, keys: &[&str]) -> Option<&str> {
        match self.get(keys)? {
            Node::Str(s) => Some(s),
            _ => None,
        }
    }

    fn int(&self, keys: &[&str]) -> Option<i64> {
        match self.get(keys)? {
            Node::Int(n) => Some(*n),
            Node::Bool(b) => Some(i64::from(*b)),
            _ => None,
        }
    }

    fn time(&self, keys: &[&str]) -> Option<Timestamp> {
        match self.get(keys)? {
            Node::Real(r) => mac_time(*r),
            _ => None,
        }
    }

    fn strings(&self, keys: &[&str]) -> Vec<String> {
        match self.get(keys) {
            Some(Node::Str(s)) => vec![s.clone()],
            Some(Node::List(items)) => {
                items.iter().filter_map(|n| if let Node::Str(s) = n { Some(s.clone()) } else { None }).collect()
            }
            _ => Vec::new(),
        }
    }

    /// Depth-first search for a dictionary key.
    fn find(&self, key: &str, depth: usize) -> Option<&Node> {
        if depth == 0 {
            return None;
        }
        match self {
            Node::Map(entries) => entries
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v)
                .or_else(|| entries.iter().find_map(|(_, v)| v.find(key, depth - 1))),
            Node::List(items) => items.iter().find_map(|v| v.find(key, depth - 1)),
            _ => None,
        }
    }
}

struct Resolver<'a> {
    objects: &'a [Value],
    work: usize,
    /// Set when a spend failed: part of the archive was not read.
    exhausted: bool,
    /// Indexes of the objects being resolved, to cut reference cycles.
    active: Vec<usize>,
}

impl Resolver<'_> {
    fn spend(&mut self, cost: usize) -> bool {
        match self.work.checked_sub(cost) {
            Some(left) => {
                self.work = left;
                true
            }
            None => {
                self.exhausted = true;
                false
            }
        }
    }

    /// A value that may be a `CF$UID` reference into `$objects`.
    fn resolve(&mut self, value: &Value, depth: usize) -> Node {
        if depth > MAX_DEPTH || !self.spend(16) {
            return Node::Null;
        }
        let Value::Uid(uid) = value else { return self.plain(value) };
        let Some(index) = usize::try_from(uid.get()).ok().filter(|i| *i < self.objects.len()) else {
            return Node::Null;
        };
        if self.active.contains(&index) {
            return Node::Null;
        }
        self.active.push(index);
        let node = match &self.objects[index] {
            Value::Dictionary(dict) => self.object(dict, depth + 1),
            plain => self.plain(plain),
        };
        self.active.pop();
        node
    }

    fn plain(&mut self, value: &Value) -> Node {
        match value {
            Value::Boolean(b) => Node::Bool(*b),
            Value::Integer(i) => i.as_signed().map_or(Node::Null, Node::Int),
            Value::Real(r) => Node::Real(*r),
            // NSKeyedArchiver writes nil as the string "$null".
            Value::String(s) if s == "$null" => Node::Null,
            Value::String(s) if self.spend(s.len()) => Node::Str(s.clone()),
            Value::Date(d) => Node::Str(d.to_xml_format()),
            _ => Node::Null,
        }
    }

    /// An archived object: the `NS.*` layouts of the Foundation classes, or a plain object
    /// whose instance variables are the keys not starting with `$`.
    fn object(&mut self, dict: &plist::Dictionary, depth: usize) -> Node {
        if let Some(Value::Array(objects)) = dict.get("NS.objects") {
            let items: Vec<Node> = objects.iter().map(|v| self.resolve(v, depth)).collect();
            return match dict.get("NS.keys") {
                Some(Value::Array(keys)) => {
                    let keys: Vec<Node> = keys.iter().map(|k| self.resolve(k, depth)).collect();
                    Node::Map(keys.into_iter().zip(items).map(|(k, v)| (key_text(k), v)).collect())
                }
                _ => Node::List(items),
            };
        }
        for key in ["NS.string", "NS.time"] {
            if let Some(v) = dict.get(key) {
                return self.resolve(v, depth);
            }
        }
        if let Some(Value::Data(bytes)) = dict.get("NS.uuidbytes") {
            return uuid(bytes).map_or(Node::Null, Node::Str);
        }
        if let Some(relative) = dict.get("NS.relative") {
            let relative = self.resolve(relative, depth);
            let base = dict.get("NS.base").map(|b| self.resolve(b, depth));
            return match (base, relative) {
                (Some(Node::Str(base)), Node::Str(rel)) if !rel.contains(':') => Node::Str(base + &rel),
                (_, relative) => relative,
            };
        }
        let mut entries = Vec::new();
        for (key, value) in dict.iter().filter(|(k, _)| !k.starts_with('$')) {
            entries.push((key.clone(), self.resolve(value, depth)));
        }
        Node::Map(entries)
    }
}

fn key_text(key: Node) -> String {
    match key {
        Node::Str(s) => s,
        Node::Int(n) => n.to_string(),
        other => format!("{other:?}"),
    }
}

fn uuid(bytes: &[u8]) -> Option<String> {
    let b: &[u8; 16] = bytes.try_into().ok()?;
    let hex = |range: std::ops::Range<usize>| -> String { b[range].iter().map(|x| format!("{x:02X}")).collect() };
    Some(format!("{}-{}-{}-{}-{}", hex(0..4), hex(4..6), hex(6..8), hex(8..10), hex(10..16)))
}

/// Names of the set bits, then any unknown remainder in hex.
fn flag_names(raw: i64, table: &[(i64, &str)]) -> Vec<String> {
    let mut names: Vec<String> = table.iter().filter(|(bit, _)| raw & bit != 0).map(|(_, n)| (*n).to_owned()).collect();
    let known = table.iter().fold(0, |acc, (bit, _)| acc | bit);
    if raw & !known != 0 {
        names.push(format!("{:#x}", raw & !known));
    }
    names
}

const TYPES: &[(i64, &str)] = &[
    (0x1, "user_item"),
    (0x2, "app"),
    (0x4, "login_item"),
    (0x8, "agent"),
    (0x10, "daemon"),
    (0x20, "developer"),
    (0x40, "spotlight"),
    (0x80, "quicklook"),
    (0x800, "curated"),
    (0x10000, "legacy"),
];
const DISPOSITIONS: &[(i64, &str)] = &[(0x1, "enabled"), (0x2, "allowed"), (0x4, "hidden"), (0x8, "notified")];

#[derive(Serialize)]
struct Item<'a> {
    /// The user as the store keys it. `FFFFEEEE-DDDD-CCCC-BBBB-AAAA` plus the uid in hex is the
    /// reserved form for local uids.
    user_uuid: &'a str,
    uid: Option<u32>,
    /// Names of the set type bits joined with `|` (for example `agent|legacy`).
    item_type: String,
    item_type_raw: Option<i64>,
    name: Option<&'a str>,
    developer_name: Option<&'a str>,
    team_id: Option<&'a str>,
    identifier: Option<&'a str>,
    bundle_id: Option<&'a str>,
    url: Option<&'a str>,
    executable_path: Option<&'a str>,
    disposition: Vec<String>,
    disposition_raw: Option<i64>,
    generation: Option<i64>,
    parent_identifier: Option<&'a str>,
    arguments: Vec<String>,
    /// When the store last changed this item, and the executable's own modification time.
    modified_time: Option<Timestamp>,
    executable_modified_time: Option<Timestamp>,
}

impl Record for Item<'_> {}

fn local_uid(user: &str) -> Option<u32> {
    let hex = user.strip_prefix("FFFFEEEE-DDDD-CCCC-BBBB-AAAA").filter(|h| h.len() == 8)?;
    u32::from_str_radix(hex, 16).ok()
}

fn parse_btm(input: &Input, sink: &mut Sink) -> Result<()> {
    let archive = parse(input.data)?;
    let Some(archive) = archive.as_dictionary().filter(|d| d.contains_key("$archiver")) else {
        return Err(Error::format("not an NSKeyedArchiver archive"));
    };
    let (Some(Value::Array(objects)), Some(Value::Dictionary(top))) = (archive.get("$objects"), archive.get("$top"))
    else {
        return Err(Error::format("archive has no $objects or $top"));
    };
    let mut resolver = Resolver { objects, work: MAX_WORK, exhausted: false, active: Vec::new() };
    let root = Node::Map(top.iter().map(|(k, v)| (k.clone(), resolver.resolve(v, 0))).collect());
    if resolver.exhausted {
        sink.warn("archive exceeds the work limit; the result may be incomplete");
    }
    let Some(Node::Map(users)) = root.find("itemsByUserIdentifier", MAX_DEPTH) else {
        return Err(Error::skipped("no itemsByUserIdentifier in the archive"));
    };
    let mut line = 0u64;
    for (user, items) in users {
        let Node::List(items) = items else { continue };
        for item in items {
            line += 1;
            let mut time = |key: &str| {
                let time = item.time(&[key]);
                if time.is_none() && matches!(item.get(&[key]), Some(Node::Real(_))) {
                    sink.warn(format!("item {line}: {key} is not a valid time; left empty"));
                }
                time
            };
            let (modified_time, executable_modified_time) =
                (time("modificationDate"), time("executableModificationDate"));
            let kind = item.int(&["type"]);
            let disposition = item.int(&["disposition"]);
            sink.emit(
                Loc::Line(line),
                &Item {
                    user_uuid: user,
                    uid: local_uid(user),
                    item_type: kind.map(|k| flag_names(k, TYPES).join("|")).unwrap_or_default(),
                    item_type_raw: kind,
                    name: item.str(&["name"]),
                    developer_name: item.str(&["developerName"]),
                    team_id: item.str(&["teamIdentifier", "teamID"]),
                    identifier: item.str(&["identifier"]),
                    bundle_id: item.str(&["bundleIdentifier"]),
                    url: item.str(&["url", "URL"]),
                    executable_path: item.str(&["executablePath", "executable"]),
                    disposition: disposition.map(|d| flag_names(d, DISPOSITIONS)).unwrap_or_default(),
                    disposition_raw: disposition,
                    generation: item.int(&["generation"]),
                    parent_identifier: item.str(&["container", "parentIdentifier"]),
                    arguments: item.strings(&["programArguments", "arguments"]),
                    modified_time,
                    executable_modified_time,
                },
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::macos::plist_util::tests::survives_damage;
    use crate::testing::{fixture, run};
    use plist::{Dictionary, Uid};

    const PATH: &str = "private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v16.btm";

    /// The fixture was written by a script with the layout documented at the top of this file
    /// (no data from a real machine).
    #[test]
    fn parses_synthetic_store() {
        insta::assert_snapshot!(run(&ARTIFACT, PATH, &fixture("btm/BackgroundItems-v16.btm"), 0));
    }

    #[test]
    fn damaged_store_does_not_panic() {
        survives_damage(&ARTIFACT, PATH, &fixture("btm/BackgroundItems-v16.btm"));
    }

    #[test]
    fn rejects_other_plists_and_empty_files() {
        assert!(run(&ARTIFACT, PATH, b"<plist version=\"1.0\"><dict/></plist>", 0)
            .contains("failed: not an NSKeyedArchiver"));
        assert!(run(&ARTIFACT, PATH, b"garbage", 0).contains("failed: not a property list"));
        assert!(run(&ARTIFACT, PATH, b"", 0).contains("skipped: empty file"));
    }

    fn archive(objects: Vec<Value>) -> Vec<u8> {
        let mut top = Dictionary::new();
        top.insert("store".into(), Value::Uid(Uid::new(1)));
        let mut doc = Dictionary::new();
        doc.insert("$archiver".into(), "NSKeyedArchiver".into());
        doc.insert("$top".into(), Value::Dictionary(top));
        doc.insert("$objects".into(), Value::Array(objects));
        let mut out = Vec::new();
        plist::to_writer_binary(&mut out, &Value::Dictionary(doc)).unwrap();
        out
    }

    fn uid(n: u64) -> Value {
        Value::Uid(Uid::new(n))
    }

    fn object(pairs: Vec<(&str, Value)>) -> Value {
        Value::Dictionary(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
    }

    #[test]
    fn cycles_and_deep_chains_terminate() {
        // 1 refers to itself through its only key; 2 is a long chain of objects.
        let mut objects = vec![Value::String("$null".into()), object(vec![("self", uid(1)), ("chain", uid(2))])];
        for n in 2..2000 {
            objects.push(object(vec![("next", uid(n + 1))]));
        }
        let out = run(&ARTIFACT, PATH, &archive(objects), 0);
        assert!(out.contains("skipped: no itemsByUserIdentifier"), "{out}");
    }

    #[test]
    fn exhausting_the_work_budget_is_reported_even_with_work_left() {
        // objects: 0 $null, 1 a string that leaves the budget off a round number, then a bomb
        // chain (each object refers to the next twice), then a real store.
        let mut objects = vec![Value::String("$null".into()), Value::String("abc".into())];
        let bomb = objects.len() as u64;
        for n in 0..40u64 {
            objects.push(object(vec![("a", uid(bomb + n + 1)), ("b", uid(bomb + n + 1))]));
        }
        objects.push(Value::String("leaf".into()));
        let store = objects.len() as u64;
        objects.push(object(vec![("itemsByUserIdentifier", uid(store + 1))]));
        objects.push(object(vec![
            ("NS.keys", Value::Array(vec![uid(store + 2)])),
            ("NS.objects", Value::Array(vec![uid(store + 3)])),
        ]));
        objects.push(Value::String("FFFFEEEE-DDDD-CCCC-BBBB-AAAA000001F5".into()));
        objects.push(object(vec![("NS.objects", Value::Array(vec![uid(store + 4)]))]));
        objects.push(object(vec![("executablePath", uid(store + 5)), ("type", Value::Integer(8.into()))]));
        objects.push(Value::String("/Users/Shared/evil".into()));
        let mut top = Dictionary::new();
        top.insert("pad".into(), uid(1));
        top.insert("bomb".into(), uid(bomb));
        top.insert("store".into(), uid(store));
        let mut doc = Dictionary::new();
        doc.insert("$archiver".into(), "NSKeyedArchiver".into());
        doc.insert("$top".into(), Value::Dictionary(top));
        doc.insert("$objects".into(), Value::Array(objects));
        let mut data = Vec::new();
        plist::to_writer_binary(&mut data, &Value::Dictionary(doc)).unwrap();
        let out = run(&ARTIFACT, PATH, &data, 0);
        assert!(out.contains("work limit"), "{out}");
    }

    #[test]
    fn line_numbers_run_on_across_users() {
        let out = run(&ARTIFACT, PATH, &fixture("btm/BackgroundItems-v16.btm"), 0);
        let lines: Vec<&str> =
            out.lines().filter_map(|l| l.split("\"source_line\":").nth(1)?.split(',').next()).collect();
        assert_eq!(lines, ["1", "2", "3", "4"][..lines.len()], "{out}");
        assert!(lines.len() > 2);
    }

    #[test]
    fn shared_objects_cannot_blow_up() {
        // Each object references the next one twice: 2^n paths, but the work budget stops it.
        let mut objects = vec![Value::String("$null".into()), object(vec![("a", uid(2)), ("b", uid(2))])];
        for n in 2..60 {
            objects.push(object(vec![("a", uid(n + 1)), ("b", uid(n + 1))]));
        }
        let out = run(&ARTIFACT, PATH, &archive(objects), 0);
        assert!(out.contains("skipped"), "{out}");
    }
}
