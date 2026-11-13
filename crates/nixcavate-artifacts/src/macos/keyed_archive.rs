//! Reads an `NSKeyedArchiver` property list (`$archiver`, `$top`, `$objects`) into plain
//! plist values. Format: Apple's `NSKeyedArchiver` archives as stored by Foundation (documented
//! by the open `Foundation` and CoreFoundation sources and `plutil -p` output): objects live in
//! the `$objects` array and refer to each other by UID; a class object names the class in
//! `$classname`.
//!
//! Hostile input: references can form cycles or share objects so that the expanded tree is
//! exponentially larger than the file. Depth and the total number of objects expanded are
//! capped, and what is beyond the cap is dropped rather than followed.

use plist::{Dictionary, Value};

const MAX_DEPTH: usize = 24;
const MAX_NODES: usize = 50_000;

struct Reader<'a> {
    objects: &'a [Value],
    nodes: usize,
}

/// The root object of the archive as plain values, or `None` when `plist` is not a keyed
/// archive. Dictionaries (`NSDictionary`), arrays and sets, strings, data, URLs and dates
/// become the matching plist values; any other class becomes a dictionary of its fields with
/// the class name under `$classname`.
pub fn unarchive(plist: &Value) -> Option<Value> {
    let top = plist.as_dictionary()?;
    if top.get("$archiver").and_then(Value::as_string)? != "NSKeyedArchiver" {
        return None;
    }
    let objects = top.get("$objects")?.as_array()?;
    let root = top.get("$top")?.as_dictionary()?.get("root")?;
    let mut reader = Reader { objects, nodes: 0 };
    reader.resolve(root, 0)
}

impl Reader<'_> {
    fn resolve(&mut self, value: &Value, depth: usize) -> Option<Value> {
        self.nodes += 1;
        if depth > MAX_DEPTH || self.nodes > MAX_NODES {
            return None;
        }
        match value {
            Value::Uid(uid) => {
                let object = self.objects.get(usize::try_from(uid.get()).ok()?)?;
                if object.as_string() == Some("$null") {
                    return None;
                }
                self.resolve(object, depth + 1)
            }
            Value::Dictionary(dict) => self.object(dict, depth),
            Value::Array(items) => {
                Some(Value::Array(items.iter().filter_map(|v| self.resolve(v, depth + 1)).collect()))
            }
            other => Some(other.clone()),
        }
    }

    fn class_name(&self, dict: &Dictionary) -> Option<String> {
        let Value::Uid(uid) = dict.get("$class")? else { return None };
        let class = self.objects.get(usize::try_from(uid.get()).ok()?)?.as_dictionary()?;
        class.get("$classname")?.as_string().map(str::to_owned)
    }

    fn list(&mut self, dict: &Dictionary, key: &str, depth: usize) -> Vec<Value> {
        match dict.get(key) {
            Some(Value::Array(items)) => items.iter().filter_map(|v| self.resolve(v, depth + 1)).collect(),
            _ => Vec::new(),
        }
    }

    fn object(&mut self, dict: &Dictionary, depth: usize) -> Option<Value> {
        let Some(class) = self.class_name(dict) else {
            // Not an object reference: a class description or a plain dictionary.
            let mut out = Dictionary::new();
            for (k, v) in dict.iter() {
                if let Some(v) = self.resolve(v, depth + 1) {
                    out.insert(k.clone(), v);
                }
            }
            return Some(Value::Dictionary(out));
        };
        match class.as_str() {
            "NSDictionary" | "NSMutableDictionary" => {
                let keys = self.list(dict, "NS.keys", depth);
                let values = match dict.get("NS.objects") {
                    Some(Value::Array(items)) => items.iter().map(|v| self.resolve(v, depth + 1)).collect(),
                    _ => Vec::new(),
                };
                let mut out = Dictionary::new();
                for (key, value) in keys.into_iter().zip(values) {
                    if let (Value::String(key), Some(value)) = (key, value) {
                        out.insert(key, value);
                    }
                }
                Some(Value::Dictionary(out))
            }
            "NSArray" | "NSMutableArray" | "NSSet" | "NSMutableSet" | "NSOrderedSet" => {
                Some(Value::Array(self.list(dict, "NS.objects", depth)))
            }
            "NSString" | "NSMutableString" => {
                self.resolve(dict.get("NS.string")?, depth + 1).filter(|v| v.as_string().is_some())
            }
            "NSData" | "NSMutableData" => {
                self.resolve(dict.get("NS.data")?, depth + 1).filter(|v| matches!(v, Value::Data(_)))
            }
            "NSURL" => {
                let relative = self.resolve(dict.get("NS.relative")?, depth + 1)?;
                let relative = relative.as_string()?;
                let base = dict.get("NS.base").and_then(|b| self.resolve(b, depth + 1));
                let url = match base.as_ref().and_then(Value::as_string) {
                    Some(base) if !relative.contains("://") => format!("{base}{relative}"),
                    _ => relative.to_string(),
                };
                Some(Value::String(url))
            }
            _ => {
                let mut out = Dictionary::new();
                out.insert("$classname".into(), Value::String(class));
                for (k, v) in dict.iter().filter(|(k, _)| *k != "$class") {
                    if let Some(v) = self.resolve(v, depth + 1) {
                        out.insert(k.clone(), v);
                    }
                }
                Some(Value::Dictionary(out))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::fixture;

    fn load(name: &str) -> Value {
        crate::macos::plist_util::parse(&fixture(&format!("sharedfilelist/{name}"))).unwrap()
    }

    #[test]
    fn dictionaries_arrays_strings_and_data_resolve() {
        let root = unarchive(&load("Example.sfl2")).unwrap();
        let items = root.as_dictionary().unwrap().get("items").unwrap().as_array().unwrap();
        assert_eq!(items.len(), 4);
        let first = items[0].as_dictionary().unwrap();
        assert_eq!(first.get("Name").unwrap().as_string(), Some("notes.txt"));
        assert_eq!(first.get("$classname").unwrap().as_string(), Some("SFLListItem"));
        assert!(matches!(first.get("Bookmark"), Some(Value::Data(_))));
    }

    #[test]
    fn a_self_referencing_object_terminates() {
        assert!(unarchive(&load("Cycle.plist")).is_some());
    }

    #[test]
    fn shared_references_cannot_expand_without_bound() {
        let started = std::time::Instant::now();
        let _ = unarchive(&load("Bomb.plist"));
        assert!(started.elapsed().as_secs() < 2);
    }

    #[test]
    fn plain_plists_are_not_archives() {
        let value = crate::macos::plist_util::parse(b"<plist version=\"1.0\"><dict/></plist>").unwrap();
        assert!(unarchive(&value).is_none());
    }
}
