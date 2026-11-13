//! UID and user-name lookups from the host's `etc/passwd`, for the binary logs that store
//! only a number (process accounting, faillog) or only a name (faillock files).

use nixcavate_source::Host;
use std::collections::HashMap;

/// `(name, uid)` of every account line, in file order.
fn accounts(host: &Host) -> Vec<(String, u32)> {
    let passwd = host.read_text("etc/passwd").unwrap_or_default();
    passwd
        .lines()
        .filter(|l| !l.starts_with('#'))
        .filter_map(|line| {
            let mut fields = line.split(':');
            Some((fields.next()?.to_string(), fields.nth(1)?.parse().ok()?))
        })
        .collect()
}

/// UID to the first account that has it, the one `getpwuid` would return.
pub(super) fn by_uid(host: &Host) -> HashMap<u32, String> {
    let mut map = HashMap::new();
    for (name, uid) in accounts(host) {
        map.entry(uid).or_insert(name);
    }
    map
}

/// User name to UID (the first entry wins, as for `getpwnam`).
pub(super) fn by_name(host: &Host) -> HashMap<String, u32> {
    let mut map = HashMap::new();
    for (name, uid) in accounts(host) {
        map.entry(name).or_insert(uid);
    }
    map
}
