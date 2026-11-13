//! Facts that one record cannot give and another can, read in a first pass over the parsed
//! records and added to the records they concern before the checks run:
//!
//! - systemd: which units are enabled (links in `*.wants/`, `*.requires/`), masked or aliased,
//!   which timer, socket or path unit starts which service (and what that service runs), and
//!   which users linger. A unit record gains a `joined` object with the result.
//! - the host's first regular account (uid 1000, the one a cloud image creates), for the
//!   `sudoers` rule that gives it passwordless sudo.
//!
//! Everything here comes from the evidence: link targets are text, never followed.

use serde_json::{json, Map, Value};
use std::collections::{HashMap, HashSet};

/// A unit in one scope: `system`, `user:<owner>` or `user:*` (every user), and the unit name.
type Key = (String, String);

/// Longest text kept per exec line or reason.
const KEPT: usize = 4096;

const EXEC_FIELDS: [&str; 5] = ["exec_start", "exec_start_pre", "exec_start_post", "exec_stop", "exec_reload"];

#[derive(Default)]
struct HostFacts {
    /// Whether any enablement record was read for the scope: only then is "not enabled" a claim.
    system_links: bool,
    user_links: bool,
    enabled: HashMap<Key, Vec<String>>,
    masked: HashSet<Key>,
    /// Alias name to the unit it names.
    aliases: HashMap<Key, String>,
    /// What each unit (and its drop-ins) runs, by exec field.
    execs: HashMap<Key, HashMap<&'static str, Vec<String>>>,
    /// Service to the timer, socket and path units that name it.
    started_by: HashMap<Key, Vec<Key>>,
    lingering: HashSet<String>,
    default_account: Option<String>,
}

#[derive(Default)]
pub struct Joins {
    hosts: HashMap<String, HostFacts>,
}

fn text<'a>(record: &'a Value, field: &str) -> &'a str {
    record.get(field).and_then(Value::as_str).unwrap_or("")
}

fn kept(s: &str) -> String {
    s.chars().take(KEPT).collect()
}

/// The scope of a unit file or link from its path, and whether it is a user scope.
fn scope_of(path: &str) -> String {
    let parts: Vec<&str> = path.split('/').collect();
    match parts.as_slice() {
        ["home", user, ..] if path.contains("systemd/user") => format!("user:{user}"),
        ["root", ..] if path.contains("systemd/user") => "user:root".into(),
        _ if path.contains("systemd/user") => "user:*".into(),
        _ => "system".into(),
    }
}

/// `foo@bar.service` also stands for its template `foo@.service`.
fn template(unit: &str) -> Option<String> {
    let (name, ext) = unit.rsplit_once('.')?;
    let (base, instance) = name.split_once('@')?;
    (!instance.is_empty()).then(|| format!("{base}@.{ext}"))
}

fn base_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn is_unit_name(name: &str) -> bool {
    [".service", ".timer", ".socket", ".path", ".target", ".mount"].iter().any(|s| name.ends_with(s))
}

/// The unit a timer, socket or path unit starts: `Unit=`/`Service=`, else the same name as a service.
fn activated(record: &Value) -> Option<String> {
    let unit = text(record, "unit");
    let (stem, kind) = unit.rsplit_once('.')?;
    let named = match kind {
        "timer" => text(record, "timer_unit"),
        "socket" | "path" => text(record, "activates"),
        _ => return None,
    };
    Some(if named.is_empty() { format!("{stem}.service") } else { named.split(" ; ").last().unwrap_or("").to_string() })
}

impl Joins {
    /// Reads one record of the first pass. Records of other artifacts are ignored.
    pub fn collect(&mut self, record: &Value) {
        let artifact = text(record, "artifact");
        if !["systemd-enablement", "systemd-units", "passwd"].contains(&artifact) {
            return;
        }
        let facts = self.hosts.entry(text(record, "host").to_string()).or_default();
        let path = text(record, "source_path");
        match artifact {
            "passwd" => {
                if record["uid"].as_u64() == Some(1000) && facts.default_account.is_none() {
                    facts.default_account = Some(text(record, "user").to_string());
                }
            }
            "systemd-enablement" => facts.collect_link(record),
            _ => {
                let scope = scope_of(path);
                let unit = text(record, "unit").to_string();
                if let Some(service) = activated(record) {
                    facts.started_by.entry((scope.clone(), service)).or_default().push((scope.clone(), unit.clone()));
                }
                let entry = facts.execs.entry((scope, unit)).or_default();
                for field in EXEC_FIELDS {
                    if let Some(value) = record.get(field).and_then(Value::as_str) {
                        entry.entry(field).or_default().push(kept(value));
                    }
                }
            }
        }
    }

    /// The record with a `joined` object added when there is something to say; `None` when the
    /// record is left as it is.
    pub fn annotate(&self, record: &Value) -> Option<Value> {
        let facts = self.hosts.get(text(record, "host"))?;
        match text(record, "artifact") {
            "systemd-units" => facts.annotate_unit(record),
            "sudoers" => facts.annotate_sudoers(record),
            _ => None,
        }
    }
}

impl HostFacts {
    fn collect_link(&mut self, record: &Value) {
        let scope = match (text(record, "scope"), text(record, "owner")) {
            ("user", "") => "user:*".to_string(),
            ("user", owner) => format!("user:{owner}"),
            _ => "system".to_string(),
        };
        let (kind, unit, target) = (text(record, "kind"), text(record, "unit"), text(record, "target"));
        if kind == "linger" {
            self.lingering.insert(text(record, "owner").to_string());
            return;
        }
        if scope.starts_with("user") {
            self.user_links = true;
        } else {
            self.system_links = true;
        }
        match kind {
            "wants" | "requires" | "upholds" => {
                let verb = match kind {
                    "wants" => "wanted",
                    "requires" => "required",
                    _ => "upheld",
                };
                let reason = format!("{verb} by {}", kept(text(record, "enabled_by")));
                let mut names = vec![unit.to_string()];
                // `ln -s /x/real.service wants/alias.service`: the file's own name is enabled too.
                if base_name(target) != unit && is_unit_name(base_name(target)) {
                    names.push(base_name(target).to_string());
                }
                for name in names {
                    if let Some(t) = template(&name) {
                        self.enabled.entry((scope.clone(), t)).or_default().push(reason.clone());
                    }
                    self.enabled.entry((scope.clone(), name)).or_default().push(reason.clone());
                }
            }
            "mask" => {
                self.masked.insert((scope, unit.to_string()));
            }
            _ => {
                if is_unit_name(base_name(target)) && base_name(target) != unit {
                    self.aliases.insert((scope, unit.to_string()), base_name(target).to_string());
                }
            }
        }
    }

    /// The scopes whose links also apply to a unit of `scope`.
    fn scopes(scope: &str) -> Vec<String> {
        if scope.starts_with("user:") && scope != "user:*" {
            vec![scope.to_string(), "user:*".into()]
        } else {
            vec![scope.to_string()]
        }
    }

    fn reasons(&self, scope: &str, unit: &str) -> Vec<String> {
        let mut names = vec![unit.to_string()];
        names.extend(template(unit));
        let mut out = Vec::new();
        for scope in Self::scopes(scope) {
            for name in &names {
                if let Some(found) = self.enabled.get(&(scope.clone(), name.clone())) {
                    out.extend(found.iter().cloned());
                }
            }
            // An alias that is enabled enables the unit it names.
            for ((alias_scope, alias), target) in &self.aliases {
                if *alias_scope == scope && names.contains(target) {
                    if let Some(found) = self.enabled.get(&(scope.clone(), alias.clone())) {
                        out.extend(found.iter().map(|r| format!("{r} (as {alias})")));
                    }
                }
            }
        }
        out.sort();
        out.dedup();
        out
    }

    fn annotate_unit(&self, record: &Value) -> Option<Value> {
        let (scope, unit) = (scope_of(text(record, "source_path")), text(record, "unit"));
        let mut joined = Map::new();
        let mut reasons = self.reasons(&scope, unit);
        let masked = Self::scopes(&scope).into_iter().any(|s| self.masked.contains(&(s, unit.to_string())));
        // A service its timer or socket starts is live when that unit is enabled.
        let mut started_by = Vec::new();
        for scopes in Self::scopes(&scope) {
            for key in [Some(unit.to_string()), template(unit)].into_iter().flatten() {
                for (activator_scope, activator) in self.started_by.get(&(scopes.clone(), key)).into_iter().flatten() {
                    let enabled = self.reasons(activator_scope, activator);
                    started_by.push(activator.clone());
                    if let Some(first) = enabled.first() {
                        reasons.push(format!("started by {activator}, {first}"));
                    }
                }
            }
        }
        started_by.sort();
        started_by.dedup();
        let links_known = if scope.starts_with("user") { self.user_links } else { self.system_links };
        let state = match (masked, reasons.is_empty(), links_known) {
            (true, _, _) => "masked",
            (false, false, _) => "enabled",
            (false, true, true) => "not-enabled",
            (false, true, false) => "unknown",
        };
        if state != "unknown" {
            joined.insert("enablement".into(), json!(state));
        }
        if !reasons.is_empty() {
            joined.insert("enabled_by".into(), json!(reasons));
        }
        if !started_by.is_empty() {
            joined.insert("started_by".into(), json!(started_by));
        }
        if let Some(owner) = scope.strip_prefix("user:").filter(|o| *o != "*" && self.lingering.contains(*o)) {
            joined.insert("owner_lingers".into(), json!(owner));
        }
        if let Some(service) = activated(record) {
            let mut starts = Map::new();
            starts.insert("unit".into(), json!(service));
            for scopes in Self::scopes(&scope) {
                for (field, values) in self.execs.get(&(scopes, service.clone())).into_iter().flatten() {
                    starts.insert((*field).into(), json!(values.join(" ; ")));
                }
            }
            joined.insert("starts".into(), Value::Object(starts));
        }
        if joined.is_empty() {
            return None;
        }
        let mut out = record.clone();
        out["joined"] = Value::Object(joined);
        Some(out)
    }

    /// `<user> ALL=(ALL) NOPASSWD: ALL` for the host's uid 1000 account, in `90-cloud-init-users`
    /// or `sudoers`, is what a cloud image ships; the record says so, and the check lowers its severity for exactly that shape.
    fn annotate_sudoers(&self, record: &Value) -> Option<Value> {
        // Only where cloud-init and the image builders put it: not any drop-in.
        if !["etc/sudoers.d/90-cloud-init-users", "etc/sudoers"].contains(&text(record, "source_path")) {
            return None;
        }
        let account = self.default_account.as_deref()?;
        let all = text(record, "commands").split(',').all(|c| c.trim() == "ALL");
        let shape = text(record, "kind") == "rule"
            && record["nopasswd"] == true
            && all
            && text(record, "who") == account
            && text(record, "hosts") == "ALL"
            && ["ALL", "ALL:ALL"].contains(&text(record, "run_as"));
        if !shape {
            return None;
        }
        let mut out = record.clone();
        out["joined"] = json!({ "default_account": account });
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link(path: &str, kind: &str, unit: &str, by: Option<&str>, target: &str) -> Value {
        let user = path.starts_with("home/");
        json!({"artifact": "systemd-enablement", "host": "h", "source_path": path, "kind": kind, "unit": unit,
               "enabled_by": by, "target": target, "scope": if user { "user" } else { "system" },
               "owner": if user { "alice" } else { "" }})
    }

    fn unit(path: &str, unit: &str, extra: Value) -> Value {
        let mut r = json!({"artifact": "systemd-units", "host": "h", "source_path": path, "unit": unit});
        for (k, v) in extra.as_object().into_iter().flatten() {
            r[k] = v.clone();
        }
        r
    }

    fn joined(joins: &Joins, record: &Value) -> Value {
        joins.annotate(record).map_or(Value::Null, |v| v["joined"].clone())
    }

    #[test]
    fn enabled_dormant_masked_and_unknown_are_told_apart() {
        let mut joins = Joins::default();
        joins.collect(&link(
            "etc/systemd/system/multi-user.target.wants/a.service",
            "wants",
            "a.service",
            Some("multi-user.target"),
            "/etc/systemd/system/a.service",
        ));
        joins.collect(&link("etc/systemd/system/b.service", "mask", "b.service", None, "/dev/null"));
        let on = unit("etc/systemd/system/a.service", "a.service", json!({}));
        let off = unit("etc/systemd/system/c.service", "c.service", json!({}));
        let masked = unit("usr/lib/systemd/system/b.service", "b.service", json!({}));
        assert_eq!(joined(&joins, &on)["enablement"], "enabled");
        assert_eq!(joined(&joins, &on)["enabled_by"][0], "wanted by multi-user.target");
        assert_eq!(joined(&joins, &off)["enablement"], "not-enabled");
        assert_eq!(joined(&joins, &masked)["enablement"], "masked");
        // No link was collected: no claim either way.
        assert_eq!(joined(&Joins::default(), &off), Value::Null);
    }

    #[test]
    fn user_units_are_joined_by_owner_and_templates_by_name() {
        let mut joins = Joins::default();
        joins.collect(&link(
            "home/alice/.config/systemd/user/default.target.wants/u.service",
            "wants",
            "u.service",
            Some("default.target"),
            "../u.service",
        ));
        joins.collect(&link(
            "etc/systemd/system/getty.target.wants/getty@tty1.service",
            "wants",
            "getty@tty1.service",
            Some("getty.target"),
            "/lib/systemd/system/getty@.service",
        ));
        let alice = unit("home/alice/.config/systemd/user/u.service", "u.service", json!({}));
        let mallory = unit("home/mallory/.config/systemd/user/u.service", "u.service", json!({}));
        let getty = unit("lib/systemd/system/getty@.service", "getty@.service", json!({}));
        assert_eq!(joined(&joins, &alice)["enablement"], "enabled");
        assert_eq!(joined(&joins, &mallory)["enablement"], "not-enabled");
        assert_eq!(joined(&joins, &getty)["enablement"], "enabled");
    }

    #[test]
    fn a_timer_is_joined_to_its_service_and_enables_it() {
        let mut joins = Joins::default();
        joins.collect(&link(
            "etc/systemd/system/timers.target.wants/t.timer",
            "wants",
            "t.timer",
            Some("timers.target"),
            "/etc/systemd/system/t.timer",
        ));
        let service = unit("etc/systemd/system/job.service", "job.service", json!({"exec_start": "/tmp/x"}));
        let timer = unit("etc/systemd/system/t.timer", "t.timer", json!({"timer_unit": "job.service"}));
        joins.collect(&service);
        joins.collect(&timer);
        let t = joined(&joins, &timer);
        assert_eq!(t["starts"]["unit"], "job.service");
        assert_eq!(t["starts"]["exec_start"], "/tmp/x");
        let s = joined(&joins, &service);
        assert_eq!(s["enablement"], "enabled");
        assert_eq!(s["started_by"][0], "t.timer");
        // Without `Unit=` a timer starts the service of its own name.
        let same = unit("etc/systemd/system/same.timer", "same.timer", json!({}));
        assert_eq!(joined(&joins, &same)["starts"]["unit"], "same.service");
    }

    #[test]
    fn linger_and_the_default_account_are_recorded() {
        let mut joins = Joins::default();
        joins.collect(&json!({"artifact": "systemd-enablement", "host": "h", "kind": "linger", "owner": "alice", "unit": "", "target": "", "scope": "system"}));
        joins.collect(&json!({"artifact": "passwd", "host": "h", "user": "rocky", "uid": 1000}));
        joins.collect(&link(
            "home/alice/.config/systemd/user/default.target.wants/u.service",
            "wants",
            "u.service",
            Some("default.target"),
            "x",
        ));
        let alice = unit("home/alice/.config/systemd/user/u.service", "u.service", json!({}));
        assert_eq!(joined(&joins, &alice)["owner_lingers"], "alice");
        let rule = |who: &str, run_as: &str| json!({"artifact": "sudoers", "host": "h", "source_path": "etc/sudoers.d/90-cloud-init-users", "kind": "rule", "who": who, "hosts": "ALL", "run_as": run_as, "nopasswd": true, "commands": "ALL"});
        assert_eq!(joined(&joins, &rule("rocky", "ALL"))["default_account"], "rocky");
        assert_eq!(joined(&joins, &rule("alice", "ALL")), Value::Null);
        assert_eq!(joined(&joins, &rule("rocky", "root")), Value::Null);
        // Only the cloud-init drop-in and the main file: another drop-in is not what an image ships.
        let mut elsewhere = rule("rocky", "ALL");
        elsewhere["source_path"] = json!("etc/sudoers.d/90-nxm-alice");
        assert_eq!(joined(&joins, &elsewhere), Value::Null);
    }
}
