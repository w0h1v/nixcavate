//! The SMF repository: `etc/svc/repository.db` and its `repository-boot*` / `repository-
//! manifest_import*` backups. One record per service instance (and per service that has no
//! instance): whether it is enabled, what its start, stop and refresh methods run, its
//! dependencies and the manifest it was imported from.
//!
//! The file is SQLite 2.1 (see [`super::sqlite2`]). Tables are `service_tbl`, `instance_tbl`,
//! `pg_tbl` (property groups), `prop_lnk_tbl` (properties, by property group and generation),
//! `value_tbl` (values, text) and the snapshot tables. An instance's effective properties are
//! the ones in its `running` snapshot, instance level before service level, as `svcprop` shows
//! them; without that snapshot, its current property groups, instance before service.
//!
//! Verified on illumos (OmniOS r151054 and r151060): the number of services, instances and
//! properties equals the repository's own `sqlite` shell's, and the start methods and enabled
//! flags equal `svcprop`. The repository does not store an import time, and the run-time state
//! (`online`, `maintenance`) lives in the non-persistent repository under `etc/svc/volatile`,
//! which is not on disk: neither is a field here. Oracle Solaris 10 and 11 repositories were not
//! available; their schema is the one documented for SMF and is read the same way.

use super::sqlite2::Db;
use crate::{Artifact, Category, Input, SOLARIS};
use nixcavate_core::{Error, Loc, Record, Result, Sink};
use serde::Serialize;
use std::collections::HashMap;

pub const ARTIFACT: Artifact = Artifact::new(
    "smf-repository",
    "SMF services: enabled state, methods, dependencies, manifest (repository.db and backups)",
    Category::Persistence,
    SOLARIS,
    &["etc/svc/repository.db", "etc/svc/repository-*"],
    parse,
);

#[derive(Serialize)]
struct Service<'a> {
    fmri: String,
    service: &'a str,
    instance: &'a str,
    /// Whether the instance is enabled, as `svcs -l` shows it: `general_ovr/enabled` when a temporary
    /// change is in place, else `general/enabled`, both read from the current property groups (the
    /// `running` snapshot, which `svcprop` shows, keeps the value from the last refresh). `None` when
    /// the instance has neither.
    enabled: Option<bool>,
    /// `general_ovr/enabled`: a temporary change made with `svcadm enable -t` or `disable -t`.
    enabled_temporary: Option<bool>,
    restarter: Option<String>,
    manifest_files: Vec<String>,
    /// The `start` method; for an inetd service (no `start` method) the `inetd_start` command inetd runs per connection.
    start_exec: Option<String>,
    stop_exec: Option<String>,
    refresh_exec: Option<String>,
    /// Every other method, as `name: command`.
    other_methods: Vec<String>,
    /// For an inetd service: `name protocol` from the `inetd` property group (`nxmkecho tcp`).
    inetd: Option<String>,
    /// The user the methods run as (`method_context/user`), when set.
    method_user: Option<String>,
    /// `transient`, `child` or `contract`, when set.
    duration: Option<String>,
    /// One entry per dependency: `name (grouping): fmri ...`.
    dependencies: Vec<String>,
    /// Names of the instance's snapshots (`initial`, `last-import`, `running`...).
    snapshots: Vec<String>,
}

impl Record for Service<'_> {}

type Props = HashMap<String, Vec<String>>;

/// A property group and its properties, each with its values in order.
struct Group {
    kind: String,
    props: Props,
}

/// All the data of one repository, indexed for lookup.
struct Repo {
    /// (pg id, generation) -> property name -> values.
    props: HashMap<(i64, i64), Props>,
    /// parent (service or instance id) -> pgs as (id, name, type, generation).
    live: HashMap<i64, Vec<(i64, String, String, i64)>>,
    /// instance id -> snapshot name -> snapshot id.
    snapshots: HashMap<i64, Vec<(String, i64)>>,
    /// snapshot id -> snapshot levels as (level number, level id).
    levels: HashMap<i64, Vec<(i64, i64)>>,
    /// level id -> pgs as (id, name, type, generation).
    level_pgs: HashMap<i64, Vec<(i64, String, String, i64)>>,
}

fn int(field: &Option<String>) -> Option<i64> {
    field.as_deref()?.parse().ok()
}

fn text(field: &Option<String>) -> &str {
    field.as_deref().unwrap_or_default()
}

type Services = Vec<(i64, String)>;
/// (instance id, service id, instance name)
type Instances = Vec<(i64, i64, String)>;
/// What to do with each row of a table: its row id and fields.
type RowFn<'a> = Box<dyn FnMut(i64, &[Option<String>]) + 'a>;

fn load(db: &Db) -> std::result::Result<(Services, Instances, Repo), String> {
    let tables = db.tables()?;
    let root = |name: &str| tables.iter().find(|(n, _, _)| n == name).map(|(_, r, _)| *r);
    let need = |name: &str| root(name).ok_or_else(|| format!("table {name} is missing"));
    let mut warn: Option<String> = None;
    let mut scan = |name: &str, mut f: RowFn<'_>| -> std::result::Result<(), String> {
        let root = need(name)?;
        if let Err(e) = db.scan(root, |row| {
            f(row.id, &row.fields);
            true
        }) {
            warn = Some(format!("{name}: {e}"));
        }
        Ok(())
    };
    let mut services = Vec::new();
    scan("service_tbl", Box::new(|id, f| services.push((id, text(f.get(1).unwrap_or(&None)).to_string()))))?;
    let mut instances = Vec::new();
    scan(
        "instance_tbl",
        Box::new(|id, f| {
            if let (Some(name), Some(svc)) = (f.get(1), f.get(2).and_then(int)) {
                instances.push((id, svc, text(name).to_string()));
            }
        }),
    )?;
    let mut repo = Repo {
        props: HashMap::new(),
        live: HashMap::new(),
        snapshots: HashMap::new(),
        levels: HashMap::new(),
        level_pgs: HashMap::new(),
    };
    scan(
        "pg_tbl",
        Box::new(|id, f| {
            if let (Some(parent), Some(gen)) = (f.get(1).and_then(int), f.get(5).and_then(int)) {
                repo.live.entry(parent).or_default().push((id, text(&f[2]).to_string(), text(&f[3]).to_string(), gen));
            }
        }),
    )?;
    let mut values: HashMap<i64, Vec<(i64, String)>> = HashMap::new();
    scan(
        "value_tbl",
        Box::new(|_, f| {
            if let (Some(id), Some(value)) = (f.first().and_then(int), f.get(2)) {
                let order = f.get(3).and_then(int).unwrap_or(0);
                values.entry(id).or_default().push((order, text(value).to_string()));
            }
        }),
    )?;
    scan(
        "prop_lnk_tbl",
        Box::new(|_, f| {
            if let (Some(pg), Some(gen), Some(name)) = (f.get(1).and_then(int), f.get(2).and_then(int), f.get(3)) {
                let mut found = f.get(5).and_then(int).and_then(|v| values.get(&v)).cloned().unwrap_or_default();
                found.sort_by_key(|(order, _)| *order);
                let list = found.into_iter().map(|(_, v)| v).collect();
                repo.props.entry((pg, gen)).or_default().insert(text(name).to_string(), list);
            }
        }),
    )?;
    scan(
        "snapshot_lnk_tbl",
        Box::new(|_, f| {
            if let (Some(inst), Some(name), Some(snap)) = (f.get(1).and_then(int), f.get(2), f.get(3).and_then(int)) {
                repo.snapshots.entry(inst).or_default().push((text(name).to_string(), snap));
            }
        }),
    )?;
    scan(
        "snaplevel_tbl",
        Box::new(|_, f| {
            if let (Some(snap), Some(num), Some(level)) =
                (f.first().and_then(int), f.get(1).and_then(int), f.get(2).and_then(int))
            {
                repo.levels.entry(snap).or_default().push((num, level));
            }
        }),
    )?;
    scan(
        "snaplevel_lnk_tbl",
        Box::new(|_, f| {
            if let (Some(level), Some(pg), Some(gen)) =
                (f.first().and_then(int), f.get(1).and_then(int), f.get(5).and_then(int))
            {
                repo.level_pgs.entry(level).or_default().push((
                    pg,
                    text(&f[2]).to_string(),
                    text(&f[3]).to_string(),
                    gen,
                ));
            }
        }),
    )?;
    match warn {
        Some(w) => Err(w),
        None => Ok((services, instances, repo)),
    }
}

impl Repo {
    fn group(&self, pg: &(i64, String, String, i64)) -> Group {
        Group { kind: pg.2.clone(), props: self.props.get(&(pg.0, pg.3)).cloned().unwrap_or_default() }
    }

    /// The current (not snapshotted) property groups of an instance.
    fn live_groups(&self, instance: i64) -> Vec<(String, Group)> {
        self.live.get(&instance).into_iter().flatten().map(|pg| (pg.1.clone(), self.group(pg))).collect()
    }

    /// The property groups in effect for an instance: its running snapshot's (instance level
    /// first), else the current ones of the instance, then of the service.
    fn groups(&self, service: i64, instance: Option<i64>) -> Vec<(String, Group)> {
        // SMF composes an instance's properties from its own groups and its service's, property by
        // property: a group name may occur twice, the instance's first, and `first` reads through both.
        let mut out: Vec<(String, Group)> = Vec::new();
        let mut add = |name: &str, group: Group| out.push((name.to_string(), group));
        let running = instance
            .and_then(|i| self.snapshots.get(&i))
            .and_then(|snaps| snaps.iter().find(|(name, _)| name == "running"))
            .and_then(|(_, snap)| self.levels.get(snap));
        if let Some(levels) = running {
            let mut levels = levels.clone();
            levels.sort();
            for (_, level) in levels {
                for pg in self.level_pgs.get(&level).into_iter().flatten() {
                    add(&pg.1, self.group(pg));
                }
            }
            return out;
        }
        for parent in instance.into_iter().chain([service]) {
            for pg in self.live.get(&parent).into_iter().flatten() {
                add(&pg.1, self.group(pg));
            }
        }
        out
    }
}

/// The first value of a property: in the instance's property group of that name, else the service's.
fn first<'a>(groups: &'a [(String, Group)], pg: &str, prop: &str) -> Option<&'a str> {
    groups.iter().filter(|(n, _)| n == pg).find_map(|(_, g)| g.props.get(prop)?.first().map(String::as_str))
}

fn flag(value: Option<&str>) -> Option<bool> {
    value.map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    let data = input.data;
    if data.is_empty() {
        return Err(Error::skipped("empty file"));
    }
    if data.starts_with(b"SQLite format 3\0") {
        return Err(Error::format(
            "an SQLite 3 database, not the SQLite 2.1 file of the SMF repositories this was checked on: not read",
        ));
    }
    let db = Db::open(data).map_err(|e| Error::format(format!("not an SMF repository: {e}")))?;
    let (services, instances, repo) = match load(&db) {
        Ok(loaded) => loaded,
        Err(e) => return Err(Error::format(format!("SMF repository is damaged or is not one: {e}"))),
    };
    let mut by_service: HashMap<i64, Vec<(i64, &str)>> = HashMap::new();
    for (id, svc, name) in &instances {
        by_service.entry(*svc).or_default().push((*id, name));
    }
    for (svc_id, name) in &services {
        let list = by_service.get(svc_id).cloned().unwrap_or_default();
        let targets: Vec<(Option<i64>, &str)> =
            if list.is_empty() { vec![(None, "")] } else { list.iter().map(|(id, n)| (Some(*id), *n)).collect() };
        for (instance, instance_name) in targets {
            let groups = repo.groups(*svc_id, instance);
            // `enabled` is read from the current property groups, not from the snapshot.
            let live = instance.map(|i| repo.live_groups(i)).unwrap_or_default();
            let live_ovr = first(&live, "general_ovr", "enabled");
            let live_enabled = live_ovr.or(first(&live, "general", "enabled"));
            let mut methods: Vec<(&str, &str)> = Vec::new();
            let mut dependencies = Vec::new();
            let mut seen: Vec<(&str, &str)> = Vec::new();
            for (pg, group) in &groups {
                // The instance's group of a name hides the service's of the same name.
                if seen.contains(&(pg.as_str(), group.kind.as_str())) {
                    continue;
                }
                seen.push((pg, &group.kind));
                match group.kind.as_str() {
                    "method" => {
                        if let Some(exec) = group.props.get("exec").and_then(|v| v.first()) {
                            methods.push((pg, exec));
                        }
                    }
                    "dependency" => {
                        let grouping = group.props.get("grouping").and_then(|v| v.first()).map_or("", String::as_str);
                        let entities = group.props.get("entities").map(|v| v.join(" ")).unwrap_or_default();
                        dependencies.push(format!("{pg} ({grouping}): {entities}"));
                    }
                    _ => {}
                }
            }
            let method = |wanted: &str| methods.iter().find(|(n, _)| *n == wanted).map(|(_, e)| (*e).to_string());
            let start = method("start").or_else(|| method("inetd_start"));
            let used_for_start = if method("start").is_some() { "start" } else { "inetd_start" };
            let manifests = groups
                .iter()
                .find(|(n, _)| n == "manifestfiles")
                .map(|(_, g)| {
                    let mut files: Vec<(&String, &Vec<String>)> = g.props.iter().collect();
                    files.sort();
                    files.into_iter().filter_map(|(_, v)| v.first().cloned()).collect()
                })
                .unwrap_or_default();
            let snapshots = instance
                .and_then(|i| repo.snapshots.get(&i))
                .map(|s| s.iter().map(|(n, _)| n.clone()).collect())
                .unwrap_or_default();
            let fmri =
                if instance_name.is_empty() { format!("svc:/{name}") } else { format!("svc:/{name}:{instance_name}") };
            sink.emit(
                Loc::Offset(*svc_id as u64),
                &Service {
                    fmri,
                    service: name,
                    instance: instance_name,
                    enabled: flag(live_enabled.or(first(&groups, "general", "enabled"))),
                    enabled_temporary: flag(live_ovr),
                    restarter: first(&groups, "general", "restarter").map(str::to_string),
                    inetd: first(&groups, "inetd", "name")
                        .map(|name| format!("{name} {}", first(&groups, "inetd", "proto").unwrap_or_default())),
                    manifest_files: manifests,
                    start_exec: start,
                    stop_exec: method("stop"),
                    refresh_exec: method("refresh"),
                    other_methods: methods
                        .iter()
                        .filter(|(n, _)| !["stop", "refresh", used_for_start].contains(n))
                        .map(|(n, e)| format!("{n}: {e}"))
                        .collect(),
                    method_user: first(&groups, "method_context", "user").map(str::to_string),
                    duration: first(&groups, "startd", "duration").map(str::to_string),
                    dependencies,
                    snapshots,
                },
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    /// The repository was made by `svccfg import` of the two manifests in `test_files/smf-manifests`; `svcprop` of the
    /// same services printed these methods, `general/enabled` (`svcs -l`: enabled) and `manifestfiles`.
    #[test]
    fn a_real_repository() {
        let out = run(&ARTIFACT, "etc/svc/repository.db", &fixture("smf-repository/repository.db"), 0);
        insta::assert_snapshot!(out);
        assert!(
            out.contains(
                r#""fmri":"svc:/site/nxmk-smf:default","service":"site/nxmk-smf","instance":"default","enabled":false"#
            ),
            "{out}"
        );
        assert!(out.contains(r#""fmri":"svc:/site/nxmk-smf-lib:default""#), "{out}");
        for want in [
            r#""start_exec":"/var/svc/method/nxmk-smf %m","stop_exec":":true""#,
            r#""start_exec":"/tmp/.NXMK_SMFLIB/agent --quiet","stop_exec":":kill""#,
            r#""manifest_files":["/var/svc/manifest/site/nxmk-smf.xml"]"#,
            r#""duration":"transient""#,
            r#""dependencies":["fs (require_all): svc:/system/filesystem/local"]"#,
            r#""snapshots":["last-import","running","initial"]"#,
        ] {
            assert!(out.contains(want), "{want}\n{out}");
        }
        // `svccfg import` leaves the instances as the manifest says: the first is disabled, the second enabled.
        assert!(
            out.contains(r#""instance":"default","enabled":true"#)
                || out.contains(r#""enabled":true,"enabled_temporary""#),
            "{out}"
        );
    }

    #[test]
    fn other_files_are_refused_with_a_reason() {
        assert!(run(&ARTIFACT, "etc/svc/repository.db", b"", 0).contains("skipped"));
        assert!(run(&ARTIFACT, "etc/svc/repository.db", b"SQLite format 3\0........", 0).contains("SQLite 3 database"));
        assert!(run(&ARTIFACT, "etc/svc/repository.db", b"not a database at all", 0).contains("not an SMF repository"));
        // A repository cut inside its tables is damaged, not empty.
        let data = fixture("smf-repository/repository.db");
        let out = run(&ARTIFACT, "etc/svc/repository.db", &data[..6 * 1024], 0);
        assert!(out.contains("failed") || out.contains("outside the file"), "{out}");
    }

    #[test]
    fn mutated_files_never_panic() {
        super::super::never_panics(&ARTIFACT, "etc/svc/repository.db", &fixture("smf-repository/repository.db"));
    }
}
