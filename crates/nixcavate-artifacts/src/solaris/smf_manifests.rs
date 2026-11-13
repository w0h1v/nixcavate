//! SMF service manifests that were added to the system: `var/svc/manifest/site/*.xml` and
//! `lib/svc/manifest/site/*.xml` (the places for local services; packages install theirs
//! elsewhere under `lib/svc/manifest`, and those are not read). A manifest is imported into the
//! repository at boot (`svc:/system/manifest-import`) or with `svccfg import`; reading the file
//! shows what the service would run even when the repository was not collected.
//!
//! One record per `<service>`: its instances and whether each is enabled, its start, stop and
//! refresh methods, the user a method runs as, its dependencies and `startd/duration`. The XML is
//! read with the small tokenizer in [`super::xml`]; it does not validate against the DTD.
//!
//! Verified on illumos (OmniOS): the harness's two manifests and the one `inetconv` generated,
//! against `svccfg export` and `svcprop` of the imported services (methods and enabled flags equal).

use super::xml::{tokens, Token};
use crate::text::lossy;
use crate::{Artifact, Category, Input, SOLARIS};
use nixcavate_core::{Basis, Error, Loc, Record, Result, Sink, Timestamp};
use serde::Serialize;

pub const ARTIFACT: Artifact = Artifact::new(
    "smf-manifests",
    "Locally added SMF service manifests (site directories)",
    Category::Persistence,
    SOLARIS,
    &[
        "var/svc/manifest/site/*.xml",
        "var/svc/manifest/site/**/*.xml",
        "lib/svc/manifest/site/*.xml",
        "lib/svc/manifest/site/**/*.xml",
    ],
    parse,
);

#[derive(Serialize)]
struct Service {
    service: String,
    bundle: String,
    /// Instances as `name (enabled)` or `name (disabled)`; the default instance is `default`.
    instances: Vec<String>,
    start_exec: Option<String>,
    stop_exec: Option<String>,
    refresh_exec: Option<String>,
    other_methods: Vec<String>,
    /// `<credential user='...'>` of a `method_context`.
    method_user: Option<String>,
    duration: Option<String>,
    dependencies: Vec<String>,
    /// The file's modification time as the collection preserved it.
    modified: Option<Timestamp>,
}

impl Record for Service {}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    let text = lossy(input.data);
    let modified = (input.mtime > 0).then(|| Timestamp::from_secs(input.mtime, Basis::Recorded));
    let mut bundle = String::new();
    let mut current: Option<Service> = None;
    let mut dependency: Option<(String, String, Vec<String>)> = None;
    let mut depth = 0usize;
    let mut emitted = 0;
    let mut stream = tokens(&text);
    let mut seen_bundle = false;
    let finish = |service: Option<Service>, sink: &mut Sink| -> Result<()> {
        if let Some(service) = service {
            sink.emit(Loc::None, &service)?;
        }
        Ok(())
    };
    for token in &mut stream {
        match token {
            Token::Start { name, attrs, empty } => {
                depth += 1;
                if depth > 64 {
                    return Err(Error::format("manifest nests deeper than 64 elements"));
                }
                let attr = |key: &str| attrs.iter().find(|(k, _)| *k == key).map(|(_, v)| v.to_string());
                match name {
                    "service_bundle" => {
                        seen_bundle = true;
                        bundle = attr("name").unwrap_or_default();
                    }
                    "service" if emitted < 1000 => {
                        emitted += 1;
                        current = Some(Service {
                            service: attr("name").unwrap_or_default(),
                            bundle: bundle.clone(),
                            instances: Vec::new(),
                            start_exec: None,
                            stop_exec: None,
                            refresh_exec: None,
                            other_methods: Vec::new(),
                            method_user: None,
                            duration: None,
                            dependencies: Vec::new(),
                            modified,
                        });
                    }
                    "create_default_instance" | "instance" => {
                        if let Some(s) = current.as_mut() {
                            let instance =
                                if name == "instance" { attr("name").unwrap_or_default() } else { "default".into() };
                            let enabled = attr("enabled").is_some_and(|v| v == "true");
                            s.instances.push(format!("{instance} ({})", if enabled { "enabled" } else { "disabled" }));
                        }
                    }
                    "exec_method" => {
                        if let (Some(s), Some(kind), Some(exec)) = (current.as_mut(), attr("name"), attr("exec")) {
                            match kind.as_str() {
                                "start" => s.start_exec = Some(exec),
                                "stop" => s.stop_exec = Some(exec),
                                "refresh" => s.refresh_exec = Some(exec),
                                _ => s.other_methods.push(format!("{kind}: {exec}")),
                            }
                        }
                    }
                    "method_credential" | "method_context" => {
                        // `<method_credential user='x'>` is the documented element; `<method_context>` holds it as a child.
                        if let (Some(s), Some(user)) = (current.as_mut(), attr("user")) {
                            s.method_user.get_or_insert(user);
                        }
                    }
                    "dependency" => {
                        dependency =
                            Some((attr("name").unwrap_or_default(), attr("grouping").unwrap_or_default(), Vec::new()))
                    }
                    "service_fmri" | "dependency_list" => {
                        if let (Some((_, _, fmris)), Some(value)) = (dependency.as_mut(), attr("value")) {
                            fmris.push(value);
                        }
                    }
                    "propval" => {
                        if let (Some(s), Some("duration"), Some(value)) =
                            (current.as_mut(), attr("name").as_deref(), attr("value"))
                        {
                            s.duration = Some(value);
                        }
                    }
                    _ => {}
                }
                if empty {
                    depth -= 1;
                    if name == "dependency" {
                        if let (Some(s), Some((n, g, f))) = (current.as_mut(), dependency.take()) {
                            s.dependencies.push(format!("{n} ({g}): {}", f.join(" ")));
                        }
                    }
                }
            }
            Token::End(name) => {
                depth = depth.saturating_sub(1);
                match name {
                    "dependency" => {
                        if let (Some(s), Some((n, g, f))) = (current.as_mut(), dependency.take()) {
                            s.dependencies.push(format!("{n} ({g}): {}", f.join(" ")));
                        }
                    }
                    "service" => finish(current.take(), sink)?,
                    _ => {}
                }
            }
            Token::Text(_) => {}
        }
    }
    finish(current.take(), sink)?;
    if !seen_bundle {
        return Err(Error::format("not an SMF manifest: no <service_bundle> element"));
    }
    if stream.failed() {
        sink.warn("the manifest is not well formed XML; what precedes the damage was read");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    #[test]
    fn real_manifests() {
        for (name, path) in [
            ("nxmk-smf.xml", "var/svc/manifest/site/nxmk-smf.xml"),
            ("nxmk-smf-lib.xml", "lib/svc/manifest/site/nxmk-smf-lib.xml"),
            ("nxmkecho-tcp.xml", "var/svc/manifest/site/nxmkecho-tcp.xml"),
        ] {
            insta::assert_snapshot!(
                name,
                run(&ARTIFACT, path, &fixture(&format!("smf-manifests/{name}")), 1_794_532_000)
            );
        }
    }

    /// `svcprop` of the imported services printed `start/exec`, `stop/exec` and `startd/duration` as read here.
    #[test]
    fn methods_instances_and_dependencies_equal_what_svcprop_printed() {
        let out = run(&ARTIFACT, "var/svc/manifest/site/nxmk-smf.xml", &fixture("smf-manifests/nxmk-smf.xml"), 0);
        for want in [
            r#""service":"site/nxmk-smf","bundle":"nxmk-smf","instances":["default (disabled)"]"#,
            r#""start_exec":"/var/svc/method/nxmk-smf %m","stop_exec":":true""#,
            r#""duration":"transient","dependencies":["fs (require_all): svc:/system/filesystem/local"]"#,
        ] {
            assert!(out.contains(want), "{want}\n{out}");
        }
        let lib =
            run(&ARTIFACT, "lib/svc/manifest/site/nxmk-smf-lib.xml", &fixture("smf-manifests/nxmk-smf-lib.xml"), 0);
        assert!(
            lib.contains(r#""instances":["default (enabled)"]"#)
                && lib.contains(r#""start_exec":"/tmp/.NXMK_SMFLIB/agent --quiet""#),
            "{lib}"
        );
        let inetd =
            run(&ARTIFACT, "var/svc/manifest/site/nxmkecho-tcp.xml", &fixture("smf-manifests/nxmkecho-tcp.xml"), 0);
        assert!(inetd.contains("network/nxmkecho/tcp") || inetd.contains("nxmkecho"), "{inetd}");
    }

    #[test]
    fn not_a_manifest_and_damaged_ones() {
        assert!(run(&ARTIFACT, "var/svc/manifest/site/x.xml", b"<html/>", 0).contains("not an SMF manifest"));
        let data = fixture("smf-manifests/nxmk-smf.xml");
        assert!(run(&ARTIFACT, "var/svc/manifest/site/x.xml", &data[..data.len() / 2], 0).contains("not well formed"));
        let deep = "<service_bundle>".to_string() + &"<a>".repeat(100);
        assert!(run(&ARTIFACT, "var/svc/manifest/site/x.xml", deep.as_bytes(), 0).contains("nests deeper"));
    }

    #[test]
    fn mutated_files_never_panic() {
        super::super::never_panics(&ARTIFACT, "var/svc/manifest/site/x.xml", &fixture("smf-manifests/nxmk-smf.xml"));
        super::super::never_panics(
            &ARTIFACT,
            "var/svc/manifest/site/x.xml",
            &fixture("smf-manifests/nxmkecho-tcp.xml"),
        );
    }
}
