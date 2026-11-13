//! Kubernetes manifests the node applies by itself, which makes them persistence:
//! the kubelet's static pods (`etc/kubernetes/manifests`, k3s `agent/pod-manifests`) start with
//! the kubelet and are restarted when deleted through the API, and k3s applies everything under
//! `server/manifests` to the cluster on start and whenever a file changes.
//!
//! One record per YAML or JSON document: the identity (`kind`, name, namespace), the facts that
//! matter for a node takeover (images, commands, host namespaces, `privileged`, `hostPath`
//! volumes) and the document text, cut at 16 KiB. Facts come from [`super::yaml_lite`], which
//! reads block YAML only: a document it cannot read is kept as text with `parsed` false and one
//! warning. Not seen: anchors and aliases, multi-line scalars outside block scalars, values
//! produced by Helm templates or `kustomize`, the contents of a `HelmChart`'s `valuesContent`.

use super::yaml_lite::{parse as parse_yaml, split_documents};
use crate::text::lossy;
use crate::{Artifact, Category, Input, LINUX};
use nixcavate_core::{Error, Loc, Record, Result, Sink};
use serde::Serialize;
use serde_json::Value;

pub const ARTIFACT: Artifact = Artifact::new(
    "k8s-manifests",
    "Kubernetes static pod and auto-applied manifests (kubelet, k3s)",
    Category::Persistence,
    LINUX,
    &[
        "etc/kubernetes/manifests/*",
        "var/lib/rancher/k3s/agent/pod-manifests/*",
        "var/lib/rancher/k3s/server/manifests/*",
        "var/lib/rancher/k3s/server/manifests/*/*",
    ],
    parse,
);

/// A file larger than this is read up to here; manifests are kilobytes.
const MAX_FILE: usize = 4 << 20;
const MAX_TEXT: usize = 16 << 10;
const MAX_LIST: usize = 64;
const MAX_ITEM: usize = 2048;

#[derive(Serialize)]
struct Manifest {
    /// `static-pod` (kubelet manifests), `k3s-static-pod` or `k3s-auto-apply`.
    source_kind: &'static str,
    document: u32,
    api_version: String,
    kind: String,
    name: String,
    namespace: String,
    /// The `component` label kubeadm puts on its control-plane pods.
    component: String,
    images: Vec<String>,
    /// `<container>: <command and args>` for each container that sets either.
    commands: Vec<String>,
    host_network: bool,
    host_pid: bool,
    host_ipc: bool,
    privileged: bool,
    host_paths: Vec<String>,
    /// For a k3s `HelmChart`: the chart and its repository.
    chart: String,
    repo: String,
    parsed: bool,
    text: String,
    text_truncated: bool,
}

impl Record for Manifest {}

#[derive(Default)]
struct Facts {
    images: Vec<String>,
    commands: Vec<String>,
    host_network: bool,
    host_pid: bool,
    host_ipc: bool,
    privileged: bool,
    host_paths: Vec<String>,
}

fn text_of<'a>(v: &'a Value, path: &[&str]) -> &'a str {
    path.iter().try_fold(v, |v, k| v.get(k)).and_then(Value::as_str).unwrap_or_default()
}

fn cap(text: &str) -> String {
    let mut end = text.len().min(MAX_ITEM);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text.get(..end).unwrap_or_default().to_string()
}

fn words(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array).into_iter().flatten().filter_map(|w| w.as_str().map(str::to_owned)).collect()
}

fn push<T>(list: &mut Vec<T>, item: T) {
    if list.len() < MAX_LIST {
        list.push(item);
    }
}

/// Collects the node-takeover facts from anywhere in the document, so a pod, a Deployment's
/// template, a DaemonSet and a List of them are all covered the same way.
fn walk(v: &Value, facts: &mut Facts, depth: usize) {
    if depth > 64 {
        return;
    }
    match v {
        Value::Object(map) => {
            for (key, value) in map {
                let on = value == &Value::Bool(true);
                match key.as_str() {
                    "hostNetwork" => facts.host_network |= on,
                    "hostPID" => facts.host_pid |= on,
                    "hostIPC" => facts.host_ipc |= on,
                    "privileged" => facts.privileged |= on,
                    "hostPath" => {
                        // `hostPath: {path: /}`; the older short form is a bare string.
                        let path = value.get("path").unwrap_or(value).as_str();
                        if let Some(path) = path {
                            push(&mut facts.host_paths, cap(path));
                        }
                    }
                    "containers" | "initContainers" | "ephemeralContainers" => {
                        for container in value.as_array().into_iter().flatten() {
                            if let Some(image) = container.get("image").and_then(Value::as_str) {
                                push(&mut facts.images, cap(image));
                            }
                            let mut command = words(container.get("command"));
                            command.extend(words(container.get("args")));
                            if !command.is_empty() {
                                let name = text_of(container, &["name"]);
                                push(&mut facts.commands, cap(&format!("{name}: {}", command.join(" "))));
                            }
                        }
                    }
                    _ => {}
                }
                walk(value, facts, depth + 1);
            }
        }
        Value::Array(items) => items.iter().for_each(|i| walk(i, facts, depth + 1)),
        _ => {}
    }
}

fn source_kind(path: &str) -> &'static str {
    if path.contains("/server/manifests/") {
        "k3s-auto-apply"
    } else if path.contains("/agent/pod-manifests/") {
        "k3s-static-pod"
    } else {
        "static-pod"
    }
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    let data = input.data.get(..input.data.len().min(MAX_FILE)).unwrap_or_default();
    if data.iter().all(u8::is_ascii_whitespace) {
        return Err(Error::skipped("empty file"));
    }
    if data.len() < input.data.len() {
        sink.warn(format!("the file is larger than {} MiB: only the first part was read", MAX_FILE >> 20));
    }
    let text = lossy(data);
    let source_kind = source_kind(input.path);
    let json = text.trim_start().starts_with('{');
    let documents: Vec<(usize, &str)> = if json { vec![(0, text.as_ref())] } else { split_documents(&text) };
    for (index, (first_line, doc)) in documents.iter().enumerate() {
        let value = if json { serde_json::from_str::<Value>(doc).map_err(|e| e.to_string()) } else { parse_yaml(doc) };
        let (value, parsed) = match value {
            Ok(value) => (value, true),
            Err(e) => {
                sink.warn(format!("document {} (line {}): not read ({e}); kept as text", index + 1, first_line + 1));
                (Value::Null, false)
            }
        };
        let mut facts = Facts::default();
        walk(&value, &mut facts, 0);
        let mut end = doc.len().min(MAX_TEXT);
        while !doc.is_char_boundary(end) {
            end -= 1;
        }
        let record = Manifest {
            source_kind,
            document: index as u32 + 1,
            api_version: text_of(&value, &["apiVersion"]).into(),
            kind: text_of(&value, &["kind"]).into(),
            name: text_of(&value, &["metadata", "name"]).into(),
            namespace: text_of(&value, &["metadata", "namespace"]).into(),
            component: text_of(&value, &["metadata", "labels", "component"]).into(),
            images: facts.images,
            commands: facts.commands,
            host_network: facts.host_network,
            host_pid: facts.host_pid,
            host_ipc: facts.host_ipc,
            privileged: facts.privileged,
            host_paths: facts.host_paths,
            chart: text_of(&value, &["spec", "chart"]).into(),
            repo: text_of(&value, &["spec", "repo"]).into(),
            parsed,
            text: doc.get(..end).unwrap_or_default().to_string(),
            text_truncated: end < doc.len(),
        };
        sink.emit(Loc::Line(*first_line as u64 + 1), &record)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::k8s_testdata::{expected, node, records};
    use super::*;
    use crate::testing::run;
    use serde_json::json;
    use std::collections::BTreeSet;

    fn manifests(flavor: &str) -> Vec<(String, Vec<serde_json::Value>)> {
        node(flavor)
            .into_iter()
            .filter(|(p, _)| {
                use nixcavate_source::glob::Pattern;
                ARTIFACT.paths.iter().any(|g| Pattern::new(g).matches(p))
            })
            .map(|(p, d)| {
                let out = run(&ARTIFACT, &p, &d, 0);
                assert!(!out.contains("--- warning") && !out.contains("--- failed"), "{p}: {out}");
                (p, records(&out))
            })
            .collect()
    }

    fn set(v: &serde_json::Value) -> BTreeSet<String> {
        v.as_array().unwrap().iter().map(|s| s.as_str().unwrap().to_string()).collect()
    }

    /// Each manifest's facts must equal what the cluster says about the pods those manifests
    /// became (`kubectl get pods -A -o json`): static pods by name, a DaemonSet's pods by prefix.
    #[test]
    fn real_manifests_give_the_facts_the_cluster_reports() {
        for flavor in ["k3s", "kind"] {
            let truth = expected(flavor);
            let pods = truth["pod_facts"].as_array().unwrap();
            let all = manifests(flavor);
            let mut compared = 0;
            for (path, docs) in &all {
                for doc in docs {
                    assert_eq!(doc["parsed"], true, "{path}");
                    let (ns, name) = (doc["namespace"].as_str().unwrap(), doc["name"].as_str().unwrap());
                    let carriers = ["Pod", "DaemonSet"].contains(&doc["kind"].as_str().unwrap());
                    if !carriers || name.is_empty() {
                        continue;
                    }
                    let found = pods
                        .iter()
                        .find(|p| p["namespace"] == ns && p["name"].as_str().unwrap().starts_with(&format!("{name}-")));
                    let Some(pod) = found else { continue };
                    compared += 1;
                    assert_eq!(set(&doc["images"]), set(&pod["images"]), "{path} images");
                    assert_eq!(doc["host_network"], pod["hostNetwork"], "{path} {name} hostNetwork");
                    assert_eq!(doc["host_pid"], pod["hostPID"], "{path} {name} hostPID");
                    assert_eq!(doc["privileged"], pod["privileged"], "{path} {name} privileged");
                    assert_eq!(set(&doc["host_paths"]), set(&pod["hostPaths"]), "{path} {name} hostPath");
                }
            }
            // k3s: the DaemonSet and the static pod; kubeadm: four control-plane pods and the static pod.
            assert!(compared >= if flavor == "k3s" { 2 } else { 5 }, "{flavor}: {compared}");
        }
    }

    #[test]
    fn kubeadm_control_plane_pods_and_the_planted_static_pod() {
        let all = manifests("kind");
        let doc = |file: &str| all.iter().find(|(p, _)| p.ends_with(file)).unwrap().1[0].clone();
        let api = doc("kube-apiserver.yaml");
        assert_eq!(
            (api["source_kind"].as_str(), api["component"].as_str()),
            (Some("static-pod"), Some("kube-apiserver"))
        );
        assert!(api["commands"][0]
            .as_str()
            .unwrap()
            .starts_with("kube-apiserver: kube-apiserver --advertise-address="));
        assert!(api["commands"][0].as_str().unwrap().contains("--audit-log-path=/var/log/kubernetes/audit/audit.log"));
        let planted = doc("static-web.yaml");
        assert_eq!(planted["privileged"], true);
        assert_eq!(planted["host_paths"], json!(["/"]));
        assert!(planted["text"].as_str().unwrap().contains("static-alive"));
    }

    #[test]
    fn k3s_auto_apply_files_and_static_pods() {
        let all = manifests("k3s");
        let kinds: BTreeSet<(String, String)> = all
            .iter()
            .flat_map(|(p, docs)| {
                docs.iter().map(move |d| {
                    (p.rsplit('/').next().unwrap().to_string(), d["source_kind"].as_str().unwrap().to_string())
                })
            })
            .collect();
        assert!(kinds.contains(&("extra-tools.yaml".into(), "k3s-auto-apply".into())));
        assert!(kinds.contains(&("static-web.yaml".into(), "k3s-static-pod".into())));
        let extra = &all.iter().find(|(p, _)| p.ends_with("extra-tools.yaml")).unwrap().1;
        assert_eq!(extra.iter().map(|d| d["kind"].as_str().unwrap()).collect::<Vec<_>>(), ["Namespace", "DaemonSet"]);
        assert_eq!(extra[1]["commands"][0], "helper: sh -c while true; do echo helper-alive; sleep 20; done");
        // The stock files are read too: the ClusterRoleBinding file has several documents.
        let stock = &all.iter().find(|(p, _)| p.ends_with("rolebindings.yaml")).unwrap().1;
        assert!(stock.len() >= 2 && stock.iter().any(|d| d["kind"] == "ClusterRole"));
    }

    #[test]
    fn unreadable_documents_are_kept_as_text_with_one_warning_each() {
        let path = "etc/kubernetes/manifests/odd.yaml";
        let data =
            b"apiVersion: v1\nkind: Pod\nmetadata:\n  name: ok\n---\nkind: Pod\nspec: *alias\n---\n- a\n- b: [1\n";
        let out = run(&ARTIFACT, path, data, 0);
        let rows = records(&out);
        assert_eq!(rows.len(), 3, "{out}");
        assert_eq!(rows.iter().map(|r| r["parsed"].as_bool().unwrap()).collect::<Vec<_>>(), [true, false, false]);
        assert_eq!(out.matches("--- warning").count(), 2);
        assert!(rows[1]["text"].as_str().unwrap().contains("*alias"));
    }

    #[test]
    fn json_manifests_and_empty_files() {
        let path = "etc/kubernetes/manifests/p.json";
        let data = br#"{"apiVersion":"v1","kind":"Pod","metadata":{"name":"p","namespace":"kube-system"},"spec":{"hostPID":true,"containers":[{"name":"c","image":"i:1","command":["/bin/sh"],"securityContext":{"privileged":true}}],"volumes":[{"name":"s","hostPath":{"path":"/var/run/docker.sock"}}]}}"#;
        let rows = records(&run(&ARTIFACT, path, data, 0));
        assert_eq!(rows.len(), 1);
        assert_eq!((rows[0]["host_pid"].clone(), rows[0]["privileged"].clone()), (json!(true), json!(true)));
        assert_eq!(rows[0]["host_paths"], json!(["/var/run/docker.sock"]));
        assert_eq!(rows[0]["commands"], json!(["c: /bin/sh"]));
        assert!(run(&ARTIFACT, path, b"  \n", 0).contains("skipped"));
    }

    #[test]
    fn mutated_manifests_never_panic() {
        let all = node("kind");
        let (path, real) = all.iter().find(|(p, _)| p.ends_with("kube-apiserver.yaml")).unwrap();
        let mut state = 0x2545_f491_4f6c_dd1du64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for round in 0..1500 {
            let mut data = real.clone();
            for _ in 0..=(round % 8) {
                let at = (next() as usize) % data.len();
                data[at] = b" :-[]{}\"'#|>&*!\n\t"[(next() as usize) % 17];
            }
            if round % 5 == 0 {
                data.truncate((next() as usize) % data.len());
            }
            run(&ARTIFACT, path, &data, 0);
        }
    }
}
