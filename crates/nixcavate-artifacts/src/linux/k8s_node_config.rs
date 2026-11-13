//! Kubernetes node configuration: the kubelet's settings (`kubelet-config`) and the kubeconfig
//! files that hold cluster credentials (`kubeconfig`).
//!
//! `kubelet-config` reads kubeadm's `var/lib/kubelet/config.yaml` and `kubeadm-flags.env`, the
//! `/etc/default/kubelet` and `/etc/sysconfig/kubelet` flag files and k3s's
//! `agent/etc/kubelet.conf.d/*.conf`, and keeps the settings that decide who may talk to the
//! kubelet and which directory it runs static pods from. Field reference: the
//! `KubeletConfiguration` type and the kubelet's command-line flags.
//!
//! `kubeconfig` lists the clusters, users and contexts of a kubeconfig file: names, server
//! URLs and whether a client certificate, key, token or password is present (embedded, or a
//! file path). It never outputs a credential value, and removes a `user:password@` part from a
//! server URL. Kubeconfig format: `client-go/tools/clientcmd/api/v1`.

use super::yaml_lite::parse as parse_yaml;
use crate::text::lossy;
use crate::{Artifact, Category, Input, LINUX};
use nixcavate_core::{Error, Loc, Record, Result, Sink};
use serde::Serialize;
use serde_json::Value;

pub const KUBELET: Artifact = Artifact::new(
    "kubelet-config",
    "Kubernetes kubelet configuration (kubeadm, k3s)",
    Category::System,
    LINUX,
    &[
        "var/lib/kubelet/config.yaml",
        "var/lib/kubelet/kubeadm-flags.env",
        "var/lib/rancher/k3s/agent/etc/kubelet.conf.d/*",
        "etc/kubernetes/kubelet-config.yaml",
        "etc/default/kubelet",
        "etc/sysconfig/kubelet",
    ],
    parse_kubelet,
);

pub const KUBECONFIG: Artifact = Artifact::new(
    "kubeconfig",
    "Kubeconfig files: clusters, users, contexts and which credentials are present",
    Category::Security,
    LINUX,
    &[
        "etc/kubernetes/*.conf",
        "etc/kubernetes/*.kubeconfig",
        "home/*/.kube/config",
        "root/.kube/config",
        "etc/rancher/k3s/k3s.yaml",
        "var/lib/rancher/k3s/agent/*.kubeconfig",
    ],
    parse_kubeconfig,
);

const MAX_FILE: usize = 4 << 20;
const MAX_ENTRIES: usize = 1000;

#[derive(Serialize)]
struct Kubelet {
    /// `config` (a KubeletConfiguration file) or `flags` (a file of command-line flags).
    kind: &'static str,
    static_pod_path: String,
    anonymous_auth: Option<bool>,
    webhook_authentication: Option<bool>,
    client_ca_file: String,
    /// `Webhook`, `AlwaysAllow`, ...
    authorization_mode: String,
    read_only_port: Option<i64>,
    port: Option<i64>,
    address: String,
    container_runtime_endpoint: String,
    cgroup_driver: String,
    /// For flag files: the `--config` and `--kubeconfig` paths.
    config_file: String,
    kubeconfig: String,
    /// Every flag of a flag file, `--name=value`, at most 64.
    flags: Vec<String>,
}

impl Record for Kubelet {}

fn at<'a>(v: &'a Value, path: &[&str]) -> Option<&'a Value> {
    path.iter().try_fold(v, |v, k| v.get(k))
}

fn string(v: &Value, path: &[&str]) -> String {
    at(v, path).and_then(Value::as_str).unwrap_or_default().to_string()
}

fn from_config(v: &Value) -> Kubelet {
    Kubelet {
        kind: "config",
        static_pod_path: string(v, &["staticPodPath"]),
        anonymous_auth: at(v, &["authentication", "anonymous", "enabled"]).and_then(Value::as_bool),
        webhook_authentication: at(v, &["authentication", "webhook", "enabled"]).and_then(Value::as_bool),
        client_ca_file: string(v, &["authentication", "x509", "clientCAFile"]),
        authorization_mode: string(v, &["authorization", "mode"]),
        read_only_port: at(v, &["readOnlyPort"]).and_then(Value::as_i64),
        port: at(v, &["port"]).and_then(Value::as_i64),
        address: string(v, &["address"]),
        container_runtime_endpoint: string(v, &["containerRuntimeEndpoint"]),
        cgroup_driver: string(v, &["cgroupDriver"]),
        config_file: String::new(),
        kubeconfig: String::new(),
        flags: Vec::new(),
    }
}

/// Flags from `KEY="--a=b --c"` lines (kubeadm-flags.env, /etc/default/kubelet).
fn from_flags(text: &str) -> Kubelet {
    let mut flags: Vec<String> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        let Some((_, value)) = line.split_once('=') else { continue };
        for word in value.trim().trim_matches(['"', '\'']).split_whitespace() {
            if word.starts_with("--") && flags.len() < 64 {
                flags.push(word.to_string());
            }
        }
    }
    let flag = |name: &str| {
        flags
            .iter()
            .rev()
            .find_map(|f| f.strip_prefix("--")?.strip_prefix(name)?.strip_prefix('='))
            .unwrap_or_default()
            .to_string()
    };
    let bool_flag = |name: &str| match flag(name).as_str() {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    };
    Kubelet {
        kind: "flags",
        static_pod_path: flag("pod-manifest-path"),
        anonymous_auth: bool_flag("anonymous-auth"),
        webhook_authentication: bool_flag("authentication-token-webhook"),
        client_ca_file: flag("client-ca-file"),
        authorization_mode: flag("authorization-mode"),
        read_only_port: flag("read-only-port").parse().ok(),
        port: flag("port").parse().ok(),
        address: flag("address"),
        container_runtime_endpoint: flag("container-runtime-endpoint"),
        cgroup_driver: flag("cgroup-driver"),
        config_file: flag("config"),
        kubeconfig: flag("kubeconfig"),
        flags,
    }
}

fn parse_kubelet(input: &Input, sink: &mut Sink) -> Result<()> {
    let data = input.data.get(..input.data.len().min(MAX_FILE)).unwrap_or_default();
    if data.iter().all(u8::is_ascii_whitespace) {
        return Err(Error::skipped("empty file"));
    }
    let text = lossy(data);
    let flag_file =
        ["kubeadm-flags.env", "default/kubelet", "sysconfig/kubelet"].iter().any(|n| input.path.ends_with(n));
    let record = if flag_file {
        from_flags(&text)
    } else {
        let value =
            parse_yaml(&text).map_err(|e| Error::format(format!("not a KubeletConfiguration YAML file: {e}")))?;
        if !value.is_object() {
            return Err(Error::format("not a KubeletConfiguration YAML file: no mapping at the top"));
        }
        from_config(&value)
    };
    sink.emit(Loc::None, &record)
}

#[derive(Serialize)]
struct Entry {
    /// `cluster`, `user` or `context`.
    kind: &'static str,
    name: String,
    /// Cluster: the API server URL, without credentials in it.
    server: String,
    /// Context: the cluster, user and namespace it joins.
    cluster: String,
    user: String,
    namespace: String,
    /// True for the file's `current-context`.
    current: bool,
    /// Cluster: `embedded`, a file path, or empty.
    certificate_authority: String,
    insecure_skip_tls_verify: bool,
    /// User: `embedded`, a file path (for a client certificate, a key, a token) or empty.
    client_certificate: String,
    client_key: String,
    token: String,
    /// `embedded` when a username/password pair is set.
    password: String,
    /// The `exec` credential plugin's command, not its arguments.
    exec_command: String,
    auth_provider: String,
}

impl Record for Entry {}

impl Entry {
    fn new(kind: &'static str, name: &str) -> Self {
        Self {
            kind,
            name: name.into(),
            server: String::new(),
            cluster: String::new(),
            user: String::new(),
            namespace: String::new(),
            current: false,
            certificate_authority: String::new(),
            insecure_skip_tls_verify: false,
            client_certificate: String::new(),
            client_key: String::new(),
            token: String::new(),
            password: String::new(),
            exec_command: String::new(),
            auth_provider: String::new(),
        }
    }
}

/// `embedded` when the inline `*-data` field is set, else the file reference, else empty.
fn credential(v: &Value, data: &str, file: &str) -> String {
    if at(v, &[data]).is_some_and(|d| d.as_str() != Some("")) {
        "embedded".into()
    } else {
        string(v, &[file])
    }
}

/// A server URL without `user:password@`.
fn without_userinfo(url: &str) -> String {
    match url.split_once("://") {
        Some((scheme, rest)) => {
            let authority_end = rest.find('/').unwrap_or(rest.len());
            match rest.get(..authority_end).and_then(|a| a.rfind('@')) {
                Some(at) => format!("{scheme}://{}", rest.get(at + 1..).unwrap_or_default()),
                None => url.to_string(),
            }
        }
        None => url.to_string(),
    }
}

fn parse_kubeconfig(input: &Input, sink: &mut Sink) -> Result<()> {
    let data = input.data.get(..input.data.len().min(MAX_FILE)).unwrap_or_default();
    if data.iter().all(u8::is_ascii_whitespace) {
        return Err(Error::skipped("empty file"));
    }
    let text = lossy(data);
    let value = if text.trim_start().starts_with('{') {
        serde_json::from_str::<Value>(&text).map_err(|e| e.to_string())
    } else {
        parse_yaml(&text)
    }
    .map_err(|e| Error::format(format!("not a kubeconfig file: {e}")))?;
    if !value.is_object()
        || value.get("clusters").is_none() && value.get("users").is_none() && value.get("contexts").is_none()
    {
        return Err(Error::format("not a kubeconfig file: no clusters, users or contexts"));
    }
    let current = string(&value, &["current-context"]);
    let list = |key: &str| {
        value
            .get(key)
            .and_then(Value::as_array)
            .map(|a| a.iter().take(MAX_ENTRIES).collect::<Vec<_>>())
            .unwrap_or_default()
    };
    for item in list("clusters") {
        let body = item.get("cluster").unwrap_or(&Value::Null);
        let mut e = Entry::new("cluster", &string(item, &["name"]));
        e.server = without_userinfo(&string(body, &["server"]));
        e.certificate_authority = credential(body, "certificate-authority-data", "certificate-authority");
        e.insecure_skip_tls_verify = at(body, &["insecure-skip-tls-verify"]) == Some(&Value::Bool(true));
        sink.emit(Loc::None, &e)?;
    }
    for item in list("users") {
        let body = item.get("user").unwrap_or(&Value::Null);
        let mut e = Entry::new("user", &string(item, &["name"]));
        e.client_certificate = credential(body, "client-certificate-data", "client-certificate");
        e.client_key = credential(body, "client-key-data", "client-key");
        e.token = credential(body, "token", "tokenFile");
        if at(body, &["password"]).is_some_and(|p| p.as_str() != Some("")) {
            e.password = "embedded".into();
        }
        e.exec_command = string(body, &["exec", "command"]);
        e.auth_provider = string(body, &["auth-provider", "name"]);
        sink.emit(Loc::None, &e)?;
    }
    for item in list("contexts") {
        let body = item.get("context").unwrap_or(&Value::Null);
        let mut e = Entry::new("context", &string(item, &["name"]));
        e.cluster = string(body, &["cluster"]);
        e.user = string(body, &["user"]);
        e.namespace = string(body, &["namespace"]);
        e.current = e.name == current;
        sink.emit(Loc::None, &e)?;
    }
    Ok(())
}

pub const CNI: Artifact = Artifact::new(
    "cni-config",
    "Container network (CNI) plugin configuration",
    Category::Network,
    LINUX,
    &["etc/cni/net.d/*", "var/lib/rancher/k3s/agent/etc/cni/net.d/*"],
    parse_cni,
);

#[derive(Serialize)]
struct Cni {
    /// The network's name.
    name: String,
    cni_version: String,
    /// The plugin `type`s in chain order (one for a plain `.conf`).
    plugins: Vec<String>,
}

impl Record for Cni {}

/// CNI network configuration lists and single configurations. Specification: containernetworking
/// `SPEC.md` ("Network Configuration").
fn parse_cni(input: &Input, sink: &mut Sink) -> Result<()> {
    if input.data.iter().all(u8::is_ascii_whitespace) {
        return Err(Error::skipped("empty file"));
    }
    let doc: Value =
        serde_json::from_slice(input.data).map_err(|e| Error::format(format!("not a CNI configuration: {e}")))?;
    let mut plugins: Vec<String> = doc
        .get("plugins")
        .and_then(Value::as_array)
        .map(|p| p.iter().take(MAX_ENTRIES).filter_map(|p| p.get("type")?.as_str().map(str::to_owned)).collect())
        .unwrap_or_default();
    if let Some(single) = doc.get("type").and_then(Value::as_str) {
        plugins.push(single.to_string());
    }
    sink.emit(Loc::None, &Cni { name: string(&doc, &["name"]), cni_version: string(&doc, &["cniVersion"]), plugins })
}

#[cfg(test)]
mod tests {
    use super::super::k8s_testdata::{node, records};
    use super::*;
    use crate::testing::run;

    fn read(flavor: &str, suffix: &str) -> (String, Vec<u8>) {
        node(flavor).into_iter().find(|(p, _)| p.ends_with(suffix)).unwrap_or_else(|| panic!("{suffix}"))
    }

    /// kubeadm's `config.yaml` and `kubeadm-flags.env`, and k3s's defaults file.
    #[test]
    fn real_kubelet_settings() {
        let (p, d) = read("kind", "var/lib/kubelet/config.yaml");
        let r = &records(&run(&KUBELET, &p, &d, 0))[0];
        assert_eq!(r["kind"], "config");
        assert_eq!(r["static_pod_path"], "/etc/kubernetes/manifests");
        assert_eq!((r["anonymous_auth"].clone(), r["webhook_authentication"].clone()), (false.into(), true.into()));
        assert_eq!(r["authorization_mode"], "Webhook");
        assert_eq!(r["client_ca_file"], "/etc/kubernetes/pki/ca.crt");
        assert!(
            r["container_runtime_endpoint"].as_str().unwrap().starts_with("unix:///")
                || r["container_runtime_endpoint"] == ""
        );
        let (p, d) = read("kind", "kubeadm-flags.env");
        let out = run(&KUBELET, &p, &d, 0);
        let r = &records(&out)[0];
        assert_eq!(r["kind"], "flags");
        assert!(r["flags"].as_array().unwrap().iter().any(|f| f.as_str().unwrap().starts_with("--node-ip=")), "{out}");
        assert!(r["flags"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f.as_str().unwrap().starts_with("--pod-infra-container-image=")));
        let (p, d) = read("k3s", "kubelet.conf.d/00-k3s-defaults.conf");
        let r = &records(&run(&KUBELET, &p, &d, 0))[0];
        assert_eq!(r["static_pod_path"], "/var/lib/rancher/k3s/agent/pod-manifests");
        assert_eq!(r["authorization_mode"], "Webhook");
        assert_eq!(r["container_runtime_endpoint"], "unix:///run/k3s/containerd/containerd.sock");
    }

    #[test]
    fn weakened_kubelet_settings_are_read_as_written() {
        let weak = b"apiVersion: kubelet.config.k8s.io/v1beta1\nkind: KubeletConfiguration\nauthentication:\n  anonymous:\n    enabled: true\nauthorization:\n  mode: AlwaysAllow\nreadOnlyPort: 10255\n";
        let r = &records(&run(&KUBELET, "var/lib/kubelet/config.yaml", weak, 0))[0];
        assert_eq!(
            (r["anonymous_auth"].clone(), r["authorization_mode"].clone(), r["read_only_port"].clone()),
            (true.into(), "AlwaysAllow".into(), 10255.into())
        );
        let flags = b"KUBELET_EXTRA_ARGS=\"--anonymous-auth=true --authorization-mode=AlwaysAllow --pod-manifest-path=/srv/pods\"\n";
        let r = &records(&run(&KUBELET, "etc/default/kubelet", flags, 0))[0];
        assert_eq!((r["anonymous_auth"].clone(), r["static_pod_path"].clone()), (true.into(), "/srv/pods".into()));
        assert!(run(&KUBELET, "var/lib/kubelet/config.yaml", b"", 0).contains("skipped"));
        assert!(run(&KUBELET, "var/lib/kubelet/config.yaml", b"- a\n- b\n", 0).contains("failed"));
    }

    /// The kubeconfigs of a real kubeadm node and a real k3s server: clusters, users and what
    /// each user authenticates with, and nothing of the credentials themselves.
    #[test]
    fn real_kubeconfigs_name_credentials_without_outputting_them() {
        let (p, d) = read("kind", "etc/kubernetes/admin.conf");
        let out = run(&KUBECONFIG, &p, &d, 0);
        assert!(!out.contains("PLANTED") && !out.contains("LS0tLS1CRUdJTi"), "{out}");
        let rows = records(&out);
        let user = rows.iter().find(|r| r["kind"] == "user").unwrap();
        assert_eq!(user["name"], "kubernetes-admin");
        assert_eq!(
            (user["client_certificate"].clone(), user["client_key"].clone()),
            ("embedded".into(), "embedded".into())
        );
        let cluster = rows.iter().find(|r| r["kind"] == "cluster").unwrap();
        assert!(cluster["server"].as_str().unwrap().starts_with("https://"));
        assert_eq!(cluster["certificate_authority"], "embedded");
        let ctx = rows.iter().find(|r| r["kind"] == "context").unwrap();
        assert_eq!((ctx["current"].clone(), ctx["user"].clone()), (true.into(), "kubernetes-admin".into()));
        let (p, d) = read("k3s", "agent/kubelet.kubeconfig");
        let rows = records(&run(&KUBECONFIG, &p, &d, 0));
        let user = rows.iter().find(|r| r["kind"] == "user").unwrap();
        assert_eq!(user["client_certificate"], "/var/lib/rancher/k3s/agent/client-kubelet.crt");
    }

    #[test]
    fn tokens_passwords_and_credentials_in_server_urls_stay_out() {
        let cfg = b"apiVersion: v1\nkind: Config\nclusters:\n- name: c\n  cluster:\n    server: https://bob:PLANTED-URL-PASSWORD@203.0.113.7:6443\n    insecure-skip-tls-verify: true\nusers:\n- name: t\n  user:\n    token: PLANTED-TOKEN\n- name: p\n  user:\n    username: bob\n    password: PLANTED-PASSWORD\n- name: e\n  user:\n    exec:\n      command: aws\n      args: [eks, get-token, --cluster-name, PLANTED-ARG]\ncurrent-context: x\n";
        let out = run(&KUBECONFIG, "home/alice/.kube/config", cfg, 0);
        assert!(!out.contains("PLANTED"), "{out}");
        let rows = records(&out);
        assert_eq!(rows[0]["server"], "https://203.0.113.7:6443");
        assert_eq!(rows[0]["insecure_skip_tls_verify"], true);
        assert_eq!(rows[1]["token"], "embedded");
        assert_eq!(rows[2]["password"], "embedded");
        assert_eq!(rows[3]["exec_command"], "aws");
        assert!(run(&KUBECONFIG, "root/.kube/config", b"a: 1\n", 0).contains("not a kubeconfig"));
    }

    #[test]
    fn cni_configurations() {
        for (flavor, suffix, plugin) in
            [("kind", "10-kindnet.conflist", "ptp"), ("k3s", "10-flannel.conflist", "flannel")]
        {
            let (p, d) = read(flavor, suffix);
            let out = run(&CNI, &p, &d, 0);
            let r = &records(&out)[0];
            assert!(r["plugins"].as_array().unwrap().iter().any(|v| v == plugin), "{out}");
            assert!(!r["name"].as_str().unwrap().is_empty() && !r["cni_version"].as_str().unwrap().is_empty());
        }
        assert!(run(&CNI, "etc/cni/net.d/x.conf", b"{", 0).contains("failed"));
    }

    #[test]
    fn mutated_configs_never_panic() {
        let (path, real) = read("kind", "etc/kubernetes/admin.conf");
        let (kpath, kreal) = read("kind", "var/lib/kubelet/config.yaml");
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for round in 0..1000 {
            for (artifact, p, original) in [(&KUBECONFIG, &path, &real), (&KUBELET, &kpath, &kreal)] {
                let mut data = original.clone();
                for _ in 0..=(round % 6) {
                    let at = (next() as usize) % data.len();
                    data[at] = b" :-[]{}\"'#|>&*!\n"[(next() as usize) % 16];
                }
                if round % 5 == 0 {
                    data.truncate((next() as usize) % data.len());
                }
                run(artifact, p, &data, 0);
            }
        }
    }
}
