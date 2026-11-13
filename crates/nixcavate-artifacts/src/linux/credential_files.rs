//! Credential files of cloud, registry and developer tools in home directories: which exist,
//! how large, when last modified, and the NAMES inside (profiles, accounts, registries, hosts,
//! tunnel-less identifiers). No secret value is ever read into a record: not an AWS secret key,
//! token, password, private key, registry `auth`, npm token, netrc password or the contents of a
//! `credentials.db`. What an analyst needs from them is that the file existed (a host with
//! `~/.aws/credentials` was a pivot to that account), for whom, and from when.
//!
//! One deliberate exception to "names only": an AWS access key ID is an identifier AWS itself
//! treats as non-secret and CloudTrail records it, so it is kept as its first four and last
//! four characters (`AKIA...WXYZ`), enough to match against CloudTrail without being the key.
//!
//! Formats: AWS CLI configuration files, Docker `config.json`, kubeconfig, npm's `.npmrc`,
//! `netrc(5)`, git's credential store, `.pypirc`, Terraform's `credentials.tfrc.json`, the OCI
//! CLI `config`, the Azure CLI's `azureProfile.json`, gcloud's `configurations` and
//! `legacy_credentials`, `gh`'s `hosts.yml`, Vault's `~/.vault-token`.

use super::ini_lite::pairs;
use super::yaml_lite::parse as parse_yaml;
use crate::common::home::user_from_path;
use crate::text::lossy;
use crate::{Artifact, Category, Input, LINUX};
use nixcavate_core::{Basis, Loc, Record, Result, Sink, Timestamp};
use serde::Serialize;
use serde_json::Value;

macro_rules! home_and_root {
    ($($p:literal),* $(,)?) => { &[$(concat!("home/*/", $p), concat!("root/", $p)),*] };
}

pub const ARTIFACT: Artifact = Artifact::new(
    "credential-files",
    "Cloud and tool credential files: which exist and which accounts they name (never secrets)",
    Category::Security,
    LINUX,
    home_and_root!(
        ".aws/credentials",
        ".aws/config",
        ".azure/azureProfile.json",
        ".azure/msal_token_cache.json",
        ".azure/accessTokens.json",
        ".config/gcloud/credentials.db",
        ".config/gcloud/access_tokens.db",
        ".config/gcloud/application_default_credentials.json",
        ".config/gcloud/legacy_credentials/*/adc.json",
        ".config/gcloud/configurations/config_*",
        ".kube/config",
        ".docker/config.json",
        ".oci/config",
        ".terraform.d/credentials.tfrc.json",
        ".vault-token",
        ".netrc",
        ".git-credentials",
        ".npmrc",
        ".pypirc",
        ".config/gh/hosts.yml",
    ),
    parse,
);

const MAX_FILE: usize = 4 << 20;
const MAX_LIST: usize = 256;

#[derive(Serialize)]
struct Found {
    tool: &'static str,
    user: String,
    /// The file's path under the home directory.
    file: String,
    size_bytes: u64,
    modified: Option<Timestamp>,
    /// Permission bits in octal when the source recorded them.
    mode: String,
    /// Profiles, accounts, registries or hosts named in the file.
    entries: Vec<String>,
    /// Non-secret facts about the entries (regions, role ARNs, user names, server URLs).
    details: Vec<String>,
    /// True when the file holds (or, for stores that are not read, can hold) secret material.
    holds_secret: bool,
}

impl Record for Found {}

#[derive(Default)]
struct Extract {
    entries: Vec<String>,
    details: Vec<String>,
    secret: bool,
}

impl Extract {
    fn entry(&mut self, name: &str) {
        if self.entries.len() < MAX_LIST && !self.entries.iter().any(|e| e == name) {
            self.entries.push(cap(name));
        }
    }

    fn detail(&mut self, text: String) {
        if self.details.len() < MAX_LIST {
            self.details.push(cap(&text));
        }
    }
}

fn cap(text: &str) -> String {
    let mut end = text.len().min(512);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text.get(..end).unwrap_or_default().to_string()
}

/// `AKIAIOSFODNN7EXAMPLE` as `AKIA...MPLE`.
fn key_hint(id: &str) -> String {
    let chars: Vec<char> = id.chars().collect();
    if chars.len() < 12 {
        return "(short)".into();
    }
    let head: String = chars.iter().take(4).collect();
    let tail: String = chars.iter().skip(chars.len() - 4).collect();
    format!("{head}...{tail}")
}

fn base64_user(encoded: &str) -> Option<String> {
    let mut bits = 0u32;
    let mut count = 0;
    let mut out = Vec::new();
    for b in encoded.bytes().take(4096) {
        let v = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' => break,
            _ => return None,
        };
        bits = (bits << 6) | u32::from(v);
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count) as u8);
            bits &= (1 << count) - 1;
        }
    }
    let user = out.split(|b| *b == b':').next()?;
    Some(String::from_utf8_lossy(user).into_owned())
}

fn str_at<'a>(v: &'a Value, path: &[&str]) -> &'a str {
    path.iter().try_fold(v, |v, k| v.get(k)).and_then(Value::as_str).unwrap_or_default()
}

fn aws(text: &str, config: bool) -> Extract {
    let mut out = Extract::default();
    for pair in pairs(text, false) {
        let profile = pair.section.strip_prefix("profile ").unwrap_or(pair.section);
        if config && profile.starts_with("sso-session ") {
            continue;
        }
        out.entry(profile);
        match pair.key {
            "aws_secret_access_key" | "aws_session_token" => out.secret = true,
            "aws_access_key_id" => out.detail(format!("{profile}: access key {}", key_hint(pair.value))),
            "region" | "role_arn" | "source_profile" | "sso_account_id" | "sso_role_name" | "sso_start_url"
            | "sso_session" | "mfa_serial" | "output" | "credential_process" => {
                out.detail(format!("{profile}: {}={}", pair.key, pair.value));
            }
            _ => {}
        }
    }
    out
}

fn json(text: &str) -> Option<Value> {
    serde_json::from_str(text).ok()
}

fn docker(text: &str) -> Extract {
    let mut out = Extract::default();
    let Some(doc) = json(text) else { return out };
    if let Some(auths) = doc.get("auths").and_then(Value::as_object) {
        for (registry, auth) in auths.iter().take(MAX_LIST) {
            out.entry(registry);
            if auth.get("auth").and_then(Value::as_str).is_some_and(|a| !a.is_empty())
                || auth.get("identitytoken").is_some()
            {
                out.secret = true;
            }
            let user = auth
                .get("auth")
                .and_then(Value::as_str)
                .and_then(base64_user)
                .or_else(|| auth.get("username").and_then(Value::as_str).map(str::to_owned));
            if let Some(user) = user.filter(|u| !u.is_empty()) {
                out.detail(format!("{registry}: user {user}"));
            }
        }
    }
    if let Some(store) = doc.get("credsStore").and_then(Value::as_str) {
        out.detail(format!("credsStore: {store}"));
    }
    for (registry, helper) in doc.get("credHelpers").and_then(Value::as_object).into_iter().flatten().take(MAX_LIST) {
        out.entry(registry);
        out.detail(format!("{registry}: credential helper {}", helper.as_str().unwrap_or_default()));
    }
    out
}

fn kube(text: &str) -> Extract {
    let mut out = Extract::default();
    let Ok(doc) = parse_yaml(text) else { return out };
    for context in doc.get("contexts").and_then(Value::as_array).into_iter().flatten().take(MAX_LIST) {
        out.entry(str_at(context, &["name"]));
    }
    for cluster in doc.get("clusters").and_then(Value::as_array).into_iter().flatten().take(MAX_LIST) {
        let server = str_at(cluster, &["cluster", "server"]);
        let server =
            server.split_once("://").map_or(server, |(_, rest)| rest.rsplit_once('@').map_or(rest, |(_, h)| h));
        out.detail(format!("cluster {}: {server}", str_at(cluster, &["name"])));
    }
    for user in doc.get("users").and_then(Value::as_array).into_iter().flatten().take(MAX_LIST) {
        let body = user.get("user").unwrap_or(&Value::Null);
        for key in ["token", "client-key-data", "password", "client-key", "tokenFile"] {
            out.secret |= body.get(key).is_some();
        }
        out.detail(format!("user {}", str_at(user, &["name"])));
    }
    out
}

fn npmrc(text: &str) -> Extract {
    let mut out = Extract::default();
    for pair in pairs(text, false) {
        let key = pair.key;
        if let Some((host, name)) = key.strip_prefix("//").and_then(|k| k.rsplit_once(':')) {
            if matches!(name, "_authToken" | "_auth" | "_password" | "username" | "email") {
                out.entry(host.trim_end_matches('/'));
                if name != "username" && name != "email" {
                    out.secret = true;
                } else if name == "username" {
                    out.detail(format!("{host}: user {}", pair.value));
                }
            }
        } else if key == "registry" || key.ends_with(":registry") {
            out.detail(format!("{key}={}", pair.value));
        } else if matches!(key, "_authToken" | "_auth" | "_password") {
            out.secret = true;
        }
    }
    out
}

fn netrc(text: &str) -> Extract {
    let mut out = Extract::default();
    let words: Vec<&str> = text.split_whitespace().collect();
    let mut machine = String::new();
    let mut i = 0;
    while let Some(word) = words.get(i) {
        match *word {
            "machine" => {
                machine = words.get(i + 1).copied().unwrap_or_default().to_string();
                out.entry(&machine);
                i += 1;
            }
            "default" => {
                machine = "default".into();
                out.entry("default");
            }
            "login" | "user" => {
                out.detail(format!("{machine}: login {}", words.get(i + 1).copied().unwrap_or_default()));
                i += 1;
            }
            "password" | "passwd" | "account" => {
                out.secret = true;
                i += 1;
            }
            _ => {}
        }
        i += 1;
    }
    out
}

fn git_credentials(text: &str) -> Extract {
    let mut out = Extract::default();
    for line in text.lines().take(MAX_LIST) {
        let Some((scheme, rest)) = line.trim().split_once("://") else { continue };
        let authority = rest.split('/').next().unwrap_or_default();
        let (userinfo, host) = authority.rsplit_once('@').unwrap_or(("", authority));
        let user = userinfo.split(':').next().unwrap_or_default();
        out.entry(&format!("{scheme}://{host}"));
        if !user.is_empty() {
            out.detail(format!("{host}: user {user}"));
        }
        out.secret |= userinfo.contains(':');
    }
    out
}

fn pypirc(text: &str) -> Extract {
    let mut out = Extract::default();
    for pair in pairs(text, false) {
        if pair.section == "distutils" {
            continue;
        }
        out.entry(pair.section);
        match pair.key {
            "password" => out.secret = true,
            "username" | "repository" => out.detail(format!("{}: {}={}", pair.section, pair.key, pair.value)),
            _ => {}
        }
    }
    out
}

fn oci(text: &str) -> Extract {
    let mut out = Extract::default();
    for pair in pairs(text, false) {
        out.entry(pair.section);
        match pair.key {
            "region" | "tenancy" | "user" | "fingerprint" | "key_file" => {
                out.detail(format!("{}: {}={}", pair.section, pair.key, pair.value));
            }
            "pass_phrase" | "security_token_file" => out.secret = true,
            _ => {}
        }
    }
    // The API signing key is a separate file the config points at.
    out.secret |= out.details.iter().any(|d| d.contains("key_file="));
    out
}

fn terraform(text: &str) -> Extract {
    let mut out = Extract::default();
    if let Some(hosts) = json(text).as_ref().and_then(|d| d.get("credentials")).and_then(Value::as_object) {
        for (host, body) in hosts.iter().take(MAX_LIST) {
            out.entry(host);
            out.secret |= body.get("token").is_some();
        }
    }
    out
}

fn azure(text: &str) -> Extract {
    let mut out = Extract::default();
    let Some(doc) = json(text.trim_start_matches('\u{feff}')) else { return out };
    for sub in doc.get("subscriptions").and_then(Value::as_array).into_iter().flatten().take(MAX_LIST) {
        out.entry(str_at(sub, &["name"]));
        out.detail(format!(
            "{}: id {}, tenant {}, user {}{}",
            str_at(sub, &["name"]),
            str_at(sub, &["id"]),
            str_at(sub, &["tenantId"]),
            str_at(sub, &["user", "name"]),
            if sub.get("isDefault") == Some(&Value::Bool(true)) { " (default)" } else { "" }
        ));
    }
    out
}

fn gcloud_config(text: &str) -> Extract {
    let mut out = Extract::default();
    for pair in pairs(text, false) {
        if matches!(pair.key, "account" | "project" | "region" | "zone") {
            if pair.key == "account" {
                out.entry(pair.value);
            }
            out.detail(format!("{}.{}={}", pair.section, pair.key, pair.value));
        }
    }
    out
}

fn gh_hosts(text: &str) -> Extract {
    let mut out = Extract::default();
    if let Some(hosts) = parse_yaml(text).ok().as_ref().and_then(Value::as_object) {
        for (host, body) in hosts.iter().take(MAX_LIST) {
            out.entry(host);
            out.secret |= body.get("oauth_token").is_some();
            let user = str_at(body, &["user"]);
            if !user.is_empty() {
                out.detail(format!("{host}: user {user}"));
            }
        }
    }
    out
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    let data = input.data.get(..input.data.len().min(MAX_FILE)).unwrap_or_default();
    let text = lossy(data);
    let path = input.path;
    let rest = path
        .strip_prefix("root/")
        .or_else(|| path.strip_prefix("home/").and_then(|r| r.split_once('/').map(|(_, f)| f)))
        .unwrap_or(path);
    let name = rest.rsplit('/').next().unwrap_or_default();
    let (tool, extract) = match rest {
        ".aws/credentials" => ("aws", aws(&text, false)),
        ".aws/config" => ("aws", aws(&text, true)),
        ".azure/azureProfile.json" => ("azure", azure(&text)),
        ".azure/msal_token_cache.json" | ".azure/accessTokens.json" => {
            ("azure", Extract { secret: true, ..Extract::default() })
        }
        ".config/gcloud/credentials.db" | ".config/gcloud/access_tokens.db" => {
            ("gcloud", Extract { secret: true, ..Extract::default() })
        }
        ".config/gcloud/application_default_credentials.json" => {
            let mut e = Extract { secret: true, ..Extract::default() };
            if let Some(doc) = json(&text) {
                for key in ["type", "client_email", "quota_project_id", "account"] {
                    let v = str_at(&doc, &[key]);
                    if !v.is_empty() {
                        e.detail(format!("{key}={v}"));
                    }
                }
            }
            ("gcloud", e)
        }
        ".kube/config" => ("kubectl", kube(&text)),
        ".docker/config.json" => ("docker", docker(&text)),
        ".oci/config" => ("oci", oci(&text)),
        ".terraform.d/credentials.tfrc.json" => ("terraform", terraform(&text)),
        ".vault-token" => ("vault", Extract { secret: true, ..Extract::default() }),
        ".netrc" => ("netrc", netrc(&text)),
        ".git-credentials" => ("git", git_credentials(&text)),
        ".npmrc" => ("npm", npmrc(&text)),
        ".pypirc" => ("pypi", pypirc(&text)),
        ".config/gh/hosts.yml" => ("gh", gh_hosts(&text)),
        _ if rest.contains(".config/gcloud/legacy_credentials/") => {
            // The account is the folder name.
            let account = rest.rsplit('/').nth(1).unwrap_or_default();
            let mut e = Extract { secret: true, ..Extract::default() };
            e.entry(account);
            ("gcloud", e)
        }
        _ if rest.contains(".config/gcloud/configurations/") => ("gcloud", gcloud_config(&text)),
        _ => (name_tool(name), Extract::default()),
    };
    sink.emit(
        Loc::None,
        &Found {
            tool,
            user: user_from_path(path).into(),
            file: rest.into(),
            size_bytes: input.data.len() as u64,
            modified: (input.mtime > 0).then(|| Timestamp::from_secs(input.mtime, Basis::Recorded)),
            mode: if input.mode == 0 { String::new() } else { format!("{:o}", input.mode & 0o7777) },
            entries: extract.entries,
            details: extract.details,
            holds_secret: extract.secret,
        },
    )
}

fn name_tool(_name: &str) -> &'static str {
    "unknown"
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};
    use nixcavate_source::glob::Pattern;
    use std::collections::BTreeSet;

    /// The files of `test_files/credential-files/tree` (built by the real aws, kubectl, npm, git,
    /// vault and docker; gcloud, az, terraform, oci, pypirc, netrc and gh are in their documented
    /// formats), as `(path relative to the host root, bytes)`.
    fn tree() -> Vec<(String, Vec<u8>)> {
        fn walk(dir: &std::path::Path, base: &std::path::Path, out: &mut Vec<(String, Vec<u8>)>) {
            for item in std::fs::read_dir(dir).unwrap().flatten() {
                let path = item.path();
                if path.is_dir() {
                    walk(&path, base, out);
                } else {
                    out.push((
                        path.strip_prefix(base).unwrap().to_str().unwrap().to_string(),
                        std::fs::read(&path).unwrap(),
                    ));
                }
            }
        }
        let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test_files/credential-files/tree");
        let mut out = Vec::new();
        walk(&base, &base, &mut out);
        out.sort();
        out
    }

    fn matches(path: &str) -> bool {
        ARTIFACT.paths.iter().any(|p| Pattern::new(p).matches(path))
    }

    fn rows() -> Vec<(String, serde_json::Value, String)> {
        tree()
            .into_iter()
            .filter(|(p, _)| matches(p))
            .map(|(p, d)| {
                let out = run(&ARTIFACT, &p, &d, 1_700_000_000);
                assert!(!out.contains("--- warning") && !out.contains("--- failed"), "{p}: {out}");
                let row: serde_json::Value = serde_json::from_str(out.lines().next().unwrap()).unwrap();
                (p, row, out)
            })
            .collect()
    }

    fn row<'a>(rows: &'a [(String, serde_json::Value, String)], suffix: &str) -> &'a serde_json::Value {
        &rows.iter().find(|(p, _, _)| p.ends_with(suffix)).unwrap_or_else(|| panic!("{suffix}")).1
    }

    fn list(v: &serde_json::Value) -> Vec<String> {
        v.as_array().unwrap().iter().map(|s| s.as_str().unwrap().to_string()).collect()
    }

    /// The point of the artifact: no secret of any fixture file may reach any output. The secrets
    /// are the `PLANTED-*` strings the build script put in, plus the base64 `auth` Docker stored.
    #[test]
    fn no_planted_secret_reaches_any_output() {
        let files = tree();
        let mut secrets = BTreeSet::new();
        for (_, data) in &files {
            let text = String::from_utf8_lossy(data);
            let mut rest = text.as_ref();
            while let Some(at) = rest.find("PLANTED-") {
                let end =
                    rest[at..].find(|c: char| !(c.is_ascii_alphanumeric() || c == '-')).map_or(rest.len(), |e| at + e);
                secrets.insert(rest[at..end].to_string());
                rest = &rest[end..];
            }
        }
        secrets.insert("YWxpY2U6UExBTlRFRC1SRUdJU1RSWS1QQVNTV09SRC0wMDA3".into());
        assert!(secrets.len() >= 18, "{secrets:?}");
        let rows = rows();
        assert!(rows.len() >= 17, "{}", rows.len());
        for (path, _, out) in &rows {
            for secret in &secrets {
                assert!(!out.contains(secret.as_str()), "{path} leaks {secret}");
            }
            // An AWS access key ID appears only as its first and last four characters.
            assert!(!out.contains("AKIAEXAMPLEPLANTED"), "{path}");
        }
    }

    /// The tools' own listings are the truth for the names.
    #[test]
    fn names_equal_what_the_tools_list() {
        let rows = rows();
        let truth = |n: &str| String::from_utf8(fixture(&format!("credential-files/truth/{n}"))).unwrap();
        // `aws configure list-profiles`
        let mut profiles: Vec<String> =
            truth("aws.truth.txt").lines().take_while(|l| !l.contains("WARNING")).map(str::to_string).collect();
        profiles.sort();
        let mut found = list(&row(&rows, ".aws/config")["entries"]);
        found.sort();
        assert_eq!(found, profiles);
        let creds = row(&rows, ".aws/credentials");
        assert_eq!(list(&creds["entries"]), ["default", "prod"]);
        assert_eq!(creds["holds_secret"], true);
        assert!(list(&creds["details"]).contains(&"default: access key AKIA...ED01".to_string()), "{creds}");
        assert!(list(&row(&rows, ".aws/config")["details"])
            .contains(&"assume: role_arn=arn:aws:iam::123456789012:role/Admin".to_string()));
        // `kubectl config get-contexts`
        let kube = row(&rows, ".kube/config");
        assert!(truth("kube.truth.txt").contains("demo"));
        assert_eq!(list(&kube["entries"]), ["demo"]);
        assert!(list(&kube["details"]).contains(&"cluster demo: 203.0.113.10:6443".to_string()), "{kube}");
        assert_eq!(kube["holds_secret"], true);
        // `npm config list` shows both registries' tokens as (protected)
        let npm = row(&rows, ".npmrc");
        for host in list(&npm["entries"]) {
            assert!(truth("npm.truth.txt").contains(&format!("//{host}/:_authToken")), "{host}");
        }
        assert_eq!(list(&npm["entries"]).len(), 2);
        // `docker login localhost:5055 -u alice`
        let docker = row(&rows, ".docker/config.json");
        assert!(truth("docker.truth.txt").contains("Login Succeeded"));
        assert_eq!(list(&docker["entries"]), ["localhost:5055"]);
        assert_eq!(list(&docker["details"]), ["localhost:5055: user alice"]);
        let git = row(&rows, ".git-credentials");
        assert_eq!(list(&git["entries"]), ["https://github.com", "https://git.example.com"]);
        assert!(list(&git["details"]).contains(&"git.example.com: user alice".to_string()));
        assert_eq!(row(&rows, ".vault-token")["holds_secret"], true);
        assert!(truth("vault.truth.txt").contains("Success"));
    }

    #[test]
    fn documented_formats_name_accounts_and_registries() {
        let rows = rows();
        assert_eq!(list(&row(&rows, ".azure/azureProfile.json")["entries"]), ["Example Subscription"]);
        assert!(
            list(&row(&rows, ".azure/azureProfile.json")["details"])[0].contains("user alice@example.com (default)")
        );
        assert_eq!(row(&rows, ".azure/msal_token_cache.json")["holds_secret"], true);
        assert_eq!(list(&row(&rows, "gcloud/configurations/config_default")["entries"]), ["alice@example.com"]);
        assert_eq!(list(&row(&rows, "adc.json")["entries"]), ["ci@example-project.iam.gserviceaccount.com"]);
        assert_eq!(row(&rows, "access_tokens.db")["tool"], "gcloud");
        assert_eq!(list(&row(&rows, ".netrc")["entries"]), ["ftp.example.com", "api.example.com", "default"]);
        assert!(list(&row(&rows, ".netrc")["details"]).contains(&"api.example.com: login bob".to_string()));
        assert_eq!(list(&row(&rows, ".pypirc")["entries"]), ["pypi", "internal"]);
        assert!(list(&row(&rows, ".pypirc")["details"]).contains(&"internal: username=alice".to_string()));
        assert_eq!(
            list(&row(&rows, ".terraform.d/credentials.tfrc.json")["entries"]),
            ["app.terraform.io", "tfe.example.com"]
        );
        let oci = row(&rows, ".oci/config");
        assert_eq!(list(&oci["entries"]), ["DEFAULT"]);
        assert!(list(&oci["details"]).contains(&"DEFAULT: region=us-ashburn-1".to_string()));
        assert_eq!(list(&row(&rows, "gh/hosts.yml")["entries"]), ["github.com"]);
        assert!(list(&row(&rows, "gh/hosts.yml")["details"]).contains(&"github.com: user alice".to_string()));
        // Size and times come from the file, the user from the path.
        let aws = row(&rows, ".aws/credentials");
        assert_eq!((aws["user"].as_str(), aws["file"].as_str()), (Some("alice"), Some(".aws/credentials")));
        assert_eq!(aws["modified"], "2023-11-14T22:13:20Z");
        assert!(aws["size_bytes"].as_u64().unwrap() > 100);
        assert!(matches("root/.aws/credentials") && matches("home/bob/.config/gcloud/legacy_credentials/x@y/adc.json"));
        assert!(!matches("home/alice/.oci/oci_api_key.pem"));
    }

    #[test]
    fn odd_input_gives_a_record_not_a_panic() {
        for (path, data) in [
            ("root/.aws/credentials", &b""[..]),
            ("root/.docker/config.json", b"{\"auths\":{\"r\":{\"auth\":\"!!!\"}},\"credsStore\":5}"),
            ("root/.docker/config.json", b"[1]"),
            ("root/.kube/config", b"\xff\xfe"),
            ("root/.netrc", b"machine"),
            ("root/.netrc", b"login password machine password"),
            ("root/.git-credentials", b"https://@\nhttps://:@h\nnot a url"),
            ("root/.npmrc", b"//:_authToken=\n//x/:\n=="),
            ("root/.oci/config", b"[\n[x\nkey_file"),
            ("root/.azure/azureProfile.json", b"\xef\xbb\xbf{\"subscriptions\":5}"),
        ] {
            let out = run(&ARTIFACT, path, data, 0);
            assert!(out.contains("\"artifact\":\"credential-files\""), "{path}: {out}");
        }
        assert_eq!(key_hint("short"), "(short)");
        assert_eq!(base64_user("YWxpY2U6eA=="), Some("alice".to_string()));
        assert_eq!(base64_user("!!"), None);
    }

    #[test]
    fn mutated_files_never_panic() {
        let mut state = 0x2545_f491_4f6c_dd1du64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let files: Vec<_> = tree().into_iter().filter(|(p, _)| matches(p)).collect();
        for round in 0..300 {
            for (path, original) in &files {
                let mut data = original.clone();
                if data.is_empty() {
                    continue;
                }
                for _ in 0..=(round % 5) {
                    let at = (next() as usize) % data.len();
                    data[at] = next() as u8;
                }
                if round % 4 == 0 {
                    data.truncate((next() as usize) % data.len());
                }
                run(&ARTIFACT, path, &data, 0);
            }
        }
    }
}
