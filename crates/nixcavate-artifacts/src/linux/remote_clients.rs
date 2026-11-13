//! Saved connections of desktop remote-access clients: Remmina profiles and FileZilla's server
//! lists. They show which servers a user connected to, as whom, and sometimes when.
//!
//! **Synthetic only.** No real Remmina or FileZilla could be driven headless here (both need their
//! GUI to create a profile), so these parsers follow the formats as documented by the projects and
//! their sample files, and are tested on synthetic fixtures. A record that does not fit is a
//! warning.
//!
//! Secrets are never output. Remmina's `password`, `ssh_password`, `ssh_passphrase` and every
//! other key whose name contains `password`, `passphrase` or `secret` are dropped, only whether a
//! password is saved is reported; FileZilla's `<Pass>` (base64 text, not encryption) and
//! `<Account>` elements are dropped the same way.

use crate::common::home::user_from_path;
use crate::linux::desktop_activity::{next_tag, unescape};
use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, UNIX};
use nixcavate_core::{Error, Event, Loc, Record, Result, Sink, Timestamp};
use serde::Serialize;

pub const REMMINA: Artifact = Artifact::new(
    "remmina-profiles",
    "Remmina saved connections: server, protocol and user (never the password)",
    Category::Network,
    UNIX,
    &[
        "home/*/.local/share/remmina/*.remmina",
        "home/*/.config/remmina/*.remmina",
        "home/*/.remmina/*.remmina",
        "home/*/.var/app/org.remmina.Remmina/data/remmina/*.remmina",
        "root/.local/share/remmina/*.remmina",
    ],
    parse_remmina,
);

pub const FILEZILLA: Artifact = Artifact::new(
    "filezilla-servers",
    "FileZilla recent servers and site manager entries: host and user (never the password)",
    Category::Network,
    UNIX,
    &[
        "home/*/.config/filezilla/recentservers.xml",
        "home/*/.config/filezilla/sitemanager.xml",
        "home/*/.filezilla/recentservers.xml",
        "home/*/.filezilla/sitemanager.xml",
        "root/.config/filezilla/recentservers.xml",
        "root/.config/filezilla/sitemanager.xml",
        "home/*/.var/app/org.filezillaproject.Filezilla/config/filezilla/recentservers.xml",
        "home/*/.var/app/org.filezillaproject.Filezilla/config/filezilla/sitemanager.xml",
    ],
    parse_filezilla,
);

#[derive(Serialize)]
struct Remmina<'a> {
    user: &'a str,
    name: String,
    group: Option<String>,
    protocol: Option<String>,
    server: Option<String>,
    username: Option<String>,
    domain: Option<String>,
    /// `ssh_tunnel_server` or `ssh_server`: the jump host of a tunnelled connection.
    ssh_server: Option<String>,
    ssh_username: Option<String>,
    /// A password is stored in the profile (its value is not read).
    password_saved: bool,
    /// `last_used`, when this Remmina version writes it (a local time, no zone).
    last_used: Option<Timestamp>,
}

impl Record for Remmina<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let message = format!(
            "{} connected {} {} as {}",
            self.user,
            self.protocol.as_deref().unwrap_or("?"),
            self.server.as_deref().unwrap_or("?"),
            self.username.as_deref().unwrap_or("?")
        );
        self.last_used.map(|t| Event::new(t, "remote_connection", message)).into_iter()
    }
}

fn secret_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    ["password", "passphrase", "secret", "pass"].iter().any(|k| key == *k || key.contains(k) && *k != "pass")
}

fn parse_remmina(input: &Input, sink: &mut Sink) -> Result<()> {
    let mut in_group = false;
    let mut profile: Option<Remmina> = None;
    let mut keys = 0;
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let text = text.trim();
        if text.starts_with('[') {
            in_group = text == "[remmina]";
            return Ok(());
        }
        let Some((key, value)) = text.split_once('=').filter(|_| in_group) else { return Ok(()) };
        keys += 1;
        let profile = profile.get_or_insert_with(|| Remmina {
            user: user_from_path(input.path),
            name: String::new(),
            group: None,
            protocol: None,
            server: None,
            username: None,
            domain: None,
            ssh_server: None,
            ssh_username: None,
            password_saved: false,
            last_used: None,
        });
        let value = value.trim();
        let owned = || Some(value.to_string()).filter(|v| !v.is_empty());
        if secret_key(key) {
            // The value is never looked at beyond "is there one".
            profile.password_saved |= key == "password" && !value.is_empty();
            return Ok(());
        }
        match key {
            "name" => profile.name = value.to_string(),
            "group" => profile.group = owned(),
            "protocol" => profile.protocol = owned(),
            "server" => profile.server = owned(),
            "username" => profile.username = owned(),
            "domain" => profile.domain = owned(),
            "ssh_tunnel_server" | "ssh_server" => profile.ssh_server = owned(),
            "ssh_tunnel_username" | "ssh_username" => profile.ssh_username = owned(),
            "last_used" => {
                profile.last_used = nixcavate_core::time::parse_iso8601(value.replacen(' ', "T", 1).as_bytes())
                    .or_else(|| {
                        nixcavate_core::time::parse_iso8601(format!("{}:00", value.replacen(' ', "T", 1)).as_bytes())
                    })
                    .map(|(parsed, _)| crate::common::stamped_log::timestamp(input, &parsed));
            }
            _ => {}
        }
        Ok(())
    })?;
    match profile {
        Some(mut p) => {
            if p.name.is_empty() {
                p.name = input.path.rsplit('/').next().unwrap_or_default().trim_end_matches(".remmina").to_string();
            }
            sink.emit(Loc::Line(1), &p)
        }
        None if keys == 0 => Err(Error::format("not a Remmina profile: no [remmina] group")),
        None => Err(Error::skipped("empty profile")),
    }
}

#[derive(Serialize)]
struct FileZillaServer<'a> {
    user: &'a str,
    /// `recent` (recentservers.xml) or `site` (sitemanager.xml).
    list: &'static str,
    name: Option<String>,
    server_host: String,
    port: Option<u32>,
    /// FileZilla's protocol number: 0 FTP (with or without TLS by `Encryption`), 1 SFTP; others as written.
    protocol: Option<u32>,
    username: Option<String>,
    /// 0 anonymous, 1 normal, 2 ask for password, 3 interactive, 4 account.
    logon_type: Option<u32>,
    remote_dir: Option<String>,
    local_dir: Option<String>,
    key_file: Option<String>,
    /// A `<Pass>` element with content is present (its value is not read).
    password_saved: bool,
}

impl Record for FileZillaServer<'_> {}

fn parse_filezilla(input: &Input, sink: &mut Sink) -> Result<()> {
    let text = lossy(input.data);
    if !text.contains("<FileZilla3") {
        return Err(Error::format("not a FileZilla settings file: no <FileZilla3> element"));
    }
    let list = if input.path.ends_with("sitemanager.xml") { "site" } else { "recent" };
    let user = user_from_path(input.path);
    let mut pos = 0;
    let mut current: Option<(u64, FileZillaServer)> = None;
    let mut field: Option<String> = None;
    let mut count = 0usize;
    while let Some(tag) = next_tag(&text, &mut pos) {
        if tag.name == "Server" && !tag.self_closing {
            if let Some((at, done)) = current.take() {
                sink.emit(Loc::Offset(at), &done)?;
            }
            count += 1;
            current = Some((
                tag.start as u64,
                FileZillaServer {
                    user,
                    list,
                    name: None,
                    server_host: String::new(),
                    port: None,
                    protocol: None,
                    username: None,
                    logon_type: None,
                    remote_dir: None,
                    local_dir: None,
                    key_file: None,
                    password_saved: false,
                },
            ));
            field = None;
        } else if tag.name == "/Server" {
            if let Some((at, done)) = current.take() {
                sink.emit(Loc::Offset(at), &done)?;
            }
        } else if let Some(name) = tag.name.strip_prefix('/') {
            let _ = name;
            field = None;
        } else if current.is_some() && !tag.self_closing {
            let content = unescape(text.get(pos..).unwrap_or_default().split('<').next().unwrap_or_default().trim());
            let Some((_, server)) = current.as_mut() else { continue };
            let some = || Some(content.clone()).filter(|c| !c.is_empty());
            match tag.name {
                "Host" => server.server_host = content.clone(),
                "Port" => server.port = content.parse().ok(),
                "Protocol" => server.protocol = content.parse().ok(),
                "User" => server.username = some(),
                "Logontype" => server.logon_type = content.parse().ok(),
                "Name" => server.name = some(),
                "RemoteDir" => server.remote_dir = some(),
                "LocalDir" => server.local_dir = some(),
                "Keyfile" => server.key_file = some(),
                // Present or not; the value is dropped here and never stored.
                "Pass" => server.password_saved |= !content.is_empty(),
                _ => {}
            }
            field = Some(tag.name.to_string());
        }
    }
    let _ = field;
    if let Some((at, done)) = current.take() {
        sink.emit(Loc::Offset(at), &done)?;
    }
    if count == 0 {
        return Err(Error::skipped("no servers"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::run;

    const REMMINA_PROFILE: &str = "[remmina]\nname=Build server\ngroup=Lab\nprotocol=RDP\nserver=10.1.2.3:3389\nusername=Administrator\ndomain=CORP\npassword=SECRET-PROFILE-PASSWORD\nssh_password=SECRET-SSH-PASSWORD\nssh_tunnel_server=jump.example.test\nssh_tunnel_username=tunnel\nssh_passphrase=SECRET-PASSPHRASE\nlast_used=2026-03-10 01:02\nresolution_mode=2\n";

    const FILEZILLA_XML: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<FileZilla3 version=\"3.60.0\" platform=\"*nix\"><Servers><Folder expanded=\"1\">Work<Server><Host>sftp.example.test</Host><Port>22</Port><Protocol>1</Protocol><Type>0</Type><User>alice</User><Pass encoding=\"base64\">U0VDUkVULUZaLVBBU1M=</Pass><Logontype>1</Logontype><Name>Prod &amp; staging</Name><RemoteDir>1 0 4 www 3 var</RemoteDir></Server></Folder><Server><Host>ftp.example.test</Host><Port>21</Port><Protocol>0</Protocol><User>anonymous</User><Logontype>0</Logontype></Server></Servers></FileZilla3>";

    #[test]
    fn remmina_profile_never_leaks_a_password() {
        let out = run(
            &REMMINA,
            "home/alice/.local/share/remmina/group_rdp_build_10-1-2-3.remmina",
            REMMINA_PROFILE.as_bytes(),
            0,
        );
        assert!(!out.contains("--- warning") && !out.contains("--- failed"), "{out}");
        assert!(!out.contains("SECRET"), "a secret leaked: {out}");
        assert!(
            out.contains("\"server\":\"10.1.2.3:3389\"")
                && out.contains("\"username\":\"Administrator\"")
                && out.contains("\"password_saved\":true"),
            "{out}"
        );
        assert!(
            out.contains("\"ssh_server\":\"jump.example.test\"")
                && out.contains("\"last_used\":\"2026-03-10T01:02:00Z\""),
            "{out}"
        );
        insta::assert_snapshot!(out);
        assert!(
            run(&REMMINA, "home/alice/.local/share/remmina/x.remmina", b"hello\n", 0).contains("not a Remmina profile")
        );
    }

    #[test]
    fn filezilla_lists_never_leak_a_password() {
        for file in ["recentservers.xml", "sitemanager.xml"] {
            let out = run(&FILEZILLA, &format!("home/alice/.config/filezilla/{file}"), FILEZILLA_XML.as_bytes(), 0);
            assert!(!out.contains("--- warning") && !out.contains("--- failed"), "{out}");
            assert!(!out.contains("U0VDUkVU") && !out.contains("SECRET"), "a secret leaked: {out}");
            assert_eq!(out.lines().take_while(|l| !l.starts_with("---")).count(), 2);
            assert!(
                out.contains("\"name\":\"Prod & staging\"")
                    && out.contains("\"password_saved\":true")
                    && out.contains("\"logon_type\":0"),
                "{out}"
            );
        }
        assert!(run(&FILEZILLA, "home/alice/.config/filezilla/sitemanager.xml", b"<x/>", 0).contains("not a FileZilla"));
    }

    #[test]
    fn hostile_input_never_panics() {
        let mut seed = 8u64;
        for (artifact, path, text) in [
            (&REMMINA, "home/a/.local/share/remmina/x.remmina", REMMINA_PROFILE),
            (&FILEZILLA, "home/a/.config/filezilla/sitemanager.xml", FILEZILLA_XML),
        ] {
            for cut in 0..text.len() {
                run(artifact, path, &text.as_bytes()[..cut], 0);
            }
            for _ in 0..1500 {
                let mut copy = text.as_bytes().to_vec();
                for _ in 0..3 {
                    seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                    let at = (seed >> 33) as usize % copy.len();
                    copy[at] = (seed >> 20) as u8;
                }
                run(artifact, path, &copy, 0);
            }
        }
    }
}
