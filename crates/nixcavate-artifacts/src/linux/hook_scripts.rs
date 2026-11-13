//! Files that run code at login, at network changes or early in boot, as root, and are plain
//! shell or `Key=value` text: message-of-the-day scripts (`update-motd.d`, run by pam_motd at
//! every login on Debian and Ubuntu), NetworkManager dispatcher scripts (run on every
//! connection event), systemd generators in `/etc` (run at early boot and on every reload) and
//! the variables PAM and systemd put into every session (`pam_env.conf`, `environment.d`).
//! Formats: pam_motd(8), NetworkManager-dispatcher(8), systemd.generator(7), pam_env.conf(5),
//! environment.d(5). The shell files are read as `rc.local` is: one record per active line.

use crate::common::script;
use crate::{Artifact, Category, LINUX};

pub const MOTD: Artifact = Artifact::new(
    "motd-scripts",
    "Message-of-the-day scripts run as root at login",
    Category::Persistence,
    LINUX,
    &["etc/update-motd.d/*"],
    script::content_lines,
);

pub const NM_DISPATCHER: Artifact = Artifact::new(
    "nm-dispatcher",
    "NetworkManager dispatcher scripts",
    Category::Persistence,
    LINUX,
    &["etc/NetworkManager/dispatcher.d/*", "etc/NetworkManager/dispatcher.d/*/*"],
    script::content_lines,
);

/// Generators shipped by a distribution live in `usr/lib`; one in `etc` was put there by an
/// administrator (or an attacker). The files are programs, so their metadata is what is read.
pub const GENERATORS: Artifact = Artifact::new(
    "systemd-generators",
    "systemd generators in /etc",
    Category::Persistence,
    LINUX,
    &["etc/systemd/system-generators/*", "etc/systemd/user-generators/*"],
    script::file_info,
);

pub const ENVIRONMENT: Artifact = Artifact::new(
    "env-config",
    "pam_env.conf and environment.d variables set for every session",
    Category::Persistence,
    LINUX,
    &["etc/security/pam_env.conf", "etc/environment.d/*.conf"],
    script::content_lines,
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::run;
    use nixcavate_source::glob::Pattern;

    #[test]
    fn motd_script_lists_active_lines() {
        let out = run(&MOTD, "etc/update-motd.d/99-x", b"#!/bin/sh\n# note\n\n/tmp/.x/agent &\n", 0);
        assert_eq!(out.matches("\"text\"").count(), 1, "{out}");
        assert!(out.contains("\"text\":\"/tmp/.x/agent &\""), "{out}");
    }

    #[test]
    fn patterns_cover_the_documented_locations() {
        let matches = |a: &Artifact, path: &str| a.paths.iter().any(|p| Pattern::new(p).matches(path));
        assert!(matches(&NM_DISPATCHER, "etc/NetworkManager/dispatcher.d/20-x"));
        assert!(matches(&NM_DISPATCHER, "etc/NetworkManager/dispatcher.d/pre-up.d/20-x"));
        assert!(matches(&GENERATORS, "etc/systemd/system-generators/x"));
        assert!(!matches(&GENERATORS, "usr/lib/systemd/system-generators/x"));
        assert!(matches(&ENVIRONMENT, "etc/security/pam_env.conf"));
        assert!(matches(&ENVIRONMENT, "etc/environment.d/10-x.conf"));
    }

    #[test]
    fn empty_and_garbage_inputs_do_not_panic() {
        for artifact in [&MOTD, &NM_DISPATCHER, &GENERATORS, &ENVIRONMENT] {
            run(artifact, "etc/x", b"", 0);
            run(artifact, "etc/x", b"\xff\xfe\0#!\x80\n\0\0", 0);
        }
    }

    /// Every byte of a real-looking input replaced by awkward values, and every truncation:
    /// no parser of this change may panic or loop.
    #[test]
    fn mutated_inputs_do_not_panic() {
        use crate::linux::{kernel_modules, logrotate, sshd_config, systemd_units};
        let seeds: [(&Artifact, &str, &[u8]); 7] = [
            (&MOTD, "etc/update-motd.d/99-x", b"#!/bin/sh\n# x\n/tmp/.x/agent >/dev/null 2>&1 &\nexit 0\n"),
            (
                &ENVIRONMENT,
                "etc/security/pam_env.conf",
                b"# c\nLD_PRELOAD DEFAULT=/x.so OVERRIDE=\"/y.so\"\nPATH=/tmp:/usr/bin\n",
            ),
            (&GENERATORS, "etc/systemd/system-generators/g", b"#!/bin/sh\necho x\n"),
            (
                &logrotate::ARTIFACT,
                "etc/logrotate.d/x",
                b"/var/log/x {\n weekly\n postrotate\n  /tmp/a &\n endscript\n}\n",
            ),
            (
                &sshd_config::ARTIFACT,
                "etc/ssh/sshd_config",
                b"AuthorizedKeysCommand=/x %u\nMatch User a\n ForceCommand internal-sftp\n",
            ),
            (&kernel_modules::ARTIFACT, "etc/modules-load.d/x.conf", b"# m\nbr_netfilter\nnxmk_x\\\n y\n"),
            (
                &systemd_units::ENABLEMENT,
                "etc/systemd/system/a.target.wants/b.service",
                b"/etc/systemd/system/b.service",
            ),
        ];
        let mut runs = 0;
        for (artifact, path, seed) in seeds {
            for i in 0..=seed.len() {
                run(artifact, path, &seed[..i], 0);
                runs += 1;
                for byte in [0u8, 0xff, b'\n', b'=', b'\\', b'[', b' ', b'$', b'"'] {
                    let mut data = seed.to_vec();
                    if let Some(slot) = data.get_mut(i) {
                        *slot = byte;
                    }
                    run(artifact, path, &data, 0);
                    runs += 1;
                }
            }
        }
        assert!(runs > 500, "{runs}");
    }
}
