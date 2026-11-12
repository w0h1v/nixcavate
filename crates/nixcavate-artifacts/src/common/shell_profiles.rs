//! Shell startup files, system-wide and per user: code here runs at every login or shell start.
//! Per-user files are listed under each home root (Linux `home/*`, `root`; macOS `Users/*`,
//! `private/var/root`).

use crate::common::script;
use crate::{Artifact, Category, ANY_OS};

pub const ARTIFACT: Artifact = Artifact::new(
    "shell-profiles",
    "Shell startup files (profile, bashrc, zshrc, fish config)",
    Category::Persistence,
    ANY_OS,
    &[
        "etc/profile",
        "etc/profile.d/*",
        "etc/profile.local",
        "etc/bash.bashrc.local",
        "etc/bash.bashrc",
        "etc/bashrc",
        "etc/zsh/*",
        "etc/zshrc",
        "etc/zprofile",
        "etc/zshenv",
        "etc/environment",
        "private/etc/profile",
        "private/etc/zshrc",
        "private/etc/zprofile",
        "private/etc/bashrc",
        "home/*/.bashrc",
        "home/*/.bash_profile",
        "home/*/.bash_login",
        "home/*/.bash_logout",
        "home/*/.profile",
        "home/*/.zshrc",
        "home/*/.zprofile",
        "home/*/.zshenv",
        "home/*/.zlogin",
        "home/*/.zlogout",
        "home/*/.config/fish/config.fish",
        "root/.bashrc",
        "home/*/.bashrc.d/*",
        "root/.bashrc.d/*",
        "root/.bash_profile",
        "root/.bash_login",
        "root/.bash_logout",
        "root/.profile",
        "root/.zshrc",
        "root/.zprofile",
        "root/.zshenv",
        "root/.zlogin",
        "root/.zlogout",
        "root/.config/fish/config.fish",
        "Users/*/.bashrc",
        "Users/*/.bash_profile",
        "Users/*/.bash_login",
        "Users/*/.bash_logout",
        "Users/*/.profile",
        "Users/*/.zshrc",
        "Users/*/.zprofile",
        "Users/*/.zshenv",
        "Users/*/.zlogin",
        "Users/*/.zlogout",
        "Users/*/.config/fish/config.fish",
        "private/var/root/.bashrc",
        "private/var/root/.bash_profile",
        "private/var/root/.bash_login",
        "private/var/root/.bash_logout",
        "private/var/root/.profile",
        "private/var/root/.zshrc",
        "private/var/root/.zprofile",
        "private/var/root/.zshenv",
        "private/var/root/.zlogin",
        "private/var/root/.zlogout",
        "private/var/root/.config/fish/config.fish",
    ],
    script::content_lines,
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    #[test]
    fn lists_active_lines_of_a_user_bashrc() {
        insta::assert_snapshot!(run(&ARTIFACT, "home/alice/.bashrc", &fixture("shell-profiles/bashrc"), 0));
    }

    #[test]
    fn suse_and_bashrc_d_files_are_covered() {
        use nixcavate_source::glob::Pattern;
        for path in ["etc/profile.local", "etc/bash.bashrc.local", "home/alice/.bashrc.d/x", "root/.bashrc.d/x"] {
            assert!(ARTIFACT.paths.iter().any(|p| Pattern::new(p).matches(path)), "{path}");
        }
    }

    #[test]
    fn empty_and_garbage_inputs_do_not_panic() {
        run(&ARTIFACT, "etc/profile", b"", 0);
        run(&ARTIFACT, "etc/profile", b"\xff\xfe\0\r\r\n\x80", 0);
    }
}
