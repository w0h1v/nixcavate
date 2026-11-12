//! Container runtime configuration: Docker `daemon.json`, containerd `config.toml`, the
//! containers-registries.conf(5) and containers.conf(5) family, and crictl.yaml. A single
//! setting (an insecure registry, an exposed TCP socket, a mirror) can matter, so every
//! non-comment line is emitted. JSON files have no comments and are emitted whole.

use crate::common::script::content_lines;
use crate::{Artifact, Category, LINUX};

pub const ARTIFACT: Artifact = Artifact::new(
    "container-config",
    "Container runtime configuration files",
    Category::Containers,
    LINUX,
    &[
        "etc/docker/daemon.json",
        "etc/containerd/config.toml",
        "etc/containers/registries.conf",
        "etc/containers/registries.conf.d/*",
        "etc/containers/containers.conf",
        "etc/crictl.yaml",
    ],
    content_lines,
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    #[test]
    fn daemon_json_every_line() {
        insta::assert_snapshot!(run(&ARTIFACT, "etc/docker/daemon.json", &fixture("container-config/daemon.json"), 0));
    }

    #[test]
    fn registries_conf_skips_comments() {
        insta::assert_snapshot!(run(
            &ARTIFACT,
            "etc/containers/registries.conf",
            &fixture("container-config/registries.conf"),
            0
        ));
    }

    #[test]
    fn empty_file_has_no_records() {
        assert_eq!(run(&ARTIFACT, "etc/crictl.yaml", b"", 0), "");
    }
}
