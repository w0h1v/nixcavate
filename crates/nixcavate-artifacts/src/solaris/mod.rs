//! Solaris and illumos artifacts. Most formats here were checked against illumos (OmniOS); each
//! module says which parts are built from the Oracle Solaris documentation only.

pub mod at_jobs;
pub mod crle;
pub mod cron_log;
pub mod default_files;
pub mod etc_system;
pub mod inittab;
pub mod ips_history;
pub mod ips_packages;
pub mod kernel_drv;
pub mod lastlog;
pub mod loginlog;
pub mod pam_conf;
pub mod project;
pub mod rbac;
pub mod rc_scripts;
pub mod rhosts;
pub mod shadow;
pub mod smf_logs;
pub mod smf_manifests;
pub mod smf_repository;
pub mod sqlite2;
pub mod sulog;
pub mod svr4;
pub mod utmpx;
pub mod when;
pub mod xml;

use crate::Artifact;

pub static ARTIFACTS: &[Artifact] = &[
    utmpx::WTMPX,
    utmpx::UTMPX,
    lastlog::ARTIFACT,
    sulog::ARTIFACT,
    loginlog::ARTIFACT,
    cron_log::ARTIFACT,
    smf_logs::ARTIFACT,
    ips_history::ARTIFACT,
    ips_packages::ARTIFACT,
    svr4::PKGINFO,
    svr4::CONTENTS,
    smf_repository::ARTIFACT,
    smf_manifests::ARTIFACT,
    shadow::ARTIFACT,
    rbac::USER_ATTR,
    rbac::RBAC,
    project::ARTIFACT,
    at_jobs::ARTIFACT,
    inittab::ARTIFACT,
    rc_scripts::ARTIFACT,
    etc_system::ARTIFACT,
    default_files::ARTIFACT,
    crle::ARTIFACT,
    kernel_drv::ARTIFACT,
    pam_conf::ARTIFACT,
    rhosts::ARTIFACT,
];

/// Runs a parser over truncations and byte changes of a real file: it must neither panic nor
/// hang, whatever the bytes. Roughly 1500 truncations and 3000 changes, whatever the size.
#[cfg(test)]
pub(crate) fn never_panics(artifact: &Artifact, path: &str, data: &[u8]) {
    use crate::testing::run;
    let step = (data.len() / 1500).max(1);
    for len in (0..data.len()).step_by(step) {
        run(artifact, path, &data[..len], 1_700_000_000);
    }
    let mut changed = data.to_vec();
    for i in (0..data.len()).step_by(step) {
        let old = changed[i];
        for byte in [old ^ 0xff, 0, 0xff] {
            changed[i] = byte;
            run(artifact, path, &changed, 1_700_000_000);
        }
        changed[i] = old;
    }
    run(artifact, path, b"", 0);
}
