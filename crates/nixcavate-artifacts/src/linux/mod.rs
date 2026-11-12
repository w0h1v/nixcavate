//! Linux artifacts.

pub mod anacron;
pub mod apt_history;
pub mod at_jobs;
pub mod audit;
pub mod auth_log;
pub mod bdb_hash;
pub mod bodyfile;
pub mod boot_scripts;
pub mod container_config;
pub mod docker;
pub mod dpkg;
pub mod firewall;
pub mod flatpak;
pub mod group;
pub mod journald;
pub mod kernel_modules;
pub mod lastlog;
pub mod ld_preload;
pub mod login_db;
pub mod networkmanager;
pub mod pam;
pub mod passwd;
pub mod podman;
pub mod resolv_conf;
pub mod rpm_db;
pub mod shadow;
pub mod snap;
pub mod sudoers;
pub mod syslog;
pub mod systemd_units;
pub mod uac_live;
pub mod udev_rules;
pub mod utmp;
pub mod xdg_autostart;
pub mod yum_dnf;

use crate::Artifact;

pub static ARTIFACTS: &[Artifact] = &[
    passwd::ARTIFACT,
    utmp::WTMP,
    utmp::BTMP,
    utmp::UTMP,
    login_db::WTMPDB,
    login_db::LASTLOG2,
    shadow::ARTIFACT,
    group::ARTIFACT,
    sudoers::ARTIFACT,
    lastlog::ARTIFACT,
    boot_scripts::RC_LOCAL,
    boot_scripts::INIT_D,
    ld_preload::ARTIFACT,
    udev_rules::ARTIFACT,
    kernel_modules::ARTIFACT,
    pam::ARTIFACT,
    xdg_autostart::ARTIFACT,
    yum_dnf::YUM_LOG,
    yum_dnf::DNF_LOG,
    yum_dnf::DNF5_LOG,
    yum_dnf::DNF_HISTORY,
    rpm_db::ARTIFACT,
    snap::ARTIFACT,
    flatpak::ARTIFACT,
    audit::ARTIFACT,
    anacron::ARTIFACT,
    at_jobs::ARTIFACT,
    systemd_units::ARTIFACT,
    dpkg::STATUS,
    dpkg::LOG,
    apt_history::ARTIFACT,
    firewall::IPTABLES,
    firewall::NFTABLES,
    networkmanager::ARTIFACT,
    resolv_conf::ARTIFACT,
    docker::CONTAINERS,
    docker::LOGS,
    docker::IMAGES,
    podman::CONTAINERS,
    podman::IMAGES,
    container_config::ARTIFACT,
    syslog::ARTIFACT,
    auth_log::ARTIFACT,
    uac_live::PROCESSES,
    uac_live::NETWORK,
    uac_live::OPEN_FILES,
    uac_live::MODULES,
    bodyfile::ARTIFACT,
    journald::ARTIFACT,
];
