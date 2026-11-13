//! Linux artifacts.

pub mod alternatives;
pub mod anacron;
pub mod apk;
pub mod apt_history;
pub mod at_jobs;
pub mod audit;
pub mod auth_log;
pub mod bdb_hash;
pub mod bodyfile;
pub mod bolt;
pub mod boot_scripts;
pub mod cloud_init;
pub mod container_config;
pub mod containerd;
pub mod crash_reports;
pub mod cups_logs;
pub mod desktop_activity;
pub mod dmesg;
pub mod docker;
pub mod dpkg;
pub mod firewall;
pub mod flatpak;
pub mod ftp_logs;
pub mod group;
pub mod hook_scripts;
pub mod java_logs;
pub mod journald;
pub mod kernel_modules;
pub mod lastlog;
pub mod ld_preload;
pub mod login_db;
pub mod login_failures;
pub mod logrotate;
pub mod mail_logs;
pub mod modsec_audit;
pub mod mysql_logs;
pub mod net_service_logs;
pub mod networkmanager;
pub mod opasswd;
pub mod pacct;
pub mod pacman;
pub mod pam;
pub mod passwd;
mod passwd_lookup;
pub mod pkg_logs;
pub mod podman;
pub mod portage;
pub mod postgres_log;
pub mod proxy_logs;
pub mod remote_clients;
pub mod resolv_conf;
pub mod rpm_db;
pub mod rpm_ndb;
pub mod samba_log;
pub mod shadow;
pub mod snap;
pub mod sshd_config;
pub mod sudo_logs;
pub mod sudoers;
pub mod syslog;
pub mod sysstat;
pub mod systemd_units;
pub mod tdnf;
pub mod uac_live;
pub mod udev_rules;
pub mod usb_devices;
pub mod utmp;
pub mod xbps;
pub mod xdg_autostart;
pub mod yum_dnf;
pub mod yum_history;
pub mod zypp;

// Kubernetes, cloud agents and remote-access tools.
pub mod cloud_agents;
pub mod containerd_containers;
pub mod credential_files;
pub mod ini_lite;
pub mod k8s_audit;
pub mod k8s_manifests;
pub mod k8s_node_config;
pub mod k8s_pod_logs;
#[cfg(test)]
mod k8s_testdata;
pub mod remote_access;
pub mod yaml_lite;

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
    systemd_units::ENABLEMENT,
    hook_scripts::MOTD,
    hook_scripts::NM_DISPATCHER,
    hook_scripts::GENERATORS,
    hook_scripts::ENVIRONMENT,
    logrotate::ARTIFACT,
    sshd_config::ARTIFACT,
    apk::INSTALLED,
    apk::WORLD,
    zypp::HISTORY,
    portage::LOG,
    portage::DB,
    xbps::ARTIFACT,
    tdnf::HISTORY,
    alternatives::ARTIFACT,
    yum_history::HISTORY,
    yum_history::YUMDB,
    pacman::LOG,
    pacman::DB,
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
    containerd::ARTIFACT,
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
    dmesg::ARTIFACT,
    cloud_init::LOG,
    cloud_init::OUTPUT,
    cloud_init::USER_DATA,
    pkg_logs::UNATTENDED_UPGRADES,
    pkg_logs::DNF_DEBUG,
    pkg_logs::ZYPPER,
    pacct::ARTIFACT,
    login_failures::FAILLOCK,
    login_failures::TALLYLOG,
    login_failures::FAILLOG,
    crash_reports::COREDUMP,
    crash_reports::APPORT,
    crash_reports::ABRT,
    crash_reports::KERNEL_CRASH,
    sudo_logs::IOLOG,
    sudo_logs::LOG,
    sudo_logs::TIMESTAMPS,
    sudo_logs::LECTURED,
    opasswd::ARTIFACT,
    sysstat::ARTIFACT,
    mail_logs::ARTIFACT,
    postgres_log::ARTIFACT,
    proxy_logs::HAPROXY,
    proxy_logs::SQUID_ACCESS,
    proxy_logs::SQUID_CACHE,
    ftp_logs::VSFTPD,
    ftp_logs::XFERLOG,
    net_service_logs::NAMED,
    net_service_logs::FAIL2BAN,
    net_service_logs::DHCPD_LEASES,
    net_service_logs::DHCLIENT_LEASES,
    samba_log::SAMBA,
    samba_log::SAMBA_AUDIT,
    mysql_logs::ERROR_LOG,
    mysql_logs::GENERAL_LOG,
    mysql_logs::SLOW_LOG,
    modsec_audit::ARTIFACT,
    java_logs::TOMCAT,
    desktop_activity::RECENT,
    desktop_activity::TRASH,
    desktop_activity::THUMBNAILS,
    usb_devices::ARTIFACT,
    cups_logs::PAGE_LOG,
    cups_logs::JOBS,
    remote_clients::REMMINA,
    remote_clients::FILEZILLA,
    k8s_pod_logs::ARTIFACT,
    k8s_audit::ARTIFACT,
    k8s_manifests::ARTIFACT,
    k8s_node_config::KUBELET,
    k8s_node_config::KUBECONFIG,
    k8s_node_config::CNI,
    containerd_containers::ARTIFACT,
    credential_files::ARTIFACT,
    cloud_agents::SSM_LOG,
    cloud_agents::WAAGENT_LOG,
    cloud_agents::REMOTE_EXEC,
    cloud_agents::AZURE_PROVISIONING,
    remote_access::CONFIG,
    remote_access::LOGS,
    remote_access::SESSIONS,
];
