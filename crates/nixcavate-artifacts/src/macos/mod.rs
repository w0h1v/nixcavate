//! macOS artifacts.

pub mod asl;
pub mod biome;
pub mod bookmark;
pub mod btm;
pub mod communications;
pub mod crash_reports;
pub mod ds_store;
pub mod dslocal;
pub mod emond;
pub mod extensions;
pub mod fsevents;
pub mod gatekeeper;
pub mod install_history;
pub mod install_log;
pub mod keyed_archive;
pub mod knowledgec;
pub mod launchd;
pub mod legacy_persistence;
pub mod netusage;
pub mod plist_util;
pub mod powerlog;
pub mod profiles;
pub mod quarantine;
pub mod rosetta;
pub mod safari;
pub mod security_db;
pub mod sharedfilelist;
pub mod system_log;
pub mod system_state;
pub mod tcc;
pub mod unified_log;
pub mod user_prefs;
pub mod util;
pub mod web_cache;
pub mod wifi;

use crate::Artifact;

pub static ARTIFACTS: &[Artifact] = &[
    knowledgec::ARTIFACT,
    biome::ARTIFACT,
    safari::HISTORY,
    safari::DOWNLOADS,
    system_log::ARTIFACT,
    install_log::ARTIFACT,
    asl::ARTIFACT,
    fsevents::ARTIFACT,
    launchd::ARTIFACT,
    btm::ARTIFACT,
    emond::ARTIFACT,
    extensions::KEXTS,
    extensions::SYSTEM_EXTENSIONS,
    profiles::ARTIFACT,
    unified_log::ARTIFACT,
    tcc::ARTIFACT,
    quarantine::ARTIFACT,
    gatekeeper::POLICY,
    gatekeeper::XPROTECT,
    install_history::ARTIFACT,
    dslocal::ARTIFACT,
    wifi::ARTIFACT,
    powerlog::ARTIFACT,
    crash_reports::ARTIFACT,
    rosetta::ARTIFACT,
    netusage::NETUSAGE,
    netusage::DHCP_LEASES,
    netusage::NETWORK_INTERFACES,
    sharedfilelist::ARTIFACT,
    web_cache::URL_CACHE,
    web_cache::COOKIES,
    web_cache::HSTS,
    ds_store::ARTIFACT,
    user_prefs::FINDER,
    user_prefs::DOCK,
    user_prefs::LOGINWINDOW,
    user_prefs::SPOTLIGHT_SHORTCUTS,
    system_state::PKG_RECEIPTS,
    system_state::CONFIG_PROFILES,
    system_state::APPLICATION_FIREWALL,
    system_state::BLUETOOTH,
    system_state::TIME_MACHINE,
    system_state::LOCKDOWN,
    security_db::AUTH_DB,
    security_db::EXEC_POLICY,
    legacy_persistence::STARTUP_ITEMS,
    legacy_persistence::RC_FILES,
    legacy_persistence::FOLDER_ACTIONS,
    legacy_persistence::PLUGINS,
    communications::MESSAGES,
    communications::MAIL,
    communications::CALLS,
];
