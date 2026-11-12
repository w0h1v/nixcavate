//! macOS artifacts.

pub mod asl;
pub mod biome;
pub mod btm;
pub mod dslocal;
pub mod emond;
pub mod extensions;
pub mod fsevents;
pub mod gatekeeper;
pub mod install_history;
pub mod install_log;
pub mod knowledgec;
pub mod launchd;
pub mod plist_util;
pub mod profiles;
pub mod quarantine;
pub mod safari;
pub mod system_log;
pub mod tcc;
pub mod unified_log;
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
];
