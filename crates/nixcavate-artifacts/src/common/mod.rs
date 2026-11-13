//! Artifacts found on both Linux and macOS, and helpers shared between parsers.

pub mod authorized_keys;
pub mod bash_history;
pub mod bsm;
pub mod chromium;
pub mod cron;
pub mod firefox;
pub mod fish_history;
pub mod home;
pub mod hosts;
pub mod logfmt;
pub mod script;
pub mod shell_profiles;
pub mod sql_redact;
pub mod ssh_config;
pub mod ssh_key;
pub mod ssh_known_hosts;
pub mod stamped_log;
pub mod syslog;
pub mod tool_history;
pub mod viminfo;
pub mod web_logs;
pub mod year;
pub mod zsh_history;

use crate::Artifact;

pub static ARTIFACTS: &[Artifact] = &[
    authorized_keys::ARTIFACT,
    shell_profiles::ARTIFACT,
    bash_history::ARTIFACT,
    zsh_history::ARTIFACT,
    fish_history::ARTIFACT,
    tool_history::PYTHON,
    tool_history::MYSQL,
    tool_history::LESS,
    viminfo::ARTIFACT,
    cron::CRON,
    cron::SCRIPTS,
    hosts::ARTIFACT,
    ssh_config::ARTIFACT,
    ssh_known_hosts::ARTIFACT,
    chromium::HISTORY,
    chromium::DOWNLOADS,
    firefox::HISTORY,
    firefox::DOWNLOADS,
    web_logs::ACCESS,
    web_logs::ERROR,
    tool_history::TOOLS,
    bsm::ARTIFACT,
    chromium::COOKIES,
    chromium::LOGINS,
    chromium::EXTENSION_SETTINGS,
    chromium::EXTENSIONS,
    firefox::EXTENSIONS,
    firefox::LOGINS,
    firefox::COOKIES,
    firefox::PREFS,
    firefox::USER_JS,
    firefox::SESSION,
];
