//! SysV boot scripts: `rc.local` (commands run at the end of boot) and `init.d` scripts.
//! Both are plain shell, so the generic script parsers apply.

use crate::common::script;
use crate::{Artifact, Category, LINUX};

pub const RC_LOCAL: Artifact = Artifact::new(
    "rc-local",
    "rc.local boot commands",
    Category::Persistence,
    LINUX,
    &["etc/rc.local", "etc/rc.d/rc.local"],
    script::content_lines,
);

pub const INIT_D: Artifact = Artifact::new(
    "init-d",
    "SysV init scripts",
    Category::Persistence,
    LINUX,
    &["etc/init.d/*", "etc/rc.d/init.d/*"],
    script::file_info,
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    #[test]
    fn rc_local_lists_commands() {
        insta::assert_snapshot!(run(&RC_LOCAL, "etc/rc.local", &fixture("rc-local/rc.local"), 0));
    }

    #[test]
    fn init_d_reports_script_metadata() {
        insta::assert_snapshot!(run(&INIT_D, "etc/init.d/cron", &fixture("init-d/cron"), 1_700_000_000));
    }

    #[test]
    fn empty_and_garbage_inputs_do_not_panic() {
        for artifact in [&RC_LOCAL, &INIT_D] {
            run(artifact, "etc/rc.local", b"", 0);
            run(artifact, "etc/rc.local", b"\xff\xfe\0#!\x80", 0);
        }
    }
}
