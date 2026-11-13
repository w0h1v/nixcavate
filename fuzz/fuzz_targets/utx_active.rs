#![no_main]
// The fixed-record form of the same artifact (`utx.lastlogin`, `utx.active`).
nixcavate_fuzz::artifact_target!("utx", "var/run/utx.active");
