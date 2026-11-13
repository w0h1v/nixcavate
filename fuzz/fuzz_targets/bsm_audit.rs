#![no_main]
// A FreeBSD host, so the event table is used as well as the token decoder.
nixcavate_fuzz::fuzz_target!(|data: &[u8]| {
    let artifact = nixcavate_artifacts::find("bsm-audit").expect("artifact id");
    let path = "var/audit/20260101000000.20260101000001";
    let files: [(&str, &[u8]); 2] = [("etc/freebsd-update.conf", b"x"), (path, data)];
    let _ = nixcavate_artifacts::testing::run_on_host(artifact, &files, path, 1_700_000_000);
});
