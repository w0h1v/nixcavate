#![no_main]
use nixcavate_fuzz::fuzz_target;

// Hostile RAID member images and a hostile fstab: assembling the arrays, reading them and
// resolving the mounts must return, whatever the bytes are.
fuzz_target!(|data: &[u8]| {
    nixcavate_source::fuzz_raid(data);
});
