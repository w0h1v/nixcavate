#![no_main]
use nixcavate_fuzz::fuzz_target;
use nixcavate_source::Tz;

// `/etc/localtime` comes from the evidence.
fuzz_target!(|data: &[u8]| {
    if let Some(tz) = Tz::parse(data) {
        for t in [i64::MIN, -1, 0, 1_700_000_000, 4_102_444_800, i64::MAX] {
            let _ = tz.offset_at(t);
            let _ = tz.to_utc(t);
        }
    }
});
