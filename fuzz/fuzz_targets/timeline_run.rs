#![no_main]
use nixcavate_core::{run::merge, Format};
use nixcavate_fuzz::fuzz_target;

// A run file is read back from disk by `super-timeline`; a damaged one must be an error.
fuzz_target!(|data: &[u8]| {
    let mut out = Vec::new();
    let _ = merge(&[data], Format::Csv, 2, &mut out);
    let _ = merge(&[data, data], Format::Json, 1, &mut out);
});
