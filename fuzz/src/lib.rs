//! Shared harness for the fuzz targets. Each target is one line naming what it feeds.

pub use libfuzzer_sys::fuzz_target;

/// A target that feeds the input to one artifact's parser as the file at `$path`, then
/// renders records and timeline the way a real run would. Any panic is a finding.
#[macro_export]
macro_rules! artifact_target {
    ($id:literal, $path:literal) => {
        $crate::fuzz_target!(|data: &[u8]| {
            let artifact = nixcavate_artifacts::find($id).expect("artifact id");
            // A fixed, non-zero modification time so year inference runs too.
            let _ = nixcavate_artifacts::testing::run(artifact, $path, data, 1_700_000_000);
        });
    };
}
