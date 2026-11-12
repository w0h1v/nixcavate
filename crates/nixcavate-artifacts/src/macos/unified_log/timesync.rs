//! The timesync database: per boot, pairs of Mach continuous time and wall clock time.
//! Format: libyal dtformats, "timesync database file format" and "Converting a Mach
//! continuous time in to wall clock time".

use super::tracev3::{Reader, Uuid};
use std::collections::HashMap;

struct Boot {
    numerator: u32,
    denominator: u32,
    /// (continuous time, wall clock nanoseconds), sorted; the boot record is (0, boot time).
    syncs: Vec<(u64, i64)>,
}

#[derive(Default)]
pub struct Timesync {
    boots: HashMap<Uuid, Boot>,
}

impl Timesync {
    /// Adds the records of one `.timesync` file. Stops at a record it does not know (or a
    /// truncated one) and returns its offset; the records before it are kept.
    pub fn add(&mut self, data: &[u8]) -> Result<(), usize> {
        let mut r = Reader::new(data);
        let mut boot: Option<Uuid> = None;
        while let (Some(signature), Some(size)) = (r.u16(), r.u16()) {
            let start = r.pos - 4;
            let Some(mut body) = data.get(start..start + size as usize).map(Reader::new) else { return Err(start) };
            body.pos = 4;
            match (signature, size) {
                (0xbbb0, 48) => {
                    body.u32();
                    let (Some(uuid), Some(numerator), Some(denominator), Some(wall)) =
                        (body.uuid(), body.u32(), body.u32(), body.u64())
                    else {
                        return Err(start);
                    };
                    let entry = self.boots.entry(uuid).or_insert(Boot { numerator, denominator, syncs: Vec::new() });
                    entry.syncs.push((0, wall as i64));
                    boot = Some(uuid);
                }
                (0x7354, 32) => {
                    body.u32();
                    let (Some(continuous), Some(wall)) = (body.u64(), body.u64()) else { return Err(start) };
                    if let Some(entry) = boot.and_then(|b| self.boots.get_mut(&b)) {
                        entry.syncs.push((continuous, wall as i64));
                    }
                }
                _ => return Err(start),
            }
            r.pos = start + size as usize;
        }
        Ok(())
    }

    pub fn finish(&mut self) {
        for boot in self.boots.values_mut() {
            boot.syncs.sort_unstable();
            boot.syncs.dedup_by_key(|s| s.0);
        }
    }

    /// Wall clock nanoseconds since the epoch for a continuous time of a boot.
    pub fn wall_nanos(&self, boot: &Uuid, continuous: u64) -> Option<i64> {
        let boot = self.boots.get(boot)?;
        let i = boot.syncs.partition_point(|s| s.0 <= continuous).checked_sub(1)?;
        let (base, wall) = boot.syncs[i];
        Some(wall.saturating_add(ticks_to_nanos(continuous - base, boot.numerator, boot.denominator)))
    }
}

pub fn ticks_to_nanos(ticks: u64, numerator: u32, denominator: u32) -> i64 {
    if denominator == 0 {
        return ticks as i64;
    }
    (ticks as i128 * numerator as i128 / denominator as i128).clamp(0, i64::MAX as i128) as i64
}
