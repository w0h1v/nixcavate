//! A reader for the RPM "ndb" package database, `Packages.db` (SUSE's default since RPM 4.15).
//! Layout worked out from RPM's ndb backend and checked against databases written by RPM 4.14
//! and 4.18; all numbers are little-endian.
//!
//! - A 32-byte header: magic `RpmP`, version (0), generation, `slotnpages` (4096-byte pages
//!   that hold the slot table), next package index. The slot table starts at offset 32.
//! - 16-byte slots: magic `Slot`, package index, `blkoff` and `blkcnt` (in 16-byte blocks from
//!   the start of the file). Index 0 is a free slot.
//! - A blob starts with a 16-byte head (`BlbS`, package index, generation, length) followed by
//!   the package's rpm header exactly as the other backends store it, then zero padding. The
//!   last 12 bytes of its blocks are a tail: Adler-32 checksum, length, `BlbE`. The checksum
//!   covers everything from the start of the head up to the tail.
//!
//! Stale blobs of removed packages stay in the file but have no slot; they are not read.
//! Every offset and length is checked against the file, and the bytes the reader will look
//! at are budgeted so slots that point at one blob over and over cannot multiply the work.

use nixcavate_core::{Error, Result};
use std::collections::HashSet;

const HEADER_MAGIC: &[u8; 4] = b"RpmP";
const SLOT_MAGIC: &[u8; 4] = b"Slot";
const BLOB_HEAD_MAGIC: &[u8; 4] = b"BlbS";
const BLOB_TAIL_MAGIC: &[u8; 4] = b"BlbE";
const PAGE: usize = 4096;
const BLOCK: usize = 16;
const HEADER_LEN: usize = 32;
const BLOB_HEAD: usize = 16;
const BLOB_TAIL: usize = 12;
const MAX_DAMAGED_SLOTS: usize = 16;

/// True when `data` starts like an ndb database.
pub fn is_ndb(data: &[u8]) -> bool {
    data.starts_with(HEADER_MAGIC)
}

/// One package slot.
pub struct Blob<'a> {
    pub package_index: u32,
    /// File offset of the blob head.
    pub offset: u64,
    /// The rpm header, or why it could not be read.
    pub header: std::result::Result<&'a [u8], String>,
}

pub struct NdbDb<'a> {
    data: &'a [u8],
    slot_end: usize,
}

fn word(data: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(data.get(at..at.checked_add(4)?)?.try_into().ok()?))
}

/// Adler-32 (RFC 1950), in runs short enough that the sums cannot overflow before reduction.
fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for run in data.chunks(5552) {
        for &byte in run {
            a += u32::from(byte);
            b += a;
        }
        a %= 65521;
        b %= 65521;
    }
    (b << 16) | a
}

impl<'a> NdbDb<'a> {
    pub fn open(data: &'a [u8]) -> Result<Self> {
        if !is_ndb(data) {
            return Err(Error::skipped("not an RPM ndb database"));
        }
        let (Some(version), Some(slot_pages)) = (word(data, 4), word(data, 12)) else {
            return Err(Error::format("ndb header is cut short"));
        };
        if version != 0 {
            return Err(Error::skipped(format!("ndb database version {version} is not supported")));
        }
        // The table cannot be longer than the file; a longer claim is read as far as it goes.
        let slot_end = (slot_pages as usize).saturating_mul(PAGE).min(data.len());
        Ok(Self { data, slot_end })
    }

    /// Calls `f` for every used slot, in slot order.
    pub fn for_each(&self, mut f: impl FnMut(Blob<'a>) -> Result<()>) -> Result<()> {
        let mut seen = HashSet::new();
        let mut budget = self.data.len().saturating_mul(2);
        let mut at = HEADER_LEN;
        let mut damaged = 0;
        while let Some(end) = at.checked_add(BLOCK).filter(|end| *end <= self.slot_end) {
            let slot = &self.data[at..end];
            at = end;
            if slot.iter().all(|b| *b == 0) {
                continue;
            }
            let (Some(index), Some(blkoff), Some(blkcnt)) = (word(slot, 4), word(slot, 8), word(slot, 12)) else {
                continue;
            };
            if &slot[..4] != SLOT_MAGIC {
                // A table full of garbage (a wrong page count, overwritten pages) is not worth
                // reporting slot by slot.
                damaged += 1;
                let why = if damaged > MAX_DAMAGED_SLOTS {
                    "slot table is damaged; stopped reading it"
                } else {
                    "damaged slot (bad magic)"
                };
                f(Blob { package_index: index, offset: at as u64 - BLOCK as u64, header: Err(why.into()) })?;
                if damaged > MAX_DAMAGED_SLOTS {
                    break;
                }
                continue;
            }
            if index == 0 {
                continue;
            }
            let offset = u64::from(blkoff) * BLOCK as u64;
            if !seen.insert(index) {
                f(Blob { package_index: index, offset, header: Err("package index used by two slots".into()) })?;
                continue;
            }
            let length = (blkcnt as usize).saturating_mul(BLOCK);
            let header = if length > budget {
                Err("blob ranges overlap more than a valid database allows".to_string())
            } else {
                budget -= length;
                self.blob(index, offset, length)
            };
            f(Blob { package_index: index, offset, header })?;
        }
        Ok(())
    }

    fn blob(&self, index: u32, offset: u64, length: usize) -> std::result::Result<&'a [u8], String> {
        let start = usize::try_from(offset).ok().filter(|start| *start >= self.slot_end);
        let end = start.and_then(|start| start.checked_add(length));
        let (Some(start), Some(end)) = (start, end) else { return Err("blob lies inside the slot table".into()) };
        let Some(blocks) = self.data.get(start..end) else { return Err("blob runs past the end of the file".into()) };
        if blocks.len() < BLOB_HEAD + BLOB_TAIL {
            return Err("blob is too small".into());
        }
        if &blocks[..4] != BLOB_HEAD_MAGIC || word(blocks, 4) != Some(index) {
            return Err("blob head does not match its slot".into());
        }
        let size = word(blocks, 12).map_or(usize::MAX, |n| n as usize);
        // The blocks hold exactly the head, the data and the tail, rounded up to a block.
        let needed = size.saturating_add(BLOB_HEAD + BLOB_TAIL);
        if needed > blocks.len() || blocks.len() - needed >= BLOCK {
            return Err("blob length does not fit its blocks".into());
        }
        let tail = &blocks[blocks.len() - BLOB_TAIL..];
        if &tail[8..] != BLOB_TAIL_MAGIC || word(tail, 4) != word(blocks, 12) {
            return Err("blob tail is damaged".into());
        }
        if word(tail, 0) != Some(adler32(&blocks[..blocks.len() - BLOB_TAIL])) {
            return Err("blob checksum does not match".into());
        }
        Ok(&blocks[BLOB_HEAD..BLOB_HEAD + size])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::fixture;

    #[test]
    fn adler32_matches_the_rfc_example() {
        assert_eq!(adler32(b"Wikipedia"), 0x11E6_0398);
        assert_eq!(adler32(b""), 1);
        // Longer than one reduction run.
        let long = vec![0xffu8; 20_000];
        let (mut a, mut b) = (1u64, 0u64);
        for byte in &long {
            a = (a + u64::from(*byte)) % 65521;
            b = (b + a) % 65521;
        }
        assert_eq!(u64::from(adler32(&long)), (b << 16) | a);
    }

    fn count(data: &[u8]) -> (usize, usize) {
        let (mut good, mut bad) = (0, 0);
        if let Ok(db) = NdbDb::open(data) {
            db.for_each(|blob| {
                match blob.header {
                    Ok(_) => good += 1,
                    Err(_) => bad += 1,
                }
                Ok(())
            })
            .unwrap();
        }
        (good, bad)
    }

    #[test]
    fn reads_every_blob_of_a_real_database() {
        // Five packages were installed and one removed, which leaves a free slot.
        assert_eq!(count(&fixture("rpm-db/Packages.db")), (4, 0));
    }

    #[test]
    fn damaged_files_never_panic_and_never_read_wrong_blobs() {
        let file = fixture("rpm-db/Packages.db");
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for len in (0..file.len()).step_by(61) {
            assert!(count(&file[..len]).0 <= 4);
        }
        for round in 0..3000 {
            let mut copy = file.clone();
            for _ in 0..1 + next() % 4 {
                let at = (next() as usize) % copy.len();
                copy[at] ^= 1 << (next() % 8);
            }
            // Slot table, header and blob heads hold the numbers; hit them most often.
            let at = if round % 2 == 0 { (next() as usize) % 160 } else { (next() as usize) % copy.len() };
            copy[at] = next() as u8;
            let (good, bad) = count(&copy);
            // The checksum covers every blob byte: a blob that still reads is the original.
            assert!(good <= 4 && good + bad <= 4096 / 16, "{good} {bad}");
        }
    }

    #[test]
    fn slots_that_share_a_blob_cannot_multiply_the_work() {
        let mut file = fixture("rpm-db/Packages.db");
        // Every slot, with its own package index, points at the first blob (blkoff 256, blkcnt 807).
        for (n, slot) in file[32..4096].chunks_exact_mut(16).enumerate() {
            slot[..4].copy_from_slice(SLOT_MAGIC);
            slot[4..8].copy_from_slice(&(n as u32 + 1).to_le_bytes());
            slot[8..12].copy_from_slice(&256u32.to_le_bytes());
            slot[12..16].copy_from_slice(&807u32.to_le_bytes());
        }
        let db = NdbDb::open(&file).unwrap();
        let (mut good, mut over_budget) = (0, 0);
        db.for_each(|blob| {
            match blob.header {
                Ok(_) => good += 1,
                Err(why) if why.contains("overlap") => over_budget += 1,
                Err(_) => {}
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(good, 1, "only index 1 matches the blob head");
        assert!(over_budget > 200, "{over_budget}");
    }
}
