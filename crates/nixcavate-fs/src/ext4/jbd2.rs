//! The ext3/ext4 journal (jbd2), replayed in memory.
//!
//! Written from the kernel documentation (docs.kernel.org/filesystems/ext4/journal.html) and
//! the kernel's `fs/jbd2/recovery.c`. Every journal integer is big-endian.
//!
//! A volume imaged while mounted has "needs recovery" set: its newest metadata (and with
//! `data=journal`, data) is in the journal and not yet in its home blocks. The kernel copies
//! each block logged by a committed transaction home before it mounts. This reader does the
//! same without writing: it builds an [`Overlay`], a map from each volume block to its newest
//! committed copy in the journal, and every block read of the volume consults it.
//!
//! The log is read from the journal superblock's `s_start` with its `s_sequence`, wrapping
//! from the end of the journal to `s_first`. It ends at the first block that is not a journal
//! block of the expected sequence; a transaction without its commit block is not replayed.
//! Blocks a committed revoke record names are not replayed from transactions up to the
//! revoke's. With `csum_v2`/`csum_v3`, the journal superblock, descriptor, revoke and commit
//! block checksums (CRC32C seeded with the journal UUID) are verified: a mismatch ends the
//! replay before that transaction, as e2fsck does. Data block checksums in the tags are not
//! verified, and the `checksum` (v1) and `async_commit` transaction checksums are not either:
//! sequence numbers and commit blocks decide. The fast-commit area is not replayed.
//!
//! Bounds: at most 1 GiB of log is read (the kernel's largest default journal), each block of
//! the log at most once per pass round the journal, and at most [`MAX_REVOKES`] revoke records.
//! Damage ends the replay where it is found; what came before is used, and the note says so.

use std::collections::HashMap;
use std::io;

use super::{Blocks, Ext4, Inode};
use crate::{be32, ReadAt};

const MAGIC: u32 = 0xC03B_3998;
const MAGIC_BYTES: [u8; 4] = MAGIC.to_be_bytes();

const DESCRIPTOR: u32 = 1;
const COMMIT: u32 = 2;
const SUPERBLOCK_V1: u32 = 3;
const SUPERBLOCK_V2: u32 = 4;
const REVOKE: u32 = 5;

const INCOMPAT_64BIT: u32 = 0x2;
const INCOMPAT_CSUM_V2: u32 = 0x8;
const INCOMPAT_CSUM_V3: u32 = 0x10;
const INCOMPAT_FAST_COMMIT: u32 = 0x20;
/// revoke, 64bit, async_commit, csum_v2, csum_v3, fast_commit.
const INCOMPAT_KNOWN: u32 = 0x3F;

const FLAG_ESCAPE: u16 = 0x1;
const FLAG_SAME_UUID: u16 = 0x2;
const FLAG_LAST_TAG: u16 = 0x8;

/// The kernel's smallest journal, and the default size of the fast-commit area.
const MIN_JOURNAL_BLOCKS: u64 = 1024;
const DEFAULT_FAST_COMMIT_BLOCKS: u64 = 256;
/// Bytes of log read at most.
const MAX_LOG_BYTES: u64 = 1 << 30;
/// Revoke records kept at most (about 24 bytes each in memory).
const MAX_REVOKES: usize = 4 << 20;

/// Where the newest committed copy of a volume block is: a block of the volume inside the
/// journal, whose first four bytes were zeroed when the copy began with the journal magic.
#[derive(Clone, Copy)]
struct Copy {
    block: u64,
    escaped: bool,
}

/// The volume as replayed: blocks with a committed copy in the journal read from there.
#[derive(Default)]
pub(super) struct Overlay {
    map: HashMap<u64, Copy>,
    block_size: u64,
}

impl Overlay {
    pub(super) fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Reads `buf` from byte `offset` of the replayed volume.
    pub(super) fn read(&self, image: &dyn ReadAt, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let bs = self.block_size;
        let end = offset.checked_add(buf.len() as u64).ok_or_else(|| io::Error::other("read past the end"))?;
        let mut pos = offset;
        while pos < end {
            let block = pos / bs;
            let within = pos % bs;
            let done = (pos - offset) as usize;
            match self.map.get(&block) {
                Some(copy) => {
                    let take = (bs - within).min(end - pos) as usize;
                    let out = &mut buf[done..done + take];
                    let from = copy.block.checked_mul(bs).and_then(|b| b.checked_add(within));
                    image.read_at(from.ok_or_else(|| io::Error::other("journal block out of range"))?, out)?;
                    if copy.escaped {
                        for (i, byte) in out.iter_mut().enumerate().take(4usize.saturating_sub(within as usize)) {
                            *byte = MAGIC_BYTES[within as usize + i];
                        }
                    }
                    pos += take as u64;
                }
                None => {
                    // The run of blocks up to the next one with a copy is read in one go.
                    let mut next = block + 1;
                    while next.saturating_mul(bs) < end && !self.map.contains_key(&next) {
                        next += 1;
                    }
                    let take = next.saturating_mul(bs).min(end) - pos;
                    image.read_at(pos, &mut buf[done..done + take as usize])?;
                    pos += take;
                }
            }
        }
        Ok(())
    }
}

/// The note for a volume whose journal is not replayed.
pub(super) fn not_replayed(why: &str) -> String {
    format!(
        "the volume was in use when it was imaged (needs recovery) and its journal is not replayed ({why}): \
         the files written last may be missing, out of date or unreadable"
    )
}

/// The journal as this reader walks it.
struct Log<'a, R> {
    fs: &'a Ext4<R>,
    inode: Inode,
    cache: Blocks,
    /// The last run of journal blocks mapped: first journal block, first volume block, length.
    run: (u64, u64, u64),
    first: u64,
    last: u64,
    is_64bit: bool,
    csum: bool,
    csum_v3: bool,
    /// CRC32C of the journal UUID: the seed of every checksum but the superblock's.
    seed: u32,
}

impl<R: ReadAt> Log<'_, R> {
    /// The volume block holding journal block `j`.
    fn locate(&mut self, j: u64) -> Result<u64, String> {
        let (start, phys, len) = self.run;
        if j >= start && j - start < len {
            return Ok(phys + (j - start));
        }
        let run = self.fs.map(&self.inode, j, &mut self.cache).map_err(|e| format!("journal block {j}: {e}"))?;
        let phys = run.phys.ok_or_else(|| format!("journal block {j} is not allocated"))?;
        self.run = (j, phys, run.len);
        Ok(phys)
    }

    fn read(&mut self, j: u64, buf: &mut [u8]) -> Result<(), String> {
        let block = self.locate(j)?;
        self.fs.read_blocks(block, 1, 0, buf).map_err(|e| format!("journal block {j}: {e}"))
    }

    /// The journal block `n` blocks after `j`, wrapping from the end to the first.
    fn advance(&self, j: u64, n: u64) -> u64 {
        self.first + (j - self.first + n) % (self.last - self.first)
    }

    /// Bytes of one descriptor tag (the kernel's `journal_tag_bytes`).
    fn tag_bytes(&self) -> usize {
        if self.csum_v3 {
            return 16;
        }
        let size = 12 + if self.csum { 2 } else { 0 };
        if self.is_64bit {
            size
        } else {
            size - 4
        }
    }

    /// Whether a descriptor or revoke block's tail checksum matches.
    fn tail_ok(&self, block: &[u8]) -> bool {
        let at = block.len() - 4;
        crc32c(crc32c(self.seed, &block[..at]), &[0; 4]) == be32(block, at)
    }

    /// Whether a commit block's checksum (`h_chksum[0]`) matches.
    fn commit_ok(&self, block: &[u8]) -> bool {
        let crc = crc32c(crc32c(crc32c(self.seed, &block[..16]), &[0; 4]), &block[20..]);
        crc == be32(block, 16)
    }
}

/// One block logged by a transaction: its home, where the copy is, and the transaction.
struct Logged {
    home: u64,
    copy: Copy,
    sequence: u32,
}

/// Whether transaction `a` comes after `b`, with sequence numbers that wrap.
fn after(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}

/// Reads the journal of `fs` (inode `ino`) and returns the overlay of committed blocks and the
/// note for the listing. An empty overlay means nothing is replayed.
pub(super) fn replay<R: ReadAt>(fs: &Ext4<R>, ino: u32) -> (Overlay, Option<String>) {
    let bs = fs.block_size;
    let fail = |why: String| (Overlay::default(), Some(not_replayed(&why)));
    let inode = match fs.inode(ino) {
        Ok(inode) if inode.mode & 0xF000 == 0x8000 => inode,
        Ok(_) => return fail(format!("journal inode {ino} is not a regular file")),
        Err(e) => return fail(format!("journal inode {ino}: {e}")),
    };
    let mut log = Log {
        fs,
        inode,
        cache: Blocks::new(),
        run: (0, 0, 0),
        first: 0,
        last: 0,
        is_64bit: false,
        csum: false,
        csum_v3: false,
        seed: 0,
    };
    let mut block = vec![0u8; bs as usize];
    if let Err(e) = log.read(0, &mut block) {
        return fail(e);
    }
    let sb = &block;
    let kind = be32(sb, 4);
    if be32(sb, 0) != MAGIC || !(kind == SUPERBLOCK_V1 || kind == SUPERBLOCK_V2) {
        return fail("no journal superblock".into());
    }
    if u64::from(be32(sb, 0xC)) != bs {
        return fail(format!("journal block size {} is not the volume's {bs}", be32(sb, 0xC)));
    }
    let (maxlen, first, sequence, start) =
        (u64::from(be32(sb, 0x10)), u64::from(be32(sb, 0x14)), be32(sb, 0x18), u64::from(be32(sb, 0x1C)));
    let incompat = if kind == SUPERBLOCK_V2 { be32(sb, 0x28) } else { 0 };
    if incompat & !INCOMPAT_KNOWN != 0 {
        return fail(format!("unknown journal features {:#x}", incompat & !INCOMPAT_KNOWN));
    }
    log.is_64bit = incompat & INCOMPAT_64BIT != 0;
    log.csum_v3 = incompat & INCOMPAT_CSUM_V3 != 0;
    log.csum = incompat & (INCOMPAT_CSUM_V2 | INCOMPAT_CSUM_V3) != 0;
    if log.csum {
        let crc = crc32c(crc32c(crc32c(!0, &sb[..0xFC]), &[0; 4]), &sb[0x100..1024]);
        if sb[0x50] != 4 || crc != be32(sb, 0xFC) {
            return fail("journal superblock checksum mismatch".into());
        }
        log.seed = crc32c(!0, &sb[0x30..0x40]);
    }
    if maxlen > log.inode.size / bs {
        return fail(format!("journal of {maxlen} blocks is longer than its inode"));
    }
    let mut last = maxlen;
    let fast_commit = incompat & INCOMPAT_FAST_COMMIT != 0;
    if fast_commit {
        let blocks = match be32(sb, 0x54) {
            0 => DEFAULT_FAST_COMMIT_BLOCKS,
            n => u64::from(n),
        };
        if maxlen.saturating_sub(blocks) >= MIN_JOURNAL_BLOCKS {
            last = maxlen - blocks;
        }
    }
    if first == 0 || first >= last {
        return fail(format!("journal area {first}..{last} is empty"));
    }
    if start == 0 {
        // A clean journal: nothing to replay, as the kernel would find.
        return (Overlay::default(), None);
    }
    if start < first || start >= last {
        return fail(format!("journal start block {start} is outside {first}..{last}"));
    }
    (log.first, log.last) = (first, last);

    // One pass from `s_start`: every committed transaction's logged blocks and revoke records.
    let mut logged: Vec<Logged> = Vec::new();
    let mut revoked: HashMap<u64, u32> = HashMap::new();
    let (mut pending, mut pending_revokes) = (Vec::new(), Vec::new());
    let (mut expect, mut at, mut read) = (sequence, start, 0u64);
    let budget = (last - first).min(MAX_LOG_BYTES / bs);
    let mut transactions = 0u64;
    let mut damage = None;
    let tag_bytes = log.tag_bytes();
    let tail = if log.csum { 4 } else { 0 };
    loop {
        if read >= budget {
            damage = Some(format!("the log runs past {budget} blocks"));
            break;
        }
        if let Err(e) = log.read(at, &mut block) {
            damage = Some(e);
            break;
        }
        if be32(&block, 0) != MAGIC || be32(&block, 8) != expect {
            break;
        }
        match be32(&block, 4) {
            DESCRIPTOR => {
                if log.csum && !log.tail_ok(&block) {
                    damage = Some(format!("descriptor block checksum mismatch in transaction {expect}"));
                    break;
                }
                let mut off = 12;
                let mut n = 0u64;
                while off + tag_bytes <= block.len() - tail {
                    let flags = u16::from_be_bytes([block[off + 6], block[off + 7]]);
                    let mut home = u64::from(be32(&block, off));
                    if log.is_64bit {
                        home |= u64::from(be32(&block, off + 8)) << 32;
                    }
                    n += 1;
                    pending.push((home, log.advance(at, n), flags & FLAG_ESCAPE != 0));
                    off += tag_bytes;
                    if flags & FLAG_SAME_UUID == 0 {
                        off += 16;
                    }
                    if flags & FLAG_LAST_TAG != 0 {
                        break;
                    }
                }
                read += 1 + n;
                at = log.advance(at, 1 + n);
            }
            COMMIT => {
                if log.csum && !log.commit_ok(&block) {
                    damage = Some(format!("commit block checksum mismatch in transaction {expect}"));
                    break;
                }
                for (home, j, escaped) in pending.drain(..) {
                    match log.locate(j) {
                        Ok(block) => logged.push(Logged { home, copy: Copy { block, escaped }, sequence: expect }),
                        Err(e) => damage = Some(e),
                    }
                }
                if damage.is_some() {
                    break;
                }
                for home in pending_revokes.drain(..) {
                    let entry = revoked.entry(home).or_insert(expect);
                    if after(expect, *entry) {
                        *entry = expect;
                    }
                }
                if revoked.len() > MAX_REVOKES {
                    damage = Some(format!("more than {MAX_REVOKES} revoke records"));
                    break;
                }
                transactions += 1;
                expect = expect.wrapping_add(1);
                read += 1;
                at = log.advance(at, 1);
            }
            REVOKE => {
                let used = be32(&block, 12) as usize;
                if (log.csum && !log.tail_ok(&block)) || used > block.len() - tail {
                    damage = Some(format!("damaged revoke block in transaction {expect}"));
                    break;
                }
                let size = if log.is_64bit { 8 } else { 4 };
                let mut off = 16;
                while off + size <= used {
                    let mut home = u64::from(be32(&block, off));
                    if size == 8 {
                        home = home << 32 | u64::from(be32(&block, off + 4));
                    }
                    pending_revokes.push(home);
                    off += size;
                }
                if pending_revokes.len() > MAX_REVOKES {
                    damage = Some(format!("more than {MAX_REVOKES} revoke records"));
                    break;
                }
                read += 1;
                at = log.advance(at, 1);
            }
            other => {
                damage = Some(format!("journal block of unknown type {other} in transaction {expect}"));
                break;
            }
        }
    }

    // Later copies replace earlier ones; a revoke hides the copies up to its transaction.
    let mut overlay = Overlay { map: HashMap::new(), block_size: bs };
    let mut outside = 0u64;
    for entry in &logged {
        if revoked.get(&entry.home).is_some_and(|&r| !after(entry.sequence, r)) {
            continue;
        }
        if entry.home >= fs.blocks_count {
            outside += 1;
            continue;
        }
        overlay.map.insert(entry.home, entry.copy);
    }
    let mut note = match &damage {
        None => format!(
            "the volume was in use when it was imaged (needs recovery): its journal was replayed \
             ({transactions} transactions, {} blocks)",
            overlay.map.len()
        ),
        Some(why) => format!(
            "the volume was in use when it was imaged (needs recovery): its journal was replayed up to damage \
             ({transactions} transactions, {} blocks; then {why}): the files written last may be missing, \
             out of date or unreadable",
            overlay.map.len()
        ),
    };
    if outside > 0 {
        note.push_str(&format!("; {outside} logged blocks outside the volume were skipped"));
    }
    if fast_commit {
        note.push_str("; its fast-commit area is not replayed: changes after the last full commit may be missing");
    }
    (overlay, Some(note))
}

/// CRC32C (Castagnoli), reflected, as the kernel's `crc32c(crc, data)`: no inversion at the
/// start or end, so the caller passes the seed and gets the raw register back.
fn crc32c(mut crc: u32, data: &[u8]) -> u32 {
    for &byte in data {
        crc = CRC32C_TABLE[((crc ^ u32::from(byte)) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc
}

const CRC32C_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { (c >> 1) ^ 0x82F6_3B78 } else { c >> 1 };
            k += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32c_check_value() {
        assert_eq!(!crc32c(!0, b"123456789"), 0xE306_9283);
    }

    #[test]
    fn sequence_numbers_wrap() {
        assert!(after(1, 0) && after(0, u32::MAX) && !after(5, 5) && !after(u32::MAX, 0));
    }

    #[test]
    fn escaped_and_split_reads() {
        // Volume of four 8-byte blocks; block 1's copy is block 3, escaped.
        let image: Vec<u8> = (0u8..32).collect();
        let mut overlay = Overlay { map: HashMap::new(), block_size: 8 };
        overlay.map.insert(1, Copy { block: 3, escaped: true });
        let mut buf = [0u8; 20];
        overlay.read(&crate::Bytes(&image), 2, &mut buf).unwrap();
        let mut expected: Vec<u8> = (2..8).collect();
        expected.extend(MAGIC_BYTES);
        expected.extend(28..32);
        expected.extend(16..22);
        assert_eq!(&buf[..], &expected[..]);
        let mut tail = [0u8; 3];
        overlay.read(&crate::Bytes(&image), 10, &mut tail).unwrap();
        assert_eq!(tail, [MAGIC_BYTES[2], MAGIC_BYTES[3], 28]);
    }
}
