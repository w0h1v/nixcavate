//! A reader for Berkeley DB hash files, as used by RPM before 4.16 (`var/lib/rpm/Packages`).
//! Format: the Berkeley DB reference guide's description of the on-disk page layout
//! ("db_page.h": generic metadata page, page header, hash page items, overflow pages) and
//! public write-ups of that layout. Written from the documentation only.
//!
//! - Page 0 is the metadata page: magic (`0x00061561` for hash) at offset 12 in the file's
//!   byte order, version at 16, page size at 20, encryption algorithm at 24, page type at 25,
//!   metadata flags at 26.
//! - Every page starts with a 26-byte header: LSN (8), pgno (4), prev_pgno (4), next_pgno (4),
//!   entries (u16), hf_offset (u16), level (u8), type (u8).
//! - Hash pages (type 13, or 2 for unsorted) follow the header with `entries` 16-bit item
//!   offsets; items alternate key, data. Item `i` runs from its offset to the offset of item
//!   `i - 1` (or the end of the page for item 0). Its first byte is its type: `H_KEYDATA` (1)
//!   holds the bytes inline; `H_OFFPAGE` (3) is 12 bytes, `{type, 3 unused, pgno u32, tlen u32}`,
//!   naming the first overflow page of a `tlen`-byte value. `H_DUPLICATE` (2) and `H_OFFDUP` (4)
//!   hold duplicate sets, which RPM does not use.
//! - Overflow pages (type 7) carry `hf_offset` bytes of the value after the header and chain
//!   through `next_pgno` (0 ends the chain).
//!
//! The reader visits every page in file order instead of following the bucket directory. That
//! needs no hash logic and still finds the records on a damaged file. Every overflow page may
//! be used by one value only, which bounds the total work by the file size and ends cycles.

use nixcavate_core::{Error, Result};

const HASH_MAGIC: u32 = 0x0006_1561;
const BTREE_MAGIC: u32 = 0x0005_3162;
const QUEUE_MAGIC: u32 = 0x0004_2253;
const HEAP_MAGIC: u32 = 0x0007_4582;

const P_HASH_UNSORTED: u8 = 2;
const P_OVERFLOW: u8 = 7;
const P_HASH: u8 = 13;

const H_KEYDATA: u8 = 1;
const H_OFFPAGE: u8 = 3;

const PAGE_HEADER: usize = 26;
/// The largest single value accepted. RPM headers are well below this.
const MAX_VALUE: usize = 64 << 20;

/// True when `data` starts like any Berkeley DB file (hash, btree, queue or heap).
pub fn is_bdb(data: &[u8]) -> bool {
    let Some(bytes) = data.get(12..16) else { return false };
    let bytes: [u8; 4] = [bytes[0], bytes[1], bytes[2], bytes[3]];
    [u32::from_le_bytes(bytes), u32::from_be_bytes(bytes)]
        .iter()
        .any(|m| matches!(*m, HASH_MAGIC | BTREE_MAGIC | QUEUE_MAGIC | HEAP_MAGIC))
}

/// One key/data pair found on a hash page.
pub struct Entry<'a> {
    /// File offset of the hash page holding the pair.
    pub page_offset: u64,
    /// The key when it is stored inline; empty otherwise.
    pub key: &'a [u8],
    /// The value, or why it could not be read.
    pub value: std::result::Result<&'a [u8], String>,
}

/// An opened hash file.
pub struct HashDb<'a> {
    data: &'a [u8],
    page_size: usize,
    pub big_endian: bool,
}

impl<'a> HashDb<'a> {
    /// Checks the metadata page. Other access methods and encrypted files are skipped.
    pub fn open(data: &'a [u8]) -> Result<Self> {
        let Some(magic) = data.get(12..16) else { return Err(Error::skipped("not a Berkeley DB file")) };
        let magic: [u8; 4] = [magic[0], magic[1], magic[2], magic[3]];
        let (le, be) = (u32::from_le_bytes(magic), u32::from_be_bytes(magic));
        let big_endian = match (le, be) {
            (HASH_MAGIC, _) => false,
            (_, HASH_MAGIC) => true,
            (BTREE_MAGIC, _) | (_, BTREE_MAGIC) => return Err(Error::skipped("Berkeley DB btree file, not a hash")),
            (QUEUE_MAGIC, _) | (_, QUEUE_MAGIC) | (HEAP_MAGIC, _) | (_, HEAP_MAGIC) => {
                return Err(Error::skipped("Berkeley DB queue or heap file, not a hash"))
            }
            _ => return Err(Error::skipped("not a Berkeley DB file")),
        };
        let db = HashDb { data, page_size: 0, big_endian };
        let page_size = db.u32_at(20).unwrap_or(0) as usize;
        if !page_size.is_power_of_two() || !(512..=65536).contains(&page_size) {
            return Err(Error::format(format!("Berkeley DB page size {page_size} is invalid")));
        }
        if data.len() % page_size != 0 {
            return Err(Error::format(format!("file size is not a multiple of the page size {page_size}")));
        }
        // Encryption (algorithm byte at 24) and page checksums (metadata flag 0x01) change the
        // page header layout; RPM uses neither.
        if data.get(24).copied().unwrap_or(0) != 0 {
            return Err(Error::skipped("encrypted Berkeley DB file"));
        }
        if data.get(26).copied().unwrap_or(0) & 0x01 != 0 {
            return Err(Error::skipped("Berkeley DB file with page checksums is not supported"));
        }
        Ok(HashDb { page_size, ..db })
    }

    fn u16_at(&self, at: usize) -> Option<u16> {
        let b = self.data.get(at..at.checked_add(2)?)?;
        Some(if self.big_endian { u16::from_be_bytes([b[0], b[1]]) } else { u16::from_le_bytes([b[0], b[1]]) })
    }

    fn u32_at(&self, at: usize) -> Option<u32> {
        let b = self.data.get(at..at.checked_add(4)?)?;
        let b = [b[0], b[1], b[2], b[3]];
        Some(if self.big_endian { u32::from_be_bytes(b) } else { u32::from_le_bytes(b) })
    }

    fn pages(&self) -> usize {
        self.data.len() / self.page_size
    }

    /// Calls `f` with every key/data pair on every hash page, in file order. Values are
    /// assembled in one reused buffer, so `f` must copy what it keeps.
    pub fn for_each(&self, mut f: impl FnMut(Entry<'_>) -> Result<()>) -> Result<()> {
        let mut used = vec![false; self.pages()];
        let mut buffer = Vec::new();
        for pgno in 1..self.pages() {
            let start = pgno * self.page_size;
            let Some(page) = self.data.get(start..start + self.page_size) else { break };
            if page[25] != P_HASH && page[25] != P_HASH_UNSORTED {
                continue;
            }
            let entries = self.u16_at(start + 20).unwrap_or(0) as usize;
            // The index must fit on the page; a larger count is corrupt, so read what fits.
            let entries = entries.min((self.page_size - PAGE_HEADER) / 2);
            let offset = |i: usize| self.u16_at(start + PAGE_HEADER + 2 * i).map_or(0, usize::from);
            let item = |i: usize| -> Option<&'a [u8]> {
                let end = if i == 0 { self.page_size } else { offset(i - 1) };
                let begin = offset(i);
                if begin < PAGE_HEADER + 2 * entries || begin >= end || end > self.page_size {
                    return None;
                }
                page.get(begin..end)
            };
            for pair in 0..entries / 2 {
                let key = match item(2 * pair) {
                    Some([H_KEYDATA, key @ ..]) => key,
                    _ => &[],
                };
                let value = match item(2 * pair + 1) {
                    Some([H_KEYDATA, value @ ..]) => Ok(value),
                    Some(off @ [H_OFFPAGE, ..]) => {
                        self.overflow(off, &mut used, &mut buffer).map(|()| buffer.as_slice())
                    }
                    Some([kind, ..]) => Err(format!("unsupported item type {kind}")),
                    _ => Err("item outside its page".to_string()),
                };
                f(Entry { page_offset: start as u64, key, value })?;
            }
        }
        Ok(())
    }

    /// Reads the off-page value an `H_OFFPAGE` item points to into `out`.
    fn overflow(&self, item: &[u8], used: &mut [bool], out: &mut Vec<u8>) -> std::result::Result<(), String> {
        out.clear();
        let word = |at: usize| {
            let b = item.get(at..at + 4)?;
            let b = [b[0], b[1], b[2], b[3]];
            Some(if self.big_endian { u32::from_be_bytes(b) } else { u32::from_le_bytes(b) })
        };
        let (Some(mut pgno), Some(total)) = (word(4), word(8)) else { return Err("short off-page item".into()) };
        let total = total as usize;
        if total > self.data.len() || total > MAX_VALUE {
            return Err(format!("off-page value of {total} bytes is larger than possible"));
        }
        out.reserve(total);
        while out.len() < total {
            let index = pgno as usize;
            match used.get_mut(index) {
                _ if index == 0 => return Err(format!("overflow chain ends after {} of {total} bytes", out.len())),
                None => return Err(format!("overflow chain reaches page {pgno}, outside the file")),
                Some(true) => return Err(format!("overflow page {pgno} is used twice")),
                Some(seen) => *seen = true,
            }
            let start = index * self.page_size;
            let page = self.data.get(start..start + self.page_size).unwrap_or(&[]);
            if page.get(25) != Some(&P_OVERFLOW) {
                return Err(format!("overflow chain reaches page {pgno}, which is not an overflow page"));
            }
            let len = self.u16_at(start + 22).unwrap_or(0) as usize;
            let len = len.min(total - out.len());
            let Some(bytes) = page.get(PAGE_HEADER..PAGE_HEADER + len) else {
                return Err(format!("overflow page {pgno} claims more bytes than it holds"));
            };
            if bytes.is_empty() {
                return Err(format!("overflow page {pgno} is empty"));
            }
            out.extend_from_slice(bytes);
            pgno = self.u32_at(start + 16).unwrap_or(0);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    const PS: usize = 512;
    /// File offset of the hash page and of its item index.
    const HASH: usize = PS;
    const INDEX: usize = HASH + PAGE_HEADER;

    fn put16(file: &mut [u8], at: usize, v: u16, be: bool) {
        file[at..at + 2].copy_from_slice(&if be { v.to_be_bytes() } else { v.to_le_bytes() });
    }

    fn put32(file: &mut [u8], at: usize, v: u32, be: bool) {
        file[at..at + 4].copy_from_slice(&if be { v.to_be_bytes() } else { v.to_le_bytes() });
    }

    /// A metadata page, one hash page holding `("k1", inline)` inline and `("k2", offpage)`
    /// as an `H_OFFPAGE` item, and the overflow pages of `offpage` from page 2 on.
    fn build(be: bool, inline: &[u8], offpage: &[u8]) -> Vec<u8> {
        let per_page = PS - PAGE_HEADER;
        let overflow_pages = offpage.len().div_ceil(per_page);
        let mut file = vec![0u8; PS * (2 + overflow_pages)];
        put32(&mut file, 12, HASH_MAGIC, be);
        put32(&mut file, 16, 9, be);
        put32(&mut file, 20, PS as u32, be);
        file[25] = 8;
        put32(&mut file, HASH + 8, 1, be);
        file[HASH + 25] = P_HASH;
        let mut off_item = vec![H_OFFPAGE, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        put32(&mut off_item, 4, 2, be);
        put32(&mut off_item, 8, offpage.len() as u32, be);
        let items: [Vec<u8>; 4] = [b"\x01k1".to_vec(), [&[H_KEYDATA], inline].concat(), b"\x01k2".to_vec(), off_item];
        let mut end = PS;
        for (i, item) in items.iter().enumerate() {
            end -= item.len();
            file[HASH + end..HASH + end + item.len()].copy_from_slice(item);
            put16(&mut file, INDEX + 2 * i, end as u16, be);
        }
        put16(&mut file, HASH + 20, items.len() as u16, be);
        put16(&mut file, HASH + 22, end as u16, be);
        for (n, chunk) in offpage.chunks(per_page).enumerate() {
            let (pgno, start) = (2 + n, (2 + n) * PS);
            put32(&mut file, start + 8, pgno as u32, be);
            let next = if n + 1 < overflow_pages { pgno as u32 + 1 } else { 0 };
            put32(&mut file, start + 16, next, be);
            put16(&mut file, start + 22, chunk.len() as u16, be);
            file[start + 25] = P_OVERFLOW;
            file[start + PAGE_HEADER..start + PAGE_HEADER + chunk.len()].copy_from_slice(chunk);
        }
        file
    }

    /// `(key, value or error)` for every pair, plus the total value bytes handed out.
    type Pair = (Vec<u8>, std::result::Result<Vec<u8>, String>);

    fn read(file: &[u8]) -> Result<(Vec<Pair>, usize)> {
        let started = Instant::now();
        let db = HashDb::open(file)?;
        let (mut out, mut total) = (Vec::new(), 0);
        db.for_each(|e| {
            total += e.value.as_ref().map_or(0, |v| v.len());
            out.push((e.key.to_vec(), e.value.map(<[u8]>::to_vec)));
            Ok(())
        })?;
        assert!(started.elapsed() < Duration::from_secs(2), "took {:?}", started.elapsed());
        // Each overflow page serves one value, so the output never outgrows the file.
        assert!(total <= file.len(), "{total} bytes from a {}-byte file", file.len());
        Ok((out, total))
    }

    fn big_value() -> Vec<u8> {
        (0..1200u32).map(|i| (i * 7) as u8).collect()
    }

    #[test]
    fn reads_inline_and_off_page_values_in_both_byte_orders() {
        for be in [false, true] {
            let file = build(be, b"inline value", &big_value());
            assert!(is_bdb(&file));
            assert_eq!(HashDb::open(&file).unwrap().big_endian, be);
            let (pairs, _) = read(&file).unwrap();
            assert_eq!(pairs.len(), 2);
            assert_eq!(pairs[0], (b"k1".to_vec(), Ok(b"inline value".to_vec())));
            assert_eq!(pairs[1], (b"k2".to_vec(), Ok(big_value())));
        }
    }

    fn value_error(file: &[u8]) -> String {
        let (pairs, _) = read(file).unwrap();
        pairs.into_iter().find_map(|(_, v)| v.err()).expect("a value fails")
    }

    #[test]
    fn rejects_damaged_structures_without_failing_the_file() {
        for be in [false, true] {
            let file = build(be, b"v", &big_value());
            let off_item = HASH + PS - 3 - 2 - 3 - 12;

            let mut cycle = file.clone();
            put32(&mut cycle, 3 * PS + 16, 2, be);
            assert!(value_error(&cycle).contains("twice"));

            let mut self_loop = file.clone();
            put32(&mut self_loop, 2 * PS + 16, 2, be);
            assert!(value_error(&self_loop).contains("twice"));

            let mut huge = file.clone();
            put32(&mut huge, off_item + 8, u32::MAX, be);
            assert!(value_error(&huge).contains("larger than possible"));

            for pgno in [5, 1000, u32::MAX] {
                let mut outside = file.clone();
                put32(&mut outside, off_item + 4, pgno, be);
                assert!(value_error(&outside).contains("outside the file"));
            }

            let mut not_overflow = file.clone();
            put32(&mut not_overflow, off_item + 4, 1, be);
            assert!(value_error(&not_overflow).contains("not an overflow page"));

            let mut short_chain = file.clone();
            put32(&mut short_chain, 2 * PS + 16, 0, be);
            assert!(value_error(&short_chain).contains("ends after 486 of 1200 bytes"));

            let mut empty_page = file.clone();
            put16(&mut empty_page, 2 * PS + 22, 0, be);
            assert!(value_error(&empty_page).contains("empty"));

            let mut too_long = file.clone();
            put16(&mut too_long, 2 * PS + 22, u16::MAX, be);
            assert!(value_error(&too_long).contains("more bytes"));

            for at in [0u16, 3, PS as u16, u16::MAX] {
                let mut bad_offset = file.clone();
                put16(&mut bad_offset, INDEX + 2, at, be);
                assert!(value_error(&bad_offset).contains("outside its page"));
            }

            let mut many = file.clone();
            put16(&mut many, HASH + 20, u16::MAX, be);
            let _ = read(&many).unwrap();
        }
    }

    #[test]
    fn a_chain_serves_one_value_only() {
        // Every pair on a full hash page points at the same long chain: one read, not 20.
        let mut file = build(false, b"v", &vec![b'x'; 40 * (PS - PAGE_HEADER)]);
        let off_item = HASH + PS - 3 - 2 - 3 - 12;
        let item: Vec<u8> = file[off_item..off_item + 12].to_vec();
        let mut end = off_item;
        for i in 4..40 {
            end -= 12;
            file[end..end + 12].copy_from_slice(&item);
            put16(&mut file, INDEX + 2 * i, (end - HASH) as u16, false);
        }
        put16(&mut file, HASH + 20, 40, false);
        let (pairs, total) = read(&file).unwrap();
        assert_eq!(pairs.iter().filter(|(_, v)| v.is_ok()).count(), 2);
        assert_eq!(total, 1 + 40 * (PS - PAGE_HEADER));
    }

    #[test]
    fn checks_the_metadata_page() {
        let file = build(false, b"v", b"w");
        for size in [0u32, 3, 256, 1000, 1 << 30, 131072, u32::MAX] {
            let mut bad = file.clone();
            put32(&mut bad, 20, size, false);
            assert!(matches!(HashDb::open(&bad), Err(Error::Format(_))), "page size {size}");
        }
        assert!(matches!(HashDb::open(&file[..file.len() - 1]), Err(Error::Format(_))));
        for be in [false, true] {
            let mut btree = build(be, b"v", b"w");
            put32(&mut btree, 12, BTREE_MAGIC, be);
            assert!(is_bdb(&btree));
            assert!(matches!(HashDb::open(&btree), Err(Error::Skipped(why)) if why.contains("btree")));
        }
        let mut encrypted = file.clone();
        encrypted[24] = 1;
        assert!(matches!(HashDb::open(&encrypted), Err(Error::Skipped(why)) if why.contains("encrypted")));
        let mut checksummed = file.clone();
        checksummed[26] = 1;
        assert!(matches!(HashDb::open(&checksummed), Err(Error::Skipped(_))));
        for short in [&b""[..], b"0123456789abcde", b"SQLite format 3\0"] {
            assert!(!is_bdb(short));
            assert!(matches!(HashDb::open(short), Err(Error::Skipped(_))));
        }
    }
}
