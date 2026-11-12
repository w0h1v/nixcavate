//! Firehose chunks and their tracepoints, and the oversize chunks that hold the values of
//! large tracepoints. Format: libyal dtformats, sections "Firehose chunk", "Firehose
//! tracepoint" (and the activity, log, signpost and loss variants), "Firehose tracepoint data
//! item" and "Oversize chunk".

use super::tracev3::{le, Reader, Uuid};

pub const ACTIVITY: u8 = 2;
pub const TRACE: u8 = 3;
pub const LOG: u8 = 4;
pub const SIGNPOST: u8 = 6;
pub const LOSS: u8 = 7;

const HAS_CURRENT_AID: u16 = 0x0001;
const STRINGS_MASK: u16 = 0x000e;
const HAS_UNIQUE_PID: u16 = 0x0010;
const HAS_LARGE_OFFSET: u16 = 0x0020;
const HAS_PRIVATE_DATA: u16 = 0x0100;
/// `has_other_aid` on activities, `has_subsystem` on everything else.
const HAS_SUBSYSTEM: u16 = 0x0200;
/// A one-byte time to live in days follows (seen only in `Special` files, values 1 to 30).
const HAS_TTL: u16 = 0x0400;
const HAS_OVERSIZE: u16 = 0x0800;
const HAS_NAME: u16 = 0x8000;

/// Where the format string lives (the flags' strings file type).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FormatAt {
    MainExe,
    SharedCache,
    Absolute,
    UuidRelative(Uuid),
}

/// The firehose chunk preamble and its public and private areas.
pub struct Firehose<'a> {
    pub proc_id: (u64, u32),
    pub base: u64,
    /// The tracepoints.
    pub public: &'a [u8],
    pub private: &'a [u8],
    /// The virtual offset at which `private` starts.
    pub private_virtual: u16,
}

impl<'a> Firehose<'a> {
    pub fn parse(data: &'a [u8]) -> Option<Firehose<'a>> {
        let mut r = Reader::new(data);
        let proc_id = (r.u64()?, r.u32()?);
        r.pos = 16;
        let (public_size, private_virtual) = (r.u16()?, r.u16()?);
        r.pos = 24;
        let base = r.u64()?;
        // The public size counts from offset 16; tracepoints start at 32.
        let public = data.get(32..(16 + public_size as usize).min(data.len())).unwrap_or_default();
        let private = match private_virtual {
            0x1000 => &[][..],
            v if v < 0x1000 => data.get(data.len().saturating_sub(0x1000 - v as usize)..).unwrap_or_default(),
            _ => &[][..],
        };
        Some(Firehose { proc_id, base, public, private, private_virtual })
    }

    /// The tracepoints, each with its offset in `public`. A tracepoint that declares more
    /// bytes than the chunk holds ends the walk with an error.
    pub fn tracepoints(&self) -> impl Iterator<Item = Result<(usize, &'a [u8]), String>> {
        let data = self.public;
        let mut pos = 0usize;
        std::iter::from_fn(move || {
            let header = data.get(pos..pos + 24)?;
            if header[0] == 0 {
                return None; // unused space
            }
            let size = u16::from_le_bytes([header[22], header[23]]) as usize;
            let at = pos;
            let Some(tracepoint) = data.get(pos..pos + 24 + size) else {
                pos = data.len();
                return Some(Err(format!(
                    "tracepoint at {at} of a firehose chunk declares {size} bytes past its end; \
                     the rest of the firehose chunk ({} bytes) is dropped",
                    data.len() - at
                )));
            };
            pos = (pos + 24 + size + 7) & !7;
            Some(Ok((at, tracepoint)))
        })
    }
}

/// One data item, resolved to its bytes.
#[derive(Clone, Copy, Debug)]
pub enum Value<'a> {
    /// An inline integer or float, 1 to 8 bytes.
    Number(&'a [u8]),
    /// A precision or width argument for `*`.
    Precision(u32),
    /// A string, object description or binary blob. `None` for a null pointer.
    Bytes(Option<&'a [u8]>),
    /// A string cut short because the tracepoint ran out of room (`log show` adds `<…>`).
    Truncated(&'a [u8]),
    /// Redacted: private or sensitive and not recorded.
    Private,
}

/// Reads `count` data items; ranges point into `values` (public) or `private`.
pub fn read_items<'a>(
    r: &mut Reader<'a>,
    count: u8,
    values_end: usize,
    private: Option<&'a [u8]>,
    out: &mut Vec<Value<'a>>,
) -> Option<()> {
    // The values follow the item headers, so find their end first.
    let mut headers = *r;
    for _ in 0..count {
        let size = r.bytes(2)?[1];
        r.bytes(size as usize)?;
    }
    let values = r.data.get(r.pos..values_end).unwrap_or_default();
    for _ in 0..count {
        let (kind, size) = (headers.u8()?, headers.u8()?);
        let bytes = headers.bytes(size as usize)?;
        let range = |area: &'a [u8]| {
            let (at, len) = (le(bytes.get(..2)?) as usize, le(bytes.get(2..4)?) as usize);
            area.get(at..at + len)
        };
        // The high nibble is the value class, the low one says where it is: 0 and 2 public,
        // 1 private and 5 sensitive (both in the private data when it was recorded).
        let empty = bytes.get(2..4).is_some_and(|l| l == [0, 0]);
        let value = match (kind >> 4, kind & 0xf) {
            (1, _) => Value::Precision(le(bytes) as u32),
            (0, 1 | 5) => Value::Private,
            (0, _) => Value::Number(bytes),
            (_, 1 | 5) => match private.and_then(range) {
                Some(found) if !empty => Value::Bytes(Some(found)),
                _ => Value::Private,
            },
            _ if empty && bytes.get(..2).is_some_and(|o| o == [0, 0]) => Value::Bytes(None),
            _ => match range(values) {
                Some(found) => Value::Bytes(Some(found)),
                None => Value::Truncated(bytes.get(..2).and_then(|o| values.get(le(o) as usize..)).unwrap_or_default()),
            },
        };
        out.push(value);
    }
    Some(())
}

/// A decoded tracepoint. Fields a record type does not carry stay zero.
#[derive(Default)]
pub struct Tracepoint<'a> {
    pub kind: u8,
    pub log_type: u8,
    pub thread: u64,
    pub delta: u64,
    pub current_aid: u64,
    pub new_aid: u64,
    pub pc: u64,
    pub format: u64,
    /// The format is `%s` (the "dynamic" bit of a small format reference).
    pub dynamic: bool,
    /// `None` when the flags name no known strings file.
    pub strings: Option<FormatAt>,
    pub subsystem: Option<u16>,
    /// Days the entry is kept (only entries in `Special` files carry one).
    pub ttl: Option<u8>,
    pub oversize: Option<u32>,
    pub items: Vec<Value<'a>>,
    /// For loss records: how many messages were lost.
    pub lost: u64,
}

impl<'a> Tracepoint<'a> {
    /// Decodes a tracepoint. `items` is reused storage for the data items.
    pub fn parse(data: &'a [u8], chunk: &Firehose<'a>, items: Vec<Value<'a>>) -> Option<Tracepoint<'a>> {
        let mut r = Reader::new(data);
        let (kind, log_type, flags, format_low) = (r.u8()?, r.u8()?, r.u16()?, r.u32()?);
        let thread = r.u64()?;
        let delta = r.u32()? as u64 | (r.u16()? as u64) << 32;
        let size = r.u16()? as usize;
        let mut tp = Tracepoint { kind, log_type, thread, delta, items, ..Default::default() };
        tp.items.clear();
        let mut r = Reader::new(data.get(..24 + size)?);
        r.pos = 24;
        let has = |flag: u16| flags & flag != 0;
        match kind {
            ACTIVITY | LOG | SIGNPOST | TRACE => {}
            LOSS => {
                r.bytes(16)?; // start and end time
                tp.lost = r.u64()?;
                return Some(tp);
            }
            _ => return Some(tp),
        }
        let mut private_range = None;
        if has(HAS_CURRENT_AID) {
            tp.current_aid = r.u64()?;
        }
        if kind == ACTIVITY {
            if has(HAS_UNIQUE_PID) {
                r.u64()?;
            }
            if has(HAS_SUBSYSTEM) {
                r.u64()?; // other activity
            }
            if log_type != 3 {
                tp.new_aid = r.u64()?;
            }
        } else if kind != TRACE && has(HAS_PRIVATE_DATA) {
            private_range = Some((r.u16()?, r.u16()?));
        }
        let pc_low = r.u32()? as u64;
        let large_offset = if has(HAS_LARGE_OFFSET) { Some(r.u16()? as u64) } else { None };
        tp.format = large_offset.map_or(format_low as u64, |l| (format_low & 0x7fff_ffff) as u64 | l << 31);
        tp.pc = pc_low;
        tp.strings = match flags & STRINGS_MASK {
            0x2 => Some(FormatAt::MainExe),
            0x4 => Some(FormatAt::SharedCache),
            0x8 => {
                tp.pc |= (r.u16()? as u64) << 32;
                Some(FormatAt::Absolute)
            }
            0xa => Some(FormatAt::UuidRelative(r.uuid()?)),
            0xc => {
                let large_cache = r.u16()? as u64;
                tp.format = (format_low & 0x7fff_ffff) as u64 | large_cache << 31;
                if let Some(large) = large_offset {
                    tp.pc = pc_low | large << 32;
                }
                Some(FormatAt::SharedCache)
            }
            _ => None,
        };
        tp.dynamic = format_low & 0x8000_0000 != 0 && large_offset.is_none() && flags & STRINGS_MASK != 0xc;
        if kind == ACTIVITY {
            return Some(tp);
        }
        if kind == TRACE {
            // Values, then one size byte per value, then the value count.
            let rest = r.rest();
            let count = rest.last().copied().unwrap_or(0) as usize;
            let sizes = rest.len().checked_sub(1 + count).map_or(&[][..], |at| &rest[at..rest.len() - 1]);
            let mut at = 0;
            for &size in sizes {
                let Some(value) = rest.get(at..at + size as usize) else { break };
                tp.items.push(Value::Number(value));
                at += size as usize;
            }
            return Some(tp);
        }
        if has(HAS_SUBSYSTEM) {
            tp.subsystem = Some(r.u16()?);
        }
        if kind == SIGNPOST {
            r.u64()?; // signpost identifier
        }
        if has(HAS_TTL) {
            tp.ttl = Some(r.u8()?);
        }
        if has(HAS_OVERSIZE) {
            tp.oversize = Some(r.u32()?);
        }
        if kind == SIGNPOST && has(HAS_NAME) {
            // The signpost name reference, with a high part when offsets are large.
            r.bytes(if large_offset.is_some() { 6 } else { 4 })?;
        }
        if r.rest().len() < 2 {
            return Some(tp); // no data items at all
        }
        let (_unknown, count) = (r.u8()?, r.u8()?);
        let private = private_range.and_then(|(at, len)| {
            let start = (at as usize).checked_sub(chunk.private_virtual as usize)?;
            chunk.private.get(start..start + len as usize)
        });
        let end = r.data.len();
        // Damaged items still leave the entry; the message shows what could be read.
        let _ = read_items(&mut r, count, end, private, &mut tp.items);
        Some(tp)
    }
}

/// An oversize chunk: the data items of one tracepoint, stored separately.
pub struct Oversize<'a> {
    pub proc_id: (u64, u32),
    pub data_ref: u32,
    pub data: &'a [u8],
    pub private_size: u16,
}

impl<'a> Oversize<'a> {
    pub fn parse(data: &'a [u8]) -> Option<Oversize<'a>> {
        let mut r = Reader::new(data);
        let proc_id = (r.u64()?, r.u32()?);
        r.pos = 24;
        let data_ref = r.u32()?;
        let (public_size, private_size) = (r.u16()?, r.u16()?);
        let data = data.get(32..32 + public_size as usize + private_size as usize)?;
        Some(Oversize { proc_id, data_ref, data, private_size })
    }

    /// The data items of an oversize chunk's `data`, whose last `private_size` bytes are
    /// its private data.
    pub fn items(data: &'a [u8], private_size: u16, out: &mut Vec<Value<'a>>) -> Option<()> {
        let public_end = data.len().checked_sub(private_size as usize)?;
        let mut r = Reader::new(data);
        let (_unknown, count) = (r.u8()?, r.u8()?);
        read_items(&mut r, count, public_end, data.get(public_end..), out)
    }
}
