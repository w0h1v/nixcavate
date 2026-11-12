//! Format strings and image paths: `uuidtext` files (one per image, named by its UUID) and the
//! shared-cache strings (`dsc`) files. Format: libyal dtformats, "UUID text file format" and
//! "Shared-Cache Strings (dsc) file format". Each file is read and indexed once per task.

use super::tracev3::{uuid_string, Reader, Uuid};
use nixcavate_source::{Data, Host};
use std::collections::HashMap;
use std::ops::Range;
use std::rc::Rc;

/// The longest image path read from a shared-cache file (`MAXPATHLEN`).
const MAX_PATH: usize = 1024;

/// The NUL-terminated string at `at`, not reading past `end`.
fn string_at(data: &[u8], at: usize, end: usize) -> Option<Range<usize>> {
    let bytes = data.get(at..end.min(data.len()))?;
    Some(at..at + memchr::memchr(0, bytes).unwrap_or(bytes.len()))
}

/// A `uuidtext` file: format strings by offset, and the image path in the footer.
pub struct Uuidtext {
    data: Data,
    /// (first string offset, size, file offset), sorted.
    ranges: Vec<(u32, u32, usize)>,
    path: Range<usize>,
}

impl Uuidtext {
    pub fn parse(data: Data) -> Option<Uuidtext> {
        let mut r = Reader::new(&data);
        if r.u32()? != 0x6677_8899 {
            return None;
        }
        let (_major, _minor, count) = (r.u32()?, r.u32()?, r.u32()?);
        let count = (count as usize).min(r.rest().len() / 8);
        let mut at = 16 + count * 8;
        let mut ranges = Vec::with_capacity(count);
        for _ in 0..count {
            let (start, size) = (r.u32()?, r.u32()?);
            ranges.push((start, size, at));
            at = at.checked_add(size as usize)?;
        }
        let path = string_at(&data, at, data.len()).unwrap_or_default();
        ranges.sort_by_key(|r| r.0);
        Some(Uuidtext { data, ranges, path })
    }

    pub fn path_text(file: &Rc<Uuidtext>) -> Text {
        Text::Uuidtext(file.clone(), file.path.clone())
    }

    /// The format string at `offset`, and the image path.
    pub fn lookup(file: &Rc<Uuidtext>, offset: u64) -> (Option<Text>, Option<Text>) {
        let format = file.format(offset).map(|r| Text::Uuidtext(file.clone(), r));
        (format, Some(Uuidtext::path_text(file)))
    }

    fn format(&self, offset: u64) -> Option<Range<usize>> {
        let i = self.ranges.partition_point(|r| r.0 as u64 <= offset).checked_sub(1)?;
        let (start, size, at) = self.ranges[i];
        let within = offset - start as u64;
        if within >= size as u64 {
            return None;
        }
        string_at(&self.data, at + within as usize, at + size as usize)
    }
}

/// A shared-cache strings file: format strings by offset, and the cache's images by text
/// address range.
pub struct SharedCache {
    data: Data,
    /// (string offset, size, file offset), sorted.
    ranges: Vec<(u64, u32, usize)>,
    /// (text offset, size, path), sorted.
    images: Vec<(u64, u32, Range<usize>)>,
    /// Image paths by UUID (the first image with each UUID).
    by_uuid: HashMap<Uuid, Range<usize>>,
}

impl SharedCache {
    pub fn parse(data: Data) -> Option<SharedCache> {
        let mut r = Reader::new(&data);
        if r.bytes(4)? != b"hcsd" {
            return None;
        }
        let (major, _minor, range_count, image_count) = (r.u16()?, r.u16()?, r.u32()?, r.u32()?);
        let v2 = major >= 2;
        let range_count = (range_count as usize).min(r.rest().len() / 16);
        let mut ranges = Vec::with_capacity(range_count);
        for _ in 0..range_count {
            let (offset, at, size) = if v2 {
                let range = (r.u64()?, r.u32()?, r.u32()?);
                r.u64()?; // image index
                range
            } else {
                r.u32()?; // image index
                (r.u32()? as u64, r.u32()?, r.u32()?)
            };
            ranges.push((offset, size, at as usize));
        }
        let image_count = (image_count as usize).min(r.rest().len() / 28);
        let mut images = Vec::with_capacity(image_count);
        let mut by_uuid = HashMap::with_capacity(image_count);
        for _ in 0..image_count {
            let text = if v2 { r.u64()? } else { r.u32()? as u64 };
            let (size, uuid, path) = (r.u32()?, r.uuid()?, r.u32()? as usize);
            let path = string_at(&data, path, path.saturating_add(MAX_PATH)).unwrap_or_default();
            by_uuid.entry(uuid).or_insert_with(|| path.clone());
            images.push((text, size, path));
        }
        ranges.sort_unstable_by_key(|r| r.0);
        images.sort_unstable_by_key(|i| i.0);
        Some(SharedCache { data, ranges, images, by_uuid })
    }

    /// The format string at `offset`, and the path of the image at `pc`.
    pub fn lookup(cache: &Rc<SharedCache>, offset: u64, pc: u64) -> (Option<Text>, Option<Text>) {
        // `log show` names no sender when the format string is not in the cache.
        let Some(format) = cache.format(offset) else { return (None, None) };
        (Some(Text::Cache(cache.clone(), format)), SharedCache::sender(cache, pc))
    }

    /// The path of the image at `pc`.
    pub fn sender(cache: &Rc<SharedCache>, pc: u64) -> Option<Text> {
        cache.image(pc).map(|path| Text::Cache(cache.clone(), path))
    }

    fn format(&self, offset: u64) -> Option<Range<usize>> {
        let i = self.ranges.partition_point(|r| r.0 <= offset).checked_sub(1)?;
        let (start, size, at) = self.ranges[i];
        let within = offset - start;
        if within >= size as u64 {
            return None;
        }
        string_at(&self.data, at + within as usize, at + size as usize)
    }

    /// The path of the image whose text holds `pc`.
    fn image(&self, pc: u64) -> Option<Range<usize>> {
        let i = self.images.partition_point(|r| r.0 <= pc).checked_sub(1)?;
        let (text, size, ref path) = self.images[i];
        (pc - text < size as u64).then(|| path.clone())
    }

    pub fn image_by_uuid(&self, uuid: &Uuid) -> Option<Range<usize>> {
        self.by_uuid.get(uuid).cloned()
    }
}

/// A string inside a loaded file.
#[derive(Clone)]
pub enum Text {
    Uuidtext(Rc<Uuidtext>, Range<usize>),
    Cache(Rc<SharedCache>, Range<usize>),
    Static(&'static str),
}

impl Text {
    pub fn bytes(&self) -> &[u8] {
        let (data, range) = match self {
            Text::Uuidtext(file, range) => (&file.data, range),
            Text::Cache(file, range) => (&file.data, range),
            Text::Static(text) => return text.as_bytes(),
        };
        data.get(range.clone()).unwrap_or_default()
    }
}

/// Lazily loaded string files for one task. Missing or invalid files are remembered as
/// `None` so each is looked up once.
pub struct Strings<'h> {
    host: &'h Host<'h>,
    /// The directory holding the two-hex-digit uuidtext folders and `dsc/`.
    root: String,
    uuidtext: HashMap<Uuid, Option<Rc<Uuidtext>>>,
    dsc: HashMap<Uuid, Option<Rc<SharedCache>>>,
}

/// The UUID as uuidtext and dsc file names spell it: upper-case hex without dashes.
fn hex(uuid: &Uuid) -> String {
    uuid_string(uuid).replace('-', "")
}

impl<'h> Strings<'h> {
    pub fn new(host: &'h Host<'h>, root: String) -> Self {
        Self { host, root, uuidtext: HashMap::new(), dsc: HashMap::new() }
    }

    fn read(&self, rel: &str) -> Option<Data> {
        match self.root.as_str() {
            "" => self.host.read(rel),
            root => self.host.read(&format!("{root}/{rel}")),
        }
    }

    pub fn uuidtext(&mut self, uuid: &Uuid) -> Option<Rc<Uuidtext>> {
        if let Some(found) = self.uuidtext.get(uuid) {
            return found.clone();
        }
        let name = hex(uuid);
        let file = self.read(&format!("{}/{}", &name[..2], &name[2..])).and_then(Uuidtext::parse).map(Rc::new);
        self.uuidtext.insert(*uuid, file.clone());
        file
    }

    pub fn dsc(&mut self, uuid: &Uuid) -> Option<Rc<SharedCache>> {
        if let Some(found) = self.dsc.get(uuid) {
            return found.clone();
        }
        let file = self.read(&format!("dsc/{}", hex(uuid))).and_then(SharedCache::parse).map(Rc::new);
        self.dsc.insert(*uuid, file.clone());
        file
    }

    /// The path of an image: from its uuidtext file, else from the shared cache.
    pub fn image_path(&mut self, uuid: &Uuid, dsc: Option<&Uuid>) -> Option<Text> {
        if let Some(file) = self.uuidtext(uuid) {
            return Some(Uuidtext::path_text(&file));
        }
        let cache = self.dsc(dsc?)?;
        let path = cache.image_by_uuid(uuid)?;
        Some(Text::Cache(cache, path))
    }
}
