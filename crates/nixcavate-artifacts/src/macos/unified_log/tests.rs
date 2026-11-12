//! Tests on a synthetic store built by the helpers below, following the layouts in the libyal
//! documentation, plus a check against the real store when the corpus is present.

use super::firehose::Value;
use super::tracev3::Uuid;
use super::*;
use crate::testing::run_on_host;

const BOOT: Uuid = *b"\xb0\x07\x00\x01\x02\x03\x40\x05\x86\x07\x08\x09\x0a\x0b\x0c\x0d";
const MAIN: Uuid = *b"\x11\x22\x33\x44\x55\x66\x47\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x00";
const DSC: Uuid = *b"\xd5\xc0\x00\x00\x00\x00\x40\x00\x80\x00\x00\x00\x00\x00\x00\x01";
const LIB: Uuid = *b"\x1b\x1b\x00\x00\x00\x00\x40\x00\x80\x00\x00\x00\x00\x00\x00\x02";

const PROC_ID: (u64, u32) = (100, 200);
/// 2023-11-14T22:13:20Z, the boot's wall clock at continuous time 0.
const BOOT_WALL: i64 = 1_700_000_000_000_000_000;
/// Continuous time of the firehose base: 3 s after boot at 125/3 ns per tick.
const BASE: u64 = 72_000_000;

fn pad8(v: &mut Vec<u8>) {
    v.resize(v.len().next_multiple_of(8), 0);
}

fn chunk(tag: u32, data: &[u8]) -> Vec<u8> {
    let mut v = [tag.to_le_bytes(), 0u32.to_le_bytes()].concat();
    v.extend_from_slice(&(data.len() as u64).to_le_bytes());
    v.extend_from_slice(data);
    pad8(&mut v);
    v
}

fn header() -> Vec<u8> {
    let mut d = Vec::new();
    d.extend_from_slice(&125u32.to_le_bytes());
    d.extend_from_slice(&3u32.to_le_bytes());
    d.extend_from_slice(&0u64.to_le_bytes());
    d.extend_from_slice(&1_700_000_000u32.to_le_bytes());
    d.resize(40, 0);
    let sub = |d: &mut Vec<u8>, tag: u32, body: &[u8]| {
        d.extend_from_slice(&tag.to_le_bytes());
        d.extend_from_slice(&(body.len() as u32).to_le_bytes());
        d.extend_from_slice(body);
    };
    sub(&mut d, 0x6100, &0u64.to_le_bytes());
    sub(&mut d, 0x6101, &[0; 56]);
    sub(&mut d, 0x6102, &[&BOOT[..], &[0; 8]].concat());
    sub(&mut d, 0x6103, &[0; 48]);
    assert_eq!(d.len(), 208);
    chunk(tracev3::HEADER, &d)
}

/// A catalog with one process: main executable MAIN, shared cache DSC, one more image (LIB,
/// loaded at 0x7000_0000) and subsystem 7 = com.example.app / network.
fn catalog() -> Vec<u8> {
    let mut strings = b"com.example.app\0network\0".to_vec();
    pad8(&mut strings);
    let mut process = Vec::new();
    for v in [0u16, 0, 0, 1] {
        process.extend_from_slice(&v.to_le_bytes());
    }
    process.extend_from_slice(&PROC_ID.0.to_le_bytes());
    process.extend_from_slice(&PROC_ID.1.to_le_bytes());
    for v in [4242u32, 501, 0, 1, 0] {
        process.extend_from_slice(&v.to_le_bytes());
    }
    process.extend_from_slice(&0x1000u32.to_le_bytes()); // image size
    process.extend_from_slice(&0u32.to_le_bytes());
    process.extend_from_slice(&2u16.to_le_bytes()); // LIB
    process.extend_from_slice(&0x7000_0000u32.to_le_bytes());
    process.extend_from_slice(&0u16.to_le_bytes());
    process.extend_from_slice(&1u32.to_le_bytes()); // one subsystem
    process.extend_from_slice(&0u32.to_le_bytes());
    for v in [7u16, 0, 16] {
        process.extend_from_slice(&v.to_le_bytes());
    }
    pad8(&mut process);
    let uuids = [MAIN, DSC, LIB].concat();
    let strings_at = uuids.len();
    let procs_at = strings_at + strings.len();
    let chunks_at = procs_at + process.len();
    let mut d = Vec::new();
    for v in [strings_at, procs_at, 1, chunks_at, 0] {
        d.extend_from_slice(&(v as u16).to_le_bytes());
    }
    d.resize(24, 0);
    d.extend_from_slice(&uuids);
    d.extend_from_slice(&strings);
    d.extend_from_slice(&process);
    chunk(tracev3::CATALOG, &d)
}

/// One tracepoint: the 24-byte header, then `data`, padded.
fn tracepoint(kind: u8, log_type: u8, flags: u16, format: u32, delta: u32, data: &[u8]) -> Vec<u8> {
    let mut v = vec![kind, log_type];
    v.extend_from_slice(&flags.to_le_bytes());
    v.extend_from_slice(&format.to_le_bytes());
    v.extend_from_slice(&0x1234u64.to_le_bytes()); // thread
    v.extend_from_slice(&delta.to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes());
    v.extend_from_slice(&(data.len() as u16).to_le_bytes());
    v.extend_from_slice(data);
    pad8(&mut v);
    v
}

/// Data items: (type, inline bytes), followed by the values area.
fn items(items: &[(u8, &[u8])], values: &[u8]) -> Vec<u8> {
    let mut v = vec![0, items.len() as u8];
    for (kind, bytes) in items {
        v.push(*kind);
        v.push(bytes.len() as u8);
        v.extend_from_slice(bytes);
    }
    v.extend_from_slice(values);
    v
}

fn range(offset: u16, size: u16) -> [u8; 4] {
    let mut r = [0; 4];
    r[..2].copy_from_slice(&offset.to_le_bytes());
    r[2..].copy_from_slice(&size.to_le_bytes());
    r
}

fn firehose(tracepoints: &[Vec<u8>], private: &[u8]) -> Vec<u8> {
    let public: Vec<u8> = tracepoints.concat();
    let mut d = Vec::new();
    d.extend_from_slice(&PROC_ID.0.to_le_bytes());
    d.extend_from_slice(&PROC_ID.1.to_le_bytes());
    d.extend_from_slice(&[0, 0, 0, 0]);
    d.extend_from_slice(&(16 + public.len() as u16).to_le_bytes());
    d.extend_from_slice(&(0x1000 - private.len() as u16).to_le_bytes());
    d.extend_from_slice(&[0, 0, 0, 0]);
    d.extend_from_slice(&BASE.to_le_bytes());
    d.extend_from_slice(&public);
    d.extend_from_slice(private);
    chunk(tracev3::FIREHOSE, &d)
}

/// Format strings of MAIN's uuidtext file, by offset.
const MAIN_FORMATS: &[&str] = &[
    "user %{public}s uid %d mask %x big %llu name %{private}s secret %{private}s obj %@ %.*s 100%%",
    "activity started",
    "oversize %{public}s",
    "bool %{bool}d errno %{errno}d addr %{network:in_addr}d id %{public,uuid_t}.16P f %.2f",
];

fn uuidtext(formats: &[&str], path: &str) -> Vec<u8> {
    let blob: Vec<u8> = formats.iter().flat_map(|f| f.bytes().chain([0])).collect();
    let mut v = Vec::new();
    for x in [0x6677_8899u32, 2, 1, 1, 0x100, blob.len() as u32] {
        v.extend_from_slice(&x.to_le_bytes());
    }
    v.extend_from_slice(&blob);
    v.extend_from_slice(path.as_bytes());
    v.push(0);
    v
}

/// The offset of format `i` in a uuidtext file built by [`uuidtext`].
fn main_format(i: usize) -> u32 {
    0x100 + MAIN_FORMATS[..i].iter().map(|f| f.len() as u32 + 1).sum::<u32>()
}

/// A version 2 shared-cache strings file: one string range at 0x2000 and one image (LIB) whose
/// text is at 0x10000.
fn dsc() -> Vec<u8> {
    let strings = b"cache says %{public}s\0";
    let path = b"/usr/lib/libexample.dylib\0";
    let data_at = 16 + 24 + 32;
    let mut v = b"hcsd".to_vec();
    v.extend_from_slice(&2u16.to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes());
    v.extend_from_slice(&1u32.to_le_bytes());
    v.extend_from_slice(&1u32.to_le_bytes());
    v.extend_from_slice(&0x2000u64.to_le_bytes());
    v.extend_from_slice(&(data_at as u32).to_le_bytes());
    v.extend_from_slice(&(strings.len() as u32).to_le_bytes());
    v.extend_from_slice(&0u64.to_le_bytes());
    v.extend_from_slice(&0x10000u64.to_le_bytes());
    v.extend_from_slice(&0x1000u32.to_le_bytes());
    v.extend_from_slice(&LIB);
    v.extend_from_slice(&((data_at + strings.len()) as u32).to_le_bytes());
    v.extend_from_slice(strings);
    v.extend_from_slice(path);
    v
}

/// A boot record at BOOT_WALL and one sync record 10 s (240,000,000 ticks) later that is
/// 0.5 s ahead of the boot record's clock.
fn timesync() -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&0xbbb0u16.to_le_bytes());
    v.extend_from_slice(&48u16.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(&BOOT);
    v.extend_from_slice(&125u32.to_le_bytes());
    v.extend_from_slice(&3u32.to_le_bytes());
    v.extend_from_slice(&BOOT_WALL.to_le_bytes());
    v.extend_from_slice(&[0; 8]);
    v.extend_from_slice(&0x7354u16.to_le_bytes());
    v.extend_from_slice(&32u16.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(&240_000_000u64.to_le_bytes());
    v.extend_from_slice(&(BOOT_WALL + 10_500_000_000).to_le_bytes());
    v.extend_from_slice(&[0; 8]);
    v
}

const MAIN_EXE: u16 = 0x0002;
const SHARED_CACHE: u16 = 0x0004;
const UUID_RELATIVE: u16 = 0x000a;

/// The inner chunks of the chunk set: a firehose chunk covering each record type and item
/// kind, an oversize chunk, a simpledump and a statedump.
fn inner_chunks() -> Vec<u8> {
    let user = b"alice\0";
    let secret = b"hunter2\0";
    let object = b"<NSObject 0x1>\0";
    let mut values = Vec::new();
    values.extend_from_slice(user);
    values.extend_from_slice(object);
    values.extend_from_slice(b"truncate me");
    let log = items(
        &[
            (0x22, &range(0, user.len() as u16)),
            (0x00, &(-5i32).to_le_bytes()),
            (0x00, &0xbeefu32.to_le_bytes()),
            (0x00, &u64::MAX.to_le_bytes()),
            (0x21, &range(0, 0)),
            (0x21, &range(0, secret.len() as u16)),
            (0x42, &range(user.len() as u16, object.len() as u16)),
            (0x12, &8u32.to_le_bytes()),
            (0x22, &range((user.len() + object.len()) as u16, 11)),
        ],
        &values,
    );
    let mut private_log = Vec::new();
    private_log.extend_from_slice(&range(0x1000 - secret.len() as u16, secret.len() as u16));
    private_log.extend_from_slice(&0x1000u32.to_le_bytes()); // pc
    private_log.extend_from_slice(&log);

    let mut cache = 0x8000_0000_0000_0001u64.to_le_bytes().to_vec(); // current activity
    cache.extend_from_slice(&0x10010u32.to_le_bytes()); // pc inside LIB's text
    cache.extend_from_slice(&7u16.to_le_bytes()); // subsystem
    cache.extend_from_slice(&items(&[(0x22, &range(0, 4))], b"hey\0"));

    let mut relative = 0x1000u32.to_le_bytes().to_vec();
    relative.extend_from_slice(&MAIN);
    let uuid = LIB;
    relative.extend_from_slice(&items(
        &[
            (0x00, &1u32.to_le_bytes()),
            (0x00, &32u32.to_le_bytes()),
            (0x00, &[192, 0, 2, 1]),
            (0x32, &range(0, 16)),
            (0x00, &2.5f64.to_bits().to_le_bytes()),
        ],
        &uuid,
    ));

    let mut activity = 0x8000_0000_0000_0042u64.to_le_bytes().to_vec(); // new activity
    activity.extend_from_slice(&0x1000u32.to_le_bytes());

    let mut oversize_ref = 0x1000u32.to_le_bytes().to_vec();
    oversize_ref.extend_from_slice(&9u32.to_le_bytes());
    oversize_ref.extend_from_slice(&[0, 0]);

    let mut missing = 0x1000u32.to_le_bytes().to_vec();
    missing.extend_from_slice(&items(&[], &[]));

    let mut dynamic = 0x10020u32.to_le_bytes().to_vec();
    dynamic.extend_from_slice(&items(&[(0x22, &range(0, 4))], b"dyn\0"));

    let mut signpost = 0x1000u32.to_le_bytes().to_vec();
    signpost.extend_from_slice(&0xabcdu64.to_le_bytes());
    signpost.extend_from_slice(&items(&[], &[]));

    let mut loss = Vec::new();
    for v in [BASE, BASE + 24, 17u64] {
        loss.extend_from_slice(&v.to_le_bytes());
    }

    let fh = firehose(
        &[
            tracepoint(4, 0x00, MAIN_EXE | 0x0100, main_format(0), 0, &private_log),
            tracepoint(4, 0x01, SHARED_CACHE | 0x0001 | 0x0200, 0x2000, 24, &cache),
            tracepoint(4, 0x10, UUID_RELATIVE, main_format(3), 48, &relative),
            tracepoint(2, 0x01, MAIN_EXE, main_format(1), 72, &activity),
            tracepoint(4, 0x11, MAIN_EXE | 0x0800, main_format(2), 96, &oversize_ref),
            tracepoint(4, 0x02, MAIN_EXE, 0x7fff_0000, 120, &missing),
            tracepoint(4, 0x00, SHARED_CACHE, 0x8001_0020, 144, &dynamic),
            tracepoint(6, 0x81, MAIN_EXE, main_format(1), 168, &signpost),
            tracepoint(7, 0x00, 0, 0, 192, &loss),
        ],
        secret,
    );

    let mut oversize = Vec::new();
    oversize.extend_from_slice(&PROC_ID.0.to_le_bytes());
    oversize.extend_from_slice(&PROC_ID.1.to_le_bytes());
    oversize.extend_from_slice(&[0; 4]);
    oversize.extend_from_slice(&BASE.to_le_bytes());
    oversize.extend_from_slice(&9u32.to_le_bytes());
    let big = items(&[(0x22, &range(0, 9))], b"big text\0");
    oversize.extend_from_slice(&(big.len() as u16).to_le_bytes());
    oversize.extend_from_slice(&0u16.to_le_bytes());
    oversize.extend_from_slice(&big);

    let mut simple = Vec::new();
    simple.extend_from_slice(&PROC_ID.0.to_le_bytes());
    simple.extend_from_slice(&PROC_ID.1.to_le_bytes());
    simple.extend_from_slice(&[0, 0, 0, 0]);
    simple.extend_from_slice(&(BASE + 300).to_le_bytes());
    simple.extend_from_slice(&0x99u64.to_le_bytes());
    simple.extend_from_slice(&0x1000u64.to_le_bytes());
    simple.extend_from_slice(&MAIN);
    simple.extend_from_slice(&DSC);
    simple.extend_from_slice(&1u32.to_le_bytes());
    simple.extend_from_slice(&5u32.to_le_bytes());
    simple.extend_from_slice(&13u32.to_le_bytes());
    simple.extend_from_slice(b"user\0service up\0\0\0");

    let mut state = Vec::new();
    state.extend_from_slice(&PROC_ID.0.to_le_bytes());
    state.extend_from_slice(&PROC_ID.1.to_le_bytes());
    state.extend_from_slice(&[0; 4]);
    state.extend_from_slice(&(BASE + 400).to_le_bytes());
    state.extend_from_slice(&0x8000_0000_0000_0043u64.to_le_bytes());
    state.extend_from_slice(&LIB);
    state.extend_from_slice(&1u32.to_le_bytes());
    state.extend_from_slice(&2u32.to_le_bytes());
    state.resize(184, 0);
    let mut title = b"Example state".to_vec();
    title.resize(64, 0);
    state.extend_from_slice(&title);
    state.extend_from_slice(b"{}");

    [chunk(tracev3::OVERSIZE, &oversize), fh, chunk(tracev3::SIMPLEDUMP, &simple), chunk(tracev3::STATEDUMP, &state)]
        .concat()
}

/// A chunk set holding `inner` as one LZ4 block followed by one stored block.
fn chunkset(inner: &[u8]) -> Vec<u8> {
    let (first, second) = inner.split_at(inner.len() / 2);
    let compressed = lz4_flex::block::compress(first);
    let mut d = b"bv41".to_vec();
    d.extend_from_slice(&(first.len() as u32).to_le_bytes());
    d.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
    d.extend_from_slice(&compressed);
    d.extend_from_slice(b"bv4-");
    d.extend_from_slice(&(second.len() as u32).to_le_bytes());
    d.extend_from_slice(second);
    d.extend_from_slice(b"bv4$");
    chunk(tracev3::CHUNKSET, &d)
}

fn tracev3() -> Vec<u8> {
    [header(), catalog(), chunkset(&inner_chunks())].concat()
}

const TRACEV3: &str = "private/var/db/diagnostics/Persist/0000000000000001.tracev3";

fn hex_path(uuid: &Uuid) -> String {
    let hex: String = uuid.iter().map(|b| format!("{b:02X}")).collect();
    format!("{}/{}", &hex[..2], &hex[2..])
}

fn run(data: &[u8]) -> String {
    let main = uuidtext(MAIN_FORMATS, "/usr/libexec/exampled");
    let dsc = dsc();
    let timesync = timesync();
    let main_path = format!("private/var/db/uuidtext/{}", hex_path(&MAIN));
    let dsc_path = format!("private/var/db/uuidtext/dsc/{}", hex_path(&DSC).replace('/', ""));
    let files: &[(&str, &[u8])] = &[
        (TRACEV3, data),
        (&main_path, &main),
        (&dsc_path, &dsc),
        ("private/var/db/diagnostics/timesync/0000000000000001.timesync", &timesync),
    ];
    run_on_host(&ARTIFACT, files, TRACEV3, 0)
}

#[test]
fn parses_a_synthetic_store() {
    insta::assert_snapshot!(run(&tracev3()));
}

#[test]
fn a_logarchive_keeps_everything_at_its_top() {
    assert_eq!(roots("x.logarchive/Persist/1.tracev3"), ("x.logarchive".into(), "x.logarchive".into()));
    assert_eq!(roots("Special/1.tracev3"), ("".into(), "".into()));
    assert_eq!(roots("x.logarchive/logdata.LiveData.tracev3"), ("x.logarchive".into(), "x.logarchive".into()));
    assert_eq!(
        roots("private/var/db/diagnostics/Signpost/1.tracev3"),
        ("private/var/db/diagnostics".into(), "private/var/db/uuidtext".into())
    );
}

#[test]
fn without_companions_entries_are_kept() {
    let out = run_on_host(&ARTIFACT, &[(TRACEV3, &tracev3())], TRACEV3, 0);
    assert_eq!(out.matches(r#""message":"<missing format string>""#).count(), 6, "{out}");
    assert!(out.contains("no timesync record"), "{out}");
}

#[test]
fn rejects_other_files() {
    assert!(run(b"").contains("skipped: empty file"));
    assert!(run(&[0u8; 64]).contains("failed: not a tracev3 file"));
}

#[test]
fn truncated_and_corrupted_files_do_not_panic() {
    let data = tracev3();
    for len in 0..data.len() {
        run(&data[..len]);
    }
    for at in 0..data.len() {
        let mut bad = data.clone();
        bad[at] ^= 0xff;
        run(&bad);
        bad[at] = 0x7f;
        run(&bad);
    }
    // The companion files are evidence too.
    let companions = [uuidtext(MAIN_FORMATS, "/usr/libexec/exampled"), dsc(), timesync()];
    for file in &companions {
        for len in 0..=file.len() {
            for at in 0..len {
                let mut bad = file[..len].to_vec();
                bad[at] ^= 0xff;
                check_companion(bad);
            }
            check_companion(file[..len].to_vec());
        }
    }
}

fn check_companion(bytes: Vec<u8>) {
    let _ = Timesync::default().add(&bytes);
    if let Some(file) = strings::Uuidtext::parse(nixcavate_source::Data::Owned(bytes.clone())) {
        let file = Rc::new(file);
        for offset in [0, 0x100, 0x120, u64::MAX] {
            let _ = Uuidtext::lookup(&file, offset);
        }
    }
    if let Some(cache) = strings::SharedCache::parse(nixcavate_source::Data::Owned(bytes)) {
        let cache = Rc::new(cache);
        for at in [0, 0x2000, 0x2005, 0x10010, u64::MAX] {
            let _ = SharedCache::lookup(&cache, at, at);
            let _ = cache.image_by_uuid(&LIB);
        }
    }
}

/// Renders `format` with `items`.
fn render(format: &str, items: &[Value]) -> String {
    let mut out = String::new();
    format::render(format, items, "<decode: missing data>", &mut out);
    out
}

#[test]
fn renders_printf_conversions() {
    let n = |v: i64, size: usize| Value::Number(Box::leak(v.to_le_bytes()[..size].to_vec().into_boxed_slice()));
    let s = |t: &'static str| Value::Bytes(Some(t.as_bytes()));
    let cases: &[(&str, Vec<Value>, &str)] = &[
        ("%d %i %u", vec![n(-7, 4), n(42, 4), n(-1, 4)], "-7 42 4294967295"),
        (
            "%ld %lld %llu %zu",
            vec![n(-7, 8), n(1 << 40, 8), n(-1, 8), n(3, 8)],
            "-7 1099511627776 18446744073709551615 3",
        ),
        ("%hhd %hd %hu", vec![n(255, 4), n(65535, 4), n(65535, 4)], "-1 -1 65535"),
        (
            "%x %X %#x %#x %o %#o",
            vec![n(255, 4), n(255, 4), n(255, 4), n(0, 4), n(8, 4), n(8, 4)],
            "ff FF 0xff 0 10 010",
        ),
        ("%p %p", vec![n(0x1000, 8), n(0, 8)], "0x1000 0x0"),
        (
            "[%5d] [%-5d] [%05d] [%+d] [%.3d]",
            vec![n(42, 4), n(42, 4), n(-42, 4), n(42, 4), n(7, 4)],
            "[   42] [42   ] [-0042] [+42] [007]",
        ),
        ("%c%c", vec![n(0x41, 4), n(0x7a, 4)], "Az"),
        ("%s|%{public}s|%@|%{public}@", vec![s("a\0"), s("b"), s("c"), s("d")], "a|b|c|d"),
        ("[%8s] [%-8s] [%.2s]", vec![s("abc"), s("abc"), s("abc")], "[     abc] [abc     ] [ab]"),
        ("%.*s|%*d", vec![Value::Precision(3), s("abcdef"), Value::Precision(4), n(7, 4)], "abc|   7"),
        ("%s %@", vec![Value::Bytes(None), Value::Bytes(None)], "(null) (null)"),
        (
            "%{private}s %d %{sensitive}s",
            vec![Value::Private, Value::Private, Value::Private],
            "<private> <private> <private>",
        ),
        ("%s|%{public}s", vec![Value::Truncated(b"abc")], "abc<…>|<decode: missing data>"),
        ("100%% done %m", vec![n(2, 4)], "100% done No such file or directory"),
        (
            "%f %.1f %e %g %g %g",
            vec![n(2.5f64.to_bits() as i64, 8); 3]
                .into_iter()
                .chain([
                    n(0.0001f64.to_bits() as i64, 8),
                    n(1e10f64.to_bits() as i64, 8),
                    n(100.0f64.to_bits() as i64, 8),
                ])
                .collect(),
            "2.500000 2.5 2.500000e+00 0.0001 1e+10 100",
        ),
        ("%{bool}d %{bool}d %{BOOL}d %{BOOL}d", vec![n(1, 4), n(0, 4), n(1, 4), n(0, 4)], "true false YES NO"),
        (
            "%{errno}d %{darwin.errno}d",
            vec![n(1, 4), n(999, 4)],
            "[1: Operation not permitted] [999: Unknown error: 999]",
        ),
        ("%{time_t}d", vec![n(1_700_000_000, 8)], "2023-11-14 22:13:20+0000"),
        ("%{network:in_addr}d %{in_addr}d", vec![n(0x0100_00c0, 4), n(0x0200_a8c0, 4)], "192.0.0.1 192.168.0.2"),
        (
            "%{public, uuid_t}.16P",
            vec![s("\x10\x74\x2e\x39\x06\x57\x41\x78\x2b\x19\x07\x0c\x5e\x2d\x0c\x2a")],
            "10742E39-0657-4178-2B19-070C5E2D0C2A",
        ),
        (
            "%{network:in6_addr}.16P",
            vec![Value::Bytes(Some(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]))],
            "2001:db8::1",
        ),
        (
            "%{network:sockaddr}.*P",
            vec![Value::Precision(16), Value::Bytes(Some(&[16, 2, 0, 80, 198, 51, 100, 7, 0, 0, 0, 0, 0, 0, 0, 0]))],
            "198.51.100.7",
        ),
        (
            "%{sensitive, mask.hash}.16P %{mask.hash}s",
            vec![Value::Bytes(Some(b"\x01\x02\x03\x04")), Value::Bytes(None)],
            "<mask.hash: 'AQIDBA=='> <mask.hash: (null)>",
        ),
        (
            "%{public, timeval}.*P",
            vec![
                Value::Precision(16),
                Value::Bytes(Some(&[0x00, 0xf1, 0x53, 0x65, 0, 0, 0, 0, 0x40, 0xe2, 0x01, 0, 0, 0, 0, 0])),
            ],
            "2023-11-14 22:13:20.123456+0000",
        ),
        (
            "%{mdns:rrtype}d %{mdns:yesno}d %{mdns:addrmv}d %{mdns:time_duration}u",
            vec![n(28, 4), n(0, 4), n(1, 4), n(1021, 4)],
            "AAAA no add 17m 1s",
        ),
        (
            "%{mdns:dns.idflags}08lX, counts: %{mdns:dns.counts}016llX",
            vec![n(0x0001_8180, 8), n(0x0001_0002_0000_0001, 8)],
            "id: 0x0001 (1), flags: 0x8180 (R/Query, RD, RA, NoError), counts: 1/2/0/1",
        ),
        (
            "%{public, mdnsresponder:domain_name}.*P",
            vec![Value::Precision(13), Value::Bytes(Some(b"\x03www\x07example\x00"))],
            "www.example.",
        ),
        ("%{network:tcp_flags}x %{network:tcp_state}d", vec![n(0x12, 4), n(4, 4)], "[S.] ESTABLISHED"),
        (
            "%{private, location:escape_only}s %{location:escape_only}s",
            vec![Value::Private, s("a\"b/c")],
            "<private> \"a\\\"b\\/c\"",
        ),
        (
            "x=%{public, signpost.description:begin_time}llu",
            vec![n(5, 8)],
            "x=__##__signpost.description#____#begin_time#_##_#5##__##",
        ),
        ("c=%{signpost.description:attribute,public}s", vec![Value::Private], "c=<private>"),
        ("%{custom:thing}d %{public}08x", vec![n(3, 4), n(255, 4)], "3 000000ff"),
        ("%d %d", vec![n(1, 4)], "1 <decode: missing data>"),
        ("%{public", vec![], "%{public"),
        ("%y %", vec![], "%y %"),
    ];
    for (format, items, expected) in cases {
        assert_eq!(render(format, items), *expected, "format {format:?}");
    }
}

#[test]
fn timesync_converts_continuous_time() {
    let mut t = Timesync::default();
    assert_eq!(t.add(&timesync()), Ok(()));
    t.finish();
    // Before the sync record: from the boot record. 24 ticks = 1000 ns.
    assert_eq!(t.wall_nanos(&BOOT, 24), Some(BOOT_WALL + 1000));
    // After it: from the sync record.
    assert_eq!(t.wall_nanos(&BOOT, 240_000_024), Some(BOOT_WALL + 10_500_001_000));
    assert_eq!(t.wall_nanos(&MAIN, 0), None);
    assert_eq!(t.add(b"not a timesync file"), Err(0));
}

/// Parses every tracev3 file of a real log archive (see the
/// task notes); nothing from it is committed.
#[test]
#[ignore]
fn corpus_archive_parses() {
    use nixcavate_core::{Format, Target};
    use nixcavate_source::{discover, Pattern, Source};
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../nixcavate-corpus/macos-unified/system_logs.logarchive");
    let root = std::env::var_os("NIXCAVATE_UNIFIED_LOG_CORPUS").map_or(root, Into::into);
    if !root.is_dir() {
        eprintln!("corpus not present at {}; skipping", root.display());
        return;
    }
    let scratch = std::env::temp_dir().join(format!("nixcavate-ulog-{}", std::process::id()));
    std::fs::create_dir_all(&scratch).unwrap();
    let source = Source::open(&root, &|_| true, &scratch).unwrap();
    let hosts = discover(&source, None);
    let host = &hosts[0];
    let mut files = 0;
    for pattern in ARTIFACT.paths {
        let pattern = Pattern::new(pattern);
        for entry in host.find(&pattern) {
            let rel = host.rel(entry);
            let data = host.open(entry).unwrap();
            let input = Input {
                host,
                path: &rel,
                data: &data,
                offset: 0,
                mtime: 0,
                mode: 0,
                uid: 0,
                gid: 0,
                scratch: &scratch,
            };
            let out = scratch.join(format!("out-{files}.jsonl"));
            let mut sink = Sink::new("corpus", ARTIFACT.id, &rel, Format::Jsonl, Target::File(out.clone()), None);
            sink = sink.without_events();
            let result = (ARTIFACT.parse)(&input, &mut sink);
            let summary = sink.finish().unwrap();
            std::fs::remove_file(&out).ok();
            assert!(result.is_ok(), "{rel}: {:?}", result.err());
            assert!(summary.records > 0, "{rel}: no records");
            files += 1;
        }
    }
    std::fs::remove_dir_all(&scratch).ok();
    assert!(files > 0);
}

// Regression tests for the review findings.

/// Runs `data` as the store's tracev3 file with MAIN's uuidtext holding `formats` and the
/// usual timesync file.
fn run_formats(formats: &[&str], data: &[u8]) -> String {
    let main = uuidtext(formats, "/usr/libexec/exampled");
    let main_path = format!("private/var/db/uuidtext/{}", hex_path(&MAIN));
    let files: &[(&str, &[u8])] = &[
        (TRACEV3, data),
        (&main_path, &main),
        ("private/var/db/diagnostics/timesync/0000000000000001.timesync", &timesync()),
    ];
    run_on_host(&ARTIFACT, files, TRACEV3, 0)
}

/// A tracev3 file whose one chunk set holds `inner`.
fn store_of(inner: &[u8]) -> Vec<u8> {
    [header(), catalog(), chunkset(inner)].concat()
}

/// One log tracepoint using MAIN's format at 0x100 with `n` empty number items.
fn one_entry(n: usize) -> Vec<u8> {
    let mut d = 0x1000u32.to_le_bytes().to_vec();
    let empty: Vec<(u8, &[u8])> = vec![(0x00, &[][..]); n];
    d.extend_from_slice(&items(&empty, &[]));
    store_of(&firehose(&[tracepoint(4, 0, MAIN_EXE, 0x100, 0, &d)], &[]))
}

/// The JSON records of a run, without the timeline and warnings.
fn records(out: &str) -> Vec<serde_json::Value> {
    out.lines().take_while(|l| l.starts_with('{')).map(|l| serde_json::from_str(l).unwrap()).collect()
}

fn n4(v: i64) -> Value<'static> {
    Value::Number(Box::leak(v.to_le_bytes()[..4].to_vec().into_boxed_slice()))
}

#[test]
fn a_percent_before_a_non_ascii_character_is_literal() {
    assert_eq!(render("50%é done", &[]), "50%é done");
    assert_eq!(render("%…", &[]), "%…");
    assert_eq!(render("%{public}é %d", &[n4(3)]), "%{public}é 3");
    let out = run_formats(&["progress 50%… ok"], &one_entry(0));
    assert_eq!(records(&out)[0]["message"], "progress 50%… ok", "{out}");
}

#[test]
fn shared_cache_image_paths_are_bounded() {
    let (images, string_area) = (2_000usize, 1usize << 20);
    let mut v = b"hcsd".to_vec();
    v.extend_from_slice(&1u16.to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes()); // no ranges
    v.extend_from_slice(&(images as u32).to_le_bytes());
    let strings_at = 16 + images * 28;
    for i in 0..images {
        v.extend_from_slice(&(i as u32 * 16).to_le_bytes());
        v.extend_from_slice(&16u32.to_le_bytes());
        v.extend_from_slice(&[0x11; 16]);
        v.extend_from_slice(&(strings_at as u32).to_le_bytes());
    }
    v.resize(strings_at + string_area, b'A'); // no NUL anywhere in the string area
    let t = std::time::Instant::now();
    let cache = Rc::new(strings::SharedCache::parse(nixcavate_source::Data::Owned(v)).unwrap());
    let path = SharedCache::sender(&cache, 0).unwrap();
    assert!(path.bytes().len() <= 1024, "an image path of {} bytes", path.bytes().len());
    assert!(t.elapsed() < std::time::Duration::from_secs(1), "parse took {:?}", t.elapsed());
}

/// An oversize chunk for `data_ref` whose items are one public string, `text`, padded with
/// zeros to `size` bytes of public data and `size` of private data.
fn oversize_chunk(data_ref: u32, text: &[u8], size: u16) -> Vec<u8> {
    let mut o = Vec::new();
    o.extend_from_slice(&PROC_ID.0.to_le_bytes());
    o.extend_from_slice(&PROC_ID.1.to_le_bytes());
    o.extend_from_slice(&[0; 4]);
    o.extend_from_slice(&BASE.to_le_bytes());
    o.extend_from_slice(&data_ref.to_le_bytes());
    let mut big = items(&[(0x22, &range(0, text.len() as u16))], text);
    let public = (size as usize).max(big.len());
    o.extend_from_slice(&(public as u16).to_le_bytes());
    o.extend_from_slice(&size.to_le_bytes());
    big.resize(public + size as usize, 0);
    o.extend_from_slice(&big);
    chunk(tracev3::OVERSIZE, &o)
}

/// A firehose chunk with one tracepoint showing oversize data `data_ref` through MAIN's
/// format 2 (`oversize %{public}s`).
fn oversize_entry(data_ref: u32) -> Vec<u8> {
    let mut d = 0x1000u32.to_le_bytes().to_vec();
    d.extend_from_slice(&data_ref.to_le_bytes());
    d.extend_from_slice(&[0, 0]);
    firehose(&[tracepoint(4, 0, MAIN_EXE | 0x0800, main_format(2), 0, &d)], &[])
}

#[test]
fn oversize_data_kept_per_task_is_bounded() {
    // 5 chunk sets of 120 chunks of 128 KiB: 75 MiB of oversize data.
    let mut file = [header(), catalog()].concat();
    let mut data_ref = 0;
    for _ in 0..5 {
        let mut inner = Vec::new();
        for _ in 0..120 {
            inner.extend_from_slice(&oversize_chunk(data_ref, b"big\0", u16::MAX));
            data_ref += 1;
        }
        let compressed = lz4_flex::block::compress(&inner);
        let mut d = b"bv41".to_vec();
        d.extend_from_slice(&(inner.len() as u32).to_le_bytes());
        d.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
        d.extend_from_slice(&compressed);
        d.extend_from_slice(b"bv4$");
        file.extend_from_slice(&chunk(tracev3::CHUNKSET, &d));
    }
    file.extend_from_slice(&chunkset(&[oversize_entry(0), oversize_entry(data_ref - 1)].concat()));
    let out = run(&file);
    let records = records(&out);
    assert_eq!(records[0]["message"], "oversize big", "{out}");
    assert_eq!(records[1]["message"], "oversize <oversize data not kept>", "{out}");
    assert_eq!(
        out.lines().filter(|l| l.starts_with("--- warning:") && l.contains("MiB of oversize data")).count(),
        1,
        "{out}"
    );
}

#[test]
fn unclosed_annotations_are_linear() {
    let format = "%{".repeat(100_000);
    let t = std::time::Instant::now();
    let out = render(&format, &[]);
    assert!(t.elapsed() < std::time::Duration::from_secs(1), "took {:?}", t.elapsed());
    // Literal text, cut at the message limit.
    assert!(out.len() <= 64 << 10 && format.starts_with(out.strip_suffix("<…>").unwrap()), "{} bytes", out.len());
}

#[test]
fn messages_formats_and_widths_are_capped() {
    assert_eq!(render("%5000d", &[n4(7)]).len(), 1024);
    assert_eq!(render("%.5000d", &[n4(7)]).len(), 1024);
    assert_eq!(render("%5000s", &[Value::Bytes(Some(b"x"))]).len(), 1024);
    // A precision limits a string; it does not pad it, so it is not capped.
    let long = "y".repeat(3000);
    assert_eq!(render("%.2500s", &[Value::Bytes(Some(long.as_bytes()))]).len(), 2500);
    // ... but a number shown through a string conversion is padded by it.
    assert_eq!(render("%.*s", &[Value::Precision(u32::MAX), n4(5)]).len(), 1024);

    let widths = "%4096d".repeat(255);
    let out = run_formats(&[&widths], &one_entry(255));
    let record = &records(&out)[0];
    let message = record["message"].as_str().unwrap();
    assert!(message.len() <= (64 << 10) + 3 && message.ends_with("<…>"), "{} bytes", message.len());

    let huge = "%d".repeat(500_000);
    let out = run_formats(&[&huge], &one_entry(0));
    let record = &records(&out)[0];
    for field in ["message", "format"] {
        let text = record[field].as_str().unwrap();
        assert!(text.len() <= (64 << 10) + 3 && text.ends_with("<…>"), "{field}: {} bytes", text.len());
    }
}

#[test]
fn uuidtext_and_shared_cache_lookups_are_indexed() {
    let count = 200_000u32;
    let mut v = Vec::new();
    for x in [0x6677_8899u32, 2, 1, count] {
        v.extend_from_slice(&x.to_le_bytes());
    }
    for i in 0..count {
        v.extend_from_slice(&(i * 2).to_le_bytes());
        v.extend_from_slice(&1u32.to_le_bytes());
    }
    v.resize(v.len() + count as usize, b'A');
    let file = Rc::new(strings::Uuidtext::parse(nixcavate_source::Data::Owned(v)).unwrap());
    let t = std::time::Instant::now();
    for _ in 0..5_000 {
        assert!(Uuidtext::lookup(&file, 0xffff_ffff).0.is_none());
    }
    assert!(Uuidtext::lookup(&file, 2 * (count as u64 - 1)).0.is_some());
    assert!(t.elapsed() < std::time::Duration::from_millis(500), "uuidtext lookups took {:?}", t.elapsed());

    let images = 100_000usize;
    let mut v = b"hcsd".to_vec();
    v.extend_from_slice(&1u16.to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(&(images as u32).to_le_bytes());
    let strings_at = 16 + images * 28;
    for i in 0..images {
        v.extend_from_slice(&(i as u32 * 16).to_le_bytes());
        v.extend_from_slice(&16u32.to_le_bytes());
        v.extend_from_slice(&(i as u128).to_le_bytes());
        v.extend_from_slice(&(strings_at as u32).to_le_bytes());
    }
    v.extend_from_slice(b"/usr/lib/libx.dylib\0");
    let cache = strings::SharedCache::parse(nixcavate_source::Data::Owned(v)).unwrap();
    let t = std::time::Instant::now();
    for _ in 0..5_000 {
        assert!(cache.image_by_uuid(&[0xff; 16]).is_none());
    }
    assert!(cache.image_by_uuid(&(images as u128 - 1).to_le_bytes()).is_some());
    assert!(t.elapsed() < std::time::Duration::from_millis(500), "image lookups took {:?}", t.elapsed());
}

const NEIGHBOUR: &str = "private/var/db/diagnostics/Persist/0000000000000000.tracev3";

#[test]
fn oversize_data_in_another_file_is_marked() {
    let data = store_of(&oversize_entry(9));
    let out = run(&data);
    assert_eq!(records(&out)[0]["message"], "oversize <oversize data in another file>", "{out}");
}

#[test]
fn oversize_data_is_found_in_the_previous_file() {
    let previous = store_of(&oversize_chunk(9, b"from before\0", 0));
    let data = store_of(&oversize_entry(9));
    let main = uuidtext(MAIN_FORMATS, "/usr/libexec/exampled");
    let main_path = format!("private/var/db/uuidtext/{}", hex_path(&MAIN));
    let files: &[(&str, &[u8])] = &[
        (NEIGHBOUR, &previous),
        (TRACEV3, &data),
        (&main_path, &main),
        ("private/var/db/diagnostics/timesync/0000000000000001.timesync", &timesync()),
    ];
    let out = run_on_host(&ARTIFACT, files, TRACEV3, 0);
    assert_eq!(records(&out)[0]["message"], "oversize from before", "{out}");
}

/// A statedump chunk titled `title` holding `payload` of data type `kind`.
fn statedump(kind: u32, title: &str, payload: &[u8]) -> Vec<u8> {
    let mut state = Vec::new();
    state.extend_from_slice(&PROC_ID.0.to_le_bytes());
    state.extend_from_slice(&PROC_ID.1.to_le_bytes());
    state.extend_from_slice(&[0; 4]);
    state.extend_from_slice(&(BASE + 400).to_le_bytes());
    state.extend_from_slice(&0x43u64.to_le_bytes());
    state.extend_from_slice(&LIB);
    state.extend_from_slice(&kind.to_le_bytes());
    state.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    state.resize(184, 0);
    let mut name = title.as_bytes().to_vec();
    name.resize(64, 0);
    state.extend_from_slice(&name);
    state.extend_from_slice(payload);
    chunk(tracev3::STATEDUMP, &state)
}

#[test]
fn statedumps_show_their_payload() {
    use plist::{Dictionary, Value as P};
    let mut inner = Dictionary::new();
    inner.insert("Has MAT".into(), P::Boolean(false));
    inner.insert("big_count".into(), P::Integer((-3).into()));
    inner.insert("ratio".into(), P::Real(0.25));
    inner.insert("short".into(), P::Data(vec![1, 2, 3]));
    inner.insert("long".into(), P::Data((0..40).collect()));
    let mut dict = Dictionary::new();
    dict.insert("name".into(), P::String("prod".into()));
    dict.insert("Auth".into(), P::Dictionary(inner));
    dict.insert("list".into(), P::Array(vec![P::String("a".into()), P::String("b c".into())]));
    dict.insert("path".into(), P::String("/usr/lib \"x\"\n".into()));
    let mut bplist = Vec::new();
    P::Dictionary(dict).to_writer_binary(&mut bplist).unwrap();
    let data = store_of(
        &[
            statedump(1, "State", &bplist),
            statedump(3, "Custom", &[1, 2, 3]),
            statedump(1, "", b"<?xml version=\"1.0\"?><plist version=\"1.0\"><array><string>a</string><string>b</string></array></plist>"),
            statedump(1, "Bar", b"{\n    0 =     {\n        a = 1;\n    };\n}\0"),
            statedump(1, "Text", b"<?xml version=\"1.0\"?><plist version=\"1.0\"><string>\nline</string></plist>"),
        ]
        .concat(),
    );
    let out = run(&data);
    let records = records(&out);
    let expected = "State\n{\n    Auth =     {\n        \"Has MAT\" = 0;\n        \"big_count\" = \"-3\";\n        long = {length = 40, bytes = 0x00010203 04050607 08090a0b 0c0d0e0f ... 20212223 24252627 };\n        ratio = \"0.25\";\n        short = {length = 3, bytes = 0x010203};\n    };\n    list =     (\n        a,\n        \"b c\"\n    );\n    name = prod;\n    path = \"/usr/lib \\\"x\\\"\\n\";\n}";
    assert_eq!(records[0]["message"], expected, "{out}");
    assert_eq!(records[1]["message"], "Custom\n<3 bytes of statedump data, type 3>", "{out}");
    assert_eq!(records[2]["message"], "(\n    a,\n    b\n)", "{out}");
    // An old-style property list is already in the form `log show` prints.
    assert_eq!(records[3]["message"], "Bar\n{\n    0 =     {\n        a = 1;\n    };\n}", "{out}");
    // A value on its own is not quoted.
    assert_eq!(records[4]["message"], "Text\n\nline", "{out}");
}

#[test]
fn entries_carry_their_ttl() {
    let mut d = 0x1000u32.to_le_bytes().to_vec();
    d.push(7); // days
    d.extend_from_slice(&items(&[], &[]));
    let out = run(&store_of(&firehose(&[tracepoint(4, 0, MAIN_EXE | 0x0400, main_format(1), 0, &d)], &[])));
    let first = &records(&out)[0];
    assert_eq!(first["message"], "activity started", "{out}");
    assert_eq!(first["ttl_days"], 7, "{out}");
    let out = run(&tracev3());
    assert!(records(&out).iter().all(|r| r["ttl_days"].is_null()), "{out}");
}

#[test]
fn estimated_times_are_marked() {
    let out = run(&tracev3());
    assert!(records(&out).iter().all(|r| r["time_estimated"] == false), "{out}");
    let out = run_on_host(&ARTIFACT, &[(TRACEV3, &tracev3())], TRACEV3, 0);
    assert!(records(&out).iter().all(|r| r["time_estimated"] == true), "{out}");
    assert_eq!(out.matches("no timesync record").count(), 1, "{out}");
}

#[test]
fn header_wall_clock_is_unsigned() {
    let mut data = tracev3();
    // The header chunk's body starts at 16; its wall clock seconds are at body offset 16.
    data[32..36].copy_from_slice(&3_000_000_000u32.to_le_bytes());
    let out = run_on_host(&ARTIFACT, &[(TRACEV3, &data)], TRACEV3, 0);
    assert_eq!(records(&out)[0]["time"], "2065-01-24T05:20:03.000000000Z", "{out}");
}

#[test]
fn rendering_matches_log_show_details() {
    assert_eq!(render("%{time_t}d", &[n4(1_700_000_000)]), "2023-11-14 22:13:20+0000");
    assert_eq!(render("[%016llX] [%14.8lf] [%-9s]", &[Value::Private; 3]), "[<private>] [<private>] [<private>]");
    assert_eq!(render("[%{public, location:escape_only}s]", &[Value::Bytes(None)]), "[]");
}

#[test]
fn entries_are_located_inside_their_chunk_set() {
    let out = run(&tracev3());
    let records = records(&out);
    // The oversize chunk (72 bytes padded) comes first; then the firehose chunk's 16-byte
    // chunk header and 32-byte preamble.
    assert_eq!(records[0]["chunk_offset"], 72 + 16 + 32, "{out}");
    let offsets: std::collections::HashSet<String> = records.iter().map(|r| r["chunk_offset"].to_string()).collect();
    assert_eq!(offsets.len(), records.len(), "{out}");
}

#[test]
fn damage_is_reported() {
    // A tracepoint that declares more bytes than its chunk holds.
    let good = tracepoint(4, 0, MAIN_EXE, main_format(1), 0, &[0x00, 0x10, 0, 0, 0, 0]);
    let mut bad = tracepoint(4, 0, MAIN_EXE, main_format(1), 0, &[0x00, 0x10, 0, 0, 0, 0]);
    bad[22..24].copy_from_slice(&0x4000u16.to_le_bytes());
    let out = run(&store_of(&firehose(&[good, bad], &[])));
    assert_eq!(records(&out).len(), 1, "{out}");
    assert!(out.contains("rest of the firehose chunk"), "{out}");

    // A top-level chunk that runs past the end of the file.
    let mut data = tracev3();
    let len = data.len();
    data.extend_from_slice(&chunk(tracev3::CHUNKSET, &[0; 8]));
    data[len + 8..len + 16].copy_from_slice(&1000u64.to_le_bytes());
    let out = run(&data);
    assert!(out.contains("24 bytes left unread"), "{out}");

    // A timesync file with an unknown record after the good ones.
    let mut sync = timesync();
    sync.extend_from_slice(&[0x99, 0x99, 8, 0, 0, 0, 0, 0]);
    let main = uuidtext(MAIN_FORMATS, "/usr/libexec/exampled");
    let main_path = format!("private/var/db/uuidtext/{}", hex_path(&MAIN));
    let files: &[(&str, &[u8])] = &[
        (TRACEV3, &tracev3()),
        (&main_path, &main),
        ("private/var/db/diagnostics/timesync/0000000000000001.timesync", &sync),
    ];
    let out = run_on_host(&ARTIFACT, files, TRACEV3, 0);
    assert!(out.contains("unknown record at offset 80"), "{out}");
    assert!(!out.contains("no timesync record"), "{out}");
}

/// `data` with every chunk set rewritten as one stored block, so that mutations reach the
/// inner chunks instead of breaking the LZ4 stream.
fn stored_copy(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = Vec::new();
    for c in tracev3::Chunks::new(data).flatten() {
        if c.tag == tracev3::CHUNKSET {
            let len = tracev3::decompress(c.data, &mut buf).unwrap();
            let mut d = b"bv4-".to_vec();
            d.extend_from_slice(&(len as u32).to_le_bytes());
            d.extend_from_slice(&buf[..len]);
            d.extend_from_slice(b"bv4$");
            out.extend_from_slice(&chunk(c.tag, &d));
        } else {
            out.extend_from_slice(&chunk(c.tag, c.data));
        }
    }
    out
}

/// xorshift64: deterministic, so a failing mutation is reproduced by rerunning the test.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

/// One to six edits: a random byte, a flipped bit, or a boundary value written over 1 to 8
/// bytes (sizes, offsets and counts are where parsers break).
fn mutate(rng: &mut Rng, data: &mut [u8]) {
    const VALUES: [u64; 12] = [0, 1, 2, 7, 8, 16, 24, 0x7f, 0xff, 0xffff, 0xffff_ffff, u64::MAX];
    for _ in 0..1 + rng.below(6) {
        if data.len() < 16 {
            return;
        }
        let at = rng.below(data.len() - 8);
        match rng.below(4) {
            0 => data[at] = rng.next() as u8,
            1 => data[at] ^= 1 << rng.below(8),
            _ => {
                let at = at & !1;
                let v = VALUES[rng.below(VALUES.len())].to_le_bytes();
                let n = [1, 2, 4, 8][rng.below(4)];
                data[at..at + n].copy_from_slice(&v[..n]);
            }
        }
    }
}

/// Mutates the synthetic store (its tracev3 file, mostly with chunk sets stored, and its
/// companions) for a few seconds; every parse must finish quickly without panicking.
#[test]
fn mutated_stores_parse_without_panics_or_stalls() {
    let original = tracev3();
    let stored = stored_copy(&original);
    assert_eq!(records(&run(&stored)).len(), records(&run(&original)).len());
    let main_path = format!("private/var/db/uuidtext/{}", hex_path(&MAIN));
    let dsc_path = format!("private/var/db/uuidtext/dsc/{}", hex_path(&DSC).replace('/', ""));
    let sync_path = "private/var/db/diagnostics/timesync/0000000000000001.timesync";
    let companions = [uuidtext(MAIN_FORMATS, "/usr/libexec/exampled"), dsc(), timesync()];
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    let mut runs = 0u64;
    while std::time::Instant::now() < deadline {
        let mut files = [
            if rng.below(4) == 0 { original.clone() } else { stored.clone() },
            companions[0].clone(),
            companions[1].clone(),
            companions[2].clone(),
        ];
        // The tracev3 file most of the time; each companion now and then.
        let which = [0, 0, 0, 0, 0, 1, 1, 2, 3][rng.below(9)];
        mutate(&mut rng, &mut files[which]);
        let host: &[(&str, &[u8])] =
            &[(TRACEV3, &files[0]), (&main_path, &files[1]), (&dsc_path, &files[2]), (sync_path, &files[3])];
        let t = std::time::Instant::now();
        let out = std::panic::catch_unwind(|| run_on_host(&ARTIFACT, host, TRACEV3, 0));
        assert!(out.is_ok(), "mutation {runs} panicked");
        assert!(t.elapsed() < std::time::Duration::from_secs(2), "mutation {runs} took {:?}", t.elapsed());
        runs += 1;
    }
    assert!(runs > 100, "only {runs} mutations ran");
}
