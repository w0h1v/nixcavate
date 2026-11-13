//! Small helpers shared by the service-log parsers (mail, proxies, databases, file transfer).

use nixcavate_core::Sink;

/// `key=value` where the key starts a token: after the line start, a space, a comma or `(`.
/// The value ends at a comma or space, or at `>` when it starts with `<`.
pub fn field<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    let bytes = text.as_bytes();
    let mut from = 0;
    while let Some(found) = text.get(from..)?.find(key) {
        let at = from + found;
        from = at + key.len();
        if at != 0 && !matches!(bytes.get(at - 1), Some(b' ' | b',' | b'(' | b';')) {
            continue;
        }
        let value = text.get(from..)?;
        let end = match value.strip_prefix('<') {
            Some(inner) => return Some(inner.split('>').next().unwrap_or_default()),
            None => value.find([',', ' ']).unwrap_or(value.len()),
        };
        return value.get(..end);
    }
    None
}

/// At most 300 bytes of `text`, cut on a character boundary.
pub fn cut(text: &str) -> &str {
    let mut end = text.len().min(300);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// Counts lines a parser did not recognise and reports them as one warning: a warning per line
/// would drown the manifest on logs with millions of lines.
#[derive(Default)]
pub struct Unparsed {
    count: u64,
    first: u64,
}

impl Unparsed {
    pub fn note(&mut self, line: u64) {
        if self.count == 0 {
            self.first = line;
        }
        self.count += 1;
    }

    pub fn report(&self, sink: &mut Sink, what: &str) {
        if self.count > 0 {
            sink.warn(format!("{} lines are not in the {what} format; the first is line {}", self.count, self.first));
        }
    }
}

use nixcavate_core::time::{month_from_abbrev, secs_from_civil};

fn two(b: &[u8], i: usize) -> Option<u32> {
    let (hi, lo) = (*b.get(i)?, *b.get(i + 1)?);
    (hi.is_ascii_digit() && lo.is_ascii_digit()).then(|| u32::from(hi - b'0') * 10 + u32::from(lo - b'0'))
}

/// `10/Mar/2024:01:02:03` (day, month name, year, time) as wall-clock seconds, plus the number
/// of bytes it used. The caller decides the zone: a Common Log Format time carries one after it,
/// HAProxy's `accept_date` does not.
pub fn clf_wall(b: &[u8]) -> Option<(i64, usize)> {
    if b.get(2) != Some(&b'/') || b.get(6) != Some(&b'/') || b.get(11) != Some(&b':') {
        return None;
    }
    let year = i64::from(two(b, 7)? * 100 + two(b, 9)?);
    let secs =
        secs_from_civil(year, month_from_abbrev(b.get(3..6)?)?, two(b, 0)?, two(b, 12)?, two(b, 15)?, two(b, 18)?)?;
    (b.get(14) == Some(&b':') && b.get(17) == Some(&b':')).then_some((secs, 20))
}

/// `10/Mar/2024:01:02:03 +0100` as UTC seconds.
pub fn clf_utc(b: &[u8]) -> Option<i64> {
    let (wall, used) = clf_wall(b)?;
    let sign = match b.get(used + 1)? {
        b'+' => 1,
        b'-' => -1,
        _ => return None,
    };
    let zone = i64::from(two(b, used + 2)? * 3600 + two(b, used + 4)? * 60);
    (b.get(used) == Some(&b' ')).then_some(wall - sign * zone)
}

/// `Fri Nov 13 01:22:03 2026` (`ctime`, 24 bytes with a space-padded day) as wall-clock seconds.
pub fn ctime_wall(b: &[u8]) -> Option<i64> {
    if b.len() < 24 || b[3] != b' ' || b[7] != b' ' || b[10] != b' ' || b[13] != b':' || b[16] != b':' || b[19] != b' '
    {
        return None;
    }
    let day = if b[8] == b' ' { u32::from(b[9].checked_sub(b'0').filter(|d| *d < 10)?) } else { two(b, 8)? };
    let year = i64::from(two(b, 20)? * 100 + two(b, 22)?);
    secs_from_civil(year, month_from_abbrev(&b[4..7])?, day, two(b, 11)?, two(b, 14)?, two(b, 17)?)
}

/// `%20`-style percent decoding (RFC 3986), as `file://` URIs, `.trashinfo` paths and
/// freedesktop thumbnails use it. Malformed escapes are kept as written; bytes that are not
/// UTF-8 are replaced.
pub fn percent_decode(text: &str) -> std::borrow::Cow<'_, str> {
    if !text.contains('%') {
        return std::borrow::Cow::Borrowed(text);
    }
    let b = text.as_bytes();
    let hex = |i: usize| b.get(i).and_then(|c| (*c as char).to_digit(16));
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            if let (Some(hi), Some(lo)) = (hex(i + 1), hex(i + 2)) {
                out.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    std::borrow::Cow::Owned(String::from_utf8_lossy(&out).into_owned())
}

/// The path of a `file:///...` URI (decoded), or the URI itself for any other scheme.
pub fn file_uri_path(uri: &str) -> std::borrow::Cow<'_, str> {
    match uri.strip_prefix("file://") {
        Some(rest) => {
            // `file://host/path`: the path starts at the first slash after the (usually empty) host.
            let path = rest.find('/').map_or("", |at| &rest[at..]);
            percent_decode(path)
        }
        None => std::borrow::Cow::Borrowed(uri),
    }
}
