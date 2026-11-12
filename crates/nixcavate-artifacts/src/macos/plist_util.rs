//! Helpers shared by the property-list and Mac-time artifacts. Format: plist(5), XML or binary
//! (bplist00). Wrong-typed values are treated as absent: a hostile plist must never stop a
//! parse. Mac absolute time is seconds since 2001-01-01 UTC, as NSDate and Core Data store it.

use nixcavate_core::{Basis, Precision, Sink, Timestamp};
use plist::{Dictionary, Value};
use serde_json::{Map, Number};
use std::time::UNIX_EPOCH;

/// Seconds between the Unix epoch and the Mac absolute time epoch (2001-01-01).
const MAC_EPOCH: i64 = 978_307_200;
/// Containers nested deeper than this are replaced by a marker in [`json`].
pub const JSON_DEPTH: usize = 8;
const HEX_BYTES: usize = 64;

pub use nixcavate_source::plist::parse;

pub fn string<'a>(dict: &'a Dictionary, key: &str) -> Option<&'a str> {
    dict.get(key)?.as_string()
}

pub fn boolean(dict: &Dictionary, key: &str) -> Option<bool> {
    dict.get(key)?.as_boolean()
}

pub fn integer(dict: &Dictionary, key: &str) -> Option<i64> {
    dict.get(key)?.as_signed_integer()
}

/// The first of several key spellings (they differ between macOS versions) that is a string.
pub fn first_string<'a>(dict: &'a Dictionary, keys: &[&str]) -> Option<&'a str> {
    keys.iter().find_map(|key| string(dict, key))
}

/// The string items of an array; a lone string counts as a one-item list.
pub fn strings(value: &Value) -> Vec<String> {
    match value {
        Value::String(s) => vec![s.clone()],
        Value::Array(items) => items.iter().filter_map(|v| v.as_string().map(str::to_owned)).collect(),
        _ => Vec::new(),
    }
}

pub fn strings_of(dict: &Dictionary, key: &str) -> Vec<String> {
    dict.get(key).map(strings).unwrap_or_default()
}

/// A plist date (always UTC) as a timestamp; `None` when it is outside 1677-2262.
pub fn date(value: &Value) -> Option<Timestamp> {
    let (secs, nanos) = match std::time::SystemTime::from(value.as_date()?).duration_since(UNIX_EPOCH) {
        Ok(d) => (i64::try_from(d.as_secs()).ok()?, d.subsec_nanos()),
        Err(e) => {
            let d = e.duration();
            let secs = i64::try_from(d.as_secs()).ok()?;
            match d.subsec_nanos() {
                0 => (-secs, 0),
                n => (-secs - 1, 1_000_000_000 - n),
            }
        }
    };
    timestamp(secs, nanos)
}

/// Mac absolute time (seconds since 2001-01-01) as a timestamp; `None` for NaN, infinities and
/// anything outside 1677-2262, which would otherwise pass for a recorded date.
pub fn mac_time(seconds: f64) -> Option<Timestamp> {
    let whole = seconds.floor();
    if whole.is_nan() || whole.abs() >= 1e11 {
        return None;
    }
    let nanos = ((seconds - whole) * 1e9).round().min(999_999_999.0) as u32;
    timestamp(whole as i64 + MAC_EPOCH, nanos)
}

/// Converts a raw time read from a file, warning when it is present but not a usable time
/// (out of range, NaN): the field is then left empty rather than filled with a wrong date.
pub fn or_warn<T: Copy + std::fmt::Display>(
    sink: &mut Sink,
    what: &str,
    raw: Option<T>,
    convert: impl Fn(T) -> Option<Timestamp>,
) -> Option<Timestamp> {
    let raw = raw?;
    let time = convert(raw);
    if time.is_none() {
        sink.warn(format!("{what} {raw} is not a valid time; left empty"));
    }
    time
}

fn timestamp(secs: i64, nanos: u32) -> Option<Timestamp> {
    // Doubles carry about 7 significant fractional digits at these magnitudes.
    let micros = nanos / 1000 * 1000;
    let precision = if micros == 0 { Precision::Seconds } else { Precision::Micros };
    Timestamp::checked(secs, micros, precision, Basis::Recorded)
}

/// A plist value as JSON: dates as RFC 3339 text, data as hex (first 64 bytes), containers
/// below `depth` levels replaced by a marker.
pub fn json(value: &Value, depth: usize) -> serde_json::Value {
    use serde_json::Value as J;
    match value {
        Value::Boolean(b) => J::Bool(*b),
        Value::String(s) => J::String(s.clone()),
        Value::Integer(i) => match (i.as_signed(), i.as_unsigned()) {
            (Some(n), _) => J::Number(n.into()),
            (None, Some(n)) => J::Number(n.into()),
            _ => J::Null,
        },
        Value::Real(r) => Number::from_f64(*r).map_or(J::Null, J::Number),
        Value::Date(d) => J::String(d.to_xml_format()),
        Value::Data(bytes) => {
            let mut hex: String = bytes.iter().take(HEX_BYTES).map(|b| format!("{b:02x}")).collect();
            if bytes.len() > HEX_BYTES {
                hex.push_str("...");
            }
            J::String(hex)
        }
        Value::Uid(uid) => J::Number(uid.get().into()),
        Value::Array(_) | Value::Dictionary(_) if depth == 0 => J::String("...".into()),
        Value::Array(items) => J::Array(items.iter().map(|v| json(v, depth - 1)).collect()),
        Value::Dictionary(dict) => {
            J::Object(dict.iter().map(|(k, v)| (k.clone(), json(v, depth - 1))).collect::<Map<_, _>>())
        }
        _ => J::Null,
    }
}

/// Compact JSON text of a value, for fields that hold a small structure as one cell.
pub fn compact(value: &Value) -> String {
    json(value, JSON_DEPTH).to_string()
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::{testing::run, Artifact};

    /// Feeds damaged copies of `data` to an artifact. Only a panic fails: the output of a
    /// damaged file is whatever the parser could still read, or an error.
    pub fn survives_damage(artifact: &Artifact, path: &str, data: &[u8]) {
        for len in 0..data.len() {
            run(artifact, path, &data[..len], 0);
        }
        let mut state = 0x9E37_79B9_7F4A_7C15_u64;
        for _ in 0..300 {
            let mut copy = data.to_vec();
            for _ in 0..3 {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                let at = (state % copy.len() as u64) as usize;
                copy[at] ^= (state >> 32) as u8 | 1;
            }
            run(artifact, path, &copy, 0);
        }
    }

    #[test]
    fn dates_and_hex() {
        let value = parse(b"<plist version=\"1.0\"><dict><key>d</key><date>1969-12-31T23:59:59.5Z</date><key>b</key><data>AAEC</data></dict></plist>")
            .unwrap();
        let dict = value.as_dictionary().unwrap();
        let t = date(dict.get("d").unwrap()).unwrap();
        assert_eq!(t.to_rfc3339(), "1969-12-31T23:59:59.500000Z");
        assert_eq!(json(dict.get("b").unwrap(), 1), serde_json::json!("000102"));
        assert_eq!(mac_time(0.0).unwrap().to_rfc3339(), "2001-01-01T00:00:00Z");
        assert!(mac_time(f64::NAN).is_none());
    }

    #[test]
    fn out_of_range_mac_times_are_dropped_not_saturated() {
        // 5e10 s after 2001 is the year 3586: it must not become a "recorded" 2262.
        for secs in [5.0e10, -5.0e10, 1.0e12, f64::INFINITY] {
            assert!(mac_time(secs).is_none(), "{secs}");
        }
        assert_eq!(mac_time(0.5).unwrap().to_rfc3339(), "2001-01-01T00:00:00.500000Z");
    }

    /// Hand-written bplist00: object k (k < levels) is the array `[k+1, k+1]`; the last is 1.
    fn bplist_laughs(levels: usize) -> Vec<u8> {
        let n = levels + 1;
        let mut out = b"bplist00".to_vec();
        let mut offsets = Vec::new();
        for k in 0..levels {
            offsets.push(out.len());
            out.extend([0xA2, (k + 1) as u8, (k + 1) as u8]);
        }
        offsets.push(out.len());
        out.extend([0x10, 1]);
        let table = out.len();
        for o in &offsets {
            out.extend((*o as u16).to_be_bytes());
        }
        let mut trailer = [0u8; 32];
        trailer[6] = 2;
        trailer[7] = 1;
        trailer[8..16].copy_from_slice(&(n as u64).to_be_bytes());
        trailer[24..32].copy_from_slice(&(table as u64).to_be_bytes());
        out.extend(trailer);
        out
    }

    #[test]
    fn shared_children_cannot_expand_a_binary_plist() {
        let started = std::time::Instant::now();
        assert!(parse(&bplist_laughs(22)).is_err());
        assert!(started.elapsed().as_secs() < 2);
        // A modest amount of sharing is fine.
        assert!(parse(&bplist_laughs(3)).is_ok());
    }

    #[test]
    fn deep_nesting_is_refused_on_a_small_stack() {
        let xml = format!("<plist version=\"1.0\">{}{}</plist>", "<array>".repeat(200_000), "</array>".repeat(200_000));
        let ascii = format!("{}{}", "(".repeat(200_000), ")".repeat(200_000));
        let nested: Vec<u8> = std::thread::Builder::new()
            .stack_size(2 << 20)
            .spawn(move || [parse(xml.as_bytes()).is_err(), parse(ascii.as_bytes()).is_err()].map(u8::from).to_vec())
            .unwrap()
            .join()
            .unwrap();
        assert_eq!(nested, [1, 1]);
        assert!(parse(b"<plist version=\"1.0\"><array><array/></array></plist>").is_ok());
        assert!(parse(b"{ a = (1, \"((((\"); }").is_ok());
    }
}
