//! Turns a record struct into one CSV row or JSON object without per-field allocation.
//!
//! A record is a flat `#[derive(Serialize)]` struct. Field names become CSV headers and JSON
//! keys. Nested values (sequences, maps, structs) are allowed: JSON keeps them nested, CSV
//! stores them as a JSON string in one cell. Enum variants that carry data are not.
//!
//! This is a small serializer of its own rather than `serde_json` plus the `csv` crate
//! because rows are the hot path: one pass, one output buffer, no intermediate values.
//!
//! Records must serialize every field every time (no `skip_serializing_if`), or CSV columns
//! would shift.

use serde::ser::{self, Impossible};
use serde::{Serialize, Serializer};
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Csv,
    Json,
    Jsonl,
}

impl Format {
    pub fn extension(self) -> &'static str {
        match self {
            Format::Csv => "csv",
            Format::Json => "json",
            Format::Jsonl => "jsonl",
        }
    }
}

/// Appends `field` as one CSV cell, quoted only when it has to be.
pub fn csv_field(out: &mut Vec<u8>, field: &[u8]) {
    let needs_quotes = memchr::memchr3(b',', b'"', b'\n', field).is_some()
        || memchr::memchr(b'\r', field).is_some()
        || field.first() == Some(&b' ')
        || field.last() == Some(&b' ');
    if !needs_quotes {
        out.extend_from_slice(field);
        return;
    }
    out.push(b'"');
    let mut rest = field;
    while let Some(i) = memchr::memchr(b'"', rest) {
        out.extend_from_slice(&rest[..=i]);
        out.push(b'"');
        rest = &rest[i + 1..];
    }
    out.extend_from_slice(rest);
    out.push(b'"');
}

/// Marks bytes that JSON must escape: `"`, `\` and control characters.
const fn needs_escape(b: u8) -> bool {
    b < 0x20 || b == b'"' || b == b'\\'
}

/// Appends `text` as a JSON string literal.
pub fn json_str(out: &mut Vec<u8>, text: &str) {
    let bytes = text.as_bytes();
    out.push(b'"');
    // Most values need no escaping. Folding without an early exit lets this check vectorize,
    // and the copy is then one memcpy.
    if !bytes.iter().fold(false, |found, &b| found | needs_escape(b)) {
        out.extend_from_slice(bytes);
        out.push(b'"');
        return;
    }
    let mut start = 0;
    for (i, &b) in bytes.iter().enumerate() {
        if !needs_escape(b) {
            continue;
        }
        out.extend_from_slice(&bytes[start..i]);
        match b {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\t' => out.extend_from_slice(b"\\t"),
            0x08 => out.extend_from_slice(b"\\b"),
            0x0c => out.extend_from_slice(b"\\f"),
            _ => {
                const HEX: &[u8; 16] = b"0123456789abcdef";
                out.extend_from_slice(&[b'\\', b'u', b'0', b'0', HEX[(b >> 4) as usize], HEX[(b & 15) as usize]]);
            }
        }
        start = i + 1;
    }
    out.extend_from_slice(&bytes[start..]);
    out.push(b'"');
}

/// The columns the sink writes in front of every record.
pub const RESERVED: [&str; 5] = ["host", "artifact", "source_path", "source_line", "source_offset"];

/// Appends `,name` for each field of `record`. Fails when a field uses a reserved name.
pub(crate) fn write_csv_header<R: Serialize>(record: &R, out: &mut Vec<u8>) -> Result<(), RowError> {
    record.serialize(Fields { out, mode: Mode::CsvHeader, keys: &[], next: 0 })
}

/// The `,"name":` fragment for each field of `record`, ready to copy in front of each value.
pub(crate) fn json_keys<R: Serialize>(record: &R) -> Result<Vec<Vec<u8>>, RowError> {
    let mut names = Vec::new();
    write_csv_header(record, &mut names)?;
    let names = names.split(|&b| b == b',').skip(1);
    Ok(names.map(|name| [b",\"", name, b"\":"].concat()).collect())
}

/// Appends `,value` (CSV) or `,"name":value` (JSON) for each field of `record`. `keys` is the
/// result of [`json_keys`] for this record type; it saves assembling each key for each row.
pub(crate) fn write_fields<R: Serialize>(
    record: &R,
    format: Format,
    keys: &[Vec<u8>],
    out: &mut Vec<u8>,
) -> Result<(), RowError> {
    let mode = if format == Format::Csv { Mode::Csv } else { Mode::Json };
    record.serialize(Fields { out, mode, keys, next: 0 })
}

#[derive(Debug)]
pub struct RowError(String);

impl fmt::Display for RowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for RowError {}

impl ser::Error for RowError {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        RowError(msg.to_string())
    }
}

#[derive(Clone, Copy)]
enum Mode {
    CsvHeader,
    Csv,
    Json,
}

/// The top-level serializer: accepts a struct and writes its fields.
struct Fields<'a> {
    out: &'a mut Vec<u8>,
    mode: Mode,
    /// Prebuilt JSON key fragments and the index of the next field.
    keys: &'a [Vec<u8>],
    next: usize,
}

fn not_a_struct<T>() -> Result<T, RowError> {
    Err(RowError("a record must be a struct".into()))
}

/// Implements the `Serializer` methods that all answer the same way.
macro_rules! reject {
    ($($method:ident($($ty:ty),*) -> $ret:ty;)*) => {
        $(fn $method(self $(, _: $ty)*) -> Result<$ret, RowError> { not_a_struct() })*
    };
}

impl<'a> Serializer for Fields<'a> {
    type Ok = ();
    type Error = RowError;
    type SerializeSeq = Impossible<(), RowError>;
    type SerializeTuple = Impossible<(), RowError>;
    type SerializeTupleStruct = Impossible<(), RowError>;
    type SerializeTupleVariant = Impossible<(), RowError>;
    type SerializeMap = Impossible<(), RowError>;
    type SerializeStruct = Self;
    type SerializeStructVariant = Impossible<(), RowError>;

    fn serialize_struct(self, _name: &'static str, _len: usize) -> Result<Self, RowError> {
        Ok(self)
    }
    fn serialize_newtype_struct<T: ?Sized + Serialize>(self, _name: &'static str, value: &T) -> Result<(), RowError> {
        value.serialize(self)
    }
    fn serialize_some<T: ?Sized + Serialize>(self, _: &T) -> Result<(), RowError> {
        not_a_struct()
    }
    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: &T,
    ) -> Result<(), RowError> {
        not_a_struct()
    }
    reject! {
        serialize_bool(bool) -> ();
        serialize_i8(i8) -> ();
        serialize_i16(i16) -> ();
        serialize_i32(i32) -> ();
        serialize_i64(i64) -> ();
        serialize_u8(u8) -> ();
        serialize_u16(u16) -> ();
        serialize_u32(u32) -> ();
        serialize_u64(u64) -> ();
        serialize_f32(f32) -> ();
        serialize_f64(f64) -> ();
        serialize_char(char) -> ();
        serialize_str(&str) -> ();
        serialize_bytes(&[u8]) -> ();
        serialize_none() -> ();
        serialize_unit() -> ();
        serialize_unit_struct(&'static str) -> ();
        serialize_unit_variant(&'static str, u32, &'static str) -> ();
        serialize_seq(Option<usize>) -> Self::SerializeSeq;
        serialize_tuple(usize) -> Self::SerializeTuple;
        serialize_tuple_struct(&'static str, usize) -> Self::SerializeTupleStruct;
        serialize_tuple_variant(&'static str, u32, &'static str, usize) -> Self::SerializeTupleVariant;
        serialize_map(Option<usize>) -> Self::SerializeMap;
        serialize_struct_variant(&'static str, u32, &'static str, usize) -> Self::SerializeStructVariant;
    }
}

impl<'a> ser::SerializeStruct for Fields<'a> {
    type Ok = ();
    type Error = RowError;

    fn serialize_field<T: ?Sized + Serialize>(&mut self, key: &'static str, value: &T) -> Result<(), RowError> {
        match self.mode {
            Mode::CsvHeader if RESERVED.contains(&key) => {
                Err(RowError(format!("record field `{key}` collides with a column every row already has")))
            }
            Mode::CsvHeader => {
                self.out.push(b',');
                self.out.extend_from_slice(key.as_bytes());
                Ok(())
            }
            Mode::Csv => {
                self.out.push(b',');
                value.serialize(Value { out: self.out, csv: true })
            }
            Mode::Json => {
                match self.keys.get(self.next) {
                    Some(fragment) => self.out.extend_from_slice(fragment),
                    None => {
                        self.out.extend_from_slice(b",\"");
                        self.out.extend_from_slice(key.as_bytes());
                        self.out.extend_from_slice(b"\":");
                    }
                }
                self.next += 1;
                value.serialize(Value { out: self.out, csv: false })
            }
        }
    }

    fn end(self) -> Result<(), RowError> {
        Ok(())
    }
}

/// Writes one value: as JSON, or as one CSV cell. A nested value in a CSV cell is written as
/// JSON first and then quoted as a whole.
struct Value<'a> {
    out: &'a mut Vec<u8>,
    csv: bool,
}

impl<'a> Value<'a> {
    fn raw(self, text: &[u8]) -> Result<(), RowError> {
        self.out.extend_from_slice(text);
        Ok(())
    }

    fn int<I: itoa::Integer>(self, value: I) -> Result<(), RowError> {
        self.raw(itoa::Buffer::new().format(value).as_bytes())
    }

    fn float<F: ryu::Float>(self, value: F, finite: bool) -> Result<(), RowError> {
        if finite {
            self.raw(ryu::Buffer::new().format_finite(value).as_bytes())
        } else {
            self.empty()
        }
    }

    fn empty(self) -> Result<(), RowError> {
        let text: &[u8] = if self.csv { b"" } else { b"null" };
        self.raw(text)
    }

    fn text(self, text: &str) -> Result<(), RowError> {
        if self.csv {
            csv_field(self.out, text.as_bytes());
        } else {
            json_str(self.out, text);
        }
        Ok(())
    }

    /// Starts a nested JSON value. JSON writes it straight into the output; CSV builds it in
    /// a side buffer and quotes it as one cell at the end.
    fn nested(self, open: u8, close: u8) -> Nested<'a> {
        let mut nested = Nested { out: self.out, side: Vec::new(), csv: self.csv, close, first: true };
        nested.json().push(open);
        nested
    }
}

/// A sequence or map being written.
struct Nested<'a> {
    out: &'a mut Vec<u8>,
    /// The JSON text of a CSV cell, before quoting. Unused in JSON mode.
    side: Vec<u8>,
    csv: bool,
    close: u8,
    first: bool,
}

impl Nested<'_> {
    /// Where the JSON text goes.
    fn json(&mut self) -> &mut Vec<u8> {
        if self.csv {
            &mut self.side
        } else {
            self.out
        }
    }

    fn comma(&mut self) {
        if !std::mem::take(&mut self.first) {
            self.json().push(b',');
        }
    }

    fn element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), RowError> {
        self.comma();
        self.value(value)
    }

    fn key<T: ?Sized + Serialize>(&mut self, key: &T) -> Result<(), RowError> {
        self.comma();
        key.serialize(Key { out: self.json() })?;
        self.json().push(b':');
        Ok(())
    }

    fn value<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), RowError> {
        value.serialize(Value { out: self.json(), csv: false })
    }

    fn finish(mut self) -> Result<(), RowError> {
        let close = self.close;
        self.json().push(close);
        if self.csv {
            csv_field(self.out, &self.side);
        }
        Ok(())
    }
}

impl ser::SerializeSeq for Nested<'_> {
    type Ok = ();
    type Error = RowError;
    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), RowError> {
        self.element(value)
    }
    fn end(self) -> Result<(), RowError> {
        self.finish()
    }
}

impl ser::SerializeTuple for Nested<'_> {
    type Ok = ();
    type Error = RowError;
    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), RowError> {
        self.element(value)
    }
    fn end(self) -> Result<(), RowError> {
        self.finish()
    }
}

impl ser::SerializeTupleStruct for Nested<'_> {
    type Ok = ();
    type Error = RowError;
    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), RowError> {
        self.element(value)
    }
    fn end(self) -> Result<(), RowError> {
        self.finish()
    }
}

impl ser::SerializeMap for Nested<'_> {
    type Ok = ();
    type Error = RowError;
    fn serialize_key<T: ?Sized + Serialize>(&mut self, key: &T) -> Result<(), RowError> {
        self.key(key)
    }
    fn serialize_value<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), RowError> {
        self.value(value)
    }
    fn end(self) -> Result<(), RowError> {
        self.finish()
    }
}

impl ser::SerializeStruct for Nested<'_> {
    type Ok = ();
    type Error = RowError;
    fn serialize_field<T: ?Sized + Serialize>(&mut self, key: &'static str, value: &T) -> Result<(), RowError> {
        self.key(key)?;
        self.value(value)
    }
    fn end(self) -> Result<(), RowError> {
        self.finish()
    }
}

fn no_variants<T>() -> Result<T, RowError> {
    Err(RowError("enum variants that carry data are not supported in records".into()))
}

impl<'a> Serializer for Value<'a> {
    type Ok = ();
    type Error = RowError;
    type SerializeSeq = Nested<'a>;
    type SerializeTuple = Nested<'a>;
    type SerializeTupleStruct = Nested<'a>;
    type SerializeTupleVariant = Impossible<(), RowError>;
    type SerializeMap = Nested<'a>;
    type SerializeStruct = Nested<'a>;
    type SerializeStructVariant = Impossible<(), RowError>;

    fn serialize_bool(self, v: bool) -> Result<(), RowError> {
        self.raw(if v { b"true" } else { b"false" })
    }
    fn serialize_i8(self, v: i8) -> Result<(), RowError> {
        self.int(v)
    }
    fn serialize_i16(self, v: i16) -> Result<(), RowError> {
        self.int(v)
    }
    fn serialize_i32(self, v: i32) -> Result<(), RowError> {
        self.int(v)
    }
    fn serialize_i64(self, v: i64) -> Result<(), RowError> {
        self.int(v)
    }
    fn serialize_u8(self, v: u8) -> Result<(), RowError> {
        self.int(v)
    }
    fn serialize_u16(self, v: u16) -> Result<(), RowError> {
        self.int(v)
    }
    fn serialize_u32(self, v: u32) -> Result<(), RowError> {
        self.int(v)
    }
    fn serialize_u64(self, v: u64) -> Result<(), RowError> {
        self.int(v)
    }
    fn serialize_f32(self, v: f32) -> Result<(), RowError> {
        self.float(v, v.is_finite())
    }
    fn serialize_f64(self, v: f64) -> Result<(), RowError> {
        self.float(v, v.is_finite())
    }
    fn serialize_char(self, v: char) -> Result<(), RowError> {
        self.text(v.encode_utf8(&mut [0; 4]))
    }
    fn serialize_str(self, v: &str) -> Result<(), RowError> {
        self.text(v)
    }
    /// Bytes are written as lowercase hex text.
    fn serialize_bytes(self, v: &[u8]) -> Result<(), RowError> {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let hex: String =
            v.iter().flat_map(|b| [HEX[(b >> 4) as usize] as char, HEX[(b & 15) as usize] as char]).collect();
        self.text(&hex)
    }
    fn serialize_none(self) -> Result<(), RowError> {
        self.empty()
    }
    fn serialize_some<T: ?Sized + Serialize>(self, value: &T) -> Result<(), RowError> {
        value.serialize(self)
    }
    fn serialize_unit(self) -> Result<(), RowError> {
        self.empty()
    }
    fn serialize_unit_struct(self, _: &'static str) -> Result<(), RowError> {
        self.empty()
    }
    fn serialize_unit_variant(self, _: &'static str, _: u32, variant: &'static str) -> Result<(), RowError> {
        self.text(variant)
    }
    fn serialize_newtype_struct<T: ?Sized + Serialize>(self, _: &'static str, value: &T) -> Result<(), RowError> {
        value.serialize(self)
    }
    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: &T,
    ) -> Result<(), RowError> {
        no_variants()
    }
    fn serialize_seq(self, _: Option<usize>) -> Result<Nested<'a>, RowError> {
        Ok(self.nested(b'[', b']'))
    }
    fn serialize_tuple(self, _: usize) -> Result<Nested<'a>, RowError> {
        Ok(self.nested(b'[', b']'))
    }
    fn serialize_tuple_struct(self, _: &'static str, _: usize) -> Result<Nested<'a>, RowError> {
        Ok(self.nested(b'[', b']'))
    }
    fn serialize_tuple_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: usize,
    ) -> Result<Self::SerializeTupleVariant, RowError> {
        no_variants()
    }
    fn serialize_map(self, _: Option<usize>) -> Result<Nested<'a>, RowError> {
        Ok(self.nested(b'{', b'}'))
    }
    fn serialize_struct(self, _: &'static str, _: usize) -> Result<Nested<'a>, RowError> {
        Ok(self.nested(b'{', b'}'))
    }
    fn serialize_struct_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: usize,
    ) -> Result<Self::SerializeStructVariant, RowError> {
        no_variants()
    }
}

/// Writes a map key, which JSON requires to be a string.
struct Key<'a> {
    out: &'a mut Vec<u8>,
}

fn bad_key<T>() -> Result<T, RowError> {
    Err(RowError("map keys must be strings or integers".into()))
}

macro_rules! reject_key {
    ($($method:ident($($ty:ty),*) -> $ret:ty;)*) => {
        $(fn $method(self $(, _: $ty)*) -> Result<$ret, RowError> { bad_key() })*
    };
}

impl Key<'_> {
    fn int<I: itoa::Integer>(self, value: I) -> Result<(), RowError> {
        json_str(self.out, itoa::Buffer::new().format(value));
        Ok(())
    }
}

impl Serializer for Key<'_> {
    type Ok = ();
    type Error = RowError;
    type SerializeSeq = Impossible<(), RowError>;
    type SerializeTuple = Impossible<(), RowError>;
    type SerializeTupleStruct = Impossible<(), RowError>;
    type SerializeTupleVariant = Impossible<(), RowError>;
    type SerializeMap = Impossible<(), RowError>;
    type SerializeStruct = Impossible<(), RowError>;
    type SerializeStructVariant = Impossible<(), RowError>;

    fn serialize_str(self, v: &str) -> Result<(), RowError> {
        json_str(self.out, v);
        Ok(())
    }
    fn serialize_char(self, v: char) -> Result<(), RowError> {
        self.serialize_str(v.encode_utf8(&mut [0; 4]))
    }
    fn serialize_i8(self, v: i8) -> Result<(), RowError> {
        self.int(v)
    }
    fn serialize_i16(self, v: i16) -> Result<(), RowError> {
        self.int(v)
    }
    fn serialize_i32(self, v: i32) -> Result<(), RowError> {
        self.int(v)
    }
    fn serialize_i64(self, v: i64) -> Result<(), RowError> {
        self.int(v)
    }
    fn serialize_u8(self, v: u8) -> Result<(), RowError> {
        self.int(v)
    }
    fn serialize_u16(self, v: u16) -> Result<(), RowError> {
        self.int(v)
    }
    fn serialize_u32(self, v: u32) -> Result<(), RowError> {
        self.int(v)
    }
    fn serialize_u64(self, v: u64) -> Result<(), RowError> {
        self.int(v)
    }
    fn serialize_unit_variant(self, _: &'static str, _: u32, variant: &'static str) -> Result<(), RowError> {
        self.serialize_str(variant)
    }
    fn serialize_newtype_struct<T: ?Sized + Serialize>(self, _: &'static str, value: &T) -> Result<(), RowError> {
        value.serialize(self)
    }
    fn serialize_some<T: ?Sized + Serialize>(self, _: &T) -> Result<(), RowError> {
        bad_key()
    }
    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: &T,
    ) -> Result<(), RowError> {
        bad_key()
    }
    reject_key! {
        serialize_bool(bool) -> ();
        serialize_f32(f32) -> ();
        serialize_f64(f64) -> ();
        serialize_bytes(&[u8]) -> ();
        serialize_none() -> ();
        serialize_unit() -> ();
        serialize_unit_struct(&'static str) -> ();
        serialize_seq(Option<usize>) -> Self::SerializeSeq;
        serialize_tuple(usize) -> Self::SerializeTuple;
        serialize_tuple_struct(&'static str, usize) -> Self::SerializeTupleStruct;
        serialize_tuple_variant(&'static str, u32, &'static str, usize) -> Self::SerializeTupleVariant;
        serialize_map(Option<usize>) -> Self::SerializeMap;
        serialize_struct(&'static str, usize) -> Self::SerializeStruct;
        serialize_struct_variant(&'static str, u32, &'static str, usize) -> Self::SerializeStructVariant;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::{Basis, Timestamp};

    #[derive(Serialize)]
    struct Sample<'a> {
        name: &'a str,
        uid: u32,
        ratio: f64,
        when: Option<Timestamp>,
        missing: Option<u8>,
        tags: Vec<&'a str>,
        ok: bool,
    }

    fn sample() -> Sample<'static> {
        Sample {
            name: "a \"quoted\", name",
            uid: 1000,
            ratio: 0.5,
            when: Some(Timestamp::from_secs(0, Basis::Recorded)),
            missing: None,
            tags: vec!["x", "y"],
            ok: true,
        }
    }

    fn render(format: Format) -> String {
        let mut out = Vec::new();
        write_fields(&sample(), format, &json_keys(&sample()).unwrap(), &mut out).unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn csv_header_lists_fields() {
        let mut out = Vec::new();
        write_csv_header(&sample(), &mut out).unwrap();
        assert_eq!(out, b",name,uid,ratio,when,missing,tags,ok");
    }

    #[test]
    fn csv_row_quotes_and_nests() {
        assert_eq!(
            render(Format::Csv),
            ",\"a \"\"quoted\"\", name\",1000,0.5,1970-01-01T00:00:00Z,,\"[\"\"x\"\",\"\"y\"\"]\",true"
        );
    }

    #[test]
    fn json_row_keeps_nesting() {
        assert_eq!(
            render(Format::Jsonl),
            ",\"name\":\"a \\\"quoted\\\", name\",\"uid\":1000,\"ratio\":0.5,\"when\":\"1970-01-01T00:00:00Z\",\"missing\":null,\"tags\":[\"x\",\"y\"],\"ok\":true"
        );
    }

    #[test]
    fn rejects_reserved_field_names() {
        #[derive(Serialize)]
        struct Clash {
            host: u8,
        }
        assert!(write_csv_header(&Clash { host: 1 }, &mut Vec::new()).is_err());
    }

    #[test]
    fn rejects_non_struct_records() {
        assert!(write_fields(&5u8, Format::Csv, &[], &mut Vec::new()).is_err());
    }

    #[test]
    fn json_strings_are_escaped_like_serde_json() {
        for text in
            ["plain", "", "quote \" and \\ slash", "tab\tnewline\nreturn\r", "\u{1}\u{1f}", "unicode é 日本 \u{7f}"]
        {
            let mut out = Vec::new();
            json_str(&mut out, text);
            assert_eq!(serde_json::from_slice::<String>(&out).unwrap(), text);
        }
    }

    #[test]
    fn nested_maps_and_structs() {
        #[derive(Serialize)]
        struct Inner {
            n: u8,
        }
        #[derive(Serialize)]
        struct Outer<'a> {
            fields: std::collections::BTreeMap<&'a str, &'a str>,
            pairs: Vec<(u8, Option<Inner>)>,
            by_id: std::collections::BTreeMap<u32, bool>,
        }
        let record = Outer {
            fields: [("A", "1"), ("B", "x,\"y\"")].into(),
            pairs: vec![(1, Some(Inner { n: 2 })), (3, None)],
            by_id: [(7, true)].into(),
        };
        let mut json = Vec::new();
        write_fields(&record, Format::Jsonl, &[], &mut json).unwrap();
        let expected = r#","fields":{"A":"1","B":"x,\"y\""},"pairs":[[1,{"n":2}],[3,null]],"by_id":{"7":true}"#;
        assert_eq!(String::from_utf8(json).unwrap(), expected);

        let mut csv = Vec::new();
        write_fields(&record, Format::Csv, &[], &mut csv).unwrap();
        let csv = String::from_utf8(csv).unwrap();
        assert!(csv.starts_with(",\"{\"\"A\"\":\"\"1\"\","), "{csv}");
        assert!(csv.ends_with(",\"{\"\"7\"\":true}\""), "{csv}");
    }

    #[test]
    fn data_carrying_variants_are_rejected() {
        #[derive(Serialize)]
        enum Kind {
            Named(u8),
        }
        #[derive(Serialize)]
        struct Bad {
            kind: Kind,
        }
        assert!(write_fields(&Bad { kind: Kind::Named(1) }, Format::Jsonl, &[], &mut Vec::new()).is_err());
    }

    #[test]
    fn csv_field_quoting() {
        let cell = |s: &str| {
            let mut out = Vec::new();
            csv_field(&mut out, s.as_bytes());
            String::from_utf8(out).unwrap()
        };
        assert_eq!(cell("plain"), "plain");
        assert_eq!(cell("a,b"), "\"a,b\"");
        assert_eq!(cell("line\nbreak"), "\"line\nbreak\"");
        assert_eq!(cell(" padded"), "\" padded\"");
    }
}
