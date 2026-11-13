//! `vm-support` splits every file larger than 1 MiB into numbered pieces
//! (`hostd.log.FRAG-00000`, `hostd.log.FRAG-00001`, ...). The cut falls wherever the byte count
//! ends, usually inside a line. Each piece is parsed as its own task, so [`run`] repairs the
//! two edges before a parser sees the data: the tail of a line begun in the previous piece is
//! dropped (the previous piece parses the whole line), and a last line with no newline is
//! completed from the start of the next piece. Pieces missing from the bundle leave their
//! edge as it is. Offsets in the records then count bytes of the repaired piece.

use crate::Input;
use nixcavate_core::{Result, Sink};

const MARKER: &str = ".FRAG-";

/// Splits `name.FRAG-00012` into (`name`, 12, number of digits).
fn split(path: &str) -> Option<(&str, u64, usize)> {
    let at = path.rfind(MARKER)?;
    let digits = &path[at + MARKER.len()..];
    if digits.is_empty() || digits.len() > 9 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((&path[..at], digits.parse().ok()?, digits.len()))
}

/// The repaired data of a piece, or `None` when the input is not one.
fn stitched(input: &Input) -> Option<Vec<u8>> {
    let (stem, number, width) = split(input.path)?;
    if input.offset != 0 {
        return None;
    }
    let sibling = |n: u64| input.host.read(&format!("{stem}{MARKER}{n:0width$}"));
    let mut data = input.data;
    if number > 0 {
        // The previous piece ended on a line end, or the first line here is a tail.
        let whole = number.checked_sub(1).and_then(sibling).is_some_and(|previous| previous.last() == Some(&b'\n'));
        if !whole {
            data = match memchr::memchr(b'\n', data) {
                Some(end) => &data[end + 1..],
                None => &[],
            };
        }
    }
    let mut out = data.to_vec();
    if out.last().is_some_and(|b| *b != b'\n') {
        if let Some(next) = number.checked_add(1).and_then(sibling) {
            let head = memchr::memchr(b'\n', &next).map_or(&next[..], |end| &next[..=end]);
            out.extend_from_slice(head);
        }
    }
    Some(out)
}

/// Runs `parse` on the input, repaired when it is a `vm-support` piece.
pub fn run(input: &Input, sink: &mut Sink, parse: fn(&Input, &mut Sink) -> Result<()>) -> Result<()> {
    match stitched(input) {
        Some(data) => parse(&Input { data: &data, ..*input }, sink),
        None => parse(input, sink),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::with_host;

    fn repaired(files: &[(&str, &[u8])], path: &str) -> Option<String> {
        with_host(files, path, 0, |input| stitched(input).map(|d| String::from_utf8_lossy(&d).into_owned()))
    }

    #[test]
    fn splits_piece_names() {
        assert_eq!(split("var/run/log/hostd.log.FRAG-00012"), Some(("var/run/log/hostd.log", 12, 5)));
        assert_eq!(split("var/run/log/hostd.log"), None);
        assert_eq!(split("a.FRAG-"), None);
        assert_eq!(split("a.FRAG-1x"), None);
        assert_eq!(split("a.FRAG-99999999999"), None);
    }

    #[test]
    fn a_line_cut_between_pieces_is_read_once_and_whole() {
        let files: [(&str, &[u8]); 3] = [
            ("var/log/x.log.FRAG-00000", b"one\ntw"),
            ("var/log/x.log.FRAG-00001", b"o\nthree\nfo"),
            ("var/log/x.log.FRAG-00002", b"ur\nfive\n"),
        ];
        assert_eq!(repaired(&files, "var/log/x.log.FRAG-00000").as_deref(), Some("one\ntwo\n"));
        assert_eq!(repaired(&files, "var/log/x.log.FRAG-00001").as_deref(), Some("three\nfour\n"));
        assert_eq!(repaired(&files, "var/log/x.log.FRAG-00002").as_deref(), Some("five\n"));
    }

    #[test]
    fn a_piece_that_starts_on_a_line_start_keeps_its_first_line() {
        let files: [(&str, &[u8]); 2] =
            [("var/log/x.log.FRAG-00000", b"one\n"), ("var/log/x.log.FRAG-00001", b"two\n")];
        assert_eq!(repaired(&files, "var/log/x.log.FRAG-00001").as_deref(), Some("two\n"));
    }

    #[test]
    fn missing_neighbours_and_other_files_are_left_alone() {
        let files: [(&str, &[u8]); 2] = [("var/log/x.log.FRAG-00003", b"tail\nhead"), ("var/log/y.log", b"y\n")];
        assert_eq!(repaired(&files, "var/log/x.log.FRAG-00003").as_deref(), Some("head"));
        assert_eq!(repaired(&files, "var/log/y.log"), None);
        let lone: [(&str, &[u8]); 1] = [("var/log/x.log.FRAG-00000", b"no newline")];
        assert_eq!(repaired(&lone, "var/log/x.log.FRAG-00000").as_deref(), Some("no newline"));
    }
}
