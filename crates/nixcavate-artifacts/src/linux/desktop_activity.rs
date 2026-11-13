//! Traces of what a user did in a graphical session, as the freedesktop.org specifications and
//! GTK write them:
//!
//! - `recently-used.xbel` (Recent File Storage Specification: XBEL bookmarks with `added`,
//!   `modified` and `visited` times, the MIME type and the applications that opened the file);
//! - the Trash (Trash specification 1.0: `Trash/info/<name>.trashinfo` with the original path
//!   and the deletion time, paired here with `Trash/files/<name>`);
//! - thumbnails (Thumbnail Managing Standard: PNG files whose `tEXt` chunks hold the original
//!   file's URI, modification time and size).
//!
//! Each is evidence that a file existed and was used, often after the file itself is gone. A
//! thumbnail proves the file was shown in a file manager. Only the PNG text chunks are read:
//! the image data is never decoded.
//!
//! Times: the XBEL times carry a zone (UTC); `DeletionDate` is local time with no zone, so the
//! host zone is assumed; `Thumb::MTime` is an epoch value. The time of the thumbnail file itself
//! is the file's modification time as collected.

use crate::common::home::user_from_path;
use crate::common::logfmt::{file_uri_path, percent_decode};
use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, UNIX};
use nixcavate_core::time::{parse_iso8601, parse_uint};
use nixcavate_core::{Basis, Error, Event, Loc, Record, Result, Sink, Timestamp};
use serde::Serialize;

pub const RECENT: Artifact = Artifact::new(
    "gtk-recent-files",
    "GTK recently-used.xbel: files a user opened, when, and with what",
    Category::Activity,
    UNIX,
    &[
        "home/*/.local/share/recently-used.xbel",
        "root/.local/share/recently-used.xbel",
        "home/*/.recently-used.xbel",
        "root/.recently-used.xbel",
    ],
    parse_recent,
);

pub const TRASH: Artifact = Artifact::new(
    "trash",
    "Freedesktop trash: files a user deleted, from where and when",
    Category::Activity,
    UNIX,
    &[
        "home/*/.local/share/Trash/info/*.trashinfo",
        "root/.local/share/Trash/info/*.trashinfo",
        ".Trash-*/info/*.trashinfo",
        ".Trash/*/info/*.trashinfo",
        "media/*/*/.Trash-*/info/*.trashinfo",
        "media/*/.Trash-*/info/*.trashinfo",
        "run/media/*/*/.Trash-*/info/*.trashinfo",
        "mnt/*/.Trash-*/info/*.trashinfo",
        "mnt/*/.Trash/*/info/*.trashinfo",
    ],
    parse_trash,
);

pub const THUMBNAILS: Artifact = Artifact::new(
    "thumbnails",
    "Freedesktop thumbnails: the URI and time of files a file manager displayed",
    Category::Activity,
    UNIX,
    &[
        "home/*/.cache/thumbnails/*/*.png",
        "home/*/.cache/thumbnails/fail/*/*.png",
        "home/*/.thumbnails/*/*.png",
        "home/*/.thumbnails/fail/*/*.png",
        "root/.cache/thumbnails/*/*.png",
        "root/.cache/thumbnails/fail/*/*.png",
        "root/.thumbnails/*/*.png",
        "home/*/.var/app/*/cache/thumbnails/*/*.png",
    ],
    parse_thumbnail,
);

// ---- a minimal XML tag reader ----

/// One tag of an XML document: its name (`/name` for a closing tag), its attributes, and whether
/// it is self-closing. The reader only knows what XBEL needs: no DTDs, no entities beyond the
/// five predefined ones and numeric references, no namespaces resolution.
pub(crate) struct Tag<'a> {
    /// Byte offset of the `<`.
    pub(crate) start: usize,
    pub(crate) name: &'a str,
    attrs: Vec<(&'a str, String)>,
    pub(crate) self_closing: bool,
}

impl Tag<'_> {
    pub(crate) fn attr(&self, name: &str) -> Option<&str> {
        self.attrs.iter().find(|(n, _)| *n == name).map(|(_, v)| v.as_str())
    }
}

pub(crate) fn unescape(raw: &str) -> String {
    if !raw.contains('&') {
        return raw.to_string();
    }
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        rest = &rest[at..];
        let Some(end) = rest.find(';').filter(|e| *e <= 10) else {
            out.push('&');
            rest = &rest[1..];
            continue;
        };
        let entity = &rest[1..end];
        let decoded = match entity {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            e => e
                .strip_prefix("#x")
                .and_then(|h| u32::from_str_radix(h, 16).ok())
                .or_else(|| e.strip_prefix('#').and_then(|d| d.parse().ok()))
                .and_then(char::from_u32),
        };
        match decoded {
            Some(c) => out.push(c),
            None => out.push_str(&rest[..=end]),
        }
        rest = &rest[end + 1..];
    }
    out.push_str(rest);
    out
}

/// The next tag at or after `*pos`, with `*pos` moved past it. Comments, declarations and
/// processing instructions are skipped. `None` at the end of the text.
pub(crate) fn next_tag<'a>(text: &'a str, pos: &mut usize) -> Option<Tag<'a>> {
    loop {
        let start = text.get(*pos..)?.find('<')? + *pos;
        let rest = text.get(start..)?;
        if rest.starts_with("<!--") {
            *pos = start + rest.find("-->").map_or(rest.len(), |e| e + 3);
            continue;
        }
        if rest.starts_with("<?") || rest.starts_with("<!") {
            *pos = start + rest.find('>').map_or(rest.len(), |e| e + 1);
            continue;
        }
        // The end of the tag: the first `>` outside a quoted attribute value.
        let mut quote = None;
        let mut end = None;
        for (i, c) in rest.char_indices().skip(1) {
            match (quote, c) {
                (None, '"' | '\'') => quote = Some(c),
                (Some(q), c) if c == q => quote = None,
                (None, '>') => {
                    end = Some(i);
                    break;
                }
                _ => {}
            }
        }
        let end = end?;
        *pos = start + end + 1;
        let inner = rest.get(1..end)?;
        let self_closing = inner.ends_with('/');
        let inner = inner.strip_suffix('/').unwrap_or(inner);
        let name_end = inner.find(|c: char| c.is_whitespace()).unwrap_or(inner.len());
        let name = inner.get(..name_end)?;
        let mut attrs = Vec::new();
        let mut rest = inner.get(name_end..)?.trim_start();
        // `name="value"` pairs; at most 32 per tag.
        while attrs.len() < 32 {
            let Some((key, after)) = rest.split_once('=') else { break };
            let after = after.trim_start();
            let Some(quote) = after.chars().next().filter(|c| *c == '"' || *c == '\'') else { break };
            let Some(value_end) = after[1..].find(quote) else { break };
            attrs.push((key.trim(), unescape(&after[1..1 + value_end])));
            rest = after[value_end + 2..].trim_start();
        }
        return Some(Tag { start, name, attrs, self_closing });
    }
}

// ---- recently-used.xbel ----

#[derive(Serialize)]
struct Application {
    name: String,
    exec: String,
    count: Option<u64>,
    modified: Option<Timestamp>,
}

#[derive(Serialize)]
struct Recent<'a> {
    user: &'a str,
    uri: String,
    /// The path when the URI is a `file://` one.
    path: String,
    added: Option<Timestamp>,
    modified: Option<Timestamp>,
    visited: Option<Timestamp>,
    mime_type: Option<String>,
    groups: Vec<String>,
    applications: Vec<Application>,
}

impl Record for Recent<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let apps: Vec<&str> = self.applications.iter().map(|a| a.name.as_str()).collect();
        let what = |verb: &str| format!("{} {verb} {} ({})", self.user, self.path, apps.join(", "));
        let mut events = Vec::new();
        if let Some(added) = self.added {
            events.push(Event::new(added, "recent_file_added", what("added to recent files:")));
        }
        for (time, kind) in [(self.modified, "recent_file_modified"), (self.visited, "recent_file_visited")] {
            if let Some(t) = time.filter(|t| Some(*t) != self.added) {
                events.push(Event::new(
                    t,
                    kind,
                    what(if kind.ends_with("modified") { "updated recent entry:" } else { "visited:" }),
                ));
            }
        }
        events.into_iter()
    }
}

fn iso(text: &str) -> Option<Timestamp> {
    parse_iso8601(text.as_bytes())?.0.recorded()
}

fn parse_recent(input: &Input, sink: &mut Sink) -> Result<()> {
    let text = lossy(input.data);
    if !text.contains("<xbel") {
        return Err(Error::format("not an XBEL file: no <xbel> element"));
    }
    let user = user_from_path(input.path);
    let mut pos = 0;
    let mut current: Option<(u64, Recent)> = None;
    let mut in_group = false;
    let mut count = 0u64;
    while let Some(tag) = next_tag(&text, &mut pos) {
        match tag.name {
            "bookmark" => {
                if let Some((at, done)) = current.take() {
                    sink.emit(Loc::Offset(at), &done)?;
                }
                count += 1;
                let uri = tag.attr("href").unwrap_or_default().to_string();
                current = Some((
                    tag.start as u64,
                    Recent {
                        user,
                        path: file_uri_path(&uri).into_owned(),
                        uri,
                        added: tag.attr("added").and_then(iso),
                        modified: tag.attr("modified").and_then(iso),
                        visited: tag.attr("visited").and_then(iso),
                        mime_type: None,
                        groups: Vec::new(),
                        applications: Vec::new(),
                    },
                ));
                if tag.self_closing {
                    if let Some((at, done)) = current.take() {
                        sink.emit(Loc::Offset(at), &done)?;
                    }
                }
            }
            "/bookmark" => {
                if let Some((at, done)) = current.take() {
                    sink.emit(Loc::Offset(at), &done)?;
                }
            }
            "mime:mime-type" => {
                if let Some((_, r)) = current.as_mut() {
                    r.mime_type = tag.attr("type").map(str::to_string);
                }
            }
            "bookmark:group" if !tag.self_closing => in_group = true,
            "/bookmark:group" => in_group = false,
            "bookmark:application" => {
                if let Some((_, r)) = current.as_mut().filter(|(_, r)| r.applications.len() < 64) {
                    r.applications.push(Application {
                        name: tag.attr("name").unwrap_or_default().to_string(),
                        exec: tag.attr("exec").unwrap_or_default().to_string(),
                        count: tag.attr("count").and_then(|c| parse_uint(c.as_bytes())),
                        modified: tag.attr("modified").and_then(iso),
                    });
                }
            }
            _ => {}
        }
        if in_group {
            // The group name is the text after the tag, up to the next `<`.
            let rest = text.get(pos..).unwrap_or_default();
            let name = rest.split('<').next().unwrap_or_default().trim();
            if let Some((_, r)) = current.as_mut().filter(|(_, r)| r.groups.len() < 64) {
                if !name.is_empty() {
                    r.groups.push(unescape(name));
                }
            }
            in_group = false;
        }
    }
    if let Some((at, done)) = current.take() {
        sink.emit(Loc::Offset(at), &done)?;
    }
    if count == 0 {
        return Err(Error::skipped("no bookmarks"));
    }
    Ok(())
}

// ---- Trash ----

#[derive(Serialize)]
struct Trashed<'a> {
    user: &'a str,
    /// The trash directory (`home/alice/.local/share/Trash`, `.Trash-1000`).
    trash_dir: &'a str,
    /// The name under `Trash/files/`.
    stored_as: &'a str,
    original_path: String,
    /// `DeletionDate`, local time with no zone.
    deleted: Option<Timestamp>,
    /// Whether `Trash/files/<name>` is in the collection. A trashed directory is found only when the
    /// collection lists directory entries.
    trashed_file_found: bool,
    size: Option<u64>,
    /// The file's modification time (a trashed file keeps its own).
    file_mtime: Option<Timestamp>,
}

impl Record for Trashed<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let message = format!(
            "{} moved {} to the trash{}",
            self.user,
            self.original_path,
            if self.trashed_file_found { "" } else { " (the trashed file is gone)" }
        );
        self.deleted.map(|t| Event::new(t, "file_trashed", message)).into_iter()
    }
}

fn parse_trash(input: &Input, sink: &mut Sink) -> Result<()> {
    let mut original = None;
    let mut deleted = None;
    let mut header = false;
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let text = text.trim();
        if text == "[Trash Info]" {
            header = true;
        } else if let Some(path) = text.strip_prefix("Path=") {
            original = Some(percent_decode(path).into_owned());
        } else if let Some(date) = text.strip_prefix("DeletionDate=") {
            deleted =
                parse_iso8601(date.as_bytes()).map(|(parsed, _)| crate::common::stamped_log::timestamp(input, &parsed));
        }
        Ok(())
    })?;
    if !header {
        return Err(Error::format("not a .trashinfo file: no [Trash Info] group"));
    }
    let Some(original_path) = original else { return Err(Error::format("a .trashinfo file with no Path key")) };
    // `<trash>/info/<name>.trashinfo` pairs with `<trash>/files/<name>`.
    let (trash_dir, name) = input.path.rsplit_once("/info/").unwrap_or(("", input.path));
    let stored_as = name.strip_suffix(".trashinfo").unwrap_or(name);
    let entry = input.host.lookup(&format!("{trash_dir}/files/{stored_as}"));
    sink.emit(
        Loc::Line(1),
        &Trashed {
            user: user_from_path(input.path),
            trash_dir,
            stored_as,
            original_path,
            deleted,
            trashed_file_found: entry.is_some(),
            size: entry.map(|e| e.size),
            file_mtime: entry.filter(|e| e.mtime > 0).map(|e| Timestamp::from_secs(e.mtime, Basis::Recorded)),
        },
    )
}

// ---- thumbnails ----

/// The text chunks, the image size and the structural problem found, if any.
type PngText = (Vec<(String, String)>, Option<(u32, u32)>, Option<&'static str>);

const PNG_SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1a\n";
/// Chunks walked per file and bytes kept per text chunk: a thumbnail has a handful of each.
const MAX_CHUNKS: usize = 4096;
const MAX_TEXT: usize = 64 << 10;

/// The text chunks (`tEXt`, and `iTXt` without compression) of a PNG and its dimensions, by
/// walking the chunk headers. Image data is skipped by length and never decoded. `Err` names
/// what is wrong with the structure; the chunks read up to that point are still returned.
fn png_text(data: &[u8]) -> PngText {
    let mut texts = Vec::new();
    let mut size = None;
    if data.get(..8) != Some(PNG_SIGNATURE) {
        return (texts, size, Some("not a PNG: bad signature"));
    }
    let mut pos = 8usize;
    for _ in 0..MAX_CHUNKS {
        let Some(header) = data.get(pos..pos.saturating_add(8)) else {
            return (texts, size, Some("the PNG ends before IEND"));
        };
        let length = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize;
        let kind = &header[4..8];
        let body_start = pos + 8;
        let Some(body_end) =
            body_start.checked_add(length).filter(|end| end.checked_add(4).is_some_and(|c| c <= data.len()))
        else {
            return (texts, size, Some("a PNG chunk is longer than the file"));
        };
        let body = &data[body_start..body_end];
        match kind {
            b"IHDR" if body.len() >= 8 => {
                size = Some((
                    u32::from_be_bytes([body[0], body[1], body[2], body[3]]),
                    u32::from_be_bytes([body[4], body[5], body[6], body[7]]),
                ));
            }
            b"tEXt" => {
                if let Some(nul) = body.iter().position(|b| *b == 0) {
                    let value = &body[nul + 1..body.len().min(nul + 1 + MAX_TEXT)];
                    // Latin-1 by the PNG specification; the thumbnail keys and values are ASCII or
                    // UTF-8 in practice, so try UTF-8 first.
                    let text = match std::str::from_utf8(value) {
                        Ok(s) => s.to_string(),
                        Err(_) => value.iter().map(|b| *b as char).collect(),
                    };
                    texts.push((String::from_utf8_lossy(&body[..nul]).into_owned(), text));
                }
            }
            b"iTXt" => {
                // keyword NUL compression-flag compression-method language NUL translated NUL text
                if let Some(nul) = body.iter().position(|b| *b == 0) {
                    if body.get(nul + 1) == Some(&0) {
                        let rest = body.get(nul + 3..).unwrap_or_default();
                        let mut parts = rest.splitn(3, |b| *b == 0);
                        let (_language, _translated, value) =
                            (parts.next(), parts.next(), parts.next().unwrap_or_default());
                        let value = &value[..value.len().min(MAX_TEXT)];
                        texts.push((
                            String::from_utf8_lossy(&body[..nul]).into_owned(),
                            String::from_utf8_lossy(value).into_owned(),
                        ));
                    }
                }
            }
            b"IEND" => return (texts, size, None),
            _ => {}
        }
        pos = body_end + 4;
    }
    (texts, size, Some("the PNG has more chunks than a thumbnail should"))
}

#[derive(Serialize)]
struct Thumbnail<'a> {
    user: &'a str,
    /// `normal` (128), `large` (256), `x-large` (512), `xx-large` (1024) or the `fail` directory.
    size_class: &'a str,
    /// A `fail/<application>/` entry: the thumbnailer could not make a thumbnail of the file.
    failed: bool,
    /// `Thumb::URI`: the original file.
    uri: String,
    path: String,
    /// `Thumb::MTime`: the original file's modification time when the thumbnail was made.
    original_mtime: Option<Timestamp>,
    /// `Thumb::Size`: the original file's size in bytes.
    original_size: Option<u64>,
    mime_type: Option<String>,
    /// `Software`: the program that wrote the thumbnail.
    software: Option<String>,
    width: Option<u32>,
    height: Option<u32>,
    /// The thumbnail file's own modification time: when the file was shown.
    thumbnail_mtime: Option<Timestamp>,
}

impl Record for Thumbnail<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let message = format!(
            "thumbnail of {} ({} bytes{})",
            self.path,
            self.original_size.unwrap_or(0),
            if self.failed { ", thumbnailing failed" } else { "" }
        );
        self.thumbnail_mtime.map(|t| Event::new(t, "thumbnail_created", message)).into_iter()
    }
}

fn parse_thumbnail(input: &Input, sink: &mut Sink) -> Result<()> {
    let (texts, size, problem) = png_text(input.data);
    if problem == Some("not a PNG: bad signature") {
        return Err(Error::format("not a PNG file"));
    }
    if let Some(problem) = problem {
        sink.warn(format!("{problem}: the text chunks before it were read"));
    }
    let get = |key: &str| texts.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str());
    let Some(uri) = get("Thumb::URI") else {
        return Err(Error::skipped("a PNG with no Thumb::URI text chunk (not a freedesktop thumbnail)"));
    };
    let dirs: Vec<&str> = input.path.split('/').collect();
    let at = dirs.iter().rposition(|d| matches!(*d, "thumbnails" | ".thumbnails")).unwrap_or(0);
    let failed = dirs.get(at + 1) == Some(&"fail");
    sink.emit(
        Loc::Offset(0),
        &Thumbnail {
            user: user_from_path(input.path),
            size_class: dirs.get(at + 1).copied().unwrap_or_default(),
            failed,
            uri: uri.to_string(),
            path: file_uri_path(uri).into_owned(),
            original_mtime: get("Thumb::MTime")
                .and_then(|m| parse_uint(m.as_bytes()))
                .and_then(|m| i64::try_from(m).ok())
                .map(|m| Timestamp::from_secs(m, Basis::Recorded)),
            original_size: get("Thumb::Size").and_then(|s| parse_uint(s.as_bytes())),
            mime_type: get("Thumb::Mimetype").map(str::to_string),
            software: get("Software").map(str::to_string),
            width: size.map(|s| s.0),
            height: size.map(|s| s.1),
            thumbnail_mtime: Some(input.mtime).filter(|m| *m > 0).map(|m| Timestamp::from_secs(m, Basis::Recorded)),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run, run_on_host};

    fn records(out: &str) -> Vec<&str> {
        out.lines().take_while(|l| !l.starts_with("---")).collect()
    }

    fn clean(out: &str) {
        assert!(!out.contains("--- warning") && !out.contains("--- failed"), "{out}");
    }

    /// The truth file the session script wrote (`say`): kind, UTC second, details.
    fn truth(kind: &str) -> Vec<Vec<String>> {
        String::from_utf8_lossy(&fixture("gtk-recent-files/truth.txt"))
            .lines()
            .filter(|l| l.starts_with(kind))
            .map(|l| l.split(' ').map(str::to_string).collect())
            .collect()
    }

    /// Fixture: a real GTK 3 session (Debian 12): `Gtk.RecentManager` adds, plus real gedit and eog
    /// opening files; 4 files, one added twice (count 2 for the first application).
    #[test]
    fn recently_used_xbel_matches_the_session() {
        let data = fixture("gtk-recent-files/recently-used.xbel");
        let out = run(&RECENT, "home/alice/.local/share/recently-used.xbel", &data, 0);
        clean(&out);
        let bookmarks = String::from_utf8_lossy(&data).matches("<bookmark ").count();
        assert_eq!(records(&out).len(), bookmarks);
        assert_eq!(bookmarks, 4);
        let report = records(&out).into_iter().find(|l| l.contains("Documents/report.txt")).unwrap_or_default();
        assert!(report.contains("\"name\":\"nxapp\",\"exec\":\"'nxapp %u'\",\"count\":2"), "{report}");
        assert!(report.contains("\"name\":\"gedit\"") && report.contains("\"mime_type\":\"text/plain\""), "{report}");
        assert!(out.contains("\"path\":\"/home/alice/Documents/café über.txt\""), "{out}");
        assert!(out.contains("\"groups\":[\"Graphics\"]"), "{out}");
        // The times against what the script did: each `recent` line of the truth file is an added time.
        for entry in truth("recent").iter().take(3) {
            let second = &entry[1];
            assert!(out.contains(&second[..second.len() - 1]), "{second} not in the output");
        }
        insta::assert_snapshot!(out);
    }

    #[test]
    fn xbel_entities_and_hostile_text() {
        let xbel = "<xbel version=\"1.0\"><bookmark href=\"file:///a%20b/&amp;c.txt\" added=\"2024-03-10T01:02:03Z\" modified=\"bad\" visited=\"2024-03-10T01:02:04Z\"><info><metadata><mime:mime-type type=\"a/b\"/><bookmark:applications><bookmark:application name=\"x&quot;y\" exec=\"e\" count=\"99999999999999999999\"/></bookmark:applications></metadata></info></bookmark></xbel>";
        let out = run(&RECENT, "home/alice/.recently-used.xbel", xbel.as_bytes(), 0);
        assert!(out.contains("\"path\":\"/a b/&c.txt\"") && out.contains("x\\\"y"), "{out}");
        assert!(run(&RECENT, "home/alice/.recently-used.xbel", b"<html></html>", 0).contains("not an XBEL"));
        let full = fixture("gtk-recent-files/recently-used.xbel");
        for cut in (0..full.len()).step_by(7) {
            run(&RECENT, "home/alice/.recently-used.xbel", &full[..cut], 0);
        }
        for junk in [
            "<xbel><bookmark",
            "<xbel><bookmark href=\"",
            "<xbel><!-- <bookmark",
            "<xbel><bookmark a='\"/>",
            "<xbel>&#xFFFFFFFF;&#;&;<bookmark href=\"&\"/>",
        ] {
            run(&RECENT, "home/alice/.recently-used.xbel", junk.as_bytes(), 0);
        }
    }

    /// Fixture: real `gio trash` on a file, a name with `%20`, a directory and a file that was then
    /// removed from `Trash/files`.
    #[test]
    fn trash_info_pairs_with_the_trashed_file() {
        let base = "home/alice/.local/share/Trash";
        let original = fixture("trash/to-trash.txt.original");
        let kept: &[(&str, &[u8])] = &[
            ("home/alice/.local/share/Trash/files/to-trash.txt", &original),
            ("home/alice/.local/share/Trash/files/also trash %20.txt", b"x"),
        ];
        let one = |name: &str| {
            let path = format!("{base}/info/{name}.trashinfo");
            let mut files: Vec<(&str, &[u8])> = kept.to_vec();
            let data = fixture(&format!("trash/{name}.trashinfo"));
            files.push((&path, &data));
            let owned = path.clone();
            run_on_host(&TRASH, &files, &owned, 0)
        };
        let normal = one("to-trash.txt");
        clean(&normal);
        assert!(
            normal.contains("\"original_path\":\"/home/alice/tmp/to-trash.txt\"")
                && normal.contains("\"trashed_file_found\":true,\"size\":9"),
            "{normal}"
        );
        let spaced = one("also trash %20.txt");
        assert!(
            spaced.contains("\"original_path\":\"/home/alice/tmp/also trash %20.txt\"")
                && spaced.contains("\"stored_as\":\"also trash %20.txt\""),
            "{spaced}"
        );
        let purged = one("purged.txt");
        assert!(
            purged.contains("\"trashed_file_found\":false,\"size\":null")
                && purged.contains("(the trashed file is gone)"),
            "{purged}"
        );
        // The deletion times against the session's `trash` lines (local time, no zone: assumed UTC here).
        for (name, entry) in [("to-trash.txt", &truth("trash")[0]), ("purged.txt", &truth("trash")[3])] {
            let second = entry[1].trim_end_matches('Z');
            assert!(one(name).contains(&format!("\"deleted\":\"{second}Z\"")), "{name}: {second}");
        }
        insta::assert_snapshot!(purged);
    }

    #[test]
    fn trashinfo_damage_is_reported() {
        let path = "home/alice/.local/share/Trash/info/x.trashinfo";
        assert!(run(&TRASH, path, b"Path=/x\n", 0).contains("not a .trashinfo"));
        assert!(run(&TRASH, path, b"[Trash Info]\nDeletionDate=2024-03-10T01:02:03\n", 0).contains("no Path key"));
        assert!(
            run(&TRASH, path, b"[Trash Info]\nPath=/a%zz%\xff\nDeletionDate=garbage\n", 0).contains("\"deleted\":null")
        );
        assert!(run(&TRASH, "x.trashinfo", b"[Trash Info]\nPath=/a\nDeletionDate=2024-03-10T01:02:03\n", 0)
            .contains("\"stored_as\":\"x\""));
    }

    /// Fixture: real libgnome-desktop thumbnails of two pictures and a failed one; the second picture
    /// was deleted afterwards, the thumbnail remains. `Thumb::MTime` is the file time of the pictures.
    #[test]
    fn thumbnails_name_the_original_files() {
        let mtime: i64 = truth("thumbnail")[0][3].parse().unwrap_or_default();
        let one = |name: &str, dir: &str| {
            run(
                &THUMBNAILS,
                &format!("home/alice/.cache/thumbnails/{dir}/{name}"),
                &fixture(&format!("thumbnails/{name}")),
                1_794_534_353,
            )
        };
        let photo = one("f399387eab8c38bd47862f209ac83c66.png", "normal");
        clean(&photo);
        assert_eq!(records(&photo).len(), 1);
        assert!(photo.contains("\"size_class\":\"normal\",\"failed\":false,\"uri\":\"file:///home/alice/Pictures/photo.png\",\"path\":\"/home/alice/Pictures/photo.png\""), "{photo}");
        assert!(
            photo.contains(&format!("\"original_mtime\":\"{}", rfc3339(mtime)))
                && photo.contains("\"width\":128,\"height\":96"),
            "{photo}"
        );
        assert!(
            photo.contains("\"software\":\"GNOME::ThumbnailFactory\"") && photo.contains("thumbnail_created"),
            "{photo}"
        );
        let gone = one("0c6ef32fbeab0b7ed53db38d46af8e09.png", "normal");
        assert!(gone.contains("/home/alice/Pictures/secret plan.jpg"), "{gone}");
        let failed = run(
            &THUMBNAILS,
            "home/alice/.cache/thumbnails/fail/gnome-thumbnail-factory/e235c1e3c768bb77932064353ec16f1a.png",
            &fixture("thumbnails/fail-e235c1e3c768bb77932064353ec16f1a.png"),
            0,
        );
        assert!(failed.contains("\"size_class\":\"fail\",\"failed\":true"), "{failed}");
        insta::assert_snapshot!(format!("{photo}{gone}{failed}"));
    }

    fn rfc3339(secs: i64) -> String {
        Timestamp::from_secs(secs, Basis::Recorded).to_rfc3339()[..19].to_string()
    }

    #[test]
    fn png_walker_is_bounded_and_never_decodes() {
        let good = fixture("thumbnails/f399387eab8c38bd47862f209ac83c66.png");
        let path = "home/alice/.cache/thumbnails/normal/x.png";
        assert!(run(&THUMBNAILS, path, b"GIF89a....", 0).contains("not a PNG"));
        assert!(
            run(&THUMBNAILS, path, &good[..8], 0).contains("ends before IEND")
                || run(&THUMBNAILS, path, &good[..8], 0).contains("no Thumb::URI")
        );
        // A chunk that claims 4 GiB.
        let mut huge = good[..8].to_vec();
        huge.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, b't', b'E', b'X', b't']);
        assert!(run(&THUMBNAILS, path, &huge, 0).contains("longer than the file"));
        // Truncated inside the text chunk after the URI was read: the URI is still reported.
        let cut = run(&THUMBNAILS, path, &good[..good.len() - 40], 0);
        assert!(cut.contains("Thumb::URI") || cut.contains("photo.png"), "{cut}");
        // A PNG that is no thumbnail.
        let mut plain = good[..33].to_vec();
        plain.extend_from_slice(&[0, 0, 0, 0, b'I', b'E', b'N', b'D', 0xae, 0x42, 0x60, 0x82]);
        assert!(run(&THUMBNAILS, path, &plain, 0).contains("no Thumb::URI"));
        let mut seed = 11u64;
        for cut in 0..good.len() {
            run(&THUMBNAILS, path, &good[..cut], 0);
        }
        for _ in 0..3000 {
            let mut copy = good.clone();
            for _ in 0..3 {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                let at = (seed >> 33) as usize % copy.len();
                copy[at] = (seed >> 20) as u8;
            }
            run(&THUMBNAILS, path, &copy, 0);
        }
    }
}
