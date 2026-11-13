//! CUPS print records: who printed what, when, from where.
//!
//! - `var/log/cups/page_log` (cupsd.conf(5) `PageLogFormat`, default `%p %u %j %T %P %C
//!   %{job-billing} %{job-originating-host-name} %{job-name} %{media} %{sides}`): one line per
//!   printed page, or a `total` line per job. The job name has spaces and is not quoted, so
//!   the last two fields are taken as the media and sides, as the default format has them. A
//!   site with another `PageLogFormat` gets a warning, not a guess.
//! - `var/spool/cups/c<job>` job control files: an IPP message (RFC 8010) that CUPS saves for
//!   every job and keeps for the jobs in its history. It holds the document title
//!   (`job-name`), the user and host, the printer and the creation time, after the job's files
//!   are long deleted.
//!
//! The IPP reader is bounded: attribute and value lengths are checked against the bytes present,
//! at most 4096 attributes are read, and nothing is decoded but the few attributes listed below.

use crate::common::logfmt::{clf_utc, cut, Unparsed};
use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, UNIX};
use nixcavate_core::time::{parse_uint, secs_from_civil};
use nixcavate_core::{Basis, Error, Event, Loc, Precision, Record, Result, Sink, Timestamp};
use serde::Serialize;

pub const PAGE_LOG: Artifact = Artifact::new(
    "cups-page-log",
    "CUPS page_log: pages and jobs printed, by user and host",
    Category::Activity,
    UNIX,
    &["var/log/cups/page_log*", "private/var/log/cups/page_log*"],
    parse_page_log,
)
.split_lines();

pub const JOBS: Artifact = Artifact::new(
    "cups-jobs",
    "CUPS job control files: document title, user, host and time of each print job",
    Category::Activity,
    UNIX,
    &["var/spool/cups/c*", "private/var/spool/cups/c*"],
    parse_job,
);

// ---- page_log ----

#[derive(Serialize)]
struct Page<'a> {
    time: Option<Timestamp>,
    printer: &'a str,
    user: &'a str,
    job_id: Option<u64>,
    /// The page number, or `total` for the line that closes a job.
    page: &'a str,
    /// Copies of the page; on a `total` line, the number of pages the job printed.
    copies: Option<u64>,
    billing: &'a str,
    /// The host the job came from.
    client_host: &'a str,
    /// The document title.
    job_name: &'a str,
    media: &'a str,
    sides: &'a str,
}

impl Record for Page<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        // The per-page lines are noise on a timeline; the job total says it once.
        let message =
            format!("{} printed \"{}\" on {} from {}", self.user, cut(self.job_name), self.printer, self.client_host);
        self.time.filter(|_| self.page == "total").map(|t| Event::new(t, "print_job", message)).into_iter()
    }
}

fn parse_page_log(input: &Input, sink: &mut Sink) -> Result<()> {
    let mut unparsed = Unparsed::default();
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let text = text.trim_end();
        if text.is_empty() {
            return Ok(());
        }
        // Fedora and RHEL leave a one-line note where the log was before it moved to the journal.
        if text.starts_with("This CUPS log has been moved into journal") {
            return Ok(());
        }
        match page_line(text) {
            Some(page) => sink.emit(Loc::Offset(line.offset), &page),
            None => {
                unparsed.note(line.number);
                Ok(())
            }
        }
    })?;
    unparsed.report(sink, "default CUPS page_log (a site-specific PageLogFormat is not read)");
    Ok(())
}

fn page_line(text: &str) -> Option<Page<'_>> {
    let (printer, rest) = text.split_once(' ')?;
    let (user, rest) = rest.split_once(' ')?;
    let (job, rest) = rest.split_once(' ')?;
    let rest = rest.strip_prefix('[')?;
    let (date, rest) = rest.split_once("] ")?;
    let mut words = rest.splitn(5, ' ');
    let (page, copies, billing, host, tail) =
        (words.next()?, words.next()?, words.next()?, words.next()?, words.next()?);
    // `job name with spaces media sides`: the media and sides are the last two words.
    let (name_and_media, sides) = tail.rsplit_once(' ')?;
    let (job_name, media) = name_and_media.rsplit_once(' ')?;
    Some(Page {
        time: clf_utc(date.as_bytes()).map(|s| Timestamp::from_secs(s, Basis::Recorded)),
        printer,
        user,
        job_id: parse_uint(job.as_bytes()),
        page,
        copies: parse_uint(copies.as_bytes()),
        billing,
        client_host: host,
        job_name,
        media,
        sides,
    })
}

// ---- job control files ----

#[derive(Serialize)]
struct Job {
    job_id: Option<u64>,
    /// `job-originating-user-name`.
    user: Option<String>,
    /// `job-originating-host-name`.
    client_host: Option<String>,
    /// `job-name`: the document title the application gave.
    title: Option<String>,
    /// The last part of `printer-uri`.
    printer: Option<String>,
    copies: Option<u32>,
    job_uuid: Option<String>,
    document_format: Option<String>,
    created: Option<Timestamp>,
    processing: Option<Timestamp>,
    completed: Option<Timestamp>,
    sheets_completed: Option<u32>,
}

impl Record for Job {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let message = format!(
            "{} submitted \"{}\" to {} from {}",
            self.user.as_deref().unwrap_or("?"),
            cut(self.title.as_deref().unwrap_or("")),
            self.printer.as_deref().unwrap_or("?"),
            self.client_host.as_deref().unwrap_or("?")
        );
        self.created.map(|t| Event::new(t, "print_job_submitted", message)).into_iter()
    }
}

const MAX_ATTRIBUTES: usize = 4096;

/// A cursor over IPP bytes; every read is bounds-checked.
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let slice = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }

    fn u8(&mut self) -> Option<u8> {
        self.bytes(1).map(|b| b[0])
    }

    fn u16(&mut self) -> Option<u16> {
        self.bytes(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }
}

/// `dateTime` (RFC 8010 3.9): year(2) month day hour minutes seconds deci-seconds, direction
/// from UTC (`+` or `-`), hours and minutes from UTC.
fn ipp_date(value: &[u8]) -> Option<Timestamp> {
    let &[y1, y0, month, day, hour, minute, second, _deci, sign, zh, zm] = <&[u8; 11]>::try_from(value).ok()?;
    let wall = secs_from_civil(
        i64::from(u16::from_be_bytes([y1, y0])),
        u32::from(month),
        u32::from(day),
        u32::from(hour),
        u32::from(minute),
        u32::from(second),
    )?;
    let east = (i64::from(zh) * 3600 + i64::from(zm) * 60) * if sign == b'-' { -1 } else { 1 };
    Timestamp::checked(wall - east, 0, Precision::Seconds, Basis::Recorded)
}

fn parse_job(input: &Input, sink: &mut Sink) -> Result<()> {
    // `c*` also matches other files in the spool directory: only `c00001` and the like are job files.
    let name = input.path.rsplit('/').next().unwrap_or_default();
    if name.strip_prefix('c').is_none_or(|n| n.is_empty() || !n.bytes().all(|b| b.is_ascii_digit())) {
        return Err(Error::skipped("not a job control file name (c followed by the job number)"));
    }
    let mut r = Reader { data: input.data, pos: 0 };
    let version = r.bytes(2).ok_or_else(|| Error::format("shorter than an IPP header"))?;
    if version[0] == 0 || version[0] > 2 {
        return Err(Error::format("not a CUPS job control file: the IPP version is not 1.x or 2.x"));
    }
    r.bytes(6).ok_or_else(|| Error::format("shorter than an IPP header"))?;
    let job_id = name.strip_prefix('c').and_then(|n| parse_uint(n.as_bytes()));
    let mut job = Job {
        job_id,
        user: None,
        client_host: None,
        title: None,
        printer: None,
        copies: None,
        job_uuid: None,
        document_format: None,
        created: None,
        processing: None,
        completed: None,
        sheets_completed: None,
    };
    let (mut created_dt, mut processing_dt, mut completed_dt) = (None, None, None);
    let mut count = 0;
    let mut ended = false;
    while let Some(tag) = r.u8() {
        if tag == 0x03 {
            ended = true;
            break;
        }
        if tag < 0x10 {
            // A group tag (operation, job, printer, ...): its attributes follow.
            continue;
        }
        count += 1;
        if count > MAX_ATTRIBUTES {
            sink.warn(format!("more than {MAX_ATTRIBUTES} IPP attributes: the rest is not read"));
            break;
        }
        let Some(name_len) = r.u16() else { break };
        let attr_name = if name_len == 0 {
            None
        } else {
            match r.bytes(usize::from(name_len)) {
                Some(n) => Some(String::from_utf8_lossy(n).into_owned()),
                None => break,
            }
        };
        let Some(value_len) = r.u16() else { break };
        let Some(value) = r.bytes(usize::from(value_len)) else {
            sink.warn("the IPP message ends inside a value");
            break;
        };
        // A value with no name is another value of the attribute before it; only the first is kept.
        let Some(attr_name) = attr_name else { continue };
        let text = || Some(String::from_utf8_lossy(value).into_owned());
        let integer = || <[u8; 4]>::try_from(value).ok().map(i32::from_be_bytes);
        let epoch = |v: Option<i32>| v.filter(|v| *v > 0).map(|v| Timestamp::from_secs(i64::from(v), Basis::Recorded));
        match (attr_name.as_str(), tag) {
            ("job-name", 0x42 | 0x41 | 0x35 | 0x36) => job.title = text(),
            ("job-originating-user-name", _) => job.user = text(),
            ("job-originating-host-name", _) => job.client_host = text(),
            ("printer-uri", 0x45) => job.printer = text().map(|u| u.rsplit('/').next().unwrap_or_default().to_string()),
            ("copies", 0x21) => job.copies = integer().and_then(|v| u32::try_from(v).ok()),
            ("job-uuid", _) => job.job_uuid = text(),
            ("document-format", _) => job.document_format = text(),
            ("job-media-sheets-completed", 0x21) => {
                job.sheets_completed = integer().and_then(|v| u32::try_from(v).ok())
            }
            ("time-at-creation", 0x21) => job.created = epoch(integer()),
            ("time-at-processing", 0x21) => job.processing = epoch(integer()),
            ("time-at-completed", 0x21) => job.completed = epoch(integer()),
            ("date-time-at-creation", 0x31) => created_dt = ipp_date(value),
            ("date-time-at-processing", 0x31) => processing_dt = ipp_date(value),
            ("date-time-at-completed", 0x31) => completed_dt = ipp_date(value),
            _ => {}
        }
    }
    // The epoch attributes are CUPS's own clock; the dateTime ones carry the same instant with a zone.
    job.created = job.created.or(created_dt);
    job.processing = job.processing.or(processing_dt);
    job.completed = job.completed.or(completed_dt);
    if !ended {
        sink.warn("the IPP message has no end-of-attributes tag (truncated or damaged); what was read is shown");
    }
    if job.title.is_none() && job.user.is_none() {
        return Err(Error::format("an IPP message with no job-name and no user: not a CUPS job control file"));
    }
    sink.emit(Loc::Offset(0), &job)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    fn records(out: &str) -> Vec<&str> {
        out.lines().take_while(|l| !l.starts_with("---")).collect()
    }

    /// Fixture: real CUPS 2.4.2 (Debian 12), a deskjet queue to /dev/null, 3 jobs by two users: a 1-page
    /// text, a 2-copy text, a 200-line text that prints 4 pages. `lp -t` sets the title.
    /// Fedora and RHEL leave a one-line note where the log was before it moved to the journal.
    #[test]
    fn the_moved_to_journal_note_is_not_a_page() {
        let note = b"This CUPS log has been moved into journal by default unless changes have been made in /etc/cups/cups-files.conf. Log messages can be got by \"$ journalctl -u cups -e\"\n";
        let out = run(&PAGE_LOG, "var/log/cups/page_log", note, 0);
        assert!(!out.contains("--- warning") && !out.contains("--- failed"), "{out}");
    }

    #[test]
    fn page_log_lists_jobs_by_user_and_title() {
        let data = fixture("cups-page-log/page_log");
        let out = run(&PAGE_LOG, "var/log/cups/page_log", &data, 0);
        assert!(!out.contains("--- warning") && !out.contains("--- failed"), "{out}");
        assert_eq!(records(&out).len(), 3);
        assert!(
            out.contains("\"user\":\"bob\",\"job_id\":3,\"page\":\"total\",\"copies\":4")
                && out.contains("\"job_name\":\"Secret-plan.pdf\""),
            "{out}"
        );
        assert!(out.contains("\"job_name\":\"Resume of A. Person.docx\""), "{out}");
        assert!(out.contains("print_job"));
        insta::assert_snapshot!(out);
        // A custom PageLogFormat is a warning, not a guess.
        assert!(run(&PAGE_LOG, "var/log/cups/page_log", b"1 2 3\n", 0).contains("not in the default CUPS page_log"));
    }

    /// The same jobs from the control files: titles, users, hosts and creation times that the
    /// session's own `lp` calls produced (the page log above has the same titles).
    #[test]
    fn job_control_files_name_the_documents() {
        let titles = [
            ("c00001", "Q3 Financial Report", "alice"),
            ("c00002", "Resume of A. Person.docx", "alice"),
            ("c00003", "Secret-plan.pdf", "bob"),
        ];
        for (name, title, user) in titles {
            let out = run(&JOBS, &format!("var/spool/cups/{name}"), &fixture(&format!("cups-jobs/{name}")), 0);
            assert!(!out.contains("--- warning") && !out.contains("--- failed"), "{out}");
            assert_eq!(records(&out).len(), 1);
            assert!(
                out.contains(&format!(
                    "\"user\":\"{user}\",\"client_host\":\"localhost\",\"title\":\"{title}\",\"printer\":\"nxprint\""
                )),
                "{out}"
            );
            assert!(out.contains("\"created\":\"2026-11-13T01:49:2"), "{out}");
            assert!(out.contains("print_job_submitted"), "{out}");
        }
        let two = run(&JOBS, "var/spool/cups/c00002", &fixture("cups-jobs/c00002"), 0);
        assert!(two.contains("\"copies\":2"), "{two}");
        insta::assert_snapshot!(run(&JOBS, "var/spool/cups/c00001", &fixture("cups-jobs/c00001"), 0));
    }

    /// CUPS's `access_log` is Common Log Format with the IPP operation and status after the size: read by `web-access-log`.
    #[test]
    fn cups_access_log_is_read_by_the_web_access_artifact() {
        let data = fixture("cups-page-log/access_log");
        let out = run(&crate::common::web_logs::ACCESS, "var/log/cups/access_log", &data, 0);
        assert!(!out.contains("--- warning") && !out.contains("--- failed"), "{out}");
        assert_eq!(records(&out).len(), String::from_utf8_lossy(&data).lines().count());
        assert!(out.contains("\"user\":\"root\"") && out.contains("\"request\":\"/printers/nxprint\""), "{out}");
    }

    #[test]
    fn other_files_and_damage_are_refused_or_reported() {
        assert!(run(&JOBS, "var/spool/cups/cache", b"\x02\x00\x00\x05", 0).contains("not a job control file name"));
        assert!(run(&JOBS, "var/spool/cups/c00009", b"hello world, not ipp", 0).contains("failed"));
        assert!(run(&JOBS, "var/spool/cups/c00009", &[2, 0, 0, 5], 0).contains("shorter than"));
        let good = fixture("cups-jobs/c00001");
        let cut = run(&JOBS, "var/spool/cups/c00001", &good[..200], 0);
        assert!(cut.contains("Q3 Financial Report") && cut.contains("no end-of-attributes"), "{cut}");
    }

    #[test]
    fn ipp_reader_survives_mutation_and_truncation() {
        let mut seed = 21u64;
        for name in ["c00001", "c00002", "c00003"] {
            let good = fixture(&format!("cups-jobs/{name}"));
            for cut in 0..good.len() {
                run(&JOBS, "var/spool/cups/c00001", &good[..cut], 0);
            }
            for _ in 0..3000 {
                let mut copy = good.clone();
                for _ in 0..4 {
                    seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                    let at = (seed >> 33) as usize % copy.len();
                    copy[at] = (seed >> 20) as u8;
                }
                run(&JOBS, "var/spool/cups/c00001", &copy, 0);
            }
        }
        // Lengths that point far past the end.
        run(&JOBS, "var/spool/cups/c00001", &[2, 0, 0, 5, 0, 0, 0, 1, 1, 0x47, 0xff, 0xff, b'a'], 0);
        run(
            &JOBS,
            "var/spool/cups/c00001",
            &[2, 0, 0, 5, 0, 0, 0, 1, 1, 0x42, 0, 3, b'a', b'b', b'c', 0xff, 0xff, 1],
            0,
        );
    }
}
