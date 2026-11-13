//! Path patterns for locating artifacts.
//!
//! A pattern is a `/`-separated path relative to the host root. Inside a segment `*` matches
//! any run of characters and `?` matches one. A whole segment of `**` matches any number of
//! directories. A leading `../` makes the pattern relative to the parent of the host root,
//! which is where UAC keeps `live_response/` next to `[root]/`.

#[derive(Clone, Debug)]
pub struct Pattern {
    text: &'static str,
    parent_relative: bool,
    segments: Vec<Segment>,
}

#[derive(Clone, Debug)]
enum Segment {
    AnyDirs,
    Name(&'static str),
}

impl Pattern {
    pub fn new(text: &'static str) -> Self {
        let (parent_relative, body) = match text.strip_prefix("../") {
            Some(body) => (true, body),
            None => (false, text),
        };
        let segments = body
            .split('/')
            .filter(|s| !s.is_empty())
            .map(|s| if s == "**" { Segment::AnyDirs } else { Segment::Name(s) })
            .collect();
        Self { text, parent_relative, segments }
    }

    pub fn text(&self) -> &'static str {
        self.text
    }

    /// True when the pattern starts with `../`.
    pub fn is_parent_relative(&self) -> bool {
        self.parent_relative
    }

    /// Matches a path relative to the pattern's base (the host root or its parent).
    pub fn matches(&self, path: &str) -> bool {
        self.tail_fits(path) && match_from(&self.segments, path)
    }

    /// Cheap reject before the full match: the pattern's last two segments, when they are names,
    /// must match the path's last two. Most paths fail here, which keeps a leading `**`
    /// affordable on listings of millions of entries.
    fn tail_fits(&self, path: &str) -> bool {
        let mut parts = path.rsplit('/');
        for segment in self.segments.iter().rev().take(2) {
            let Segment::Name(pattern) = segment else { return true };
            match parts.next() {
                Some(name) if wildcard(pattern.as_bytes(), name.as_bytes()) => {}
                _ => return false,
            }
        }
        true
    }

    /// Matches when the pattern fits some trailing part of `path`, starting at a segment
    /// boundary. Used before the host root is known, to decide which archive entries to keep.
    pub fn matches_suffix(&self, path: &str) -> bool {
        // Most paths fail on the file name, so test that first.
        if let Some(Segment::Name(last)) = self.segments.last() {
            let name = path.rsplit('/').next().unwrap_or(path);
            if !wildcard(last.as_bytes(), name.as_bytes()) {
                return false;
            }
        }
        let mut rest = path;
        loop {
            if match_from(&self.segments, rest) {
                return true;
            }
            match rest.split_once('/') {
                Some((_, tail)) => rest = tail,
                None => return false,
            }
        }
    }
}

fn match_from(segments: &[Segment], path: &str) -> bool {
    let Some((first, later)) = segments.split_first() else {
        return path.is_empty();
    };
    match first {
        Segment::AnyDirs => {
            if later.is_empty() {
                return true;
            }
            let mut rest = path;
            loop {
                if match_from(later, rest) {
                    return true;
                }
                match rest.split_once('/') {
                    Some((_, tail)) => rest = tail,
                    None => return false,
                }
            }
        }
        Segment::Name(pattern) => {
            if path.is_empty() {
                return false;
            }
            let (head, tail) = path.split_once('/').unwrap_or((path, ""));
            wildcard(pattern.as_bytes(), head.as_bytes()) && match_from(later, tail)
        }
    }
}

/// Matches one path segment against a pattern with `*` and `?`.
pub fn wildcard(pattern: &[u8], name: &[u8]) -> bool {
    let (mut p, mut n) = (0, 0);
    // Where to resume after the most recent `*` fails to match as tried.
    let mut backtrack: Option<(usize, usize)> = None;
    while n < name.len() {
        match pattern.get(p) {
            Some(b'*') => {
                backtrack = Some((p, n));
                p += 1;
            }
            Some(&c) if c == b'?' || c == name[n] => {
                p += 1;
                n += 1;
            }
            _ => match backtrack {
                Some((star, at)) => {
                    backtrack = Some((star, at + 1));
                    p = star + 1;
                    n = at + 1;
                }
                None => return false,
            },
        }
    }
    pattern[p..].iter().all(|&c| c == b'*')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcards_within_a_segment() {
        assert!(wildcard(b"auth.log*", b"auth.log"));
        assert!(wildcard(b"auth.log*", b"auth.log.2.gz"));
        assert!(wildcard(b"*.journal", b"system@abc.journal"));
        assert!(wildcard(b"a*b*c", b"aXbXbXc"));
        assert!(wildcard(b"?tmp", b"wtmp"));
        assert!(!wildcard(b"?tmp", b"tmp"));
        assert!(!wildcard(b"*.journal", b"system.journal~"));
        assert!(wildcard(b"*", b""));
        assert!(!wildcard(b"", b"x"));
    }

    #[test]
    fn full_matches() {
        let p = Pattern::new("var/log/auth.log*");
        assert!(p.matches("var/log/auth.log.1"));
        assert!(!p.matches("var/log/sub/auth.log"));
        assert!(!p.matches("x/var/log/auth.log"));

        let p = Pattern::new("home/*/.bash_history");
        assert!(p.matches("home/alice/.bash_history"));
        assert!(!p.matches("home/alice/x/.bash_history"));
    }

    #[test]
    fn tail_reject_agrees_with_the_full_match() {
        let p = Pattern::new("**/image/*/imagedb/content/sha256/*");
        assert!(p.matches("data/docker/image/overlay2/imagedb/content/sha256/ab"));
        assert!(!p.matches("data/docker/image/overlay2/imagedb/content/sha257/ab"));
        assert!(!p.matches("sha256/ab"));
        let p = Pattern::new("**/containers/*/config.v2.json");
        assert!(p.matches("srv/docker/containers/abc/config.v2.json"));
        assert!(p.matches("containers/abc/config.v2.json"));
        assert!(!p.matches("config.v2.json"));
        assert!(!p.matches("containers/config.v2.json"));
    }

    #[test]
    fn any_dirs() {
        let p = Pattern::new("var/log/journal/**/*.journal");
        assert!(p.matches("var/log/journal/abc/system.journal"));
        assert!(p.matches("var/log/journal/system.journal"));
        assert!(!p.matches("var/log/system.journal"));

        let p = Pattern::new("etc/systemd/**");
        assert!(p.matches("etc/systemd/system/a.service"));
        assert!(!p.matches("etc/system/a.service"));
    }

    #[test]
    fn suffix_matches_under_any_prefix() {
        let p = Pattern::new("etc/passwd");
        assert!(p.matches_suffix("[root]/etc/passwd"));
        assert!(p.matches_suffix("etc/passwd"));
        assert!(!p.matches_suffix("[root]/etc/passwd-"));
        assert!(!p.matches_suffix("[root]/notetc/passwd"));

        let p = Pattern::new("../live_response/process/ps*.txt");
        assert!(p.is_parent_relative());
        assert!(p.matches_suffix("uac-host/live_response/process/ps_auxwww.txt"));
        assert!(p.matches("live_response/process/ps_auxwww.txt"));
    }
}
