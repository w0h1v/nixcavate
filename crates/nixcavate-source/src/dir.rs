//! Lists a directory tree without following symlinks or touching special files.

use crate::{Entry, Store};
use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

pub(crate) fn walk(root: &Path) -> io::Result<Vec<Entry>> {
    let mut entries = Vec::new();
    // (directory, its path inside the source)
    let mut pending = vec![(root.to_path_buf(), String::new())];
    while let Some((dir, prefix)) = pending.pop() {
        let listing = match fs::read_dir(&dir) {
            Ok(listing) => listing,
            // The evidence root must be readable; an unreadable subdirectory is skipped.
            Err(e) if prefix.is_empty() => return Err(e),
            Err(_) => continue,
        };
        for item in listing.flatten() {
            let name = item.file_name();
            let logical = if prefix.is_empty() {
                name.to_string_lossy().into_owned()
            } else {
                format!("{prefix}/{}", name.to_string_lossy())
            };
            let Ok(kind) = item.file_type() else { continue };
            if kind.is_dir() {
                pending.push((item.path(), logical));
            } else if kind.is_file() {
                if let Ok(entry) = file_entry(&item.path(), logical) {
                    entries.push(entry);
                }
            } else if kind.is_symlink() {
                if let (Ok(target), Ok(meta)) = (fs::read_link(item.path()), item.metadata()) {
                    let mut entry = entry_from(&meta, logical, Store::Dropped);
                    entry.size = 0;
                    entry.link = Some(target.to_string_lossy().into_owned());
                    entries.push(entry);
                }
            }
            // Sockets, FIFOs and devices are never opened.
        }
    }
    Ok(entries)
}

pub(crate) fn file_entry(path: &Path, logical: String) -> io::Result<Entry> {
    // Follows links: callers pass either a walked regular file or a path the user named.
    let meta = fs::metadata(path)?;
    if !meta.is_file() {
        return Err(io::Error::other(format!("{} is not a regular file", path.display())));
    }
    Ok(entry_from(&meta, logical, Store::File(path.to_path_buf())))
}

fn entry_from(meta: &fs::Metadata, path: String, store: Store) -> Entry {
    Entry {
        path,
        size: meta.len(),
        mtime: meta.mtime(),
        mode: meta.mode(),
        uid: meta.uid(),
        gid: meta.gid(),
        link: None,
        store,
    }
}
