//! Runs tasks on a fixed pool of worker threads.
//!
//! Workers pull the next task from an atomic index, so tasks start in plan order (largest
//! first). Each task owns its sink and output files: nothing on the hot path is shared. A
//! parser panic is caught at the task boundary and recorded as a failed task.

use crate::plan::Task;
use nixcavate_artifacts::Input;
use nixcavate_core::manifest::{Status, TaskEntry};
use nixcavate_core::{Basis, Error, Format, Precision, Sink, Summary, Target, Timestamp};
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Instant;

pub struct Settings<'a> {
    pub format: Format,
    pub threads: usize,
    pub scratch: &'a Path,
    /// Paths in task entries are made relative to this directory.
    pub output_root: &'a Path,
    /// Where a task writes its records and its timeline runs (a path stem; `None` means the
    /// run has no timeline and events are not collected).
    pub target: &'a (dyn Fn(&Task) -> (Target, Option<PathBuf>) + Sync),
}

/// Runs every task and returns one manifest entry per task, in task order.
pub fn execute(tasks: &[Task], settings: &Settings) -> Vec<TaskEntry> {
    let next = AtomicUsize::new(0);
    let workers = settings.threads.clamp(1, tasks.len().max(1));
    // Panics are reported in the manifest, not as backtraces in the middle of the summary.
    let hook = panic::take_hook();
    panic::set_hook(Box::new(|_| {}));
    let mut finished: Vec<(usize, TaskEntry)> = thread::scope(|scope| {
        let handles: Vec<_> = (0..workers)
            .map(|_| {
                scope.spawn(|| {
                    let mut done = Vec::new();
                    loop {
                        let index = next.fetch_add(1, Ordering::Relaxed);
                        let Some(task) = tasks.get(index) else { return done };
                        done.push((index, run_task(task, settings)));
                    }
                })
            })
            .collect();
        // A worker only panics outside a parser, which is a bug in nixcavate itself: do not
        // pretend its tasks never existed.
        handles.into_iter().flat_map(|h| h.join().unwrap_or_else(|payload| panic::resume_unwind(payload))).collect()
    });
    panic::set_hook(hook);
    finished.sort_by_key(|&(index, _)| index);
    finished.into_iter().map(|(_, entry)| entry).collect()
}

fn run_task(task: &Task, settings: &Settings) -> TaskEntry {
    let started = Instant::now();
    let (status, error, summary) = parse(task, settings);
    let elapsed = started.elapsed();
    let relative = |paths: Vec<PathBuf>| -> Vec<String> {
        paths.iter().map(|p| p.strip_prefix(settings.output_root).unwrap_or(p).to_string_lossy().into_owned()).collect()
    };
    TaskEntry {
        host: task.host.name.clone(),
        artifact: task.artifact.id.to_string(),
        input: task.rel.clone(),
        input_offset: task.offset(),
        input_bytes: task.bytes,
        status,
        error,
        duration_ms: elapsed.as_millis() as u64,
        records: summary.records,
        records_per_sec: (summary.records as f64 / elapsed.as_secs_f64().max(1e-6)) as u64,
        events: summary.events,
        first_event: summary.first_event.map(|t| t.to_rfc3339()),
        last_event: summary.last_event.map(|t| t.to_rfc3339()),
        input_modified: (task.entry.mtime > 0)
            .then(|| Timestamp::checked(task.entry.mtime, 0, Precision::Seconds, Basis::Recorded))
            .flatten()
            .map(|t| t.to_rfc3339()),
        warnings: summary.warnings,
        outputs: relative(summary.outputs),
        timeline_runs: relative(summary.runs),
    }
}

fn parse(task: &Task, settings: &Settings) -> (Status, Option<String>, Summary) {
    if task.bytes == 0 {
        return (Status::Skipped, Some("empty file".into()), Summary::default());
    }
    let whole;
    let data: &[u8] = match &task.chunk {
        Some((data, range)) => &data[range.clone()],
        None => match task.host.open(task.entry) {
            Ok(data) => {
                whole = data;
                &whole
            }
            Err(e) => return (Status::Failed, Some(format!("cannot read input: {e}")), Summary::default()),
        },
    };
    let input = Input {
        host: task.host,
        path: &task.rel,
        data,
        offset: task.offset(),
        mtime: task.entry.mtime,
        mode: task.entry.mode,
        uid: task.entry.uid,
        gid: task.entry.gid,
        scratch: settings.scratch,
    };
    let (target, run_base) = (settings.target)(task);
    let timeline = run_base.is_some();
    let mut sink = Sink::new(&task.host.name, task.artifact.id, &task.rel, settings.format, target, run_base);
    if !timeline {
        sink = sink.without_events();
    }
    let outcome = panic::catch_unwind(AssertUnwindSafe(|| (task.artifact.parse)(&input, &mut sink)));
    // Whatever was parsed before a failure is still written: partial results beat none.
    let (summary, flush_error) = match sink.finish() {
        Ok(summary) => (summary, None),
        Err(e) => (Summary::default(), Some(format!("cannot write output: {e}"))),
    };
    let (status, error) = match (outcome, flush_error) {
        (_, Some(e)) => (Status::Failed, Some(e)),
        (Ok(Ok(())), None) => (Status::Succeeded, None),
        (Ok(Err(Error::Skipped(why))), None) => (Status::Skipped, Some(why)),
        (Ok(Err(e)), None) => (Status::Failed, Some(e.to_string())),
        (Err(payload), None) => {
            let message = payload
                .downcast_ref::<&str>()
                .map(|s| s.to_string())
                .or_else(|| payload.downcast_ref::<String>().cloned());
            (Status::Failed, Some(format!("parser panicked: {}", message.unwrap_or_else(|| "unknown panic".into()))))
        }
    };
    (status, error, summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nixcavate_artifacts::{Artifact, Category, LINUX};
    use nixcavate_core::{Loc, Record};
    use nixcavate_source::{discover, Source};

    #[derive(serde::Serialize)]
    struct Row {
        n: u8,
    }
    impl Record for Row {}

    fn panics_after_one_record(_: &Input, sink: &mut Sink) -> nixcavate_core::Result<()> {
        sink.emit(Loc::Line(1), &Row { n: 1 })?;
        panic!("boom at record 2");
    }

    fn fails(_: &Input, _: &mut Sink) -> nixcavate_core::Result<()> {
        Err(Error::format("bad magic"))
    }

    fn works(_: &Input, sink: &mut Sink) -> nixcavate_core::Result<()> {
        sink.emit(Loc::Line(1), &Row { n: 7 })
    }

    static PANICS: Artifact = Artifact::new("panics", "test", Category::Logs, LINUX, &["a"], panics_after_one_record);
    static FAILS: Artifact = Artifact::new("fails", "test", Category::Logs, LINUX, &["a"], fails);
    static WORKS: Artifact = Artifact::new("works", "test", Category::Logs, LINUX, &["a"], works);

    #[test]
    fn a_panicking_parser_fails_its_task_and_nothing_else() {
        let source = Source::from_memory(&[("a", b"data")]);
        let hosts = discover(&source, None);
        let entry = &source.entries()[0];
        let task = |artifact| Task {
            host_index: 0,
            host: &hosts[0],
            artifact,
            entry,
            rel: "a".into(),
            name: "a".into(),
            chunk: None,
            bytes: entry.size,
        };
        let tasks = [task(&PANICS), task(&FAILS), task(&WORKS), task(&WORKS)];
        let target = |_: &Task| (Target::Memory, None);
        let settings = Settings {
            format: Format::Jsonl,
            threads: 2,
            scratch: Path::new("unused"),
            output_root: Path::new(""),
            target: &target,
        };
        let done = execute(&tasks, &settings);
        assert_eq!(done.len(), 4);
        assert_eq!(done[0].status, Status::Failed);
        assert_eq!(done[0].error.as_deref(), Some("parser panicked: boom at record 2"));
        assert_eq!(done[0].records, 1, "records written before the panic are kept");
        assert_eq!((done[1].status, done[1].error.as_deref()), (Status::Failed, Some("bad magic")));
        assert_eq!((done[2].status, done[3].status), (Status::Succeeded, Status::Succeeded));
        assert_eq!(done[0].artifact, "panics", "entries come back in task order");
    }
}
