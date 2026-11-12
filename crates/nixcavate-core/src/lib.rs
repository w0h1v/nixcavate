//! The record and event model shared by every nixcavate crate.

pub mod error;
pub mod manifest;
pub mod row;
pub mod run;
pub mod sink;
pub mod time;

pub use error::{Error, Result};
pub use row::Format;
pub use run::Loc;
pub use sink::{Event, Record, Sink, Summary, Target};
pub use time::{Basis, Precision, Timestamp};
