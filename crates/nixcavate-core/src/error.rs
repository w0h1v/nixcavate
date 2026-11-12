use std::{fmt, io};

/// Why a parser or a run step stopped.
#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    /// The input does not follow its format.
    Format(String),
    /// The input is valid but there is nothing to parse (wrong variant, empty file).
    Skipped(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn format(msg: impl Into<String>) -> Self {
        Error::Format(msg.into())
    }

    pub fn skipped(msg: impl Into<String>) -> Self {
        Error::Skipped(msg.into())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "{e}"),
            Error::Format(msg) | Error::Skipped(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}
