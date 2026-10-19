//! One error type for the whole library. Fallible functions return `Result<T, Error>`;
//! the `?` operator propagates the error to the caller (there are no exceptions in Rust).

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// A parameter is out of range (e.g. `parties < threshold`).
    InvalidParameters(&'static str),
    /// `reconstruct` was given two shares with the same index.
    DuplicateIndices,
    /// Signing needs at least `2t-1` signers.
    TooFewSigners { required: usize },
    /// A recipient found an invalid share from a dealer during the DKG.
    DkgComplaint { dealer: usize, recipient: usize },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidParameters(reason) => write!(f, "invalid parameters: {reason}"),
            Error::DuplicateIndices => write!(f, "duplicate share indices"),
            Error::TooFewSigners { required } => {
                write!(f, "at least {required} signers are required")
            }
            Error::DkgComplaint { dealer, recipient } => {
                write!(
                    f,
                    "party {recipient} received an invalid share from party {dealer}"
                )
            }
        }
    }
}

impl std::error::Error for Error {}
