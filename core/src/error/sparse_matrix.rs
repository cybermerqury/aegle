use std::{error::Error, fmt::Display, str::FromStr};

#[derive(Debug)]
pub enum SparseMatrixError {
    BadAListFile(String),
    ConversionError(<usize as FromStr>::Err),
    IOError(std::io::Error),
    ExpectedTuple(String),
    FileTooShort,
    FileTooLong,
}

impl Display for SparseMatrixError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadAListFile(msg) => writeln!(f, "Alist file is malformed: {}", msg),
            Self::ConversionError(e) => writeln!(f, "Error while performing conversion: {}", e),
            Self::IOError(e) => writeln!(f, "Error durion IO: {}", e),
            Self::FileTooShort => writeln!(f, "File shorted than expected"),
            Self::FileTooLong => writeln!(f, "File longer than expected"),
            Self::ExpectedTuple(l) => writeln!(f, "Expected a tuple, got: {}", l),
        }
    }
}

impl From<std::num::ParseIntError> for SparseMatrixError {
    fn from(value: std::num::ParseIntError) -> Self {
        SparseMatrixError::ConversionError(value)
    }
}

impl From<std::io::Error> for SparseMatrixError {
    fn from(value: std::io::Error) -> Self {
        SparseMatrixError::IOError(value)
    }
}

impl Error for SparseMatrixError {}
