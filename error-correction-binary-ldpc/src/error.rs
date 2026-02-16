// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// SPDX-FileCopyrightText:  © 2024 - 2026 Merqury Cybersecurity Ltd <info@merqury.eu>

use std::error::Error;
use std::fmt::Display;
use std::num;
use std::str::FromStr;

#[derive(Debug)]
pub enum ParityMatrixError {
    BadAListFile(String),
    ConversionError(<usize as FromStr>::Err),
    IOError(std::io::Error),
    ExpectedTuple(String),
    FileTooShort,
    FileTooLong,
}

impl Display for ParityMatrixError {
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

impl From<num::ParseIntError> for ParityMatrixError {
    fn from(value: num::ParseIntError) -> Self {
        ParityMatrixError::ConversionError(value)
    }
}

impl From<std::io::Error> for ParityMatrixError {
    fn from(value: std::io::Error) -> Self {
        ParityMatrixError::IOError(value)
    }
}

impl Error for ParityMatrixError {}
