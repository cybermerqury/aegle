// SPDX-FileCopyrightText: © 2024 Merqury Cybersecurity Ltd <info@merqury.eu>
use std::fmt::{Debug, Display};
use std::result;

// TODO: Remove the PpaasResult type with the core::Result one.
pub type PpaasResult<T> = result::Result<T, PpaasError>;

#[derive(Debug)]
pub enum PpaasError {
    Other,
}

impl std::error::Error for PpaasError {}

impl Display for PpaasError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Other => writeln!(f, "Unexpected PPaaS error!"),
        }
    }
}
