// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// SPDX-FileCopyrightText:  © 2024 - 2026 Merqury Cybersecurity Ltd <info@merqury.eu>

use std::error::Error;
use std::fmt::{Debug, Display};

pub type SubsystemResult = Result<(), SubsystemError>;
pub type EmulatorResult<T> = Result<T, Box<dyn EmulatorError>>;

#[derive(Debug)]
pub struct SubsystemError(String);

impl Display for SubsystemError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{}", self.0)
    }
}

impl Error for SubsystemError {}

struct MainErrorStruct<E>
where
    E: Error,
{
    inner: E,
}

impl<E> Debug for MainErrorStruct<E>
where
    E: Error,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Error in main: {:?}", self.inner)
    }
}

impl From<Box<dyn EmulatorError>> for SubsystemError {
    fn from(value: Box<dyn EmulatorError>) -> Self {
        SubsystemError(format!("{:?}", value).to_string())
    }
}

impl From<tokio::task::JoinError> for SubsystemError {
    fn from(value: tokio::task::JoinError) -> Self {
        SubsystemError(format!("{:?}", value).to_string())
    }
}

impl From<std::io::Error> for SubsystemError {
    fn from(value: std::io::Error) -> Self {
        SubsystemError(format!("{:?}", value).to_string())
    }
}

impl From<ErrorMessage> for SubsystemError {
    fn from(value: ErrorMessage) -> Self {
        SubsystemError(format!("{:?}", value).to_string())
    }
}

#[derive(Debug)]
pub struct ErrorMessage(pub &'static str);

impl Display for ErrorMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{}", self.0)
    }
}

impl Error for ErrorMessage {}

pub trait EmulatorError: Debug + Sync + Send {}

impl<E> EmulatorError for MainErrorStruct<E> where E: Error + Sync + Send {}

impl<E> From<E> for Box<dyn EmulatorError>
where
    E: Error + Sync + Send + 'static,
{
    fn from(value: E) -> Self {
        Box::new(MainErrorStruct { inner: value })
    }
}
