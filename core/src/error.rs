// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// SPDX-FileCopyrightText:  © 2024 - 2026 Merqury Cybersecurity Ltd <info@merqury.eu>

pub mod parity_matrix;

use serde::{Deserialize, Serialize};
use std::env::VarError;
use std::fmt;
use std::fmt::Debug;
use std::result;

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone, Copy)]
pub enum ErrorKind {
    ConfigParse,
    Conversion,
    CryptoSetup,
    Database,
    EnvVar,
    InconsistentData,
    IntraprocessCommunication,
    Io,
    JoinError,
    Lapin,
    Neo4j,
    Network,
    Nft,
    NotImplemented,
    NotSupported,
    Numerical,
    OutOfRange,
    PoisonError,
    PostProcessing,
    Prometheus,
    ResourceUnavailable,
    Serialisation,
    Tracing,
    TrafficGuard,
    Validation,
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let str_value = match &self {
            Self::ConfigParse => "ConfigParse",
            Self::Conversion => "Conversion",
            Self::CryptoSetup => "CryptoSetup",
            Self::Database => "Database",
            Self::EnvVar => "EnvVar",
            Self::InconsistentData => "InconsistentData",
            Self::IntraprocessCommunication => "IntraprocessCommunication",
            Self::Io => "Io",
            Self::JoinError => "JoinError",
            Self::Lapin => "Lapin",
            Self::Neo4j => "Neo4j",
            Self::Network => "Network",
            Self::Nft => "Nft",
            Self::NotImplemented => "NotImplemented",
            Self::NotSupported => "NotSupported",
            Self::Numerical => "Numerical",
            Self::OutOfRange => "OutOfRange",
            Self::PoisonError => "PoisonError",
            Self::PostProcessing => "PostProcessing",
            Self::Prometheus => "Prometheus",
            Self::ResourceUnavailable => "ResourceUnavailable",
            Self::Serialisation => "Serialisation",
            Self::Tracing => "Tracing",
            Self::TrafficGuard => "TrafficGuard",
            Self::Validation => "Validation",
        };

        f.write_str(str_value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Error {
    pub error_kind: ErrorKind,
    pub msg: String,
}

impl Error {
    pub fn new(error_kind: ErrorKind, msg: impl Into<String>) -> Self {
        Self {
            error_kind,
            msg: msg.into(),
        }
    }

    pub fn kind(&self) -> ErrorKind {
        self.error_kind
    }
}

pub type Result<T> = result::Result<T, Error>;

impl std::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Type: '{}' | Msg: '{}'", self.error_kind, self.msg)
    }
}

// ErrorKind::Conversion
impl From<std::num::TryFromIntError> for Error {
    fn from(e: std::num::TryFromIntError) -> Error {
        Error {
            error_kind: ErrorKind::Conversion,
            msg: format!("Description: TryFromIntError - '{}'", e),
        }
    }
}

impl From<std::net::AddrParseError> for Error {
    fn from(e: std::net::AddrParseError) -> Error {
        Error {
            error_kind: ErrorKind::Conversion,
            msg: format!("Description: AddrParseError - '{}'", e),
        }
    }
}

// ErrorKind::EnvVar
impl From<VarError> for Error {
    fn from(e: VarError) -> Error {
        Error {
            error_kind: ErrorKind::EnvVar,
            msg: format!("Description: EnvVar - '{}'", e),
        }
    }
}

// ErrorKind::Io
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Error {
        Error {
            error_kind: ErrorKind::Io,
            msg: format!("Description: IO - '{}'", e),
        }
    }
}

// ErrorKind::Tracing
impl From<tracing::dispatcher::SetGlobalDefaultError> for Error {
    fn from(e: tracing::dispatcher::SetGlobalDefaultError) -> Error {
        Error {
            error_kind: ErrorKind::Tracing,
            msg: format!("Description: Tracing - '{}'", e),
        }
    }
}

// Poison error
impl<T> From<std::sync::PoisonError<T>> for Error {
    fn from(e: std::sync::PoisonError<T>) -> Error {
        Error {
            error_kind: ErrorKind::PoisonError,
            msg: format!("Description: PoisonError - '{}'", e),
        }
    }
}

// ErrorKind::Network
#[cfg(feature = "reqwest")]
impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Self {
        Error {
            error_kind: ErrorKind::Network,
            msg: format!("Description: Network - Reqwest HTTP error '{}'", e),
        }
    }
}

#[cfg(feature = "ureq")]
impl From<ureq::Error> for Error {
    fn from(e: ureq::Error) -> Self {
        Error {
            error_kind: ErrorKind::Network,
            msg: format!("Description: Network - Ureq HTTP error '{}'", e),
        }
    }
}
