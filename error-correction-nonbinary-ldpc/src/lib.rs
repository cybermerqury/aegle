// SPDX-FileCopyrightText: © 2025 Merqury Cybersecurity Ltd <info@merqury.eu>
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

#![doc = include_str!("../README.md")]

pub mod polynomial;
pub mod finite_field;
pub mod decoder;
pub mod utils;

pub use decoder::{ChannelError, Symmetric, Decoder};

