// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// SPDX-FileCopyrightText:  © 2024 - 2026 Merqury Cybersecurity Ltd <info@merqury.eu>

#![doc = include_str!("../README.md")]

pub mod decoder;
pub mod finite_field;
pub mod polynomial;
pub mod utils;

pub use decoder::{ChannelError, Decoder, Symmetric};
