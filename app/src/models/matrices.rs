// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// SPDX-FileCopyrightText:  © 2024 - 2026 Merqury Cybersecurity Ltd <info@merqury.eu>

pub const CODEWORD_SIZE: usize = 6;
pub const WORD_SIZE: usize = 2;
pub const CHECKS_SIZE: usize = CODEWORD_SIZE - WORD_SIZE;

/// A sample (15,10) parity check matrix.
/// Sourced from 'Information Theory, Inference, and Learning Algorithms' by David J.C. MacKay, page 221.
// pub const PARITY_MATRIX: [[u8; CODEWORD_SIZE]; CHECKS_SIZE] = [
//     [1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
//     [1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
//     [0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0],
//     [0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0],
//     [0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0],
//     [0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1],
//     [0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0],
//     [0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0],
//     [0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0],
//     [0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1],
// ];

pub const PARITY_MATRIX: [[u8; CODEWORD_SIZE]; CHECKS_SIZE] = [
    [0, 1, 1, 0, 0, 0],
    [1, 1, 0, 1, 0, 0],
    [1, 0, 0, 0, 1, 0],
    [0, 1, 0, 0, 0, 1],
];

#[cfg(feature = "ec_simcommsys")]
pub const SCS_CODEC_ID: &str = "aegle-codec";
