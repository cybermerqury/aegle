// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// SPDX-FileCopyrightText:  © 2024 - 2026 Merqury Cybersecurity Ltd <info@merqury.eu>

pub mod error;
pub mod fs;
pub mod key_state_machine;
pub mod models;
pub mod sync;
pub mod traits;

use sha3::{Digest, Sha3_512};

/// Hash the given bitslice using SHA3_512. Returns a byte-vec representing the hash.
pub fn obtain_key_hash(key: &bitvec::slice::BitSlice) -> Vec<u8> {
    let array = key.iter().by_vals().map(|b| b as u8).collect::<Vec<u8>>();

    Sha3_512::digest(array).to_vec()
}
