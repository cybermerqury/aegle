// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// SPDX-FileCopyrightText:  © 2024 - 2026 Merqury Cybersecurity Ltd <info@merqury.eu>

pub mod error;
pub mod fs;
pub mod key_state_machine;
pub mod models;
pub mod sync;
pub mod traits;

pub fn obtain_key_hash(key: &bitvec::slice::BitSlice) -> u64 {
    use std::hash::{Hash, Hasher};

    let mut hasher = std::hash::DefaultHasher::new();
    key.hash(&mut hasher);

    hasher.finish()
}
