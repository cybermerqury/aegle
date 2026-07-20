// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// SPDX-FileCopyrightText:  © 2024 - 2026 Merqury Cybersecurity Ltd <info@merqury.eu>

pub mod ids;
pub mod matrix;
pub mod parity_matrix;

use bitvec::vec::BitVec;
use uuid::Uuid;

#[derive(Clone, serde::Serialize, serde::Deserialize, Debug)]
pub struct Toeplitz {
    n_input: usize,
    n_output: usize,
    inner: BitVec,
}

impl Toeplitz {
    pub fn new(n_input: usize, n_output: usize) -> Self {
        let mut inner = BitVec::new();
        for _ in 0..(n_input + n_output - 1) {
            inner.push(rand::random())
        }
        Self {
            n_input,
            n_output,
            inner,
        }
    }

    pub fn from_bitvec(n_input: usize, n_output: usize, data: BitVec) -> Option<Self> {
        if data.len() != n_input + n_output - 1 {
            return None;
        }
        Some(Self {
            n_input,
            n_output,
            inner: data,
        })
    }

    pub fn hash_data(&self, other: BitVec) -> Option<BitVec> {
        if other.len() != self.n_input {
            return None;
        }
        let mut result = BitVec::new();
        for window in self.inner.windows(self.n_input).rev() {
            let val = window.to_bitvec() & other.as_bitslice();
            result.push(val.count_ones() % 2 == 1);
        }
        Some(result)
    }
}

pub type DeviceId = Uuid;
pub type KeyId = Uuid;
