// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// SPDX-FileCopyrightText:  © 2024 - 2026 Merqury Cybersecurity Ltd <info@merqury.eu>

pub mod follower_comms;
pub mod generator_matrix;
pub mod ids;
pub mod matrix;
pub mod parity_matrix;
pub mod sparse_matrix;

use bitvec::vec::BitVec;
use uuid::Uuid;

use crate::error::{Error, ErrorKind, Result};

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

    pub fn hash_data(&self, other: BitVec) -> Result<BitVec> {
        if other.len() != self.n_input {
            return Err(Error::new(
                ErrorKind::InconsistentData,
                format!(
                    "Length mismatch. Toeplitz length: {}, Other length: {}",
                    self.n_input,
                    other.len()
                ),
            ));
        }

        let mut result = BitVec::new();
        for window in self.inner.windows(self.n_input).rev() {
            let val = window.to_bitvec() & other.as_bitslice();
            result.push(val.count_ones() % 2 == 1);
        }
        Ok(result)
    }
}

pub type DeviceId = Uuid;
pub type KeyId = Uuid;

#[cfg(test)]
mod tests {

    use bitvec::prelude::*;

    use super::*;

    #[test]
    fn test_toeplitz() {
        let v = bitvec!(0, 1, 0, 0, 1, 1, 0);
        let w = bitvec!(1, 1, 0, 1, 0);
        let top = Toeplitz::from_bitvec(5, 3, v).expect("Wrong size of data");
        let hashed = top.hash_data(w);
        let result = hashed.expect("Wrong input length");
        assert_eq!(result, bitvec![1, 0, 1]);
    }

    #[test]
    fn test_bad_toeplitz() {
        let v = bitvec!(0, 1, 0, 0, 1, 1, 0);
        let w = bitvec!(1, 1, 0, 1);
        let top = Toeplitz::from_bitvec(5, 3, v).expect("Wrong size of data");
        let hashed = top.hash_data(w);
        assert!(hashed.is_err());
        let w = bitvec!(1, 1, 0, 1, 1, 1);
        let hashed = top.hash_data(w);
        assert!(hashed.is_err());
    }
}
