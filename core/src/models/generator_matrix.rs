// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// SPDX-FileCopyrightText:  © 2024 - 2026 Merqury Cybersecurity Ltd <info@merqury.eu>

use bitvec::prelude::*;
use std::{ops::Deref, path::Path};

use crate::{error::sparse_matrix::SparseMatrixError, models::sparse_matrix::SparseMatrix};

#[derive(Debug)]
pub struct GeneratorMatrix {
    inner: SparseMatrix,
}

impl GeneratorMatrix {
    pub fn from_array<T>(array: &[T]) -> Self
    where
        T: AsRef<[u8]>,
    {
        Self {
            inner: SparseMatrix::from_array(array),
        }
    }

    pub fn from_alist_file(file: &Path) -> Result<Self, SparseMatrixError> {
        Ok(Self {
            inner: SparseMatrix::from_alist_file(file)?,
        })
    }

    pub fn from_alist_str(src: &str) -> Result<Self, SparseMatrixError> {
        Ok(Self {
            inner: SparseMatrix::from_alist_str(src)?,
        })
    }

    pub fn generate_codeword(&self, message: &BitSlice, codeword_len: usize) -> Option<BitVec> {
        let factors_count = self.inner.factors_len();

        if message.len() != factors_count {
            tracing::warn!(
                "Mismatch between word length and factors. Word length: {}, factor_len: {}",
                message.len(),
                factors_count
            );
            return None;
        }

        let mut codeword = bitvec![0; codeword_len];

        for (&factor, neighbours) in self.inner.iter_factors() {
            let msg_bit = message.get(factor)?;

            for &gen_bit in neighbours {
                *codeword.get_mut(gen_bit)? ^= *msg_bit;
            }
        }

        Some(codeword)
    }
}

impl Deref for GeneratorMatrix {
    type Target = SparseMatrix;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}
