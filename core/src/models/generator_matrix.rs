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

    pub fn from_alist(file: &Path) -> Result<Self, SparseMatrixError> {
        Ok(Self {
            inner: SparseMatrix::from_alist(file)?,
        })
    }

    pub fn generate_codeword(&self, message: &BitSlice) -> Option<BitVec> {
        if message.len() != self.inner.factors_len() {
            return None;
        }

        let mut codeword = bitvec![0; self.inner.factors_len()];

        for (factor, neighbours) in self.inner.iter_factors() {
            codeword.set(
                *factor,
                neighbours
                    .iter()
                    .map(|&idx| message[idx])
                    .collect::<BitVec>()
                    .count_ones()
                    % 2
                    == 1,
            );
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
