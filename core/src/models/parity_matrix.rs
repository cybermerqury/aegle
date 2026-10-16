// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// SPDX-FileCopyrightText:  © 2024 - 2026 Merqury Cybersecurity Ltd <info@merqury.eu>

use bitvec::prelude::*;
use std::{ops::Deref, path::Path};

use crate::{error::sparse_matrix::SparseMatrixError, models::sparse_matrix::SparseMatrix};

#[derive(Debug)]
pub struct ParityMatrix {
    inner: SparseMatrix,
}

impl ParityMatrix {
    pub fn from_array<T>(array: &[T]) -> Self
    where
        T: AsRef<[u8]>,
    {
        Self {
            inner: SparseMatrix::from_array(array),
        }
    }

    pub fn from_alist_str(src: &str) -> Result<Self, SparseMatrixError> {
        Ok(Self {
            inner: SparseMatrix::from_alist_str(src)?,
        })
    }

    pub fn from_alist_str_short(src: &str) -> Result<Self, SparseMatrixError> {
        Ok(Self {
            inner: SparseMatrix::from_alist_str_short(src)?,
        })
    }

    pub fn from_alist_file(file: &Path) -> Result<Self, SparseMatrixError> {
        Ok(Self {
            inner: SparseMatrix::from_alist_file(file)?,
        })
    }

    pub fn from_alist_file_short(file: &Path) -> Result<Self, SparseMatrixError> {
        Ok(Self {
            inner: SparseMatrix::from_alist_file_short(file)?,
        })
    }

    pub fn calculate_syndrome(&self, message: &BitSlice) -> BitVec {
        let mut syndrome = bitvec![0; self.inner.factors_len()];
        for (factor, neighbours) in self.inner.iter_factors() {
            syndrome.set(
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
        syndrome
    }
}

impl Deref for ParityMatrix {
    type Target = SparseMatrix;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}
