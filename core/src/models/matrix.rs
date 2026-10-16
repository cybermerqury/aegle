// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// SPDX-FileCopyrightText:  © 2024 - 2026 Merqury Cybersecurity Ltd <info@merqury.eu>

use std::fmt::Display;
use std::ops::{Index, IndexMut};

pub struct Matrix<T> {
    rows: usize,
    cols: usize,
    data: Vec<T>,
}

impl Matrix<f64> {
    pub fn zeros(rows: usize, cols: usize) -> Matrix<f64> {
        let data = vec![0.0; rows * cols];
        Matrix { rows, cols, data }
    }

    pub fn apply(&self, f: fn(f64) -> f64) -> Matrix<f64> {
        let new_data = self.data.iter().cloned().map(f).collect();
        Self {
            rows: self.rows,
            cols: self.cols,
            data: new_data,
        }
    }
}

impl<T> Index<usize> for Matrix<T> {
    type Output = [T];

    fn index(&self, index: usize) -> &Self::Output {
        let start = self.cols * index;
        let stop = start + self.cols;
        &self.data[start..stop]
    }
}

impl<T> IndexMut<usize> for Matrix<T> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        let start = self.cols * index;
        let stop = start + self.cols;
        &mut self.data[start..stop]
    }
}

impl<T> std::fmt::Debug for Matrix<T>
where
    T: Display,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for i in 0..self.rows {
            let row = &self[i];
            writeln!(
                f,
                "{}",
                row.iter()
                    .map(|elem| format!("{}", elem))
                    .collect::<Vec<String>>()
                    .join(",")
            )?;
        }
        Ok(())
    }
}
