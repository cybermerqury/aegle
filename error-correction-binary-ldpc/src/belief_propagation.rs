// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// SPDX-FileCopyrightText:  © 2024 - 2026 Merqury Cybersecurity Ltd <info@merqury.eu>

use bitvec::prelude::*;
use std::borrow::Cow;

use crate::{matrix::Matrix, parity_matrix::ParityMatrix};

#[derive(Debug)]
pub enum BPResult {
    Converged {
        estimate: BitVec,
        llr: Vec<f64>,
        iterations: usize,
    },
    Failed {
        llr: Vec<f64>,
        iterations: usize,
    },
}

impl BPResult {
    pub fn get_estimate(&self) -> Cow<'_, BitVec> {
        match self {
            Self::Converged { estimate, .. } => Cow::Borrowed(estimate),
            Self::Failed { llr, .. } => Cow::Owned(llr.iter().map(|x| x < &0.0).collect()),
        }
    }
}

pub fn propagate(
    parity_matrix: &ParityMatrix,
    message: &BitSlice,
    syndrome: &BitSlice,
    p_error: f64,
    max_iter: usize,
) -> BPResult {
    let initial_llr: Vec<f64> = message
        .iter()
        .by_refs()
        .map(|&v| {
            if v {
                p_error / (1.0 - p_error)
            } else {
                (1.0 - p_error) / p_error
            }
        })
        .map(f64::ln)
        .collect();
    let mut variable_to_factor = Matrix::zeros(syndrome.len(), message.len());
    for i in 0..syndrome.len() {
        variable_to_factor[i].copy_from_slice(&initial_llr)
    }
    let mut factor_to_variable = Matrix::zeros(message.len(), syndrome.len());
    let mut current_llr = vec![0.0; message.len()];
    let mut current_estimate = bitvec![0; message.len()];

    for iter in 0..max_iter {
        let tanhm = variable_to_factor.apply(|x| f64::tanh(x * 0.5));
        for (factor, neighbours) in parity_matrix.iter_factors() {
            let tanhmrow = &tanhm[*factor];
            let sign = if syndrome[*factor] { -1.0 } else { 1.0 };
            for j in neighbours {
                let b1 = neighbours.iter().filter(|&v| v != j);
                factor_to_variable[*j][*factor] =
                    sign * 2.0 * b1.map(|&idx| tanhmrow[idx]).product::<f64>().atanh();
            }
        }
        for (variable, neighbours) in parity_matrix.iter_variables() {
            let erow = &factor_to_variable[*variable];
            current_llr[*variable] =
                neighbours.iter().map(|&idx| erow[idx]).sum::<f64>() + initial_llr[*variable];
        }
        for (idx, l) in current_llr.iter().enumerate() {
            current_estimate.set(idx, l < &0.0);
        }
        let z_syndrome = parity_matrix.calculate_syndrome(&current_estimate);
        if z_syndrome == syndrome {
            return BPResult::Converged {
                estimate: current_estimate,
                llr: current_llr,
                iterations: iter,
            };
        }
        for (variable, neighbours) in parity_matrix.iter_variables() {
            let erow = &factor_to_variable[*variable];
            let first_llr = initial_llr[*variable];
            for j in neighbours {
                let a1 = neighbours.iter().filter(|&k| k != j);
                variable_to_factor[*j][*variable] =
                    a1.map(|&idx| erow[idx]).sum::<f64>() + first_llr;
            }
        }
    }
    BPResult::Failed {
        llr: current_llr,
        iterations: max_iter,
    }
}
