// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// SPDX-FileCopyrightText:  © 2024 - 2026 Merqury Cybersecurity Ltd <info@merqury.eu>

pub mod belief_propagation;

use bitvec::vec::BitVec;
use std::{convert::Infallible, path::Path};

use core::{
    key_state_machine::{Key, Reconciled, Reconciling},
    models::parity_matrix::ParityMatrix,
    traits::{
        FollowerRequests, FollowerResponse, PPError, PPStep, PostProcessingSetup,
        PostProcessingStep,
    },
};

use belief_propagation::BPResult;

pub struct BinaryLDPC {
    key: Key<Reconciling>,
    parity_matrix: ParityMatrix,
    max_iter: usize,
    error_estimate: f64,
    syndrome: Option<BitVec>,
    reconciled_key: Option<BitVec>,
}

impl PostProcessingStep for BinaryLDPC {
    type Result = ();

    type FinalStage = Reconciled;

    type InitialStage = Reconciling;

    fn step(&mut self) -> Result<PPStep<(), FollowerRequests>, PPError> {
        match &self.syndrome {
            None => {
                let indicies: Vec<Vec<usize>> = self
                    .parity_matrix
                    .iter_factors()
                    .map(|(_, idx)| idx.clone())
                    .collect();
                Ok(PPStep::GetUpdate(FollowerRequests::Syndrome(indicies)))
            }
            Some(syndrome) => {
                let result = belief_propagation::propagate(
                    &self.parity_matrix,
                    self.key.get_interior_ref(),
                    syndrome,
                    self.error_estimate,
                    self.max_iter,
                );
                match result {
                    BPResult::Converged { estimate, .. } => {
                        self.reconciled_key = Some(estimate);
                        Ok(PPStep::Result(()))
                    }
                    BPResult::Failed { .. } => Ok(PPStep::Abort),
                }
            }
        }
    }

    fn update(&mut self, update: FollowerResponse) -> Result<(), PPError> {
        match update {
            FollowerResponse::Syndrome(syndrome) => {
                self.syndrome = Some(syndrome);
                Ok(())
            }
            _ => Err(PPError::new("Did not expect this update")),
        }
    }

    fn finalize(self) -> Result<Key<Self::FinalStage>, PPError> {
        match (self.reconciled_key, self.syndrome) {
            (Some(reconciled), Some(syndrome)) => {
                Ok(self.key.reconcile(reconciled.into(), syndrome.len()))
            }
            _ => Err(PPError::new("Unable to finalize key, not yet reconciled")),
        }
    }
}

pub struct SetupBinaryLDPC {
    parity_matrix_alist_file: String,
    max_iter: usize,
}

impl SetupBinaryLDPC {
    pub fn new(max_iter: usize, parity_matrix_alist_file: String) -> Self {
        Self {
            max_iter,
            parity_matrix_alist_file,
        }
    }
}

impl PostProcessingSetup for SetupBinaryLDPC {
    type InitialStage = <Self::Worker as PostProcessingStep>::InitialStage;

    type Worker = BinaryLDPC;

    type SetupArgs = f64;
    type SetupErr = Infallible;

    fn setup(
        self,
        key: Key<Self::InitialStage>,
        args: Self::SetupArgs,
    ) -> Result<Self::Worker, Self::SetupErr> {
        let parity_matrix =
            ParityMatrix::from_alist(Path::new(&self.parity_matrix_alist_file)).unwrap();

        Ok(Self::Worker {
            error_estimate: args,
            key,
            parity_matrix,
            max_iter: self.max_iter,
            reconciled_key: None,
            syndrome: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use bitvec::prelude::*;

    use core::models::parity_matrix::ParityMatrix;

    use crate::belief_propagation;

    const H: [[u8; 6]; 4] = [
        [1, 1, 0, 1, 0, 0],
        [0, 1, 1, 0, 1, 0],
        [1, 0, 0, 0, 1, 1],
        [0, 0, 1, 1, 0, 1],
    ];

    #[test]
    fn syndrome_calc() {
        let message = bitvec![0, 1, 1, 1, 0, 0];
        let pm = ParityMatrix::from_array(&H);
        let pm_syndrome = pm.calculate_syndrome(&message);
        let mut naive_syndrome = bitvec![];
        for row in H {
            let mut val = 0;
            for (x, m) in row.iter().zip(message.iter().by_vals()) {
                if m {
                    val += x;
                }
            }
            naive_syndrome.push((val % 2) == 1)
        }
        assert_eq!(naive_syndrome, pm_syndrome);
    }

    #[test]
    fn check_bp() {
        let message = bitvec![1, 0, 1, 0, 1, 1];
        let corrupted = bitvec![0, 0, 1, 0, 1, 1];
        let pm = ParityMatrix::from_array(&H);
        let syndrome = pm.calculate_syndrome(&message);
        let result = belief_propagation::propagate(&pm, &corrupted, &syndrome, 0.2, 100);
        let recovered = result.get_estimate();
        assert_eq!(&message, recovered.as_ref());
    }
}
