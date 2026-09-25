// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// SPDX-FileCopyrightText:  © 2024 - 2026 Merqury Cybersecurity Ltd <info@merqury.eu>

use ppaas_core::{
    key_state_machine::{Key, Reconciled, Reconciling},
    models::follower_comms::{FollowerRequests, FollowerResponse},
    traits::{PPError, PPStep, PostProcessingStep},
};
use std::{collections::HashMap, sync::Arc};

use bitvec::vec::BitVec;
use tracing::{Level, debug, info, instrument, warn};

use crate::{client::SCSApi, config::CodeProperties};

/// Represents the next step to be performed by the follower.
#[derive(Debug, Clone, Copy)]
enum FollowerPendingStep {
    Register,
    GetSyndrome,
    DecodeKey,
}

pub struct SimCommSys {
    error_rate: f64,
    code: Arc<CodeProperties>,
    key: Key<Reconciling>,
    /// Contains the final error-corrected key data.
    corrected_key: Option<BitVec>,
    leaked_bits: usize,
    client: Arc<SCSApi>,
    /// Stores the follower syndromes once returned.
    follower_syndromes: Option<HashMap<usize, BitVec>>,
    follower_next_step: FollowerPendingStep,
}

impl SimCommSys {
    pub(crate) fn new(
        error_rate: f64,
        code: Arc<CodeProperties>,
        key: Key<Reconciling>,
        client: Arc<SCSApi>,
    ) -> Self {
        Self {
            error_rate,
            code,
            key,
            corrected_key: None,
            leaked_bits: 0,
            client,
            follower_syndromes: None,
            follower_next_step: FollowerPendingStep::Register,
        }
    }
}

impl PostProcessingStep for SimCommSys {
    type Result = ();
    type FinalStage = Reconciled;
    type InitialStage = Reconciling;

    /// Error-correction main loop. Follows the below state machine:
    ///
    /// 1. `FollowerPendingStep::Register` -> Follower registers LDPC code to be used.
    /// 2. `FollowerPendingStep::GetSyndrome` -> Follower obtains syndrome for the key (split into fixed-size chunks of key data according to code size).
    /// 3. `FollowerPendingStep::DecodeKey` -> Perform final decoding of the key.
    #[instrument(skip_all, err(level = Level::ERROR))]
    fn step(&mut self) -> Result<PPStep<Self::Result, FollowerRequests>, PPError> {
        match self.follower_next_step {
            FollowerPendingStep::Register => {
                info!("Follower needs to register chosen code '{}'.", self.code.id);

                Ok(PPStep::GetUpdate(FollowerRequests::SCSRegisterCode(
                    self.code.id.clone(),
                )))
            }
            FollowerPendingStep::GetSyndrome => {
                info!("Requesting syndromes from follower.");
                Ok(PPStep::GetUpdate(FollowerRequests::SCSSyndrome))
            }
            FollowerPendingStep::DecodeKey => {
                info!("Decoding key of {} bits.", self.key.length());

                let Some(follower_syndromes) = &self.follower_syndromes else {
                    return Err(PPError::new(
                        "Reached decoding step, but no syndromes were yet retrieved from the follower",
                    ));
                };

                let (codewords, remainder) = self.key.chunks(self.code.block_length);

                #[cfg(debug_assertions)]
                if let Some(remainder) = remainder {
                    let remaining_bits = remainder.len();
                    warn!(
                        "Key does not fit cleanly into block. Block length: {}, key size: {}, total remaining bits: {}, remaining bits: {}",
                        self.code.block_length,
                        self.key.get_interior_ref().len(),
                        remainder.len(),
                        remaining_bits
                    );
                }

                let mut syndromes_vec = follower_syndromes.into_iter().collect::<Vec<_>>();

                if !syndromes_vec.is_sorted_by_key(|(i, _)| i) {
                    warn!("Syndromes are out-of-order. Re-sorting.");
                    syndromes_vec.sort_by_key(|(i, _)| **i);
                }

                self.leaked_bits += syndromes_vec.iter().fold(0, |acc, (_, s)| acc + s.len());

                if syndromes_vec.len() != codewords.len() {
                    warn!(
                        "Incorrect quantity of syndromes or codewords. Syndrome count: {}, Codeword count: {}",
                        syndromes_vec.len(),
                        codewords.len()
                    );

                    return Err(PPError::new(
                        "Syndromes and codewords quantity mismatch. Cannot proceed",
                    ));
                }

                let syndromes_vec = syndromes_vec
                    .into_iter()
                    .map(|(_, s)| s)
                    .collect::<Vec<_>>();

                let mut corrected_codewords = Vec::with_capacity(codewords.len());

                for (codeword, syndrome) in codewords.into_iter().zip(syndromes_vec) {
                    let corrected_codeword = match self.client.decode(
                        &self.code.id,
                        self.error_rate,
                        &codeword,
                        syndrome,
                    ) {
                        Ok(corrected_codeword) => corrected_codeword,
                        Err(e) => {
                            warn!(
                                "Failed to retrieve corrected codeword from SimCommSys. Error: {e}"
                            );
                            return Err(PPError::new("Error decoding key with SimCommSys"));
                        }
                    };

                    #[cfg(debug_assertions)]
                    debug!(
                        "Original: {codeword}, Syndrome: {syndrome}, Corrected codeword: {corrected_codeword}"
                    );

                    corrected_codewords.push(corrected_codeword);
                }

                let new_key = corrected_codewords
                    .into_iter()
                    .flatten()
                    .collect::<BitVec>();

                #[cfg(debug_assertions)]
                {
                    use ppaas_core::obtain_key_hash;

                    let old_key_slice = if self.key.get_interior_ref().len() >= new_key.len() {
                        &self.key.get_interior_ref()[0..new_key.len()]
                    } else {
                        return Err(PPError::new(
                            "New key is too large; Shape does not match expected shape.",
                        ));
                    };

                    let total_diff: usize = old_key_slice
                        .iter()
                        .zip(new_key.as_bitslice())
                        .fold(0, |acc, (l, r)| acc + (*l == *r) as usize);

                    let unsliced_key_hash = obtain_key_hash(self.key.get_interior_ref());
                    let old_key_hash = obtain_key_hash(old_key_slice);
                    let new_key_hash = obtain_key_hash(&new_key);

                    info!(
                        "Corrected bits: {}. Original key hash: {}, Key hash BEFORE SCS: {}, Key hash AFTER SCS: {}",
                        total_diff, unsliced_key_hash, old_key_hash, new_key_hash
                    );
                }

                self.corrected_key = Some(new_key);

                Ok(PPStep::Result(()))
            }
        }
    }

    #[instrument(skip_all, err(level = Level::ERROR))]
    fn update(&mut self, response: FollowerResponse) -> Result<(), PPError> {
        #[cfg(debug_assertions)]
        debug!("Received follower response '{response:?}'.");

        match (self.follower_next_step, response) {
            (FollowerPendingStep::Register, FollowerResponse::SCSRegisterCode(true)) => {
                info!("Follower registered with SimCommSys successfully.");
                self.follower_next_step = FollowerPendingStep::GetSyndrome;
                Ok(())
            }
            (FollowerPendingStep::Register, FollowerResponse::SCSRegisterCode(false)) => Err(
                PPError::new("Follower SimCommSys code registration failed."),
            ),
            (FollowerPendingStep::GetSyndrome, FollowerResponse::SCSSyndrome(Some(syndromes))) => {
                info!("Obtained syndromes from follower.");
                debug!("Syndromes: {syndromes:?}.");
                self.follower_next_step = FollowerPendingStep::DecodeKey;

                self.follower_syndromes = Some(syndromes);

                Ok(())
            }
            (FollowerPendingStep::GetSyndrome, FollowerResponse::SCSSyndrome(None)) => {
                Err(PPError::new("Follower failed to compute syndromes."))
            }
            _ => Err(PPError::new("Unexpected follower response received.")),
        }
    }

    fn finalize(self) -> Result<Key<Self::FinalStage>, PPError> {
        let (reconciled_key, _) = match (self.corrected_key, self.follower_syndromes) {
            (Some(key), Some(syndromes)) => Ok((key, syndromes)),
            (Some(_), None) => {
                // SAFETY - We couldn't have computed the reconciled keys without first storing the syndromes.
                unreachable!("Reconciled key present but syndromes not set for some reason.")
            }
            (None, Some(_)) => Err(PPError::new("Reconciled key not yet generated")),
            (None, None) => Err(PPError::new("No reconciled key or syndromes generated")),
        }?;

        let key_len = reconciled_key.len();

        info!(
            "Reconciling {key_len}-bit key with {} leaked bits.",
            self.leaked_bits
        );

        Ok(self.key.reconcile(reconciled_key.into(), self.leaked_bits))
    }
}
