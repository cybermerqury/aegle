// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// SPDX-FileCopyrightText:  © 2024 - 2026 Merqury Cybersecurity Ltd <info@merqury.eu>

use core::{
    key_state_machine::{Key, Reconciled, Reconciling},
    models::follower_comms::{FollowerRequests, FollowerResponse},
    traits::{PPError, PPStep, PostProcessingStep},
};
use std::sync::Arc;

use bitvec::vec::BitVec;
use tracing::{debug, info, warn};

use crate::client::SCSApi;

/// Represents the next step to be performed by the follower.
#[derive(Debug, Clone, Copy)]
enum FollowerPendingStep {
    Register,
    GetSyndrome,
    DecodeKey,
}

pub struct SimCommSys {
    error_rate: f64,
    codec_id: String,
    key: Key<Reconciling>,
    /// Contains the final error-corrected key data.
    reconciled_key: Option<BitVec>,
    word_size: usize,
    codeword_size: usize,
    client: Arc<SCSApi>,
    /// Stores the follower syndromes once returned.
    follower_syndromes: Option<Vec<BitVec>>,
    follower_next_step: FollowerPendingStep,
}

impl SimCommSys {
    pub(crate) fn new(
        error_rate: f64,
        codec_id: String,
        word_size: usize,
        codeword_size: usize,
        key: Key<Reconciling>,
        client: Arc<SCSApi>,
    ) -> Self {
        Self {
            error_rate,
            codec_id,
            key,
            reconciled_key: None,
            word_size,
            codeword_size,
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
    /// 3. `FollowerPendingStep::DecodeKey` ->
    fn step(&mut self) -> Result<PPStep<Self::Result, FollowerRequests>, PPError> {
        match self.follower_next_step {
            FollowerPendingStep::Register => Ok(PPStep::GetUpdate(
                FollowerRequests::SCSRegisterCode(self.codec_id.clone()),
            )),
            FollowerPendingStep::GetSyndrome => Ok(PPStep::GetUpdate(
                FollowerRequests::SCSSyndrome(self.codec_id.clone()),
            )),
            FollowerPendingStep::DecodeKey => {
                info!("Decoding key of {} bits.", self.key.length());

                let Some(follower_syndromes) = &self.follower_syndromes else {
                    return Err(PPError::new(
                        "Reached decoding step, but no syndromes were yet retrieved from the follower",
                    ));
                };

                let (codewords, remainder) = self.key.chunks(self.codeword_size);

                if let Some(remainder) = remainder {
                    warn!(
                        "Key does not fit cleanly into word size. Word size: {}, key size: {}, remaining bits: {}",
                        self.codeword_size,
                        self.key.get_interior_ref().len(),
                        remainder.len()
                    );
                }

                if follower_syndromes.len() != codewords.len() {
                    warn!(
                        "Incorrect quantity of syndromes or codewords. Syndrome count: {}, Codeword count: {}",
                        follower_syndromes.len(),
                        codewords.len()
                    );

                    return Err(PPError::new(
                        "Syndromes and codewords quantity mismatch. Cannot proceed",
                    ));
                }

                let mut corrected_codewords = Vec::with_capacity(codewords.len());

                for (codeword, syndrome) in codewords.into_iter().zip(follower_syndromes) {
                    let corrected_codeword = match self.client.decode(
                        &self.codec_id,
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

                info!(
                    "Old key: {}, New key: {}",
                    self.key.get_interior_ref(),
                    new_key
                );

                self.reconciled_key = Some(new_key);

                Ok(PPStep::Result(()))
            }
        }
    }

    fn update(&mut self, response: FollowerResponse) -> Result<(), PPError> {
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
        let (reconciled_key, syndromes) = match (self.reconciled_key, self.follower_syndromes) {
            (Some(key), Some(syndromes)) => Ok((key, syndromes)),
            (Some(_), None) => {
                // SAFETY - We couldn't have computed the reconciled keys without first storing the syndromes.
                unreachable!("Reconciled key present but syndromes not set for some reason.")
            }
            (None, Some(_)) => Err(PPError::new("Reconciled key not yet generated")),
            (None, None) => Err(PPError::new("No reconciled key or syndromes generated")),
        }?;

        let key_len = reconciled_key.len();
        let leaked_bits = syndromes.into_iter().flatten().count();

        info!("Reconciling {key_len}-bit key with {leaked_bits} leaked bits.");

        // TODO: Verify validity of leaked bits.
        Ok(self.key.reconcile(reconciled_key.into(), 0))
    }
}
