// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// SPDX-FileCopyrightText:  © 2024 - 2026 Merqury Cybersecurity Ltd <info@merqury.eu>

use core::{
    key_state_machine::{Key, Reconciled, Reconciling},
    models::follower_comms::{FollowerRequests, FollowerResponse},
    traits::{PPError, PPStep, PostProcessingStep},
};

use bitvec::vec::BitVec;
use tracing::{debug, info};

use crate::client::SCSApi;

#[derive(Debug, Clone, Copy)]
enum FollowerPendingStep {
    Register,
    GetSyndrome,
    DecodeKey,
}

pub struct SimCommSys {
    codec_id: String,
    key: Key<Reconciling>,
    client: SCSApi,
    follower_syndromes: Option<Vec<BitVec>>,
    follower_next_step: FollowerPendingStep,
}

impl SimCommSys {
    pub(crate) fn new(codec_id: String, key: Key<Reconciling>, client: SCSApi) -> Self {
        Self {
            codec_id,
            key,
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

    fn step(&mut self) -> Result<PPStep<Self::Result, FollowerRequests>, PPError> {
        match self.follower_next_step {
            FollowerPendingStep::Register => Ok(PPStep::GetUpdate(
                FollowerRequests::SCSRegisterCode(self.codec_id.clone()),
            )),
            FollowerPendingStep::GetSyndrome => Ok(PPStep::GetUpdate(
                FollowerRequests::SCSSyndrome(self.codec_id.clone()),
            )),
            FollowerPendingStep::DecodeKey => {
                info!("Decoding key.");

                Err(PPError::new(
                    "Post-DecodeKey reconciliation and PA pending.",
                ))
            }
            _ => Err(PPError::new(
                "SimCommSys processing step to be implemented.",
            )),
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
        Err(PPError::new("SimCommSys finalization to be implemented."))
    }
}
