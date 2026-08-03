use core::{
    key_state_machine::{Key, Reconciled, Reconciling},
    models::follower_comms::{FollowerRequests, FollowerResponse},
    traits::{PPError, PPStep, PostProcessingStep},
};

use bitvec::vec::BitVec;
use tracing::{info, warn};

use crate::client::SCSApi;

enum FollowerPendingStep {
    Register,
    GetSyndrome,
    DecodeKey,
}

pub struct SimCommSys {
    codec_id: String,
    key: Key<Reconciling>,
    client: SCSApi,
    syndrome: Option<BitVec>,
    follower_next_step: FollowerPendingStep,
}

impl SimCommSys {
    pub(crate) fn new(codec_id: String, key: Key<Reconciling>, client: SCSApi) -> Self {
        Self {
            codec_id,
            key,
            client,
            syndrome: None,
            follower_next_step: FollowerPendingStep::Register,
        }
    }
}

impl PostProcessingStep for SimCommSys {
    type Result = ();
    type FinalStage = Reconciled;
    type InitialStage = Reconciling;

    fn step(&mut self) -> Result<PPStep<Self::Result, FollowerRequests>, PPError> {
        // TODO Move this to follower.
        // let response = self
        //     .client
        //     .calculate_syndrome(&self.codec_id, &self.key)
        //     .map_err(|e| {
        //         warn!("Calculate syndrome failed. Error: {e}");
        //         PPError::new("Failed to calculate syndrome")
        //     })?;

        match self.follower_next_step {
            FollowerPendingStep::Register => Ok(PPStep::GetUpdate(
                FollowerRequests::SCSRegisterCode(self.codec_id.clone()),
            )),
            FollowerPendingStep::GetSyndrome => Ok(PPStep::GetUpdate(
                FollowerRequests::SCSSyndrome(self.codec_id.clone()),
            )),
            _ => Err(PPError::new(
                "SimCommSys processing step to be implemented.",
            )),
        }
    }

    fn update(&mut self, response: FollowerResponse) -> Result<(), PPError> {
        match response {
            FollowerResponse::SCSRegisterCode(true) => {
                info!("Follower registered with SimCommSys successfully.");
                self.follower_next_step = FollowerPendingStep::GetSyndrome;
                Ok(())
            }
            FollowerResponse::SCSRegisterCode(false) => Err(PPError::new(
                "Follower SimCommSys code registration failed.",
            )),
            _ => Err(PPError::new("Unexpected follower response received.")),
        }
    }

    fn finalize(self) -> Result<Key<Self::FinalStage>, PPError> {
        Err(PPError::new("SimCommSys finalization to be implemented."))
    }
}
