use core::{
    key_state_machine::{Key, Reconciled, Reconciling},
    models::follower_comms::{FollowerRequests, FollowerResponse},
    traits::{PPError, PPStep, PostProcessingStep},
};

use bitvec::vec::BitVec;
use tracing::warn;

use crate::client::SCSApi;

pub struct SimCommSys {
    codec_id: String,
    key: Key<Reconciling>,
    client: SCSApi,
    syndrome: Option<BitVec>,
}

impl SimCommSys {
    pub(crate) fn new(codec_id: String, key: Key<Reconciling>, client: SCSApi) -> Self {
        Self {
            codec_id,
            key,
            client,
            syndrome: None,
        }
    }
}

impl PostProcessingStep for SimCommSys {
    type Result = ();
    type FinalStage = Reconciled;
    type InitialStage = Reconciling;

    fn step(&mut self) -> Result<PPStep<Self::Result, FollowerRequests>, PPError> {
        // TODO Move this to follower.
        let response = self
            .client
            .calculate_syndrome(&self.codec_id, &self.key)
            .map_err(|e| {
                warn!("Calculate syndrome failed. Error: {e}");
                PPError::new("Failed to calculate syndrome")
            })?;

        Err(PPError::new(
            "SimCommSys processing step to be implemented.",
        ))
    }

    fn update(&mut self, _: FollowerResponse) -> Result<(), PPError> {
        Err(PPError::new(
            "SimCommSys processing update to be implemented.",
        ))
    }

    fn finalize(self) -> Result<Key<Self::FinalStage>, PPError> {
        Err(PPError::new("SimCommSys finalization to be implemented."))
    }
}
