pub(crate) mod client;

use core::{
    key_state_machine::{Key, Reconciled, Reconciling},
    traits::{
        FollowerRequests, FollowerResponse, PPError, PPStep, PostProcessingSetup,
        PostProcessingStep,
    },
};

pub struct SetupSimCommSys;

impl SetupSimCommSys {
    pub fn new() -> Self {
        Self {}
    }
}

impl PostProcessingSetup for SetupSimCommSys {
    type Worker = SimCommSys;
    type InitialStage = Reconciling;
    type SetupArgs = f64;

    fn setup(self, _: Key<Self::InitialStage>, _: Self::SetupArgs) -> Self::Worker {
        SimCommSys {}
    }
}

pub struct SimCommSys;

impl PostProcessingStep for SimCommSys {
    type InitialStage = Reconciling;
    type FinalStage = Reconciled;
    type Result = ();

    fn step(&mut self) -> Result<PPStep<Self::Result, FollowerRequests>, PPError> {
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
