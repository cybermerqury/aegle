use core::{
    key_state_machine::{Key, Reconciled, Reconciling},
    traits::{
        FollowerRequests, FollowerResponse, PPError, PPStep, PostProcessingSetup,
        PostProcessingStep,
    },
};

pub struct SetupSimCommSys;

impl PostProcessingSetup for SetupSimCommSys {
    type Worker = SimCommSys;
    type InitialStage = Reconciling;
    type SetupArgs = f64;

    fn setup(self, _: Key<Self::InitialStage>, _: Self::SetupArgs) -> Self::Worker {
        SimCommSys {}
    }
}

pub struct SimCommSys;

impl PostProcessingSetup for SimCommSys {
    type Worker = SimCommSys;
    type InitialStage = Reconciling;
    type SetupArgs = f64;

    fn setup(self, _: Key<Self::InitialStage>, _: Self::SetupArgs) -> Self::Worker {
        Self {}
    }
}

impl PostProcessingStep for SimCommSys {
    type InitialStage = Reconciling;
    type FinalStage = Reconciled;
    type Result = ();

    fn step(&mut self) -> Result<PPStep<Self::Result, FollowerRequests>, PPError> {
        unimplemented!("SimCommSys processing step to be implemented.");
    }

    fn update(&mut self, _: FollowerResponse) -> Result<(), PPError> {
        unimplemented!("SimCommSys processing update to be implemented.");
    }

    fn finalize(self) -> Result<Key<Self::FinalStage>, PPError> {
        unimplemented!("SimCommSys finalization to be implemented.");
    }
}
