pub(crate) mod client;

use core::{
    key_state_machine::{Key, Reconciled, Reconciling},
    models::parity_matrix::ParityMatrix,
    traits::{
        FollowerRequests, FollowerResponse, PPError, PPStep, PostProcessingSetup,
        PostProcessingStep,
    },
};
use std::path::{Path, PathBuf};

use tracing::error;

use crate::client::SCSApi;

pub const SCS_CODEC_ID: &str = "aegle-codec";

pub struct SetupSimCommSys {
    matrix_filepath: PathBuf,
    client: SCSApi,
}

impl SetupSimCommSys {
    pub fn new(matrix_filepath: &Path, client: SCSApi) -> Self {
        Self {
            matrix_filepath: matrix_filepath.to_path_buf(),
            client,
        }
    }

    /// Register this setup with simcommsys.
    /// Loads the parity matrix from an alist file then submits it to simcommsys.
    /// Returns whether the endpoint was successful or not.
    fn register_with_scs(&self) -> bool {
        let parity_matrix = match ParityMatrix::from_alist(&self.matrix_filepath) {
            Ok(pm) => pm,
            Err(e) => {
                error!("Failed to load parity matrix. Error: {e}");
                return false;
            }
        };

        self.client
            .register(SCS_CODEC_ID, &parity_matrix)
            .inspect_err(|e| error!("Error during setup. Error: {e}"))
            .is_ok()
    }
}

impl PostProcessingSetup for SetupSimCommSys {
    type Worker = SimCommSys;
    type InitialStage = <Self::Worker as PostProcessingStep>::InitialStage;
    type SetupArgs = f64;

    fn setup(self, key: Key<Self::InitialStage>, _: Self::SetupArgs) -> Self::Worker {
        let setup_success = self.register_with_scs();

        SimCommSys {
            is_ready: setup_success,
            key,
            client: self.client,
        }
    }
}

pub struct SimCommSys {
    is_ready: bool,
    key: Key<Reconciling>,
    client: SCSApi,
}

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
