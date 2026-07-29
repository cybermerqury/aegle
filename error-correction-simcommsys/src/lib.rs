pub(crate) mod client;

use core::{
    key_state_machine::{Key, Reconciled, Reconciling},
    models::parity_matrix::ParityMatrix,
    traits::{
        FollowerRequests, FollowerResponse, PPError, PPStep, PostProcessingSetup,
        PostProcessingStep,
    },
};

use std::path::Path;

use tracing::{debug, error};

use crate::client::SCSApi;

pub struct SetupSimCommSys {
    codec_id: String,
    matrix: ParityMatrix,
    client: SCSApi,
}

impl SetupSimCommSys {
    pub fn from_array<T>(
        codec_id: &str,
        matrix_array: &[T],
        base_url: &str,
    ) -> core::error::Result<Self>
    where
        T: AsRef<[u8]>,
    {
        let client = SCSApi::new(base_url)?;

        Ok(Self {
            codec_id: codec_id.to_string(),
            matrix: ParityMatrix::from_array(matrix_array),
            client,
        })
    }

    pub fn from_file(codec_id: &str, matrix_filepath: &Path, client: SCSApi) -> Self {
        // TODO - Remove unwrap.
        Self {
            codec_id: codec_id.to_string(),
            matrix: ParityMatrix::from_alist(matrix_filepath).unwrap(),
            client,
        }
    }

    /// Register this setup with simcommsys.
    /// Loads the parity matrix from an alist file then submits it to simcommsys.
    fn register_with_scs(&self) -> core::error::Result<()> {
        debug!(
            "Registering with simcommsys server as '{}'. Matrix: {:?}",
            self.codec_id, self.matrix
        );

        self.client
            .register(&self.codec_id, &self.matrix)
            .inspect_err(|e| error!("Error during setup. Error: {e:?}"))
    }
}

impl PostProcessingSetup for SetupSimCommSys {
    type Worker = SimCommSys;
    type InitialStage = <Self::Worker as PostProcessingStep>::InitialStage;
    type SetupArgs = f64;
    type SetupErr = core::error::Error;

    fn setup(
        self,
        key: Key<Self::InitialStage>,
        _: Self::SetupArgs,
    ) -> Result<Self::Worker, Self::SetupErr> {
        self.register_with_scs()?;

        Ok(SimCommSys {
            is_ready: true,
            key,
            client: self.client,
        })
    }
}

pub struct SimCommSys {
    is_ready: bool,
    key: Key<Reconciling>,
    client: SCSApi,
}

impl PostProcessingStep for SimCommSys {
    type Result = ();
    type FinalStage = Reconciled;
    type InitialStage = Reconciling;

    fn step(&mut self) -> Result<PPStep<Self::Result, FollowerRequests>, PPError> {
        match self.is_ready {
            true => Err(PPError::new(
                "SimCommSys processing step to be implemented.",
            )),
            false => Err(PPError::new("SimCommSys was not set up successfully.")),
        }
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
