// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// SPDX-FileCopyrightText:  © 2024 - 2026 Merqury Cybersecurity Ltd <info@merqury.eu>

use core::{
    key_state_machine::Key,
    models::parity_matrix::ParityMatrix,
    traits::{PostProcessingSetup, PostProcessingStep},
};
use std::sync::Arc;

use tracing::{debug, error};

use crate::{client::SCSApi, pipeline::stage::SimCommSys};

pub struct SetupSimCommSys {
    codec_id: String,
    matrix: ParityMatrix,
    client: Arc<SCSApi>,
    codeword_size: u64,
}

impl SetupSimCommSys {
    pub fn new(
        codec_id: &str,
        parity_matrix: ParityMatrix,
        client: Arc<SCSApi>,
        codeword_size: u64,
    ) -> core::error::Result<Self> {
        Ok(Self {
            codec_id: codec_id.to_string(),
            matrix: parity_matrix,
            codeword_size,
            client,
        })
    }

    /// Register this setup with simcommsys.
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
        error_rate: Self::SetupArgs,
    ) -> Result<Self::Worker, Self::SetupErr> {
        self.register_with_scs()?;

        Ok(SimCommSys::new(
            error_rate,
            self.codec_id,
            self.codeword_size,
            key,
            self.client,
        ))
    }
}
