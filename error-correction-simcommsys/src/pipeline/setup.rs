// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// SPDX-FileCopyrightText:  © 2024 - 2026 Merqury Cybersecurity Ltd <info@merqury.eu>

use core::{
    error::ErrorKind,
    key_state_machine::Key,
    models::parity_matrix::ParityMatrix,
    traits::{PostProcessingSetup, PostProcessingStep},
};
use std::sync::Arc;

use tracing::{debug, error};

use crate::{
    client::SCSApi,
    config::{CodeProperties, LdpcCodes, MatrixDefinition},
    pipeline::stage::SimCommSys,
};

pub struct SetupSimCommSys {
    ldpc_codes: LdpcCodes,
    client: Arc<SCSApi>,
}

impl SetupSimCommSys {
    pub fn new(ldpc_codes: LdpcCodes, client: Arc<SCSApi>) -> core::error::Result<Self> {
        Ok(Self { ldpc_codes, client })
    }

    /// Register this setup with simcommsys.
    fn register_with_scs(
        &self,
        code: &CodeProperties,
        matrix: &ParityMatrix,
    ) -> core::error::Result<()> {
        debug!(
            "Registering with simcommsys server as '{}'. Matrix: {:?}",
            code.id, matrix
        );

        self.client
            .register(&code.id, matrix)
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
        let code = self.ldpc_codes.first().ok_or_else(|| {
            core::error::Error::new(
                ErrorKind::InconsistentData,
                "No LDPC codes defined in config",
            )
        })?;

        let matrix = match &code.matrix {
            MatrixDefinition::Array(arr) => ParityMatrix::from_array(arr),
            MatrixDefinition::AListFile(file_path) => ParityMatrix::from_alist_file(&file_path)
                .map_err(|e| {
                    core::error::Error::new(
                        ErrorKind::ConfigParse,
                        format!("Failed to load code from alist file. Error: {e}"),
                    )
                })?,
        };

        self.register_with_scs(code, &matrix)?;

        Ok(SimCommSys::new(
            error_rate,
            code.id.clone(),
            code.block_length,
            key,
            self.client,
        ))
    }
}
