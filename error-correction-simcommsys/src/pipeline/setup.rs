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

    /// Pick an LDPC code based on the ber and key length.
    fn pick_code(&self, ber: f64, key_len: u64) -> Option<Arc<CodeProperties>> {
        debug!("Choosing appropriate LDPC code. Target BER: {ber}, key length: {key_len}");

        self.ldpc_codes.iter().find_map(|code| {
            let ber_range = code.min_ber..=code.max_ber;

            if ber_range.contains(&ber) && key_len >= code.block_length {
                Some(code.clone())
            } else {
                None
            }
        })
    }

    /// Register this setup with simcommsys.
    fn register_with_scs(
        &self,
        code: &Arc<CodeProperties>,
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
        ber: Self::SetupArgs,
    ) -> Result<Self::Worker, Self::SetupErr> {
        let code = self.pick_code(ber, key.length() as u64).ok_or_else(|| {
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

        self.register_with_scs(&code, &matrix)?;

        Ok(SimCommSys::new(ber, code, key, self.client))
    }
}
