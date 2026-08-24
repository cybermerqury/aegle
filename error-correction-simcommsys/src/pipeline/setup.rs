// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// SPDX-FileCopyrightText:  © 2024 - 2026 Merqury Cybersecurity Ltd <info@merqury.eu>

use ppaas_core::{
    error::ErrorKind,
    key_state_machine::Key,
    models::parity_matrix::ParityMatrix,
    traits::{PostProcessingSetup, PostProcessingStep},
};
use std::sync::Arc;

use tracing::{debug, error, info, instrument};

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
    pub fn new(ldpc_codes: LdpcCodes, client: Arc<SCSApi>) -> ppaas_core::error::Result<Self> {
        Ok(Self { ldpc_codes, client })
    }

    /// Pick an LDPC code based on the ber and key length.
    /// Chooses the best code based on the below process:
    /// 1. Filter those codes which do not support the estimated BER.
    /// 2. Filter out codes which do not fit the key length.
    /// 3. Prefer the code which has the least key bits wasted (those trailing bits which do not fit into another block).
    #[instrument(skip(self))]
    fn pick_code(&self, ber: f64, key_len: u64) -> Option<Arc<CodeProperties>> {
        debug!("Choosing appropriate LDPC code.");
        let mut current_required_blocks = f64::MAX;
        let mut selected_code = None;

        for code in self.ldpc_codes.iter() {
            let ber_range = code.min_ber..code.max_ber;

            if !ber_range.contains(&ber) {
                continue;
            }

            let required_blocks = key_len as f64 / code.block_length as f64;

            debug!(
                "Checking code '{}'. Required blocks: {:.02}",
                code.id, required_blocks
            );

            if required_blocks >= 1. && required_blocks < current_required_blocks {
                current_required_blocks = required_blocks;
                selected_code = Some(code.clone());
            }
        }

        selected_code
    }

    /// Register this setup with simcommsys.
    fn register_with_scs(
        &self,
        code: &Arc<CodeProperties>,
        matrix: &ParityMatrix,
    ) -> ppaas_core::error::Result<()> {
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
    type SetupErr = ppaas_core::error::Error;

    fn setup(
        self,
        key: Key<Self::InitialStage>,
        ber: Self::SetupArgs,
    ) -> Result<Self::Worker, Self::SetupErr> {
        let code = self.pick_code(ber, key.length() as u64).ok_or_else(|| {
            ppaas_core::error::Error::new(
                ErrorKind::InconsistentData,
                "No LDPC codes defined in config",
            )
        })?;

        info!("Selected code '{}'.", code.id);

        let matrix = match &code.matrix {
            MatrixDefinition::Array(arr) => ParityMatrix::from_array(arr),
            MatrixDefinition::AListFile(file_path) => {
                ParityMatrix::from_alist_file_short(&file_path).map_err(|e| {
                    ppaas_core::error::Error::new(
                        ErrorKind::ConfigParse,
                        format!("Failed to load code from alist file. Error: {e}"),
                    )
                })?
            }
        };

        self.register_with_scs(&code, &matrix)?;

        Ok(SimCommSys::new(ber, code, key, self.client))
    }
}
