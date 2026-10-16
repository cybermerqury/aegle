// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// SPDX-FileCopyrightText:  © 2024 - 2026 Merqury Cybersecurity Ltd <info@merqury.eu>

use std::{path::PathBuf, sync::Arc};

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct SimCommSysConfig {
    pub base_url: String,
    pub ldpc_codes: LdpcCodes,
}

#[derive(Debug, Deserialize)]
pub struct CodeProperties {
    pub id: String,
    pub min_ber: f64,
    pub max_ber: f64,
    pub block_length: u64,
    pub matrix: MatrixDefinition,
}

#[derive(Debug, Deserialize)]
pub enum MatrixDefinition {
    #[serde(rename = "definition")]
    Array(Vec<Vec<u8>>),
    #[serde(rename = "file")]
    AListFile(PathBuf),
}

pub type LdpcCodes = Arc<Vec<Arc<CodeProperties>>>;
