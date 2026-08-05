// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// SPDX-FileCopyrightText:  © 2024 - 2026 Merqury Cybersecurity Ltd <info@merqury.eu>

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct SimCommSysConfig {
    pub base_url: String,
}
