// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// SPDX-FileCopyrightText:  © 2024 - 2026 Merqury Cybersecurity Ltd <info@merqury.eu>

use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
pub struct CliArgs {
    pub config: PathBuf,
}
