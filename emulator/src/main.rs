// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// SPDX-FileCopyrightText:  © 2024 - 2026 Merqury Cybersecurity Ltd <info@merqury.eu>

mod cli;
mod config;
mod emulator;
mod errors;

use clap::Parser;
use config::Config;
use errors::{EmulatorResult, ErrorMessage, SubsystemResult};
use std::path::Path;
use std::str::FromStr;
use tracing::{debug, error, info};
use tracing_subscriber::{prelude::*, EnvFilter};

use emulator::handle_link;
use ppaas_core::spawn_subsystem;
use ppaas_core::sync::tasks::TaskManager;

fn load_config(filename: &Path) -> EmulatorResult<Config> {
    debug!("loading config {}", filename.display());
    let contents = std::fs::read_to_string(filename)?;
    Ok(toml::from_str::<Config>(&contents)?)
}

#[tokio::main]
async fn main() -> SubsystemResult {
    let args = cli::CliArgs::parse();
    let config = load_config(args.config.as_ref())?;

    setup_logging_infra(&config);

    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| ErrorMessage("Unable to install crypto provider"))?;

    let mut tm = TaskManager::new();
    for link in config.links {
        spawn_subsystem!(tm, handle_link(.monitor, link));
    }
    match tm.monitor().await {
        Err(e) => error!("Unable to monitor subsystems: {}", e),
        Ok(Err(e)) => error!("A link raised the following error: {}", e),
        Ok(Ok(())) => info!("Exiting"),
    }
    Ok(())
}

fn setup_logging_infra(config: &Config) {
    let stdout_logging_layer = tracing_subscriber::fmt::Layer::new()
        .with_writer(std::io::stdout as fn() -> std::io::Stdout)
        .pretty()
        .with_thread_names(true)
        .with_thread_ids(true)
        .with_filter(EnvFilter::from_str(config.log_level.as_str()).unwrap());

    tracing_subscriber::registry()
        .with(stdout_logging_layer)
        .init();
}
