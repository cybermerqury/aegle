mod cli;
mod communication;
mod config;
mod errors;
mod models;
mod subsystems;
use clap::Parser;
use cli::CliArgs;
use config::ModuleConfig;
use tracing::{error, info};
use tracing_subscriber::prelude::*;

use crate::subsystems::start_subsystems;

use self::errors::{ErrorMessage, MainResult};

pub enum Roles {
    Leader,
    Follower,
}

#[tokio::main]
async fn main() -> MainResult<()> {
    let args = CliArgs::parse();
    let config: ModuleConfig = core::fs::config::load_toml_config(args.config_file)?;

    setup_logging_infra(&config);

    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| ErrorMessage("Unable to install crypto provider"))?;

    info!("Starting ppaas module");
    info!("Config is: '{:?}'", config);

    let tm = start_subsystems(&config.module, config.peers)?;
    match tm.monitor().await {
        Ok(Ok(())) => info!("Goodbye"),
        Ok(Err(e)) => error!("Subsystem error: {}", e),
        Err(e) => error!("Error setting up monitoring: {}", e),
    }

    Ok(())
}

fn setup_logging_infra(config: &ModuleConfig) {
    let stdout_logging_layer = tracing_subscriber::fmt::Layer::new()
        .with_writer(std::io::stdout as fn() -> std::io::Stdout)
        .pretty()
        .with_thread_names(true)
        .with_thread_ids(true)
        .with_filter(config.stdout_level());

    tracing_subscriber::registry()
        .with(stdout_logging_layer)
        .with(config.module.logfile.as_ref().map(|x| {
            tracing_subscriber::fmt::layer()
                .with_writer(x.file.clone())
                .json()
                .with_filter(config.logfile_level())
        }))
        .init();
}
