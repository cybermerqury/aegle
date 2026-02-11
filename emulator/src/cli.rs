use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
pub struct CliArgs {
    pub config: PathBuf,
}
