use clap::Parser;

#[derive(Parser, Debug)]
#[command(version, about="PPAAS module. A leader module runs error correction, a follower module acts as the counterparty to a leader module.", long_about = None)]
pub struct CliArgs {
    /// toml configuration file
    #[clap(short, long)]
    pub config_file: String,
}
