use quinn::{
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
    TransportConfig,
};
use rustls::RootCertStore;
use serde::Deserialize;
use std::fmt::Display;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tracing_appender::{
    non_blocking,
    non_blocking::{NonBlocking, WorkerGuard},
    rolling::daily,
};
use tracing_subscriber::EnvFilter;

use core::fs::certificate_handling::load_key_and_certificate;

use crate::errors::MainResult;
use crate::models::{OwnID, PeerInfo};

fn file_writer_from_string<'de, D>(deserializer: D) -> Result<Option<RotatingLog>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let maybe_path: Option<PathBuf> = Deserialize::deserialize(deserializer)?;
    let Some(path) = maybe_path else {
        return Ok(None);
    };
    let Some(file) = path.file_name() else {
        return Err(serde::de::Error::custom(
            "Path for log doesn't include a filename",
        ));
    };
    let (rotating, _guard) = non_blocking(daily(path.parent().unwrap_or(Path::new(".")), file));
    let non_blocking = RotatingLog {
        file: rotating,
        _guard,
    };
    Ok(Some(non_blocking))
}

#[derive(Debug)]
pub struct RotatingLog {
    pub file: NonBlocking,
    _guard: WorkerGuard,
}

#[derive(Deserialize, Debug)]
pub struct ModuleConfig {
    pub module: Module,
    pub peers: Vec<PeerInfo>,
}

impl ModuleConfig {
    // The following unwraps are safe, as we already parsed the objects as EnvFilters
    pub fn logfile_level(&self) -> EnvFilter {
        EnvFilter::from_str(format!("{}", self.module.logfile_level).as_str()).unwrap()
    }

    pub fn stdout_level(&self) -> EnvFilter {
        EnvFilter::from_str(format!("{}", self.module.stdout_level).as_str()).unwrap()
    }
}

fn default_log() -> EnvFilter {
    EnvFilter::from_str("ppaas_module=info").unwrap()
}

fn log_filter<'de, D>(deserializer: D) -> Result<EnvFilter, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    EnvFilter::builder()
        .parse(s)
        .map_err(|e| serde::de::Error::custom(format!("Unable to create log filter: {}", e)))
}

#[derive(Deserialize, Debug)]
pub struct Module {
    pub uuid: OwnID,
    pub error_correction: Vec<String>,
    pub peer_addr: SocketAddr,
    pub qkd_addr: SocketAddr,
    root_cert: PathBuf,
    module_cert: PathBuf,
    #[serde(default, deserialize_with = "file_writer_from_string")]
    pub logfile: Option<RotatingLog>,

    #[serde(default = "default_log", deserialize_with = "log_filter")]
    logfile_level: EnvFilter,
    #[serde(default = "default_log", deserialize_with = "log_filter")]
    stdout_level: EnvFilter,
}

impl Display for ModuleConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Uuid: {}", self.module.uuid)?;
        writeln!(
            f,
            "Known Correction Algos: {}",
            self.module.error_correction.join(",")
        )?;
        write!(f, "Peers:")?;
        for peer in &self.peers {
            writeln!(f, "\n  Uuid: {}", peer.uuid)?;
            writeln!(f, "    IP: {}", peer.addr)?;
            writeln!(f, "    QKD:")?;
            for qkd in &peer.qkd {
                writeln!(f, "    local {}", qkd.local)?;
                writeln!(f, "    remote {}", qkd.remote)?;
            }
        }
        Ok(())
    }
}

fn load_root(root_cert: &Path) -> MainResult<RootCertStore> {
    let pem_file_location = &root_cert;
    let pem_file = std::fs::File::open(pem_file_location)?;
    let mut pem_data = std::io::BufReader::new(pem_file);

    let mut roots = rustls::RootCertStore::empty();
    let certificates = rustls_pemfile::certs(&mut pem_data);

    for root in certificates {
        roots.add(root?)?
    }
    Ok(roots)
}

impl Module {
    pub fn server_config(&self) -> MainResult<quinn::ServerConfig> {
        let roots = load_root(&self.root_cert)?;

        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots)).build()?;
        let (private_key, cert) = load_key_and_certificate(&self.module_cert)?;
        let crypto = rustls::ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(vec![cert], private_key.into())?;

        let config =
            quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(crypto)?));
        Ok(config)
    }
    pub fn client_config(&self) -> MainResult<quinn::ClientConfig> {
        let roots = load_root(&self.root_cert)?;

        let (private_key, cert) = load_key_and_certificate(&self.module_cert)?;
        let crypto = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(vec![cert], private_key.into())?;
        let mut transport = TransportConfig::default();
        transport.keep_alive_interval(Some(Duration::from_secs(5)));
        let mut config = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(crypto)?));
        config.transport_config(Arc::new(transport));
        Ok(config)
    }
}
