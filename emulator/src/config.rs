use quinn::{crypto::rustls::QuicClientConfig, TransportConfig};
use rustls::RootCertStore;
use serde::{Deserialize, Deserializer};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

use core::fs::certificate_handling::load_key_and_certificate;

use crate::errors::{EmulatorResult, ErrorMessage};

#[derive(Deserialize, Debug)]
pub struct Config {
    pub links: Vec<Link>,
}

#[derive(Deserialize, Debug)]
pub struct Link {
    pub length: usize,
    #[serde(deserialize_with = "prob_from_float")]
    pub error_rate: Probability,
    #[serde(deserialize_with = "duration_from_string")]
    pub frequency: Duration,
    root_cert: PathBuf,
    client_cert: PathBuf,
    pub modules: (Module, Module),
}

#[derive(Deserialize, Debug)]
pub struct Module {
    pub addr: SocketAddr,
    pub uuid: Uuid,
}

fn load_root(root_cert: &Path) -> EmulatorResult<RootCertStore> {
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

fn prob_from_float<'de, D>(deserializer: D) -> Result<Probability, D::Error>
where
    D: Deserializer<'de>,
{
    let p: f64 = Deserialize::deserialize(deserializer)?;
    Probability::new(p).map_err(|e| serde::de::Error::custom(e.to_string()))
}

fn duration_from_string<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: Deserializer<'de>,
{
    let strtime: String = Deserialize::deserialize(deserializer)?;
    duration_str::parse(strtime).map_err(|e| serde::de::Error::custom(e.to_string()))
}

#[derive(Debug)]
pub struct Probability(f64);

impl Probability {
    pub fn new(value: f64) -> Result<Self, ErrorMessage> {
        if (0.0..1.0).contains(&value) {
            Ok(Self(value))
        } else {
            Err(ErrorMessage("A probability must be between 0 and 1"))
        }
    }

    pub fn val(&self) -> f64 {
        self.0
    }
}

impl Link {
    pub fn client_config(&self) -> EmulatorResult<quinn::ClientConfig> {
        let roots = load_root(&self.root_cert)?;

        let (private_key, cert) = load_key_and_certificate(&self.client_cert)?;
        let crypto = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(vec![cert], private_key.into())?;

        let mut config = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(crypto)?));
        let mut transport = TransportConfig::default();
        transport.keep_alive_interval(Some(Duration::from_secs(5)));
        config.transport_config(Arc::new(transport));
        Ok(config)
    }
}
