use rustls::{
    pki_types::{CertificateDer, PrivatePkcs8KeyDer},
    RootCertStore,
};

use rustls_pemfile::Item;
use std::path::Path;
use std::{
    fs,
    io::{BufReader, Read},
};

use tracing::{debug, warn};

use crate::error::{Error, ErrorKind, Result};

pub fn load_key_and_certificate(
    pem_file_location: &Path,
) -> Result<(PrivatePkcs8KeyDer<'static>, CertificateDer<'static>)> {
    let pem_file = fs::File::open(pem_file_location)?;
    let mut pem_data = BufReader::new(pem_file);

    let mut opt_key: Option<PrivatePkcs8KeyDer> = None;
    let mut opt_certificate: Option<CertificateDer> = None;

    for item in rustls_pemfile::read_all(&mut pem_data) {
        match item? {
            Item::Pkcs8Key(read_key) => opt_key = Some(read_key),
            Item::X509Certificate(read_crt) => opt_certificate = Some(read_crt),
            _ => warn!("Unsupported file encoding detected."),
        }
    }

    let private_key = if let Some(pkcs8) = opt_key {
        pkcs8
    } else {
        return Err(Error::new(
            ErrorKind::Io,
            format!("No PKCS8 key found in pemfile ({:?})", pem_file_location),
        ));
    };

    let certificate = if let Some(cert) = opt_certificate {
        cert
    } else {
        return Err(Error::new(
            ErrorKind::Io,
            format!(
                "No X509 certificate key found in pemfile ({:?})",
                pem_file_location
            ),
        ));
    };

    Ok((private_key, certificate))
}

pub fn load_root_certificate_store(pem_file_location: &Path) -> Result<RootCertStore> {
    let pem_file = fs::File::open(pem_file_location)?;
    let mut pem_data = BufReader::new(pem_file);

    let mut roots = rustls::RootCertStore::empty();
    let certificates = rustls_pemfile::certs(&mut pem_data);

    for root in certificates {
        match roots.add(root?) {
            Ok(_) => debug!("Certificate added."),
            Err(e) => warn!("Failed to add certificate: {}.", e),
        }
    }

    Ok(roots)
}

fn load_ca_certificate(ca_certificate_path: &Path) -> Result<String> {
    Ok(fs::read_to_string(ca_certificate_path)?)
}
