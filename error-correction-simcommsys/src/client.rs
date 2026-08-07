// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// SPDX-FileCopyrightText:  © 2024 - 2026 Merqury Cybersecurity Ltd <info@merqury.eu>

use std::format;

use bitvec::{slice::BitSlice, vec::BitVec};
// use reqwest::{Client, ClientBuilder};
use serde::Deserialize;
use serde_json::json;
use tracing::{debug, instrument, warn};
use ureq::Agent;

use core::{
    error::{Error, ErrorKind, Result},
    models::parity_matrix::ParityMatrix,
};

/// A basic client/wrapper around a simcommsys REST API.
pub struct SCSApi {
    base_url: String,
    client: Agent,
}

impl SCSApi {
    pub const REGISTER_CODEC_URL: &str = "register";
    pub const CALCULATE_SYNDROME_URL: &str = "calculate-syndrome";
    pub const DECODE_URL: &str = "decode";

    pub fn new(base_url: &str) -> Result<Self> {
        let agent_config = Agent::config_builder().http_status_as_error(false).build();

        Ok(Self {
            base_url: base_url.to_string(),
            client: Agent::new_with_config(agent_config),
        })
    }

    /// Register a parity matrix with simcommsys.
    #[instrument(skip(self, matrix))]
    pub fn register(&self, codec_name: &str, matrix: &ParityMatrix) -> Result<()> {
        let url = self.url(Self::REGISTER_CODEC_URL);

        debug!("Generating config.");

        let config = parity_matrix_to_codec(matrix)?;

        #[cfg(debug_assertions)]
        debug!("Generated config: {config}");

        let response = self.client.post(url).send_json(&json!({
            "codec_id": codec_name,
            "config": &config.trim()
        }))?;

        debug!("Response status: {}", response.status());

        let body = response.into_body().read_json::<RegisterResponse>()?;

        match body {
            RegisterResponse::Ok {
                success: true,
                message,
            } => {
                debug!("SCS codec registered. Server message: {message}");
                Ok(())
            }
            RegisterResponse::Ok {
                success: false,
                message,
            } => Err(Error::new(ErrorKind::Network, message)),
            RegisterResponse::Err(e) => Err(e.into()),
        }
    }

    pub fn calculate_syndrome(&self, codec_name: &str, codeword: &BitSlice) -> Result<BitVec> {
        let url = self.url(Self::CALCULATE_SYNDROME_URL);

        let codeword = codeword.iter().by_vals().map(u8::from).collect::<Vec<_>>();

        let payload = json!({
            "codec_id": codec_name,
            "codeword": codeword
        });

        let response = self.client.post(url).send_json(payload)?;

        let body = response
            .into_body()
            .read_json::<CalculateSyndromeResponse>()?;

        #[cfg(debug_assertions)]
        debug!("Syndrome response: {body:?}");

        match body {
            CalculateSyndromeResponse::Ok { syndrome } => {
                Ok(syndrome.into_iter().map(|bit| bit != 0).collect())
            }
            CalculateSyndromeResponse::Err(e) => Err(e.into()),
        }
    }

    pub fn decode(
        &self,
        codec_name: &str,
        codeword: &BitSlice,
        syndrome: &BitSlice,
    ) -> Result<BitVec> {
        /// Binary code so set to 2.
        const Q: usize = 2;

        const ALMOST_ZERO: f32 = 1e-10;

        let url = self.url(Self::CALCULATE_SYNDROME_URL);

        let codeword = codeword.iter().by_vals().map(u8::from).collect::<Vec<_>>();

        let syndrome = syndrome.iter().by_vals().map(u8::from).collect::<Vec<_>>();

        let payload = json!({
            "codec_id": codec_name,
            "noisy_codeword": codeword,
            "syndrome": syndrome,
            "q": Q,
            "almostzero": ALMOST_ZERO
        });

        let response = self.client.post(url).send_json(payload)?;

        let body = response.into_body().read_json::<DecodeResponse>()?;

        match body {
            DecodeResponse::Ok { corrected_syndrome } => {
                Ok(corrected_syndrome.into_iter().map(|bit| bit != 0).collect())
            }
            DecodeResponse::Err(e) => Err(e.into()),
        }
    }

    fn url(&self, additional_url: &str) -> String {
        format!("{}/{}", self.base_url, additional_url)
    }
}

#[derive(Deserialize, Debug)]
pub struct ErrorResponse {
    #[serde(rename = "detail")]
    message: String,
}

impl From<ErrorResponse> for Error {
    fn from(value: ErrorResponse) -> Self {
        Self::new(ErrorKind::Network, value.message)
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
pub enum RegisterResponse {
    Ok { success: bool, message: String },
    Err(ErrorResponse),
}

#[cfg_attr(debug_assertions, derive(Debug))]
#[derive(Deserialize)]
#[serde(untagged)]
pub enum CalculateSyndromeResponse {
    Ok { syndrome: Vec<u8> },
    Err(ErrorResponse),
}

#[cfg_attr(debug_assertions, derive(Debug))]
#[derive(Deserialize)]
#[serde(untagged)]
pub enum DecodeResponse {
    Ok { corrected_syndrome: Vec<u8> },
    Err(ErrorResponse),
}

/// Convert a given parity matrix to a codec config,
pub fn parity_matrix_to_codec(matrix: &ParityMatrix) -> Result<String> {
    // Get max dimension weights.

    let max_row_weight = matrix
        .iter_factors()
        .map(|(_, f)| f.len())
        .max()
        .ok_or_else(|| Error::new(ErrorKind::InconsistentData, "Max row weight not found."))?;
    let max_col_weight = matrix
        .iter_variables()
        .map(|(_, v)| v.len())
        .max()
        .ok_or_else(|| Error::new(ErrorKind::InconsistentData, "Max col weight not found."))?;

    // Get the respective indices in one-indexed format, padded with 0's if needed.

    let row_indices = matrix
        .iter_factors()
        .map(|(_, f)| f.iter().map(|i| i + 1))
        .map(|row| {
            let mut buffer = row.collect::<Vec<_>>();
            if buffer.len() < max_col_weight {
                for _ in 0..(max_col_weight - buffer.len()) {
                    buffer.push(0);
                }
            }
            buffer
        })
        .collect::<Vec<_>>();

    let col_indices = matrix
        .iter_variables()
        .map(|(_, v)| v.iter().map(|i| i + 1))
        .map(|col| {
            let mut buffer = col.collect::<Vec<_>>();
            // if buffer.len() < max_col_weight {
            //     for _ in 0..(max_col_weight - buffer.len()) {
            //         buffer.push(0);
            //     }
            // }
            buffer
        })
        .collect::<Vec<_>>();

    // Weight vectors

    let row_weights_vec = row_indices
        .iter()
        .map(|row| row.iter().filter(|i| **i != 0).count().to_string())
        .collect::<Vec<_>>();

    let col_weights_vec = col_indices
        .iter()
        .map(|col| col.iter().filter(|i| **i != 0).count().to_string())
        .collect::<Vec<_>>();

    let mut col_weights_str = String::new();
    for col in col_indices.iter() {
        let count = col.len();
        let col_iter = col.iter();
        let mut col_line = format!("{count}\n");
        for c in col_iter {
            col_line.push_str(format!("{c} ").as_str());
        }
        col_weights_str.push_str(format!("{}\n", col_line.trim_end()).as_str());
    }

    let mut codec_config = "# Codec\nldpc<gf2,double>\n".to_string();

    codec_config.push_str("# Version\n5\n");
    codec_config.push_str("# SPA type (trad|gdl)\ngdl\n");
    codec_config.push_str("# Number of iterations\n50\n");
    codec_config.push_str("# Clipping method\nzero\n");
    codec_config.push_str("# Value of almostzero\n1e-100\n");
    codec_config.push_str("# Reduce generator matrix to REF?\n1\n");

    codec_config.push_str(&format!("# Length (n)\n{}\n", col_indices.len()));
    codec_config.push_str(&format!("# Dimension (m)\n{}\n", row_indices.len()));
    codec_config.push_str(&format!("# Max column weight\n{max_col_weight}\n"));
    codec_config.push_str(&format!("# Max row weight\n{max_row_weight}\n"));

    codec_config.push_str("# Non-zero values (ones|random|provided)\nones\n");

    codec_config.push_str(&format!(
        "# Column weight vector\n{col_weight_vec_len}\n{col_weight_vec}\n",
        col_weight_vec_len = col_weights_vec.len(),
        col_weight_vec = col_weights_vec.join(" ")
    ));
    codec_config.push_str(&format!(
        "# Row weight vector\n{row_weight_vec_len}\n{row_weight_vec}\n",
        row_weight_vec_len = row_weights_vec.len(),
        row_weight_vec = row_weights_vec.join(" "),
    ));
    codec_config.push_str(&format!(
        "# Non zero positions per col\n{col_weights_str}\n",
    ));

    Ok(codec_config)
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use core::models::parity_matrix::ParityMatrix;

    /// Sample parity matrix of the dollowing shape:
    /// [1, 1, 0, 1, 0, 0]
    /// [0, 1, 1, 0, 1, 0]
    /// [0, 0, 0, 0, 1, 1]
    /// [0, 0, 1, 1, 0, 1]
    const H_ALIST: &str = "\
        6 4\n\
        2 3\n\
        1 2 2 2 2 2\n\
        3 3 2 3\n\
        1 0\n\
        1 2\n\
        2 4\n\
        1 4\n\
        2 3\n\
        3 4\n\
        1 2 4\n\
        2 3 5\n\
        5 6 0\n\
        3 4 6\n\
        ";

    #[test]
    fn build_codec_from_valid_parity_matrix() {
        let mut temp_file =
            tempfile::NamedTempFile::new().expect("Error creating a temporary file");
        write!(temp_file, "{}", H_ALIST).unwrap();

        let matrix = ParityMatrix::from_alist(temp_file.path()).unwrap();

        let config = super::parity_matrix_to_codec(&matrix).unwrap();

        println!("{config}");
    }
}
