use core::{error::Result, models::parity_matrix::ParityMatrix};
use std::{format, println};

use reqwest::blocking::{Client, ClientBuilder};
use serde_json::json;

pub struct SCSApi {
    base_url: String,
    client: Client,
}

impl SCSApi {
    pub const REGISTER_CODEC_URL: &str = "/register";
    pub const CALC_SYNDROME_URL: &str = "/calculate-syndrome";
    pub const DECODE_URL: &str = "/decode";

    pub fn new(base_url: &str) -> Result<Self> {
        let client = ClientBuilder::new().build()?;

        Ok(Self {
            base_url: base_url.to_string(),
            client,
        })
    }

    pub fn register(&self, matrix: &ParityMatrix) -> Result<()> {
        let url = self.url(Self::REGISTER_CODEC_URL);

        let id: &str = "aegle-codec";
        let config = parity_matrix_to_codec(matrix)?;

        let response = self
            .client
            .get(url)
            .json(&json!({
                "codec_id": id,
                "config": config
            }))
            .send()?;

        Ok(())
    }

    fn url(&self, additional_url: &str) -> String {
        format!("{}/{}", self.base_url, additional_url)
    }
}

/// Convert a given parity matrix to a codec config,
pub fn parity_matrix_to_codec(matrix: &ParityMatrix) -> Result<String> {
    // Get max dimension weights.

    let max_row_weight = matrix.iter_factors().map(|(_, f)| f.len()).max().unwrap();
    let max_col_weight = matrix.iter_variables().map(|(_, v)| v.len()).max().unwrap();

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
            if buffer.len() < max_col_weight {
                for _ in 0..(max_col_weight - buffer.len()) {
                    buffer.push(0);
                }
            }
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

    let codec_config = format!(
        r#"
        # Codec
        ldpc<gf2,double>
        # Version
        5
        # SPA type (trad|gdl)
        gdl
        # Number of iterations
        50
        # Clipping method
        zero
        # Value of almostzero
        1e-100
        # Reduce generator matrix to REF?
        1
        # Length (n)
        {length}
        # Dimension (m)
        {dimension},
        # Max column weight
        {max_col_weight}
        # Max row weight
        {max_row_weight}
        # Non-zero values (ones|random|provided)
        ones
        # Column weight vector
        {col_weight_vec_len}
        {col_weight_vec}
        # Row weight vector
        {row_weight_vec_len}
        {row_weight_vec}
        # Non zero positions per col
        {col_weights_str}
        "#,
        length = col_indices.len(),
        dimension = row_indices.len(),
        col_weight_vec_len = col_weights_vec.len(),
        col_weight_vec = col_weights_vec.join(" "),
        row_weight_vec_len = row_weights_vec.len(),
        row_weight_vec = row_weights_vec.join(" "),
        col_weights_str = col_weights_str
    );

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
