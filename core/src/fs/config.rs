// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// SPDX-FileCopyrightText:  © 2024 - 2026 Merqury Cybersecurity Ltd <info@merqury.eu>

use std::path::Path;

use crate::error::{Error, ErrorKind, Result};

pub fn load_toml_config<T, P>(filename: P) -> Result<T>
where
    T: serde::de::DeserializeOwned,
    P: AsRef<Path>,
{
    let contents = std::fs::read_to_string(filename)?;
    match toml::from_str::<T>(&contents) {
        Ok(config) => Ok(config),
        Err(e) => {
            let mut msg = format!("Error while parsing config. {}", e.message());
            if let Some(span) = e.span() {
                let line_positions: Vec<usize> = contents[..span.start]
                    .match_indices('\n')
                    .map(|x| x.0)
                    .collect();
                let line_no = line_positions.len();
                let line_start = *line_positions.last().unwrap_or(&0);
                msg.push('\n');
                msg.push_str(
                    format!(
                        "On line {}, column {}: {}",
                        line_no,
                        span.start - line_start,
                        &contents[line_start..span.end]
                    )
                    .as_str(),
                );
            }
            Err(Error::new(ErrorKind::ConfigParse, msg))
        }
    }
}
