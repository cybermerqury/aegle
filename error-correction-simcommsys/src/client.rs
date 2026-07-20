use core::error::Result;

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

    pub fn register(&self) -> Result<()> {
        let url = self.url(Self::REGISTER_CODEC_URL);

        let id: &str = "aegle-codec";

        let response = self
            .client
            .get(url)
            .json(&json!({
                "codec_id": id
            }))
            .send()?;

        Ok(())
    }

    fn url(&self, additional_url: &str) -> String {
        format!("{}/{}", self.base_url, additional_url)
    }
}
