use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct SimCommSysConfig {
    pub base_url: String,
}
