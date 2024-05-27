use serde::{Deserialize, Serialize};
use serde_yml;

#[derive(Serialize, Deserialize, Debug)]
pub struct Limits {
    pub login: u64,
    pub password: u64,
    pub ip: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Timeouts {
    bucket_active_secs: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub limits: Limits,
    timeouts: Timeouts,
}

impl Config {
    pub fn parse(file_path: &str) -> Result<Self, Box<serde_yml::Error>> {
        let content = std::fs::read_to_string(file_path).unwrap();
        let config: Config = serde_yml::from_str(&content)?;
        Ok(config)
    }
}
