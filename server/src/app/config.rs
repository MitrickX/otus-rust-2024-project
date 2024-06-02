use serde::{Deserialize, Serialize};
use serde_yml;
use std::path::Path;

#[derive(Serialize, Deserialize, Debug)]
pub struct Limits {
    pub login: u64,
    pub password: u64,
    pub ip: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Timeouts {
    pub bucket_active_secs: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DB {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: String,
    pub name: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub limits: Limits,
    pub timeouts: Timeouts,
    pub db: DB,
}

impl Config {
    pub fn parse(file_path: &Path) -> Result<Self, Box<serde_yml::Error>> {
        let content = std::fs::read_to_string(file_path).unwrap();
        let config: Config = serde_yml::from_str(&content)?;
        Ok(config)
    }
}
