use serde::{Deserialize, Serialize};
use serde_yml;
use std::{env, path::Path};

#[derive(Serialize, Deserialize, Debug)]
pub struct Limits {
    pub login: u64,
    pub password: u64,
    pub ip: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Timeouts {
    pub bucket_active_secs: u64,
    pub auth_token_expiration_secs: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub limits: Limits,
    pub timeouts: Timeouts,
}

impl Config {
    pub fn parse(file_path: &Path) -> Self {
        let content = std::fs::read_to_string(file_path).unwrap();
        serde_yml::from_str(&content).unwrap()
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DbConfig {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: String,
    pub name: String,
    pub connection_retries: u32,
    pub connection_timeout: u32,
}

impl DbConfig {
    pub fn from_env() -> Self {
        Self {
            host: env::var("DB_HOST").unwrap_or("127.0.0.1".to_owned()),
            port: env::var("DB_PORT")
                .unwrap_or("5432".to_owned())
                .parse()
                .unwrap(),
            user: env::var("DB_USER").unwrap_or("postgres".to_owned()),
            password: env::var("DB_PASSWORD").unwrap_or("postgres".to_owned()),
            name: env::var("DB_NAME").unwrap_or("postgres".to_owned()),
            connection_retries: env::var("DB_CONNECTION_RETRIES")
                .unwrap_or("0".to_owned())
                .parse()
                .unwrap(),
            connection_timeout: env::var("DB_CONNECTION_TIMEOUT")
                .unwrap_or("10".to_owned())
                .parse()
                .unwrap(),
        }
    }
}

pub fn get_tokens_signing_key() -> String {
    env::var("TOKENS_SIGNING_KEY").expect("TOKENS_SIGNING_KEY must be set")
}
