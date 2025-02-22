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
    pub access_token_expiration_secs: u64,
    pub refresh_token_expiration_secs: u64,
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
    /// Create a new `DbConfig` from environment variables.
    ///
    /// The variables are:
    ///
    /// - `DB_HOST`: the database host, defaults to `"127.0.0.1"`
    /// - `DB_PORT`: the database port, defaults to `"5432"`
    /// - `DB_USER`: the database username, defaults to `"postgres"`
    /// - `DB_PASSWORD`: the database password, defaults to `"postgres"`
    /// - `DB_NAME`: the database name, defaults to `"postgres"`
    /// - `DB_CONNECTION_RETRIES`: number of times to retry connecting to
    ///   the database if it fails, defaults to `"0"`
    /// - `DB_CONNECTION_TIMEOUT`: time in seconds to wait between retries,
    ///   defaults to `"10"`
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

/// Returns the key used to sign tokens.
///
/// This key is expected to be set as an environment variable
/// named `TOKENS_SIGNING_KEY`. If the variable is not set,
/// this function will panic.
pub fn get_tokens_signing_key() -> String {
    env::var("TOKENS_SIGNING_KEY").expect("TOKENS_SIGNING_KEY must be set")
}
