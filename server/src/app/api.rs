use crate::app::{
    ip_list::{ip::Ip, list::List},
    rate_limit::{rate::Rate, RateLimit},
};
use std::{str::FromStr, sync::Arc, time::Duration};
use tokio::sync::Mutex;

use crate::app::config::Config;

use super::ip_list::ip::ParseError;

type Result<T> = std::result::Result<T, ApiError>;
type Client = Arc<Mutex<tokio_postgres::Client>>;

pub struct Credentials {
    pub login: String,
    pub password: String,
    pub ip: String,
}

#[derive(Debug)]
pub enum ApiError {
    IpParseError(ParseError),
    IpListError(Box<dyn std::error::Error>),
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for ApiError {}

#[derive(Debug)]
pub struct Api {
    rate_limit_login: Arc<Mutex<RateLimit<String>>>,
    rate_limit_password: Arc<Mutex<RateLimit<String>>>,
    rate_limit_ip: Arc<Mutex<RateLimit<String>>>,
    black_ip_list: List,
    white_ip_list: List,
}

impl Api {
    pub fn new(config: &Config, client: Client) -> Self {
        let bucket_active_secs = Duration::from_secs(config.timeouts.bucket_active_secs);
        let rate_limit_login = Arc::new(Mutex::new(RateLimit::new(
            Rate::PerMinute(config.limits.login),
            bucket_active_secs,
        )));
        let rate_limit_password = Arc::new(Mutex::new(RateLimit::new(
            Rate::PerMinute(config.limits.password),
            bucket_active_secs,
        )));
        let rate_limit_ip = Arc::new(Mutex::new(RateLimit::new(
            Rate::PerMinute(config.limits.ip),
            bucket_active_secs,
        )));

        let black_list_ip_list = List::new(Arc::clone(&client), "black");
        let white_list_ip_list = List::new(Arc::clone(&client), "white");

        Self {
            rate_limit_login,
            rate_limit_password,
            rate_limit_ip,
            black_ip_list: black_list_ip_list,
            white_ip_list: white_list_ip_list,
        }
    }

    pub async fn check_can_auth(&self, credentials: Credentials) -> Result<bool> {
        let is_ip_conformed = self.is_ip_conformed(credentials.ip).await?;

        Ok(is_ip_conformed
            && self.is_password_conformed(credentials.password).await
            && self.is_login_conformed(credentials.login).await)
    }

    async fn is_login_conformed(&self, login: String) -> bool {
        Arc::clone(&self.rate_limit_login)
            .lock()
            .await
            .is_conformed(login)
    }

    async fn is_password_conformed(&self, password: String) -> bool {
        Arc::clone(&self.rate_limit_password)
            .lock()
            .await
            .is_conformed(password)
    }

    async fn is_ip_conformed(&self, ip: String) -> Result<bool> {
        let ip_addr = Ip::from_str(&ip).map_err(ApiError::IpParseError)?;

        // if ip conform black list - no auth (even if ip conform white list)
        let is_conform_black_list = self
            .black_ip_list
            .is_conform(&ip_addr)
            .await
            .map_err(ApiError::IpListError)?;

        if is_conform_black_list {
            return Ok(false);
        }

        // if ip conform white list - auth is ok
        let is_conform_white_list = self
            .white_ip_list
            .is_conform(&ip_addr)
            .await
            .map_err(ApiError::IpListError)?;

        if is_conform_white_list {
            return Ok(true);
        }

        Ok(Arc::clone(&self.rate_limit_ip)
            .lock()
            .await
            .is_conformed(ip))
    }

    pub async fn add_ip_in_white_list(&self, ip: String) -> Result<()> {
        let ip_addr = Ip::from_str(&ip).map_err(ApiError::IpParseError)?;
        self.white_ip_list
            .add(&ip_addr)
            .await
            .map_err(ApiError::IpListError)
    }

    pub async fn add_ip_in_black_list(&self, ip: String) -> Result<()> {
        let ip_addr = Ip::from_str(&ip).map_err(ApiError::IpParseError)?;
        self.black_ip_list
            .add(&ip_addr)
            .await
            .map_err(ApiError::IpListError)
    }

    pub async fn delete_ip_from_white_list(&self, ip: String) -> Result<()> {
        let ip_addr = Ip::from_str(&ip).map_err(ApiError::IpParseError)?;
        self.white_ip_list
            .delete(&ip_addr)
            .await
            .map_err(ApiError::IpListError)
    }

    pub async fn delete_ip_from_black_list(&self, ip: String) -> Result<()> {
        let ip_addr = Ip::from_str(&ip).map_err(ApiError::IpParseError)?;
        self.black_ip_list
            .delete(&ip_addr)
            .await
            .map_err(ApiError::IpListError)
    }

    pub async fn is_ip_in_white_list(&self, ip: String) -> Result<bool> {
        let ip_addr = Ip::from_str(&ip).map_err(ApiError::IpParseError)?;
        self.white_ip_list
            .has(&ip_addr)
            .await
            .map_err(ApiError::IpListError)
    }

    pub async fn is_ip_in_black_list(&self, ip: String) -> Result<bool> {
        let ip_addr = Ip::from_str(&ip).map_err(ApiError::IpParseError)?;
        self.black_ip_list
            .has(&ip_addr)
            .await
            .map_err(ApiError::IpListError)
    }
}
