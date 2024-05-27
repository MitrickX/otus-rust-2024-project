use crate::server::rate_limit::rate::Rate;
use crate::server::rate_limit::RateLimit;
use std::{collections::HashMap, hash::Hash, sync::Arc, time::SystemTime};
use tokio::sync::Mutex;

use super::config::Config;

pub struct Credentials {
    pub login: String,
    pub password: String,
    pub ip: String,
}

#[derive(Debug)]
pub struct Auth {
    rate_limit_login: Arc<Mutex<RateLimit<String>>>,
    rate_limit_password: Arc<Mutex<RateLimit<String>>>,
    rate_limit_ip: Arc<Mutex<RateLimit<String>>>,
}

impl Auth {
    pub fn new(config: Config) -> Self {
        let rate_limit_login = Arc::new(Mutex::new(RateLimit::new(Rate::PerMinute(
            config.limits.login,
        ))));
        let rate_limit_password = Arc::new(Mutex::new(RateLimit::new(Rate::PerMinute(
            config.limits.password,
        ))));
        let rate_limit_ip = Arc::new(Mutex::new(RateLimit::new(Rate::PerMinute(
            config.limits.ip,
        ))));
        Self {
            rate_limit_login,
            rate_limit_password,
            rate_limit_ip,
        }
    }

    pub async fn check(&self, credentials: Credentials) -> bool {
        self.is_login_conformed(credentials.login).await
            && self.is_password_conformed(credentials.password).await
            && self.is_ip_conformed(credentials.ip).await
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

    async fn is_ip_conformed(&self, ip: String) -> bool {
        Arc::clone(&self.rate_limit_ip)
            .lock()
            .await
            .is_conformed(ip)
    }
}
