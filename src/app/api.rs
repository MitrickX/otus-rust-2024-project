use super::auth::token::TokenReleaser;
use super::auth::token::TokenReleaserError;
use super::ip_list::ip::ParseError;
use super::roles::permission::Permission;
use super::roles::role::Role;
use super::roles::storage::Storage;
use crate::app::config::Config;
use crate::app::{
    ip_list::{ip::Ip, list::List},
    rate_limit::{rate::Rate, RateLimit},
};
use log::info;
use prometheus_exporter::prometheus::{labels, opts, register_int_gauge};
use std::{str::FromStr, sync::Arc, time::Duration};
use tokio::sync::Mutex;

type Result<T> = std::result::Result<T, ApiError>;
type Client = Arc<tokio_postgres::Client>;
type RL<T> = Arc<Mutex<RateLimit<T>>>;

pub struct Credentials {
    pub login: String,
    pub password: String,
    pub ip: String,
}

#[derive(Debug)]
pub enum ApiError {
    IpParseError(ParseError),
    IpListError(Box<dyn std::error::Error>),
    AuthNotAllowed,
    Unauthorized,
    PermissionDenied,
    RolesStorageError(Box<dyn std::error::Error>),
    AuthTokenReleaseError(TokenReleaserError),
    AuthTokenVerifyError(TokenReleaserError),
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IpParseError(e) => write!(f, "ip parse error: {}", e),
            Self::IpListError(e) => write!(f, "ip list error: {}", e),
            Self::AuthNotAllowed => write!(f, "auth not allowed"),
            Self::Unauthorized => write!(f, "unauthorized"),
            Self::PermissionDenied => write!(f, "permission denied"),
            Self::RolesStorageError(e) => write!(f, "roles storage error: {}", e),
            Self::AuthTokenReleaseError(e) => write!(f, "auth token release error: {}", e),
            Self::AuthTokenVerifyError(e) => write!(f, "auth token verify error: {}", e),
        }
    }
}

impl std::error::Error for ApiError {}

pub struct Api {
    rate_limit_login: RL<String>,
    rate_limit_password: RL<String>,
    rate_limit_ip: RL<String>,
    black_ip_list: List,
    white_ip_list: List,
    roles_storage: Storage,
    token_releaser: TokenReleaser,
    access_token_expiration_time: Duration,
    refresh_token_expiration_time: Duration,
}

impl Api {
    /// Create new `Api` instance
    ///
    /// # Arguments
    ///
    /// * `config` - `Config` instance
    /// * `client` - `Client` instance
    /// * `tokens_signing_key` - signing key for tokens
    /// * `need_expose_metrics` - whether to expose metrics or not
    ///
    /// # Returns
    ///
    /// * `Api` instance
    pub fn new(
        config: &Config,
        client: Client,
        tokens_signing_key: String,
        need_expose_metrics: bool,
    ) -> Self {
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

        clear_inactive_worker(
            Arc::clone(&rate_limit_login),
            Arc::clone(&rate_limit_password),
            Arc::clone(&rate_limit_ip),
            Duration::from_secs(config.timeouts.bucket_active_secs),
            need_expose_metrics,
        );

        let black_ip_list = List::new(Arc::clone(&client), "black");
        let white_ip_list = List::new(Arc::clone(&client), "white");
        let roles_storage = Storage::new(Arc::clone(&client));
        let token_releaser = TokenReleaser::new(tokens_signing_key).unwrap();

        Self {
            rate_limit_login,
            rate_limit_password,
            rate_limit_ip,
            black_ip_list,
            white_ip_list,
            roles_storage,
            token_releaser,
            access_token_expiration_time: Duration::from_secs(
                config.timeouts.access_token_expiration_secs,
            ),
            refresh_token_expiration_time: Duration::from_secs(
                config.timeouts.refresh_token_expiration_secs,
            ),
        }
    }

    /// Adds a role to the storage.
    ///
    /// # Arguments
    ///
    /// * `role` - A reference to the `Role` object to be added.
    ///
    /// # Returns
    ///
    /// * `Result<()>` - Returns `Ok(())` if the role is successfully added,
    ///   otherwise returns an `ApiError::RolesStorageError` if an error occurs
    ///   during the storage operation.
    pub async fn add_role_to_storage(&self, role: &Role) -> Result<()> {
        self.roles_storage
            .add(role)
            .await
            .map_err(ApiError::RolesStorageError)?;

        Ok(())
    }

    /// Checks if the provided credentials are allowed to authenticate in light of antibruteforce rules
    ///
    /// This function verifies that the IP address, password, and login associated
    /// with the credentials conform to predefined antibruteforce rules. It returns `true` if all
    /// checks pass, indicating that the credentials are valid for authentication right now.
    ///
    /// # Arguments
    ///
    /// * `credentials` - A `Credentials` instance containing the IP, login, and password
    ///   to be checked.
    ///
    /// # Returns
    ///
    /// * `Result<bool>` - Returns `Ok(true)` if the IP, password, and login conform
    ///   to the rules, otherwise returns `Ok(false)`. In case of an error during
    ///   the verification process, an appropriate `ApiError` is returned.
    pub async fn check_can_auth(&self, credentials: Credentials) -> Result<bool> {
        let is_ip_conformed = self.is_ip_conformed(credentials.ip).await?;

        Ok(is_ip_conformed
            && self.is_password_conformed(credentials.password).await
            && self.is_login_conformed(credentials.login).await)
    }

    /// Resets the antibruteforce rate limiter for the given IP address.
    ///
    /// This function is used to reset the rate limiter for the given IP address.
    ///
    /// # Arguments
    ///
    /// * `ip` - The IP address for which the rate limiter should be reset.
    ///
    /// # Returns
    ///
    /// * `()`
    pub async fn reset_ip_rate_limiter(&self, ip: String) {
        Arc::clone(&self.rate_limit_ip).lock().await.reset(ip);
    }

    /// Checks if login is conformed the antibruteforce rule
    ///
    /// # Arguments
    ///
    /// * `login` - login to check
    ///
    /// # Returns
    ///
    /// * `bool` - true if login is conformed, false otherwise
    async fn is_login_conformed(&self, login: String) -> bool {
        Arc::clone(&self.rate_limit_login)
            .lock()
            .await
            .is_conformed(login)
    }

    /// Checks if password is conformed the antibruteforce rule
    ///
    /// # Arguments
    ///
    /// * `password` - password to check
    ///
    /// # Returns
    ///
    /// * `bool` - true if password is conformed, false otherwise
    async fn is_password_conformed(&self, password: String) -> bool {
        Arc::clone(&self.rate_limit_password)
            .lock()
            .await
            .is_conformed(password)
    }

    /// Checks if IP address is conformed to the antibruteforce rules.
    ///
    /// First, it checks if the IP is in the black list. If it is, no auth is allowed.
    /// Then, it checks if the IP is in the white list. If it is, auth is allowed.
    /// Finally, if the IP is not in the black nor white list, it checks if the IP
    /// conforms the antibruteforce rules using the rate limiter.
    ///
    /// # Arguments
    ///
    /// * `ip` - The IP address to be checked.
    ///
    /// # Returns
    ///
    /// * `Result<bool>` - Returns `Ok(true)` if the IP is conformed, otherwise returns
    ///   `Ok(false)`. In case of an error during the verification process, an
    ///   appropriate `ApiError` is returned.
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

    /// Adds the given IP address to the white list.
    ///
    /// # Arguments
    ///
    /// * `ip` - The IP address to be added to the white list.
    ///
    /// # Returns
    ///
    /// * `Result<()>` - Returns `Ok(())` if the IP address is successfully added
    ///   to the white list. In case of an error during the addition process,
    ///   an appropriate `ApiError` is returned.
    pub async fn add_ip_in_white_list(&self, ip: String) -> Result<()> {
        let ip_addr = Ip::from_str(&ip).map_err(ApiError::IpParseError)?;
        self.white_ip_list
            .add(&ip_addr)
            .await
            .map_err(ApiError::IpListError)
    }

    /// Adds the given IP address to the black list.
    ///
    /// # Arguments
    ///
    /// * `ip` - The IP address to be added to the black list.
    ///
    /// # Returns
    ///
    /// * `Result<()>` - Returns `Ok(())` if the IP address is successfully added
    ///   to the black list. In case of an error during the addition process,
    ///   an appropriate `ApiError` is returned.
    pub async fn add_ip_in_black_list(&self, ip: String) -> Result<()> {
        let ip_addr = Ip::from_str(&ip).map_err(ApiError::IpParseError)?;
        self.black_ip_list
            .add(&ip_addr)
            .await
            .map_err(ApiError::IpListError)
    }

    /// Removes the given IP address from the white list.
    ///
    /// # Arguments
    ///
    /// * `ip` - The IP address to be removed from the white list.
    ///
    /// # Returns
    ///
    /// * `Result<()>` - Returns `Ok(())` if the IP address is successfully removed
    ///   from the white list. In case of an error during the removal process,
    ///   an appropriate `ApiError` is returned.
    pub async fn delete_ip_from_white_list(&self, ip: String) -> Result<()> {
        let ip_addr = Ip::from_str(&ip).map_err(ApiError::IpParseError)?;
        self.white_ip_list
            .delete(&ip_addr)
            .await
            .map_err(ApiError::IpListError)
    }

    /// Removes the given IP address from the black list.
    ///
    /// # Arguments
    ///
    /// * `ip` - The IP address to be removed from the black list.
    ///
    /// # Returns
    ///
    /// * `Result<()>` - Returns `Ok(())` if the IP address is successfully removed
    ///   from the black list. In case of an error during the removal process,
    ///   an appropriate `ApiError` is returned.
    pub async fn delete_ip_from_black_list(&self, ip: String) -> Result<()> {
        let ip_addr = Ip::from_str(&ip).map_err(ApiError::IpParseError)?;
        self.black_ip_list
            .delete(&ip_addr)
            .await
            .map_err(ApiError::IpListError)
    }

    /// Checks whether the given IP address is in the white list or not.
    ///
    /// # Arguments
    ///
    /// * `ip` - The IP address to be checked.
    ///
    /// # Returns
    ///
    /// * `Result<bool>` - Returns `Ok(true)` if the IP address is in the white list,
    ///   `Ok(false)` otherwise. In case of an error during the check process,
    ///   an appropriate `ApiError` is returned.
    pub async fn is_ip_in_white_list(&self, ip: String) -> Result<bool> {
        let ip_addr = Ip::from_str(&ip).map_err(ApiError::IpParseError)?;
        self.white_ip_list
            .has(&ip_addr)
            .await
            .map_err(ApiError::IpListError)
    }

    /// Checks whether the given IP address is in the black list or not.
    ///
    /// # Arguments
    ///
    /// * `ip` - The IP address to be checked.
    ///
    /// # Returns
    ///
    /// * `Result<bool>` - Returns `Ok(true)` if the IP address is in the black list,
    ///   `Ok(false)` otherwise. In case of an error during the check process,
    ///   an appropriate `ApiError` is returned.
    pub async fn is_ip_in_black_list(&self, ip: String) -> Result<bool> {
        let ip_addr = Ip::from_str(&ip).map_err(ApiError::IpParseError)?;
        self.black_ip_list
            .has(&ip_addr)
            .await
            .map_err(ApiError::IpListError)
    }

    /// Clears the black list of all IP addresses.
    ///
    /// # Returns
    ///
    /// * `Result<()>` - Returns `Ok(())` if the black list is successfully cleared.
    ///   In case of an error during the clearing process, an appropriate `ApiError` is returned.
    pub async fn clear_black_list(&self) -> Result<()> {
        self.black_ip_list
            .clear()
            .await
            .map_err(ApiError::IpListError)
    }

    /// Clears the white list of all IP addresses.
    ///
    /// # Returns
    ///
    /// * `Result<()>` - Returns `Ok(())` if the white list is successfully cleared.
    ///   In case of an error during the clearing process, an appropriate `ApiError` is returned.
    pub async fn clear_white_list(&self) -> Result<()> {
        self.white_ip_list
            .clear()
            .await
            .map_err(ApiError::IpListError)
    }

    /// Checks whether the given access token has the given permission.
    ///
    /// # Arguments
    ///
    /// * `token` - The access token to be checked.
    /// * `permission` - The permission to be checked.
    ///
    /// # Returns
    ///
    /// * `Result<()>` - Returns `Ok(())` if the token has the given permission,
    ///   `Err(ApiError::PermissionDenied)` otherwise. In case of an error during the verification process,
    ///   an appropriate `ApiError` is returned.
    pub async fn check_permission(&self, token: &str, permission: Permission) -> Result<()> {
        let token_permissions = self
            .token_releaser
            .verify_access_token(token)
            .map_err(ApiError::AuthTokenVerifyError)?;

        if !token_permissions.contains(&permission) {
            return Err(ApiError::PermissionDenied);
        }

        Ok(())
    }

    /// Authenticates the user with the given credentials and returns a pair of access and refresh tokens.
    ///
    /// The access token is a JWT that contains the user's login and permissions. It is valid for the duration of
    /// `access_token_expiration_time` and can be used to access protected endpoints.
    ///
    /// The refresh token is a JWT that contains the user's login and is valid for the duration of
    /// `refresh_token_expiration_time`. It can be used to obtain a new pair of access and refresh tokens using the
    /// `refresh_tokens` endpoint.
    ///
    /// If the credentials are invalid or the user does not exist, an `ApiError::Unauthorized` error is returned.
    ///
    /// If the user is not allowed to authenticate (e.g. due to an IP ban), an `ApiError::AuthNotAllowed` error is
    /// returned.
    ///
    /// If an error occurs while retrieving the user's role from the storage, an `ApiError::RolesStorageError` error is
    /// returned.
    ///
    /// If an error occurs while releasing the access token, an `ApiError::AuthTokenReleaseError` error is returned.
    pub async fn auth(&self, credentials: Credentials) -> Result<(String, String)> {
        let login = credentials.login.clone();
        let password = credentials.password.clone();

        let can_auth = self.check_can_auth(credentials).await?;
        if !can_auth {
            return Err(ApiError::AuthNotAllowed);
        }

        let role = self
            .roles_storage
            .get(&login, &password)
            .await
            .map_err(ApiError::RolesStorageError)?
            .ok_or(ApiError::Unauthorized)?;

        let access_token = self
            .token_releaser
            .release_access_token(&role, self.access_token_expiration_time)
            .map_err(ApiError::AuthTokenReleaseError)?;

        let refresh_token = self
            .token_releaser
            .release_refresh_token(&access_token, self.refresh_token_expiration_time)
            .map_err(ApiError::AuthTokenReleaseError)?;

        Ok((access_token, refresh_token))
    }

    /// Refreshes the access token using the provided refresh token.
    ///
    /// This function takes an existing access token and a refresh token to generate a new pair of access
    /// and refresh tokens. The new access token is valid for the duration defined by
    /// `access_token_expiration_time`.
    ///
    /// If the refresh operation fails, an `ApiError::AuthTokenReleaseError` is returned.
    ///
    /// # Arguments
    ///
    /// * `access_token` - The current access token to be refreshed.
    /// * `refresh_token` - The refresh token used to obtain a new access token.
    ///
    /// # Returns
    ///
    /// A tuple containing the new access token and refresh token.
    pub async fn refresh_access_token(
        &self,
        access_token: &str,
        refresh_token: &str,
    ) -> Result<(String, String)> {
        let (access_token, refresh_token) = self
            .token_releaser
            .refresh_access_token(
                access_token,
                refresh_token,
                self.access_token_expiration_time,
            )
            .map_err(ApiError::AuthTokenReleaseError)?;

        Ok((access_token, refresh_token))
    }
}

fn clear_inactive_worker(
    rate_limit_login: RL<String>,
    rate_limit_password: RL<String>,
    rate_limit_ip: RL<String>,
    active_duration: Duration,
    need_expose_metrics: bool,
) {
    let login_rate_limit_buckets_clean_count = if need_expose_metrics {
        Some(
            register_int_gauge!(opts!(
                "buckets_clean_count",
                "How many inactive buckets were cleaned",
                labels! {
                    "credentials_type" => "login",
                }
            ))
            .unwrap(),
        )
    } else {
        None
    };

    let password_rate_limit_buckets_clean_count = if need_expose_metrics {
        Some(
            register_int_gauge!(opts!(
                "buckets_clean_count",
                "How many inactive buckets were cleaned",
                labels! {
                    "credentials_type" => "password",
                }
            ))
            .unwrap(),
        )
    } else {
        None
    };

    let ip_rate_limit_buckets_clean_count = if need_expose_metrics {
        Some(
            register_int_gauge!(opts!(
                "buckets_clean_count",
                "How many inactive buckets were cleaned",
                labels! {
                    "credentials_type" => "ip",
                }
            ))
            .unwrap(),
        )
    } else {
        None
    };

    info!("start clear inactive buckets worker");

    tokio::spawn(async move {
        let sleep = tokio::time::sleep(active_duration);
        tokio::pin!(sleep);

        loop {
            tokio::select! {
                () = &mut sleep => {
                    let login_buckets = Arc::clone(&rate_limit_login).lock().await.clear_inactive();
                    let password_buckets = Arc::clone(&rate_limit_password)
                        .lock()
                        .await
                        .clear_inactive();
                    let ip_buckets = Arc::clone(&rate_limit_ip).lock().await.clear_inactive();

                    info!(
                        "clear inactive buckets: login={}, password={}, ip={}",
                        login_buckets, password_buckets, ip_buckets
                    );

                    if let Some(gauge) = &login_rate_limit_buckets_clean_count {
                        gauge.set(login_buckets as i64);
                    }

                    if let Some(gauge) = &password_rate_limit_buckets_clean_count {
                        gauge.set(password_buckets as i64);
                    }

                    if let Some(gauge) = &ip_rate_limit_buckets_clean_count {
                        gauge.set(ip_buckets as i64);
                    }

                    sleep.as_mut().reset(tokio::time::Instant::now() + active_duration);
                },
            }
        }
    });
}
