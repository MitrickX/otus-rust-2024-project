use crate::app::roles::{permission::Permission, role::Role};
use hmac::{Hmac, Mac};
use jwt::{AlgorithmType, Error, Header, SignWithKey, Token, VerifyWithKey};
use sha2::Sha384;
use std::{
    collections::BTreeMap,
    str::FromStr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(Debug)]
pub enum TokenReleaserError {
    InvalidSignature(hmac::digest::InvalidLength),
    ReleaseFailed(Error),
    TokenExpired,
    InvalidExpirationTime,
    VerifyFailed(Error),
    InvalidRefreshToken,
}

impl std::fmt::Display for TokenReleaserError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSignature(e) => write!(f, "invalid signature: {}", e),
            Self::ReleaseFailed(e) => write!(f, "release failed: {}", e),
            Self::TokenExpired => write!(f, "token expired"),
            Self::InvalidExpirationTime => write!(f, "invalid expiration time"),
            Self::VerifyFailed(e) => write!(f, "verify failed: {}", e),
            Self::InvalidRefreshToken => write!(f, "invalid refresh token"),
        }
    }
}

impl std::error::Error for TokenReleaserError {}

const PAYLOAD_EXPIRED_AT: &str = "expired_at";
const PAYLOAD_LOGIN: &str = "login";
const PAYLOAD_PERMISSIONS: &str = "permissions";
const PAYLOAD_TOKEN: &str = "token";

pub struct TokenReleaser {
    signing_key: Hmac<Sha384>,
}

type Result<T> = std::result::Result<T, TokenReleaserError>;

impl TokenReleaser {
    /// Creates a new `TokenReleaser` from a secret key.
    ///
    /// `signing_key` must be a secret key that is at least 32 bytes long.
    ///
    /// # Errors
    ///
    /// Returns an error if the key is too short.
    pub fn new(signing_key: String) -> Result<Self> {
        Ok(Self {
            signing_key: Hmac::new_from_slice(signing_key.as_bytes())
                .map_err(TokenReleaserError::InvalidSignature)?,
        })
    }

    /// Releases a new access token for the given `role` that is valid for the given `expiration_time`.
    ///
    /// The `expiration_time` is a duration since the current moment, and the returned token will be valid until the
    /// current moment plus the given duration.
    ///
    /// # Errors
    ///
    /// Returns an error if the token could not be released.
    pub fn release_access_token(&self, role: &Role, expiration_time: Duration) -> Result<String> {
        self.release_access_token_expired_at(role, SystemTime::now() + expiration_time)
    }

    fn release_access_token_expired_at(
        &self,
        role: &Role,
        expired_at: SystemTime,
    ) -> Result<String> {
        let permissions: Vec<String> = role.permissions.iter().map(|p| p.to_string()).collect();

        self.release_token(
            BTreeMap::from([
                (PAYLOAD_LOGIN.to_owned(), role.login.clone()),
                (PAYLOAD_PERMISSIONS.to_owned(), permissions.join(",")),
            ]),
            expired_at,
        )
    }

    /// Verifies the given access token and returns the permissions it contains.
    ///
    /// # Arguments
    ///
    /// * `token` - The access token to be verified.
    ///
    /// # Returns
    ///
    /// A `Result<Vec<Permission>>` containing the set of permissions associated with the token.
    /// If the token is invalid or cannot be verified, a `TokenReleaserError` is returned.
    pub fn verify_access_token(&self, token: &str) -> Result<Vec<Permission>> {
        let payload = self.verify_token(token)?;

        self.get_permissions(&payload)
    }

    pub fn release_refresh_token(
        &self,
        access_token: &str,
        expiration_time: Duration,
    ) -> Result<String> {
        self.release_refresh_token_expired_at(access_token, SystemTime::now() + expiration_time)
    }

    /// Releases a new refresh token for the given `access_token` that is valid until the given `expired_at` time.
    ///
    /// # Errors
    ///
    /// Returns an error if the token could not be released.
    fn release_refresh_token_expired_at(
        &self,
        access_token: &str,
        expired_at: SystemTime,
    ) -> Result<String> {
        self.release_token(
            BTreeMap::from([(PAYLOAD_TOKEN.to_owned(), access_token.to_owned())]),
            expired_at,
        )
    }

    /// Verifies the given refresh token and returns the access token associated with it.
    ///
    /// # Arguments
    ///
    /// * `token` - The refresh token to be verified.
    ///
    /// # Returns
    ///
    /// A `Result<String>` containing the access token associated with the refresh token.
    /// If the token is invalid or cannot be verified, a `TokenReleaserError` is returned.
    pub fn verify_refresh_token(&self, token: &str) -> Result<String> {
        let payload = self.verify_token(token)?;

        self.get_payload_item(&payload, PAYLOAD_TOKEN)
    }

    fn verify_token(&self, token: &str) -> Result<BTreeMap<String, String>> {
        let payload = self.verify_token_without_expiration(token)?;
        self.check_expiration(&payload)?;
        Ok(payload)
    }

    fn verify_token_without_expiration(&self, token: &str) -> Result<BTreeMap<String, String>> {
        let token: Token<Header, BTreeMap<String, String>, _> = token
            .verify_with_key(&self.signing_key)
            .map_err(TokenReleaserError::VerifyFailed)?;

        let header = token.header();
        self.check_header_algo(header)?;

        let payload = token.claims();
        Ok(payload.clone())
    }

    /// Refreshes an access token using the given refresh token and expiration time for new access token.
    ///
    /// If the refresh token is invalid or the user is not allowed to refresh the token, an error is returned.
    ///
    /// The returned tuple contains the new access and refresh tokens.
    pub fn refresh_access_token(
        &self,
        access_token: &str,
        refresh_token: &str,
        expiration_time: Duration,
    ) -> Result<(String, String)> {
        self.refresh_access_token_expired_at(
            access_token,
            refresh_token,
            SystemTime::now() + expiration_time,
        )
    }

    fn refresh_access_token_expired_at(
        &self,
        access_token: &str,
        refresh_token: &str,
        access_token_expired_at: SystemTime,
    ) -> Result<(String, String)> {
        let payload = self.verify_token(refresh_token)?;
        let token = self.get_payload_item(&payload, PAYLOAD_TOKEN)?;
        if token != access_token {
            return Err(TokenReleaserError::InvalidRefreshToken);
        }

        let expired_at_ts = self
            .get_payload_item(&payload, PAYLOAD_EXPIRED_AT)?
            .parse::<u64>()
            .map_err(|_| TokenReleaserError::InvalidExpirationTime)?;

        let refresh_token_expired_at = UNIX_EPOCH
            .checked_add(Duration::from_secs(expired_at_ts))
            .ok_or(TokenReleaserError::TokenExpired)?;

        let payload = self.verify_token_without_expiration(access_token)?;

        let permissions = self
            .get_permissions(&payload)?
            .into_iter()
            .map(|p| p.to_string())
            .collect::<Vec<String>>();
        let login = self.get_payload_item(&payload, PAYLOAD_LOGIN)?;

        let new_access_token = self.release_token(
            BTreeMap::from([
                (PAYLOAD_LOGIN.to_owned(), login),
                (PAYLOAD_PERMISSIONS.to_owned(), permissions.join(",")),
            ]),
            access_token_expired_at,
        )?;

        let new_refresh_token =
            self.release_refresh_token_expired_at(&new_access_token, refresh_token_expired_at)?;

        Ok((new_access_token, new_refresh_token))
    }

    fn get_payload_item(&self, payload: &BTreeMap<String, String>, key: &str) -> Result<String> {
        Ok(payload
            .get(key)
            .ok_or_else(|| TokenReleaserError::VerifyFailed(Error::NoKeyWithKeyId(key.to_owned())))?
            .to_owned())
    }

    fn check_header_algo(&self, header: &Header) -> Result<()> {
        if header.algorithm != AlgorithmType::Hs384 {
            return Err(TokenReleaserError::VerifyFailed(Error::AlgorithmMismatch(
                AlgorithmType::Hs384,
                AlgorithmType::None,
            )));
        }

        Ok(())
    }

    fn check_expiration(&self, payload: &BTreeMap<String, String>) -> Result<()> {
        let expired_at = self.get_payload_item(payload, PAYLOAD_EXPIRED_AT)?;
        let expired_at = expired_at
            .parse::<u64>()
            .map_err(|_| TokenReleaserError::InvalidExpirationTime)?;

        if expired_at
            < SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
        {
            return Err(TokenReleaserError::TokenExpired);
        }

        Ok(())
    }

    fn get_permissions(&self, payload: &BTreeMap<String, String>) -> Result<Vec<Permission>> {
        let permissions = self.get_payload_item(payload, PAYLOAD_PERMISSIONS)?;

        Ok(permissions
            .split(',')
            .flat_map(Permission::from_str)
            .collect())
    }

    fn release_token(
        &self,
        payload: BTreeMap<String, String>,
        expired_at: SystemTime,
    ) -> Result<String> {
        let header = Header {
            algorithm: AlgorithmType::Hs384,
            ..Default::default()
        };

        let mut payload = payload;
        payload.insert(
            PAYLOAD_EXPIRED_AT.to_owned(),
            expired_at
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                .to_string(),
        );

        let token = Token::new(header, payload)
            .sign_with_key(&self.signing_key)
            .map_err(TokenReleaserError::ReleaseFailed)?;

        Ok(token.as_str().to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_release_access_token() {
        let signing_key = "secret".to_owned();
        let releaser = TokenReleaser::new(signing_key).unwrap();
        let role = Role::new(
            "test_login".to_owned(),
            "test_password".to_owned(),
            "test_description".to_owned(),
            vec![Permission::ManageRole, Permission::ManageIpList],
        );
        let result = releaser.release_access_token(&role, Duration::from_secs(60));
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_access_token() {
        let signing_key = "secret".to_owned();
        let releaser = TokenReleaser::new(signing_key).unwrap();
        let role = Role::new(
            "test_login".to_owned(),
            "test_password".to_owned(),
            "test_description".to_owned(),
            vec![Permission::ManageRole, Permission::ManageIpList],
        );
        let token = releaser
            .release_access_token(&role, Duration::from_secs(60))
            .unwrap();
        let result = releaser.verify_access_token(&token);
        assert!(result.is_ok());

        let permissions = result.unwrap();
        assert_eq!(
            permissions,
            vec![Permission::ManageRole, Permission::ManageIpList]
        );

        let signing_key = "other_secret".to_owned();
        let releaser = TokenReleaser::new(signing_key).unwrap();
        let result = releaser.verify_access_token(&token);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_access_token_expired() {
        let signing_key = "secret".to_owned();
        let releaser = TokenReleaser::new(signing_key).unwrap();
        let role = Role::new(
            "test_login".to_owned(),
            "test_password".to_owned(),
            "test_description".to_owned(),
            vec![Permission::ManageRole, Permission::ManageIpList],
        );
        let expired_at = SystemTime::now() - Duration::from_secs(60);
        let token = releaser
            .release_access_token_expired_at(&role, expired_at)
            .unwrap();
        let result = releaser.verify_access_token(&token);
        assert!(result.is_err());

        let err = result.unwrap_err().to_string();
        assert!(err.contains("token expired"));
    }

    #[test]
    fn test_release_refresh_token() {
        let signing_key = "secret".to_owned();
        let releaser = TokenReleaser::new(signing_key).unwrap();
        let access_token = "test_access_token";
        let result = releaser.release_refresh_token(access_token, Duration::from_secs(60));
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_refresh_token() {
        let signing_key = "secret".to_owned();
        let releaser = TokenReleaser::new(signing_key).unwrap();
        let access_token = "test_access_token";
        let token = releaser
            .release_refresh_token(access_token, Duration::from_secs(60))
            .unwrap();
        let result = releaser.verify_refresh_token(&token);
        assert!(result.is_ok());

        assert_eq!(result.unwrap(), access_token);

        let signing_key = "other_secret".to_owned();
        let releaser = TokenReleaser::new(signing_key).unwrap();
        let result = releaser.verify_access_token(&token);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_refresh_token_expired() {
        let signing_key = "secret".to_owned();
        let releaser = TokenReleaser::new(signing_key).unwrap();
        let access_token = "test_access_token";
        let expired_at = SystemTime::now() - Duration::from_secs(60);
        let token = releaser
            .release_refresh_token_expired_at(access_token, expired_at)
            .unwrap();
        let result = releaser.verify_access_token(&token);
        assert!(result.is_err());

        let err = result.unwrap_err().to_string();
        assert!(err.contains("token expired"));
    }

    #[test]
    fn test_refresh_access_token_success() {
        let signing_key = "secret".to_owned();
        let releaser = TokenReleaser::new(signing_key).unwrap();
        let role = Role::new(
            "test_login".to_owned(),
            "test_password".to_owned(),
            "test_description".to_owned(),
            vec![Permission::ManageRole, Permission::ManageIpList],
        );
        let access_token_expired_at = SystemTime::now() - Duration::from_secs(2);
        let access_token = releaser
            .release_access_token_expired_at(&role, access_token_expired_at)
            .unwrap();

        let refresh_token_expired_at = SystemTime::now() + Duration::from_secs(60);
        let refresh_token = releaser
            .release_refresh_token_expired_at(&access_token, refresh_token_expired_at)
            .unwrap();

        let new_access_token_expired_at = SystemTime::now() + Duration::from_secs(60);

        let (new_access_token, new_refresh_token) = releaser
            .refresh_access_token_expired_at(
                &access_token,
                &refresh_token,
                new_access_token_expired_at,
            )
            .unwrap();

        assert_ne!(new_access_token, access_token);
        assert_ne!(new_refresh_token, refresh_token);

        let pemissions = releaser.verify_access_token(&new_access_token).unwrap();
        assert_eq!(
            pemissions,
            vec![Permission::ManageRole, Permission::ManageIpList]
        );

        let token = releaser.verify_refresh_token(&new_refresh_token).unwrap();
        assert_eq!(new_access_token, token);

        let payload = releaser.verify_token(&new_refresh_token).unwrap();
        let expired_at = payload
            .get(PAYLOAD_EXPIRED_AT)
            .unwrap()
            .parse::<u64>()
            .unwrap();

        assert_eq!(
            expired_at,
            refresh_token_expired_at
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
        );
    }

    #[test]
    fn test_refresh_access_invalid_token() {
        let signing_key = "secret".to_owned();
        let releaser = TokenReleaser::new(signing_key).unwrap();
        let role = Role::new(
            "test_login".to_owned(),
            "test_password".to_owned(),
            "test_description".to_owned(),
            vec![Permission::ManageRole, Permission::ManageIpList],
        );
        let access_token_expired_at = SystemTime::now();
        let access_token = releaser
            .release_access_token_expired_at(&role, access_token_expired_at)
            .unwrap();

        let refresh_token_expired_at = SystemTime::now() + Duration::from_secs(60);
        let refresh_token = releaser
            .release_refresh_token_expired_at(&access_token, refresh_token_expired_at)
            .unwrap();

        // release another access token
        let role = Role::new(
            "test_login_2".to_owned(),
            "test_password_2".to_owned(),
            "test_description_2".to_owned(),
            vec![Permission::ManageRole, Permission::ManageIpList],
        );
        let access_token_expired_at = SystemTime::now() + Duration::from_secs(60);
        let access_token = releaser
            .release_access_token_expired_at(&role, access_token_expired_at)
            .unwrap();

        let new_access_token_expired_at = SystemTime::now() + Duration::from_secs(60);

        // pass wrong pair of access and refresh tokens
        let result = releaser.refresh_access_token_expired_at(
            &access_token,
            &refresh_token,
            new_access_token_expired_at,
        );

        assert!(result.is_err());

        let err = result.unwrap_err().to_string();
        assert!(err.contains("invalid refresh token"));
    }
}
