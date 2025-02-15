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
    VerifyFailed(Error),
}

impl std::fmt::Display for TokenReleaserError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSignature(e) => write!(f, "invalid signature: {}", e),
            Self::ReleaseFailed(e) => write!(f, "release failed: {}", e),
            Self::TokenExpired => write!(f, "token expired"),
            Self::VerifyFailed(e) => write!(f, "verify failed: {}", e),
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
    pub fn new(signing_key: String) -> Result<Self> {
        Ok(Self {
            signing_key: Hmac::new_from_slice(signing_key.as_bytes())
                .map_err(TokenReleaserError::InvalidSignature)?,
        })
    }

    pub fn release_access_token(&self, role: Role, expiration_time: Duration) -> Result<String> {
        self.release_access_token_expired_at(role, SystemTime::now() + expiration_time)
    }

    fn release_access_token_expired_at(
        &self,
        role: Role,
        expired_at: SystemTime,
    ) -> Result<String> {
        let permissions: Vec<String> = role
            .permissions
            .into_iter()
            .map(|p| p.to_string())
            .collect();

        self.release_token(
            BTreeMap::from([
                (PAYLOAD_LOGIN.to_owned(), role.login),
                (PAYLOAD_PERMISSIONS.to_owned(), permissions.join(",")),
            ]),
            expired_at,
        )
    }

    pub fn verify_access_token(&self, token: &str) -> Result<Vec<Permission>> {
        let token: Token<Header, BTreeMap<String, String>, _> = token
            .verify_with_key(&self.signing_key)
            .map_err(TokenReleaserError::VerifyFailed)?;

        let header = token.header();
        self.check_header_algo(header)?;

        let payload = token.claims();
        self.check_expiration(payload)?;

        self.get_permissions(payload)
    }

    pub fn release_refresh_token(
        &self,
        access_token: &str,
        expiration_time: Duration,
    ) -> Result<String> {
        self.release_refresh_token_expired_at(access_token, SystemTime::now() + expiration_time)
    }

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

    pub fn verify_refresh_token(&self, token: &str) -> Result<String> {
        let token: Token<Header, BTreeMap<String, String>, _> = token
            .verify_with_key(&self.signing_key)
            .map_err(TokenReleaserError::VerifyFailed)?;

        let header = token.header();
        self.check_header_algo(header)?;

        let payload = token.claims();
        self.check_expiration(payload)?;

        Ok(self.get_payload_item(payload, PAYLOAD_TOKEN)?)
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
            .map_err(|_| TokenReleaserError::TokenExpired)?;

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
        let result = releaser.release_access_token(role, Duration::from_secs(60));
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
            .release_access_token(role, Duration::from_secs(60))
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
            .release_access_token_expired_at(role, expired_at)
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
            .release_refresh_token(&access_token, Duration::from_secs(60))
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
            .release_refresh_token_expired_at(&access_token, expired_at)
            .unwrap();
        let result = releaser.verify_access_token(&token);
        assert!(result.is_err());

        let err = result.unwrap_err().to_string();
        assert!(err.contains("token expired"));
    }
}
