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

    pub fn release_token(&self, role: Role, expiration_time: Duration) -> Result<String> {
        self.release_token_expired_at(role, SystemTime::now() + expiration_time)
    }

    fn release_token_expired_at(&self, role: Role, expired_at: SystemTime) -> Result<String> {
        let header = Header {
            algorithm: AlgorithmType::Hs384,
            ..Default::default()
        };
        let permissions: Vec<String> = role
            .permissions
            .into_iter()
            .map(|p| p.to_string())
            .collect();

        let claims = BTreeMap::from([
            ("login".to_owned(), role.login),
            ("permissions".to_owned(), permissions.join(",")),
            (
                "expired_at".to_owned(),
                expired_at
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    .to_string(),
            ),
        ]);
        let token = Token::new(header, claims)
            .sign_with_key(&self.signing_key)
            .map_err(TokenReleaserError::ReleaseFailed)?;

        Ok(token.as_str().to_owned())
    }

    pub fn verify_token(&self, token: &str) -> Result<Vec<Permission>> {
        let token: Token<Header, BTreeMap<String, String>, _> = token
            .verify_with_key(&self.signing_key)
            .map_err(TokenReleaserError::VerifyFailed)?;

        let header = token.header();
        if header.algorithm != AlgorithmType::Hs384 {
            return Err(TokenReleaserError::VerifyFailed(Error::AlgorithmMismatch(
                AlgorithmType::Hs384,
                AlgorithmType::None,
            )));
        }

        let claims = token.claims();
        if let Some(expired_at) = claims.get("expired_at") {
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
        };

        let permissions: Vec<Permission> = if let Some(permissions) = claims.get("permissions") {
            permissions
                .split(',')
                .flat_map(Permission::from_str)
                .collect()
        } else {
            Vec::new()
        };

        Ok(permissions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_release_token() {
        let signing_key = "secret".to_owned();
        let releaser = TokenReleaser::new(signing_key).unwrap();
        let role = Role::new(
            "test_login".to_owned(),
            "test_password".to_owned(),
            "test_description".to_owned(),
            vec![Permission::ManageRole, Permission::ManageIpList],
        );
        let result = releaser.release_token(role, Duration::from_secs(60));
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_token() {
        let signing_key = "secret".to_owned();
        let releaser = TokenReleaser::new(signing_key).unwrap();
        let role = Role::new(
            "test_login".to_owned(),
            "test_password".to_owned(),
            "test_description".to_owned(),
            vec![Permission::ManageRole, Permission::ManageIpList],
        );
        let token = releaser
            .release_token(role, Duration::from_secs(60))
            .unwrap();
        let result = releaser.verify_token(&token);
        assert!(result.is_ok());

        let claims = result.unwrap();
        assert_eq!(
            claims,
            vec![Permission::ManageRole, Permission::ManageIpList]
        );

        let signing_key = "other_secret".to_owned();
        let releaser = TokenReleaser::new(signing_key).unwrap();
        let result = releaser.verify_token(&token);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_token_expired() {
        let signing_key = "secret".to_owned();
        let releaser = TokenReleaser::new(signing_key).unwrap();
        let role = Role::new(
            "test_login".to_owned(),
            "test_password".to_owned(),
            "test_description".to_owned(),
            vec![Permission::ManageRole, Permission::ManageIpList],
        );
        let expired_at = SystemTime::now() - Duration::from_secs(60);
        let token = releaser.release_token_expired_at(role, expired_at).unwrap();
        let result = releaser.verify_token(&token);
        assert!(result.is_err());

        let err = result.unwrap_err().to_string();
        assert!(err.contains("token expired"));
    }
}
