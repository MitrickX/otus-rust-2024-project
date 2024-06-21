use hmac::{Hmac, Mac};
use jwt::{AlgorithmType, Error, Header, SignWithKey, Token, VerifyWithKey};
use sha2::Sha384;
use std::collections::BTreeMap;

#[derive(Debug)]
pub enum TokenReleaserError {
    InvalidSignature(hmac::digest::InvalidLength),
    ReleaseFailed(Error),
    VerifyFailed(Error),
}

impl std::fmt::Display for TokenReleaserError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSignature(e) => write!(f, "invalid signature: {}", e),
            Self::ReleaseFailed(e) => write!(f, "release failed: {}", e),
            Self::VerifyFailed(e) => write!(f, "verify failed: {}", e),
        }
    }
}

impl std::error::Error for TokenReleaserError {}

pub struct TokenReleaser {
    signing_key: Hmac<Sha384>,
}

type Result<T> = std::result::Result<T, TokenReleaserError>;
type Claims = BTreeMap<String, String>;

impl TokenReleaser {
    pub fn new(signing_key: &[u8]) -> Result<Self> {
        Ok(Self {
            signing_key: Hmac::new_from_slice(signing_key)
                .map_err(TokenReleaserError::InvalidSignature)?,
        })
    }

    pub fn release_token(&self, claims: Claims) -> Result<String> {
        let header = Header {
            algorithm: AlgorithmType::Hs384,
            ..Default::default()
        };
        let token = Token::new(header, claims)
            .sign_with_key(&self.signing_key)
            .map_err(TokenReleaserError::ReleaseFailed)?;

        Ok(token.as_str().to_owned())
    }

    pub fn verify_token(&self, token: &str) -> Result<Claims> {
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

        Ok(token.claims().clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn test_release_token() {
        let signing_key = b"secret";
        let releaser = TokenReleaser::new(signing_key).unwrap();
        let mut claims = BTreeMap::new();
        claims.insert("test_1".to_owned(), "value_1".to_owned());
        claims.insert("test_2".to_owned(), "value_2".to_owned());
        let result = releaser.release_token(claims);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_token() {
        let signing_key = b"secret";
        let releaser = TokenReleaser::new(signing_key).unwrap();
        let mut claims = BTreeMap::new();
        claims.insert("test_1".to_owned(), "value_1".to_owned());
        claims.insert("test_2".to_owned(), "value_2".to_owned());
        let token = releaser.release_token(claims).unwrap();
        let result = releaser.verify_token(&token);
        assert!(result.is_ok());

        let claims = result.unwrap();
        assert_eq!(claims.len(), 2);
        assert_eq!(claims.get("test_1").unwrap(), "value_1");
        assert_eq!(claims.get("test_2").unwrap(), "value_2");

        let signing_key = b"other_secret";
        let releaser = TokenReleaser::new(signing_key).unwrap();
        let result = releaser.verify_token(&token);
        assert!(result.is_err());
    }
}
