use super::permission::Permission;
use password_auth::{generate_hash, verify_password};

#[derive(Debug, PartialEq)]
pub struct Role {
    pub login: String,
    pub description: String,
    pub permissions: Vec<Permission>,
    pub(super) password_hash: String,
}

impl Role {
    /// Creates a new `Role` from a login, password, description, and permissions.

    /// The `password` argument is used to generate a hash, which is stored in the
    /// `password_hash` field of the returned `Role`. The `password` argument is not
    /// stored in plaintext anywhere.
    pub fn new(
        login: String,
        password: String,
        description: String,
        permissions: Vec<Permission>,
    ) -> Self {
        Self {
            login,
            description,
            permissions,
            password_hash: generate_hash(password),
        }
    }

    /// Verifies that the given password matches the one stored in this role.
    ///
    /// # Arguments
    ///
    /// * `password` - The password to be verified.
    ///
    /// # Returns
    ///
    /// `true` if the password matches, `false` otherwise.
    pub(super) fn is_password_verified(&self, password: &str) -> bool {
        verify_password(password, &self.password_hash).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_hash() {
        let role = Role::new(
            "test_login".to_owned(),
            "test_password_123123".to_owned(),
            "test_description".to_owned(),
            vec![Permission::ManageRole, Permission::ManageIpList],
        );
        assert!(role.is_password_verified("test_password_123123"));
        assert!(!role.is_password_verified("test_other_password_123123"));
    }
}
