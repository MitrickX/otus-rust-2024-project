use super::permission::Permission;
use password_auth::{generate_hash, verify_password};
use std::collections::HashSet;

#[derive(Debug, PartialEq)]
pub struct Role {
    pub login: String,
    pub description: String,
    pub permissions: HashSet<Permission>,
    pub(super) password_hash: String,
}

impl Role {
    pub fn new(
        login: String,
        password: String,
        description: String,
        permissions: HashSet<Permission>,
    ) -> Self {
        Self {
            login,
            description,
            permissions,
            password_hash: generate_hash(password),
        }
    }

    pub fn is_password_verified(&self, password: String) -> bool {
        verify_password(password, &self.password_hash).is_ok()
    }

    pub fn has_permission(&self, permission: &Permission) -> bool {
        self.permissions.contains(permission)
    }
}
