use super::permission::Permission;
use std::collections::HashSet;

#[derive(Debug, PartialEq)]
pub struct Role {
    pub login: String,
    pub description: String,
    pub password_hash: String,
    pub permissions: HashSet<Permission>,
}
