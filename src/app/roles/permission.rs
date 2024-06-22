use postgres_types::{FromSql, ToSql};
use std::{fmt::Display, str::FromStr};

#[derive(Debug, PartialEq, Eq, Hash, Clone, ToSql, FromSql)]
#[postgres(name = "permission", rename_all = "snake_case")]
pub enum Permission {
    ManageRole,
    ModifyIpList,
    ResetRateLimiter,
}

impl Display for Permission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Permission::ManageRole => write!(f, "manage_role"),
            Permission::ModifyIpList => write!(f, "modify_ip_list"),
            Permission::ResetRateLimiter => write!(f, "reset_rate_limiter"),
        }
    }
}

impl Permission {
    pub fn get_all() -> Vec<Permission> {
        vec![
            Permission::ManageRole,
            Permission::ModifyIpList,
            Permission::ResetRateLimiter,
        ]
    }
}

#[derive(Debug)]
pub struct UnknownPermissionError;

impl std::fmt::Display for UnknownPermissionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Unknown permission")
    }
}

impl std::error::Error for UnknownPermissionError {}

impl FromStr for Permission {
    type Err = UnknownPermissionError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "manage_role" => Ok(Permission::ManageRole),
            "modify_ip_list" => Ok(Permission::ModifyIpList),
            "reset_rate_limiter" => Ok(Permission::ResetRateLimiter),
            _ => Err(UnknownPermissionError),
        }
    }
}
