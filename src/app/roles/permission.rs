use std::str::FromStr;

#[derive(Debug, PartialEq, Eq, Hash)]
pub enum Permission {
    CreateRole,
    ModifyIpList,
    ResetRateLimiter,
}

#[derive(Debug)]
pub struct UnsupportedPermission {}

impl std::fmt::Display for UnsupportedPermission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for UnsupportedPermission {}

impl FromStr for Permission {
    type Err = UnsupportedPermission;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "create_role" {
            Ok(Permission::CreateRole)
        } else if s == "modify_ip_list" {
            Ok(Permission::ModifyIpList)
        } else if s == "reset_rate_limiter" {
            Ok(Permission::ResetRateLimiter)
        } else {
            Err(UnsupportedPermission {})
        }
    }
}
