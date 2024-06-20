use postgres_types::{FromSql, ToSql};

#[derive(Debug, PartialEq, Eq, Hash, Clone, ToSql, FromSql)]
#[postgres(name = "permission", rename_all = "snake_case")]
pub enum Permission {
    ManageRole,
    ModifyIpList,
    ResetRateLimiter,
}
