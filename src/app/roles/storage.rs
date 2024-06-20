use super::{permission::Permission, role::Role};
use std::{collections::HashSet, sync::Arc};

type Client = Arc<tokio_postgres::Client>;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub struct Storage {
    client: Client,
}

impl Storage {
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    pub async fn add(&self, role: &Role) -> Result<()> {
        Arc::clone(&self.client)
            .execute(
                r#"INSERT INTO roles (login, description, password_hash, permissions) 
VALUES ($1, $2, $3, $4)
ON CONFLICT (login) DO UPDATE 
SET 
    description = EXCLUDED.description, 
    password_hash = EXCLUDED.password_hash,
    permissions = EXCLUDED.permissions"#,
                &[
                    &role.login,
                    &role.description,
                    &role.password_hash,
                    &role.permissions.iter().collect::<Vec<&Permission>>(),
                ],
            )
            .await?;

        Ok(())
    }

    pub async fn get(&self, login: &str) -> Result<Option<Role>> {
        let rows = Arc::clone(&self.client)
            .query(
                r#"
    SELECT login, description, password_hash, permissions
    FROM roles 
    WHERE login = $1
"#,
                &[&login],
            )
            .await?;

        let row = rows.first();
        match row {
            Some(row) => {
                let role = Role {
                    login: row.get("login"),
                    description: row.get("description"),
                    permissions: HashSet::from_iter(
                        row.get::<&str, Vec<Permission>>("permissions"),
                    ),
                    password_hash: row.get("password_hash"),
                };
                Ok(Some(role))
            }
            None => Ok(None),
        }
    }
}
