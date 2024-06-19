use super::{permission::Permission, role::Role};
use std::str::FromStr;
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

    pub async fn get(&self, login: &str) -> Result<Option<Role>> {
        let rows = Arc::clone(&self.client)
            .query(
                r#"
    SELECT login, description, password_hash, permissions::TEXT[]
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
                    password_hash: row.get("password_hash"),
                    permissions: HashSet::from_iter(
                        row.get::<&str, Vec<String>>("permissions")
                            .iter()
                            .flat_map(|p| Permission::from_str(p)),
                    ),
                };
                Ok(Some(role))
            }
            None => Ok(None),
        }
    }
}
