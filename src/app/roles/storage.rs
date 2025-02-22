use super::{permission::Permission, role::Role};
use std::sync::Arc;

type Client = Arc<tokio_postgres::Client>;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub struct Storage {
    client: Client,
}

impl Storage {
    /// Creates a new `Storage` instance with the provided database client.
    ///
    /// # Arguments
    ///
    /// * `client` - An `Arc` wrapped `tokio_postgres::Client` used to interact with the database.
    ///
    /// # Returns
    ///
    /// A new `Storage` instance.
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    /// Adds a new role to the database.
    ///
    /// # Arguments
    ///
    /// * `role` - The role to be added.
    ///
    /// # Returns
    ///
    /// `Ok(())` if the role is successfully added, otherwise an error is returned.
    ///
    /// # Errors
    ///
    /// If an error occurs while executing the database query, an error is returned.
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

    /// Retrieves a role from the database, given the login and password.
    ///
    /// # Arguments
    ///
    /// * `login` - The login of the role to be retrieved.
    /// * `password` - The password of the role to be retrieved.
    ///
    /// # Returns
    ///
    /// `Ok(Some(role))` if the role exists and the password is correct, `Ok(None)` otherwise.
    ///
    /// # Errors
    ///
    /// If an error occurs while executing the database query, an error is returned.
    pub async fn get(&self, login: &str, password: &str) -> Result<Option<Role>> {
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
                    permissions: row.get::<&str, Vec<Permission>>("permissions"),
                    password_hash: row.get("password_hash"),
                };

                if role.is_password_verified(password) {
                    Ok(Some(role))
                } else {
                    Ok(None)
                }
            }
            None => Ok(None),
        }
    }
}
