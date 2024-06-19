use server::app::{
    config::DbConfig,
    connection::connect,
    migrations::run_app_migrations,
    roles::{permission::Permission, role::Role, storage::Storage},
};
use std::{collections::HashSet, sync::Arc};
use tokio::sync::OnceCell;

static ONCE_RUN_MIGRATIONS: OnceCell<()> = OnceCell::const_new();

async fn once_run_migrations() {
    ONCE_RUN_MIGRATIONS
        .get_or_init(|| async {
            let db_config = DbConfig::from_env();
            let (mut client, connection) = connect(&db_config).await;

            // The connection object performs the actual communication with the database,
            // so spawn it off to run on its own.
            tokio::spawn(async move {
                connection.await.unwrap();
            });

            run_app_migrations(&mut client).await;
        })
        .await;
}

#[tokio::test]
async fn test_get() {
    once_run_migrations().await;

    let db_config = DbConfig::from_env();
    let (client, connection) = connect(&db_config).await;

    // The connection object performs the actual communication with the database,
    // so spawn it off to run on its own.
    tokio::spawn(async move {
        connection.await.unwrap();
    });

    let client = Arc::new(client);
    let storage = Storage::new(Arc::clone(&client));

    Arc::clone(&client)
        .execute(
            r#"INSERT INTO roles (login, description, password_hash, permissions) 
VALUES ('test-login', 'test-description', 'test-password-hash', '{"create_role", "modify_ip_list"}')
ON CONFLICT (login) DO UPDATE 
SET 
    description = EXCLUDED.description, 
    password_hash = EXCLUDED.password_hash, 
    permissions = EXCLUDED.permissions"#,
            &[],
        )
        .await
        .unwrap();

    let role = storage.get("test-login").await.unwrap();
    assert_eq!(
        Some(Role {
            login: "test-login".to_string(),
            description: "test-description".to_string(),
            password_hash: "test-password-hash".to_string(),
            permissions: HashSet::from([Permission::CreateRole, Permission::ModifyIpList]),
        }),
        role
    );
}
