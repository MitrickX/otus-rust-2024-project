use server::app::{
    config::DbConfig,
    connection::connect,
    migrations::run_app_migrations,
    roles::{permission::Permission, role::Role, storage::Storage},
};
use std::sync::Arc;
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
async fn test_crud() {
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

    storage
        .add(&Role::new(
            "test-login".to_string(),
            "test-password-54321".to_string(),
            "test-description".to_string(),
            vec![Permission::ManageRole, Permission::ModifyIpList],
        ))
        .await
        .unwrap();

    let role = storage
        .get("test-login", "test-password-54321")
        .await
        .unwrap();
    assert!(role.is_some());

    let role = role.unwrap();
    assert_eq!("test-login", role.login);
    assert_eq!("test-description", role.description);
    assert_eq!(
        vec![Permission::ManageRole, Permission::ModifyIpList],
        role.permissions
    );

    let role = storage.get("test-login", "test-password").await.unwrap();
    assert!(role.is_none());
}
