use tokio_postgres::Client;

pub mod embedded {
    use refinery::embed_migrations;
    embed_migrations!("./sql");
}

/// Runs the database migrations on the given database client.
///
/// This function is intended to be called once at application startup. It will
/// run all embedded migrations on the database client and block until they
/// complete.
///
/// In case of any error during the migration process, this function will panic.
///
pub async fn run_app_migrations(client: &mut Client) {
    embedded::migrations::runner()
        .run_async(client)
        .await
        .unwrap();
}
