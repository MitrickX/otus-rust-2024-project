use tokio_postgres::Client;

pub mod embedded {
    use refinery::embed_migrations;
    embed_migrations!("./sql");
}

pub async fn run_app_migrations(client: &mut Client) {
    embedded::migrations::runner()
        .run_async(client)
        .await
        .unwrap();
}
