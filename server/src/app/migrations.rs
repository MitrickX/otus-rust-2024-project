use super::config::Db;
use tokio_postgres::NoTls;

pub mod embedded {
    use refinery::embed_migrations;
    embed_migrations!("./sql");
}

pub async fn run_app_migrations(config: &Db) {
    let (mut client, connection) = tokio_postgres::Config::new()
        .host(&config.host)
        .user(&config.user)
        .dbname(&config.name)
        .password(&config.password)
        .port(config.port)
        .connect(NoTls)
        .await
        .unwrap();

    // The connection object performs the actual communication with the database,
    // so spawn it off to run on its own.
    tokio::spawn(async move {
        connection.await.unwrap();
    });

    embedded::migrations::runner()
        .run_async(&mut client)
        .await
        .unwrap();
}
