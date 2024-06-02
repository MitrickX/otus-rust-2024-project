use tokio_postgres::NoTls;

use super::config::Config;

pub mod embedded {
    use refinery::embed_migrations;
    embed_migrations!("./sql");
}

pub async fn run_app_migrations(config: &Config) {
    let (mut client, connection) = tokio_postgres::Config::new()
        .host(&config.db.host)
        .user(&config.db.user)
        .dbname(&config.db.name)
        .password(&config.db.password)
        .port(config.db.port)
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
