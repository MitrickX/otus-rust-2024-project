use super::config::Db;
use postgres::{tls::NoTlsStream, Socket};
use tokio_postgres::NoTls;

pub async fn connect(
    config: &Db,
) -> (
    tokio_postgres::Client,
    tokio_postgres::Connection<Socket, NoTlsStream>,
) {
    tokio_postgres::Config::new()
        .host(&config.host)
        .user(&config.user)
        .dbname(&config.name)
        .password(&config.password)
        .port(config.port)
        .connect(NoTls)
        .await
        .unwrap()
}
