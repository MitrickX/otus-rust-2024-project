use super::config::DbConfig;
use log::warn;
use postgres::{tls::NoTlsStream, Socket};
use tokio::time::{sleep, Duration};
use tokio_postgres::NoTls;

pub async fn connect(
    config: &DbConfig,
) -> (
    tokio_postgres::Client,
    tokio_postgres::Connection<Socket, NoTlsStream>,
) {
    for i in 0..config.connection_retries {
        match try_connect(config).await {
            Ok((client, connection)) => {
                return (client, connection);
            }
            Err(e) => {
                warn!("Failed to connect to database {}", e);
                warn!(
                    "Will retry #{} in {} seconds...",
                    i + 1,
                    config.connection_timeout
                );
                sleep(Duration::from_secs(config.connection_timeout as u64)).await
            }
        }
    }

    try_connect(config).await.unwrap()
}

async fn try_connect(
    config: &DbConfig,
) -> Result<
    (
        tokio_postgres::Client,
        tokio_postgres::Connection<Socket, NoTlsStream>,
    ),
    postgres::Error,
> {
    tokio_postgres::Config::new()
        .host(&config.host)
        .user(&config.user)
        .dbname(&config.name)
        .password(&config.password)
        .port(config.port)
        .connect(NoTls)
        .await
}
