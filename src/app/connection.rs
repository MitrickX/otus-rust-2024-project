use super::config::DbConfig;
use log::warn;
use postgres::{tls::NoTlsStream, Socket};
use tokio::time::{sleep, Duration};
use tokio_postgres::NoTls;

/// Connect to the PostgreSQL database with the given configuration.
///
/// This function will attempt to connect to the database up to
/// `config.connection_retries` times. If the connection fails, it will
/// wait for `config.connection_timeout` seconds before retrying.
///
/// If all retries fail, it will return the last error.
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

/// Attempt to establish a connection to the PostgreSQL database using the provided configuration.
///
/// # Arguments
///
/// * `config` - A reference to `DbConfig` containing the database connection parameters.
///
/// # Returns
///
/// * `Result<(tokio_postgres::Client, tokio_postgres::Connection<Socket, NoTlsStream>), postgres::Error>` -
///   On success, returns a tuple containing a `tokio_postgres::Client` and a `tokio_postgres::Connection`.
///   On failure, returns a `postgres::Error`.
///
/// This function utilizes the `tokio_postgres` library to create a connection to the database
/// specified by the parameters in `DbConfig`. It returns the connection and client if successful,
/// otherwise returns an error detailing why the connection could not be established.

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
