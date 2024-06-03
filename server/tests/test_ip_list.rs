use serde::{Deserialize, Serialize};
use serde_yml;
use server::app::{
    config::Db,
    connection::connect,
    ip_list::{ip::Ip, list::List},
    migrations::run_app_migrations,
};
use std::{path::Path, str::FromStr};
use tokio::sync::OnceCell;
use tokio_postgres::Client;

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub db: Db,
}

const CONFIG_PATH: &str = "../configs/tests/config.yaml";

impl Config {
    pub fn parse(file_path: &Path) -> Result<Self, Box<serde_yml::Error>> {
        let content = std::fs::read_to_string(file_path).unwrap();
        let config: Config = serde_yml::from_str(&content)?;
        Ok(config)
    }
}

static ONCE: OnceCell<Config> = OnceCell::const_new();

async fn setup() -> &'static Config {
    ONCE.get_or_init(|| async {
        let mut path = std::env::current_dir().unwrap();
        path.push(CONFIG_PATH);

        println!("Path: {:?}", path);

        let config = Config::parse(path.as_path()).unwrap();
        println!("Config: {:?}", config);

        let (mut client, connection) = connect(&config.db).await;

        // The connection object performs the actual communication with the database,
        // so spawn it off to run on its own.
        tokio::spawn(async move {
            connection.await.unwrap();
        });

        run_app_migrations(&mut client).await;

        //client
        config
    })
    .await
}

#[tokio::test]
async fn test_ip_list() {
    let config = setup().await;

    let (mut client, connection) = connect(&config.db).await;

    // The connection object performs the actual communication with the database,
    // so spawn it off to run on its own.
    tokio::spawn(async move {
        connection.await.unwrap();
    });

    let list = List::new(&client, "test");
    let ip = Ip::from_str("192.168.56.0/24").unwrap();

    list.add(&ip).await.unwrap();
}

#[tokio::test]
async fn test_ip_list_2() {
    setup().await;
}
