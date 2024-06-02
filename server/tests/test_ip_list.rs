use serde::{Deserialize, Serialize};
use serde_yml;
use server::app::config::Db;
use server::app::migrations::run_app_migrations;
use std::path::Path;
use tokio::sync::OnceCell;

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

static ONCE: OnceCell<()> = OnceCell::const_new();

async fn setup() -> &'static () {
    ONCE.get_or_init(|| async {
        let mut path = std::env::current_dir().unwrap();
        path.push(CONFIG_PATH);

        println!("Path: {:?}", path);

        let config = Config::parse(path.as_path()).unwrap();
        println!("Config: {:?}", config);

        run_app_migrations(&config.db).await;
    })
    .await
}

#[tokio::test]
async fn test_ip_list() {
    setup().await;
}

#[tokio::test]
async fn test_ip_list_2() {
    setup().await;
}
