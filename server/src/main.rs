use proto::api_server::{Api, ApiServer};
use server::app::{
    api::Api as ApiService, api::Credentials, config::Config, connection::connect,
    migrations::run_app_migrations,
};
use std::{error::Error, sync::Arc};
use tokio::sync::Mutex;
use tonic::transport::Server;

mod proto {
    tonic::include_proto!("api");

    pub(crate) const FILE_DESCRIPTOR_SET: &[u8] =
        tonic::include_file_descriptor_set!("api_descriptor");
}

// TODO: move port to env var
const ADDR: &str = "[::1]:50051";
// TODO: move db connections to env var (and use docker compose)
const CONFIG_PATH: &str = "./configs/server/config.yaml";

#[tonic::async_trait]
impl Api for ApiService {
    async fn auth(
        &self,
        request: tonic::Request<proto::AuthRequest>,
    ) -> Result<tonic::Response<proto::AuthResponse>, tonic::Status> {
        println!("Got a request: {:?}", request);

        let input = request.get_ref();

        let is_ok_auth = self
            .check(Credentials {
                login: input.login.clone(),
                password: input.password.clone(),
                ip: input.ip.clone(),
            })
            .await
            .unwrap_or_else(|e| {
                // TODO: Log error
                println!("Error: {:?}", e);
                false
            });

        let response = proto::AuthResponse { ok: is_ok_auth };
        println!("Response: {:?}", response);
        Ok(tonic::Response::new(response))
    }

    async fn add_in_black_list(
        &self,
        _request: tonic::Request<proto::AddIpInListRequest>,
    ) -> Result<tonic::Response<proto::None>, tonic::Status> {
        // let input = request.get_ref();
        // self.add(&input.ip).await.unwrap();
        Ok(tonic::Response::new(proto::None {}))
    }

    async fn add_in_white_list(
        &self,
        _request: tonic::Request<proto::AddIpInListRequest>,
    ) -> std::result::Result<tonic::Response<proto::None>, tonic::Status> {
        Ok(tonic::Response::new(proto::None {}))
    }
}
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let addr = ADDR.parse()?;

    let mut path = std::env::current_dir()?;
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

    let auth = ApiService::new(&config, Arc::new(Mutex::new(client)));

    let reflection = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(proto::FILE_DESCRIPTOR_SET)
        .build()?;

    Server::builder()
        .add_service(ApiServer::new(auth))
        .add_service(reflection)
        .serve(addr)
        .await?;

    Ok(())
}
