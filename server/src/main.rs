use proto::auth_server::{Auth, AuthServer};
use server::app::{
    config::Config,
    connection::connect,
    migrations::run_app_migrations,
    service::auth::{Auth as AuthAppService, Credentials},
};
use std::{error::Error, sync::Arc};
use tokio::sync::Mutex;
use tonic::transport::Server;

mod proto {
    tonic::include_proto!("auth");

    pub(crate) const FILE_DESCRIPTOR_SET: &[u8] =
        tonic::include_file_descriptor_set!("auth_descriptor");
}

const ADDR: &str = "[::1]:50051";
const CONFIG_PATH: &str = "./configs/server/config.yaml";

#[tonic::async_trait]
impl Auth for AuthAppService {
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

    let auth = AuthAppService::new(&config, Arc::new(Mutex::new(client)));

    let reflection = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(proto::FILE_DESCRIPTOR_SET)
        .build()?;

    Server::builder()
        .add_service(AuthServer::new(auth))
        .add_service(reflection)
        .serve(addr)
        .await?;

    Ok(())
}
