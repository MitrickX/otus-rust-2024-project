use proto::api_server::{Api, ApiServer};
use server::app::{
    api::{Api as ApiService, ApiError, Credentials},
    config::Config,
    connection::connect,
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

// TODO: cleaning inactive buckets

// TODO: move port to env var
const ADDR: &str = "[::1]:50051";
// TODO: move db connections to env var (and use docker compose)
const CONFIG_PATH: &str = "./configs/server/config.yaml";

fn map_api_to_grpc_error(err: ApiError) -> tonic::Status {
    match err {
        ApiError::IpParseError(e) => {
            tonic::Status::new(tonic::Code::InvalidArgument, e.to_string())
        }
        ApiError::IpListError(_) => tonic::Status::new(tonic::Code::Internal, err.to_string()),
    }
}

#[tonic::async_trait]
impl Api for ApiService {
    async fn is_auth_allowed(
        &self,
        request: tonic::Request<proto::IsAuthAllowedRequest>,
    ) -> Result<tonic::Response<proto::IsAuthAllowedResponse>, tonic::Status> {
        let input = request.get_ref();

        let is_ok_auth = self
            .check_can_auth(Credentials {
                login: input.login.clone(),
                password: input.password.clone(),
                ip: input.ip.clone(),
            })
            .await
            .map_err(map_api_to_grpc_error)?;

        let response = proto::IsAuthAllowedResponse { ok: is_ok_auth };
        Ok(tonic::Response::new(response))
    }

    async fn add_ip_in_black_list(
        &self,
        request: tonic::Request<proto::AddIpInListRequest>,
    ) -> Result<tonic::Response<proto::AddIpInListResponse>, tonic::Status> {
        let input = request.get_ref();
        self.add_ip_in_black_list(input.ip.clone())
            .await
            .map_err(map_api_to_grpc_error)?;

        Ok(tonic::Response::new(proto::AddIpInListResponse {}))
    }

    async fn add_ip_in_white_list(
        &self,
        request: tonic::Request<proto::AddIpInListRequest>,
    ) -> std::result::Result<tonic::Response<proto::AddIpInListResponse>, tonic::Status> {
        let input = request.get_ref();
        self.add_ip_in_white_list(input.ip.clone())
            .await
            .map_err(map_api_to_grpc_error)?;

        Ok(tonic::Response::new(proto::AddIpInListResponse {}))
    }

    async fn delete_ip_from_black_list(
        &self,
        request: tonic::Request<proto::DeleteIpFromListRequest>,
    ) -> std::result::Result<tonic::Response<proto::DeleteIpFromListResponse>, tonic::Status> {
        let input = request.get_ref();
        self.delete_ip_from_black_list(input.ip.clone())
            .await
            .map_err(map_api_to_grpc_error)?;

        Ok(tonic::Response::new(proto::DeleteIpFromListResponse {}))
    }

    async fn delete_ip_from_white_list(
        &self,
        request: tonic::Request<proto::DeleteIpFromListRequest>,
    ) -> std::result::Result<tonic::Response<proto::DeleteIpFromListResponse>, tonic::Status> {
        let input = request.get_ref();
        self.delete_ip_from_white_list(input.ip.clone())
            .await
            .map_err(map_api_to_grpc_error)?;

        Ok(tonic::Response::new(proto::DeleteIpFromListResponse {}))
    }

    async fn is_ip_in_black_list(
        &self,
        request: tonic::Request<proto::IsIpInListRequest>,
    ) -> std::result::Result<tonic::Response<proto::IsIpInListResponse>, tonic::Status> {
        let input = request.get_ref();
        let ok = self
            .is_ip_in_black_list(input.ip.clone())
            .await
            .map_err(map_api_to_grpc_error)?;

        Ok(tonic::Response::new(proto::IsIpInListResponse { ok }))
    }

    async fn is_ip_in_white_list(
        &self,
        request: tonic::Request<proto::IsIpInListRequest>,
    ) -> std::result::Result<tonic::Response<proto::IsIpInListResponse>, tonic::Status> {
        let input = request.get_ref();
        let ok = self
            .is_ip_in_white_list(input.ip.clone())
            .await
            .map_err(map_api_to_grpc_error)?;

        Ok(tonic::Response::new(proto::IsIpInListResponse { ok }))
    }

    async fn clear_black_list(
        &self,
        _request: tonic::Request<proto::ClearListRequest>,
    ) -> std::result::Result<tonic::Response<proto::ClearBucketResponse>, tonic::Status> {
        self.clear_black_list()
            .await
            .map_err(map_api_to_grpc_error)?;

        Ok(tonic::Response::new(proto::ClearBucketResponse {}))
    }

    async fn clear_white_list(
        &self,
        _request: tonic::Request<proto::ClearListRequest>,
    ) -> std::result::Result<tonic::Response<proto::ClearBucketResponse>, tonic::Status> {
        self.clear_white_list()
            .await
            .map_err(map_api_to_grpc_error)?;

        Ok(tonic::Response::new(proto::ClearBucketResponse {}))
    }

    async fn reset_rate_limiter(
        &self,
        request: tonic::Request<proto::ResetRateLimiterRequest>,
    ) -> std::result::Result<tonic::Response<proto::ResetRateLimiterResponse>, tonic::Status> {
        let input = request.get_ref();
        if let Some(ip) = input.ip.as_ref() {
            self.reset_ip_rate_limiter(ip.clone()).await;
        }

        Ok(tonic::Response::new(proto::ResetRateLimiterResponse {}))
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
