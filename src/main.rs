use clap::Parser;
use log::info;
use proto::api_server::{Api, ApiServer};
use server::app::{
    api::{Api as ApiService, ApiError, Credentials},
    config::{get_tokens_signing_key, Config, DbConfig},
    connection::connect,
    migrations::run_app_migrations,
    roles::permission::Permission,
    roles::role::Role,
};
use std::{error::Error, path::Path, sync::Arc};
use tonic::transport::Server;

mod proto {
    tonic::include_proto!("api");

    pub(crate) const FILE_DESCRIPTOR_SET: &[u8] =
        tonic::include_file_descriptor_set!("api_descriptor");
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(
        long,
        value_name = "ADDR:PORT",
        help = "server ip address with port e.g. 127.0.0.1:50051"
    )]
    addr: String,

    #[arg(
        long,
        help = "path to file for configuration application server (limits and etc)"
    )]
    config_path: String,

    #[arg(
        long,
        help = "metrics exporter ip address with port e.g. 127.0.0.1:50052"
    )]
    metrics_addr: Option<String>,
}

fn map_api_to_grpc_error(err: ApiError) -> tonic::Status {
    match err {
        ApiError::IpParseError(e) => {
            tonic::Status::new(tonic::Code::InvalidArgument, e.to_string())
        }
        ApiError::IpListError(_) => tonic::Status::new(tonic::Code::Internal, err.to_string()),
        ApiError::Unauthorized => tonic::Status::new(tonic::Code::Unauthenticated, err.to_string()),
        ApiError::AuthNotAllowed => {
            tonic::Status::new(tonic::Code::PermissionDenied, err.to_string())
        }
        ApiError::RolesStorageError(_) => {
            tonic::Status::new(tonic::Code::Internal, err.to_string())
        }
        ApiError::AuthTokenReleaseError(_) => {
            tonic::Status::new(tonic::Code::Internal, err.to_string())
        }
        ApiError::AuthTokenVerifyError(_) => {
            tonic::Status::new(tonic::Code::PermissionDenied, err.to_string())
        }
        ApiError::PermissionDenied => {
            tonic::Status::new(tonic::Code::PermissionDenied, err.to_string())
        }
    }
}

#[tonic::async_trait]
impl Api for ApiService {
    async fn add_role(
        &self,
        request: tonic::Request<proto::AddRoleRequest>,
    ) -> Result<tonic::Response<proto::AddRoleResponse>, tonic::Status> {
        let input = request.get_ref();

        self.check_permission(&input.token, Permission::ManageRole)
            .await
            .map_err(map_api_to_grpc_error)?;

        let permissions: Vec<Permission> = input
            .permissions
            .iter()
            .flat_map(|p| match *p {
                x if x == proto::Permission::ViewIpList as i32 => Some(Permission::ViewIpList),
                x if x == proto::Permission::ManageIpList as i32 => Some(Permission::ManageIpList),
                x if x == proto::Permission::ResetRateLimiter as i32 => {
                    Some(Permission::ResetRateLimiter)
                }
                x if x == proto::Permission::ManageRole as i32 => Some(Permission::ManageRole),
                _ => None,
            })
            .collect();

        let role = Role::new(
            input.login.clone(),
            input.password.clone(),
            input.description.clone(),
            permissions,
        );

        self.add_role_to_storage(&role)
            .await
            .map_err(map_api_to_grpc_error)?;

        let response = proto::AddRoleResponse {};
        Ok(tonic::Response::new(response))
    }

    async fn add_ip_in_black_list(
        &self,
        request: tonic::Request<proto::AddIpInListRequest>,
    ) -> Result<tonic::Response<proto::AddIpInListResponse>, tonic::Status> {
        let input = request.get_ref();

        self.check_permission(&input.token, Permission::ManageIpList)
            .await
            .map_err(map_api_to_grpc_error)?;

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

        self.check_permission(&input.token, Permission::ManageIpList)
            .await
            .map_err(map_api_to_grpc_error)?;

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

        self.check_permission(&input.token, Permission::ManageIpList)
            .await
            .map_err(map_api_to_grpc_error)?;

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

        self.check_permission(&input.token, Permission::ManageIpList)
            .await
            .map_err(map_api_to_grpc_error)?;

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

        self.check_permission(&input.token, Permission::ViewIpList)
            .await
            .map_err(map_api_to_grpc_error)?;

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

        self.check_permission(&input.token, Permission::ViewIpList)
            .await
            .map_err(map_api_to_grpc_error)?;

        let ok = self
            .is_ip_in_white_list(input.ip.clone())
            .await
            .map_err(map_api_to_grpc_error)?;

        Ok(tonic::Response::new(proto::IsIpInListResponse { ok }))
    }

    async fn clear_black_list(
        &self,
        request: tonic::Request<proto::ClearListRequest>,
    ) -> std::result::Result<tonic::Response<proto::ClearBucketResponse>, tonic::Status> {
        let input = request.get_ref();

        self.check_permission(&input.token, Permission::ManageIpList)
            .await
            .map_err(map_api_to_grpc_error)?;

        self.clear_black_list()
            .await
            .map_err(map_api_to_grpc_error)?;

        Ok(tonic::Response::new(proto::ClearBucketResponse {}))
    }

    async fn clear_white_list(
        &self,
        request: tonic::Request<proto::ClearListRequest>,
    ) -> std::result::Result<tonic::Response<proto::ClearBucketResponse>, tonic::Status> {
        let input = request.get_ref();

        self.check_permission(&input.token, Permission::ManageIpList)
            .await
            .map_err(map_api_to_grpc_error)?;

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

        self.check_permission(&input.token, Permission::ResetRateLimiter)
            .await
            .map_err(map_api_to_grpc_error)?;

        if let Some(ip) = input.ip.as_ref() {
            self.reset_ip_rate_limiter(ip.clone()).await;
        }

        Ok(tonic::Response::new(proto::ResetRateLimiterResponse {}))
    }

    async fn health_check(
        &self,
        _request: tonic::Request<proto::HealthCheckRequest>,
    ) -> std::result::Result<tonic::Response<proto::HealthCheckResponse>, tonic::Status> {
        Ok(tonic::Response::new(proto::HealthCheckResponse {}))
    }

    async fn auth(
        &self,
        request: tonic::Request<proto::AuthRequest>,
    ) -> std::result::Result<tonic::Response<proto::AuthResponse>, tonic::Status> {
        let input = request.get_ref();
        let token = self
            .auth(Credentials {
                login: input.login.clone(),
                password: input.password.clone(),
                ip: input.ip.clone(),
            })
            .await
            .map_err(map_api_to_grpc_error)?;
        Ok(tonic::Response::new(proto::AuthResponse { token }))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    let args = Args::parse();
    info!("Args: {:?}", args);

    let addr = args.addr.parse().unwrap();
    let path = Path::new(&args.config_path);

    let config = Config::parse(path);
    info!("Config: {:?}", config);

    let db_config = DbConfig::from_env();
    info!("DbConfig: {:?}", db_config);

    let (mut client, connection) = connect(&db_config).await;

    // The connection object performs the actual communication with the database,
    // so spawn it off to run on its own.
    tokio::spawn(async move {
        connection.await.unwrap();
    });

    run_app_migrations(&mut client).await;

    let metrics_addr = &args.metrics_addr;
    if let Some(metrics_addr) = metrics_addr {
        let metrics_addr = metrics_addr.parse().unwrap();
        prometheus_exporter::start(metrics_addr).unwrap();
    }

    let tokens_signing_key = get_tokens_signing_key();
    let auth = ApiService::new(
        &config,
        Arc::new(client),
        tokens_signing_key,
        metrics_addr.is_some(),
    );

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
