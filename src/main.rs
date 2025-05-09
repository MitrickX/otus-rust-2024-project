use clap::Parser;
use log::info;
use proto::api_server::{Api, ApiServer};
use serde::Serialize;
use server::app::{
    api::{Api as ApiService, ApiError, Credentials},
    config::{get_tokens_signing_key, Config, DbConfig},
    connection::connect,
    migrations::run_app_migrations,
    roles::permission::Permission,
    roles::role::Role,
};
use std::panic;
use std::{error::Error, path::Path, sync::Arc};
use structured_logger::Builder;
use tokio::signal;
use tonic::transport::Server;

mod proto {
    tonic::include_proto!("api");

    pub(crate) const FILE_DESCRIPTOR_SET: &[u8] =
        tonic::include_file_descriptor_set!("api_descriptor");
}

#[derive(Parser, Debug, Serialize)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(
        long,
        value_name = "ADDR:PORT",
        help = "server ip address with port e.g. 127.0.0.1:50051"
    )]
    pub addr: String,

    #[arg(
        long,
        help = "path to file for configuration application server (limits and etc)"
    )]
    pub config_path: String,

    #[arg(
        long,
        help = "metrics exporter ip address with port e.g. 127.0.0.1:50052"
    )]
    pub metrics_addr: Option<String>,
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
    /// Handles the addition of a new role to the system.
    ///
    /// # Arguments
    ///
    /// * `request` - A `tonic::Request` containing a `proto::AddRoleRequest`, which includes
    ///   the details of the role to be added, such as login, password, description,
    ///   permissions, and access token.
    ///
    /// # Returns
    ///
    /// * `Result<tonic::Response<proto::AddRoleResponse>, tonic::Status>` - Returns a
    ///   `tonic::Response` with an `AddRoleResponse` on success, or a `tonic::Status`
    ///   error if the operation fails due to permission issues or storage errors.
    ///
    /// # Errors
    ///
    /// This function returns a `tonic::Status` error in the following cases:
    /// - If the access token does not have the `ManageRole` permission, an error is returned.
    /// - If there is an error adding the role to the storage, an error is returned.
    ///
    /// The permissions for the role are parsed from the `permissions` field in the request,
    /// and only valid permissions are included in the role being added.
    async fn add_role(
        &self,
        request: tonic::Request<proto::AddRoleRequest>,
    ) -> Result<tonic::Response<proto::AddRoleResponse>, tonic::Status> {
        let input = request.get_ref();

        self.check_permission(&input.access_token, Permission::ManageRole)
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

    /// Adds the given IP address to the black list.
    ///
    /// # Arguments
    ///
    /// * `request` - A `tonic::Request` containing a `proto::AddIpInListRequest`, which includes
    ///   the IP address to be added and an access token.
    ///
    /// # Returns
    ///
    /// * `Result<tonic::Response<proto::AddIpInListResponse>, tonic::Status>` - Returns a
    ///   `tonic::Response` with an `AddIpInListResponse` on success, or a `tonic::Status`
    ///   error if the operation fails due to permission issues or storage errors.
    ///
    /// # Errors
    ///
    /// This function returns a `tonic::Status` error in the following cases:
    /// - If the access token does not have the `ManageIpList` permission, an error is returned.
    /// - If there is an error adding the IP address to the storage, an error is returned.
    async fn add_ip_in_black_list(
        &self,
        request: tonic::Request<proto::AddIpInListRequest>,
    ) -> Result<tonic::Response<proto::AddIpInListResponse>, tonic::Status> {
        let input = request.get_ref();

        self.check_permission(&input.access_token, Permission::ManageIpList)
            .await
            .map_err(map_api_to_grpc_error)?;

        self.add_ip_in_black_list(input.ip.clone())
            .await
            .map_err(map_api_to_grpc_error)?;

        Ok(tonic::Response::new(proto::AddIpInListResponse {}))
    }

    /// Adds the given IP address to the white list.
    ///
    /// # Arguments
    ///
    /// * `request` - A `tonic::Request` containing a `proto::AddIpInListRequest`, which includes
    ///   the IP address to be added and an access token.
    ///
    /// # Returns
    ///
    /// * `Result<tonic::Response<proto::AddIpInListResponse>, tonic::Status>` - Returns a
    ///   `tonic::Response` with an `AddIpInListResponse` on success, or a `tonic::Status`
    ///   error if the operation fails due to permission issues or storage errors.
    ///
    /// # Errors
    ///
    /// This function returns a `tonic::Status` error in the following cases:
    /// - If the access token does not have the `ManageIpList` permission, an error is returned.
    /// - If there is an error adding the IP address to the storage, an error is returned.
    async fn add_ip_in_white_list(
        &self,
        request: tonic::Request<proto::AddIpInListRequest>,
    ) -> std::result::Result<tonic::Response<proto::AddIpInListResponse>, tonic::Status> {
        let input = request.get_ref();

        self.check_permission(&input.access_token, Permission::ManageIpList)
            .await
            .map_err(map_api_to_grpc_error)?;

        self.add_ip_in_white_list(input.ip.clone())
            .await
            .map_err(map_api_to_grpc_error)?;

        Ok(tonic::Response::new(proto::AddIpInListResponse {}))
    }

    /// Removes the given IP address from the black list.
    ///
    /// # Arguments
    ///
    /// * `request` - A `tonic::Request` containing a `proto::DeleteIpFromListRequest`, which includes
    ///   the IP address to be removed and an access token.
    ///
    /// # Returns
    ///
    /// * `Result<tonic::Response<proto::DeleteIpFromListResponse>, tonic::Status>` - Returns a
    ///   `tonic::Response` with a `DeleteIpFromListResponse` on success, or a `tonic::Status`
    ///   error if the operation fails due to permission issues or storage errors.
    ///
    /// # Errors
    ///
    /// This function returns a `tonic::Status` error in the following cases:
    /// - If the access token does not have the `ManageIpList` permission, an error is returned.
    /// - If there is an error removing the IP address from the storage, an error is returned.
    async fn delete_ip_from_black_list(
        &self,
        request: tonic::Request<proto::DeleteIpFromListRequest>,
    ) -> std::result::Result<tonic::Response<proto::DeleteIpFromListResponse>, tonic::Status> {
        let input = request.get_ref();

        self.check_permission(&input.access_token, Permission::ManageIpList)
            .await
            .map_err(map_api_to_grpc_error)?;

        self.delete_ip_from_black_list(input.ip.clone())
            .await
            .map_err(map_api_to_grpc_error)?;

        Ok(tonic::Response::new(proto::DeleteIpFromListResponse {}))
    }

    /// Removes the given IP address from the white list.
    ///
    /// # Arguments
    ///
    /// * `request` - A `tonic::Request` containing a `proto::DeleteIpFromListRequest`, which includes
    ///   the IP address to be removed and an access token.
    ///
    /// # Returns
    ///
    /// * `Result<tonic::Response<proto::DeleteIpFromListResponse>, tonic::Status>` - Returns a
    ///   `tonic::Response` with a `DeleteIpFromListResponse` on success, or a `tonic::Status`
    ///   error if the operation fails due to permission issues or storage errors.
    ///
    /// # Errors
    ///
    /// This function returns a `tonic::Status` error in the following cases:
    /// - If the access token does not have the `ManageIpList` permission, an error is returned.
    /// - If there is an error removing the IP address from the storage, an error is returned.
    async fn delete_ip_from_white_list(
        &self,
        request: tonic::Request<proto::DeleteIpFromListRequest>,
    ) -> std::result::Result<tonic::Response<proto::DeleteIpFromListResponse>, tonic::Status> {
        let input = request.get_ref();

        self.check_permission(&input.access_token, Permission::ManageIpList)
            .await
            .map_err(map_api_to_grpc_error)?;

        self.delete_ip_from_white_list(input.ip.clone())
            .await
            .map_err(map_api_to_grpc_error)?;

        Ok(tonic::Response::new(proto::DeleteIpFromListResponse {}))
    }

    /// Checks if the given IP address is in the black list.
    ///
    /// # Arguments
    ///
    /// * `request` - A `tonic::Request` containing a `proto::IsIpInListRequest`, which includes
    ///   the IP address to be checked and an access token.
    ///
    /// # Returns
    ///
    /// * `Result<tonic::Response<proto::IsIpInListResponse>, tonic::Status>` - Returns a
    ///   `tonic::Response` with an `IsIpInListResponse` on success, or a `tonic::Status`
    ///   error if the operation fails due to permission issues or storage errors.
    ///
    /// # Errors
    ///
    /// This function returns a `tonic::Status` error in the following cases:
    /// - If the access token does not have the `ViewIpList` permission, an error is returned.
    /// - If there is an error checking the IP address in the storage, an error is returned.
    async fn is_ip_in_black_list(
        &self,
        request: tonic::Request<proto::IsIpInListRequest>,
    ) -> std::result::Result<tonic::Response<proto::IsIpInListResponse>, tonic::Status> {
        let input = request.get_ref();

        self.check_permission(&input.access_token, Permission::ViewIpList)
            .await
            .map_err(map_api_to_grpc_error)?;

        let ok = self
            .is_ip_in_black_list(input.ip.clone())
            .await
            .map_err(map_api_to_grpc_error)?;

        Ok(tonic::Response::new(proto::IsIpInListResponse { ok }))
    }

    /// Checks if the given IP address is in the white list.
    ///
    /// # Arguments
    ///
    /// * `request` - A `tonic::Request` containing a `proto::IsIpInListRequest`, which includes
    ///   the IP address to be checked and an access token.
    ///
    /// # Returns
    ///
    /// * `Result<tonic::Response<proto::IsIpInListResponse>, tonic::Status>` - Returns a
    ///   `tonic::Response` with an `IsIpInListResponse` on success, or a `tonic::Status`
    ///   error if the operation fails due to permission issues or storage errors.
    ///
    /// # Errors
    ///
    /// This function returns a `tonic::Status` error in the following cases:
    /// - If the access token does not have the `ViewIpList` permission, an error is returned.
    /// - If there is an error checking the IP address in the storage, an error is returned.
    async fn is_ip_in_white_list(
        &self,
        request: tonic::Request<proto::IsIpInListRequest>,
    ) -> std::result::Result<tonic::Response<proto::IsIpInListResponse>, tonic::Status> {
        let input = request.get_ref();

        self.check_permission(&input.access_token, Permission::ViewIpList)
            .await
            .map_err(map_api_to_grpc_error)?;

        let ok = self
            .is_ip_in_white_list(input.ip.clone())
            .await
            .map_err(map_api_to_grpc_error)?;

        Ok(tonic::Response::new(proto::IsIpInListResponse { ok }))
    }

    /// Clears the black list of all IP addresses.
    ///
    /// # Arguments
    ///
    /// * `request` - A `tonic::Request` containing a `proto::ClearListRequest`, which includes
    ///   an access token.
    ///
    /// # Returns
    ///
    /// * `Result<tonic::Response<proto::ClearBucketResponse>, tonic::Status>` - Returns a
    ///   `tonic::Response` with an empty `ClearBucketResponse` on success, or a `tonic::Status`
    ///   error if the operation fails due to permission issues or storage errors.
    ///
    /// # Errors
    ///
    /// This function returns a `tonic::Status` error in the following cases:
    /// - If the access token does not have the `ManageIpList` permission, an error is returned.
    /// - If there is an error clearing the black list in the storage, an error is returned.
    async fn clear_black_list(
        &self,
        request: tonic::Request<proto::ClearListRequest>,
    ) -> std::result::Result<tonic::Response<proto::ClearBucketResponse>, tonic::Status> {
        let input = request.get_ref();

        self.check_permission(&input.access_token, Permission::ManageIpList)
            .await
            .map_err(map_api_to_grpc_error)?;

        self.clear_black_list()
            .await
            .map_err(map_api_to_grpc_error)?;

        Ok(tonic::Response::new(proto::ClearBucketResponse {}))
    }

    /// Clears the white list of all IP addresses.
    ///
    /// # Arguments
    ///
    /// * `request` - A `tonic::Request` containing a `proto::ClearListRequest`, which includes
    ///   an access token.
    ///
    /// # Returns
    ///
    /// * `Result<tonic::Response<proto::ClearBucketResponse>, tonic::Status>` - Returns a
    ///   `tonic::Response` with an empty `ClearBucketResponse` on success, or a `tonic::Status`
    ///   error if the operation fails due to permission issues or storage errors.
    ///
    /// # Errors
    ///
    /// This function returns a `tonic::Status` error in the following cases:
    /// - If the access token does not have the `ManageIpList` permission, an error is returned.
    /// - If there is an error clearing the white list in the storage, an error is returned.
    async fn clear_white_list(
        &self,
        request: tonic::Request<proto::ClearListRequest>,
    ) -> std::result::Result<tonic::Response<proto::ClearBucketResponse>, tonic::Status> {
        let input = request.get_ref();

        self.check_permission(&input.access_token, Permission::ManageIpList)
            .await
            .map_err(map_api_to_grpc_error)?;

        self.clear_white_list()
            .await
            .map_err(map_api_to_grpc_error)?;

        Ok(tonic::Response::new(proto::ClearBucketResponse {}))
    }

    /// Resets the rate limiter for the given IP address, if present.
    ///
    /// # Arguments
    ///
    /// * `request` - A `tonic::Request` containing a `proto::ResetRateLimiterRequest`, which includes
    ///   an access token and an optional IP address.
    ///
    /// # Returns
    ///
    /// * `Result<tonic::Response<proto::ResetRateLimiterResponse>, tonic::Status>` - Returns a
    ///   `tonic::Response` with an empty `ResetRateLimiterResponse` on success, or a `tonic::Status`
    ///   error if the operation fails due to permission issues or storage errors.
    ///
    /// # Errors
    ///
    /// This function returns a `tonic::Status` error in the following cases:
    /// - If the access token does not have the `ResetRateLimiter` permission, an error is returned.
    /// - If there is an error resetting the rate limiter in the storage, an error is returned.
    async fn reset_rate_limiter(
        &self,
        request: tonic::Request<proto::ResetRateLimiterRequest>,
    ) -> std::result::Result<tonic::Response<proto::ResetRateLimiterResponse>, tonic::Status> {
        let input = request.get_ref();

        self.check_permission(&input.access_token, Permission::ResetRateLimiter)
            .await
            .map_err(map_api_to_grpc_error)?;

        if let Some(ip) = input.ip.as_ref() {
            self.reset_ip_rate_limiter(ip.clone()).await;
        }

        Ok(tonic::Response::new(proto::ResetRateLimiterResponse {}))
    }

    /// A simple health check function that always returns a successful response.
    ///
    /// # Arguments
    ///
    /// * `_request` - A `tonic::Request` containing a `proto::HealthCheckRequest`.
    ///
    /// # Returns
    ///
    /// * `Result<tonic::Response<proto::HealthCheckResponse>, tonic::Status>` - Always returns a
    ///   successful `tonic::Response` with an empty `HealthCheckResponse`.
    async fn health_check(
        &self,
        _request: tonic::Request<proto::HealthCheckRequest>,
    ) -> std::result::Result<tonic::Response<proto::HealthCheckResponse>, tonic::Status> {
        Ok(tonic::Response::new(proto::HealthCheckResponse {}))
    }

    /// Authenticates a user with the given credentials and returns a pair of access and refresh tokens.
    ///
    /// # Arguments
    ///
    /// * `request` - A `tonic::Request` containing a `proto::AuthRequest`, which includes the user's
    ///   login credentials and IP address.
    ///
    /// # Returns
    ///
    /// * `Result<tonic::Response<proto::AuthResponse>, tonic::Status>` - Returns a `tonic::Response` with
    ///   an `AuthResponse` containing the access and refresh tokens on success, or a `tonic::Status` error
    ///   if the operation fails due to permission issues or storage errors.
    ///
    /// # Errors
    ///
    /// This function returns a `tonic::Status` error in the following cases:
    /// - If the credentials are invalid or the user does not exist, an error is returned.
    /// - If the user is not allowed to authenticate (e.g. due to an IP ban), an error is returned.
    /// - If an error occurs while retrieving the user's role from the storage, an error is returned.
    async fn auth(
        &self,
        request: tonic::Request<proto::AuthRequest>,
    ) -> std::result::Result<tonic::Response<proto::AuthResponse>, tonic::Status> {
        let input = request.get_ref();
        let (access_token, refresh_token) = self
            .auth(Credentials {
                login: input.login.clone(),
                password: input.password.clone(),
                ip: input.ip.clone(),
            })
            .await
            .map_err(map_api_to_grpc_error)?;
        Ok(tonic::Response::new(proto::AuthResponse {
            access_token,
            refresh_token,
        }))
    }

    /// Refreshes the access token using the provided refresh token.
    ///
    /// # Arguments
    ///
    /// * `request` - A `tonic::Request` containing a `proto::RefreshAccessTokenRequest`, which includes
    ///   the current access token and refresh token to be refreshed.
    ///
    /// # Returns
    ///
    /// * `Result<tonic::Response<proto::RefreshAccessTokenResponse>, tonic::Status>` - Returns a
    ///   `tonic::Response` with a `RefreshAccessTokenResponse` containing the new access and refresh
    ///   tokens on success, or a `tonic::Status` error if the operation fails due to permission issues
    ///   or storage errors.
    ///
    /// # Errors
    ///
    /// This function returns a `tonic::Status` error in the following cases:
    /// - If the refresh operation fails, an error is returned.
    /// - If an error occurs while releasing the access token, an error is returned.
    async fn refresh_access_token(
        &self,
        request: tonic::Request<proto::RefreshAccessTokenRequest>,
    ) -> std::result::Result<tonic::Response<proto::RefreshAccessTokenResponse>, tonic::Status>
    {
        let input = request.get_ref();
        let access_token = input.access_token.clone();
        let refresh_token = input.refresh_token.clone();
        let (new_access_token, new_refresh_token) = self
            .refresh_access_token(&access_token, &refresh_token)
            .await
            .map_err(map_api_to_grpc_error)?;

        Ok(tonic::Response::new(proto::RefreshAccessTokenResponse {
            access_token: new_access_token,
            refresh_token: new_refresh_token,
        }))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    Builder::new().init();

    let args = Args::parse();

    info!(args:serde = args; "cli arguments");

    let addr = args.addr.parse().unwrap();
    let path = Path::new(&args.config_path);

    let config = Config::parse(path);

    info!(config:serde = config; "server config");

    let db_config = DbConfig::from_env();

    info!(config:serde = db_config; "db config");

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
        .serve_with_shutdown(addr, shutdown_signal())
        .await?;

    Ok(())
}

/// Graceful shutdown.
async fn shutdown_signal() {
    // сигнал "ctrl_c"
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    // сигнал terminate
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };
    // отслеживание всех сигналов завершения
    tokio::select! {
        _ = ctrl_c => { info!("Shutting down server...") },
        _ = terminate => { info!("Shutting down server...") },
    }
}
