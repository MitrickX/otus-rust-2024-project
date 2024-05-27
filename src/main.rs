use auth::server::service::auth::{Auth as AuthAppService, Credentials};
use proto::auth_server::{Auth, AuthServer};
use std::error::Error;
use tonic::transport::Server;

mod proto {
    tonic::include_proto!("auth");

    pub(crate) const FILE_DESCRIPTOR_SET: &[u8] =
        tonic::include_file_descriptor_set!("auth_descriptor");
}

#[derive(Debug, Default)]
struct AuthService {
    auth_app_service: AuthAppService,
}

#[tonic::async_trait]
impl Auth for AuthService {
    async fn auth(
        &self,
        request: tonic::Request<proto::AuthRequest>,
    ) -> Result<tonic::Response<proto::AuthResponse>, tonic::Status> {
        println!("Got a request: {:?}", request);

        let input = request.get_ref();

        let is_ok_auth = self
            .auth_app_service
            .check(Credentials {
                login: input.login.clone(),
                password: input.password.clone(),
                ip: input.ip.clone(),
            })
            .await;
        let response = proto::AuthResponse { ok: is_ok_auth };

        println!("Response: {:?}", response);

        Ok(tonic::Response::new(response))
    }
}

const ADDR: &str = "[::1]:50051";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let addr = ADDR.parse()?;
    let auth = AuthService::default();

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
