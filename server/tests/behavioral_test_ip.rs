use cucumber::{given, then, when, World as _};
use proto::api_client::ApiClient;
use std::str::FromStr;

#[derive(Debug, Clone, Copy)]
enum ListKind {
    White,
    Black,
}

impl FromStr for ListKind {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "white" => Ok(ListKind::White),
            "black" => Ok(ListKind::Black),
            _ => Err(format!("Unknown list kind: {}", s)),
        }
    }
}

// TODO: move port to env var
const ADDR: &str = "http://[::1]:50051";

pub mod proto {
    tonic::include_proto!("api");
}

#[derive(Debug)]
enum Status {
    Ok(String),
    Error(String),
}

impl Default for Status {
    fn default() -> Self {
        Status::Ok("ok".to_string())
    }
}

impl Status {
    pub fn is_ok(&self) -> bool {
        matches!(*self, Status::Ok(_))
    }

    pub fn from_grpc(status: tonic::Status) -> Self {
        Status::Error(format!("grpc status: {:?}", status))
    }

    pub fn panic(&self) {
        panic!("{:?}", self);
    }

    pub fn ok_or_panic(&self, f: impl FnOnce(&str)) {
        match *self {
            Status::Ok(ref s) => f(s),
            Status::Error(_) => self.panic(),
        }
    }
}

#[derive(cucumber::World, Debug, Default)]
struct World {
    status: Status,
}

#[given(regex = r#"^empty (.+) list$"#)]
async fn empty_list(_w: &mut World, list_kind: String) {
    let req = proto::ClearListRequest {};
    let request = tonic::Request::new(req);

    let mut client = ApiClient::connect(ADDR).await.unwrap();

    match ListKind::from_str(&list_kind).unwrap() {
        ListKind::White => client.clear_white_list(request).await,
        ListKind::Black => client.clear_black_list(request).await,
    }
    .unwrap();
}

#[given(regex = r#"(.+) list with ip (.+)$"#)]
async fn given_list_with_ip(_w: &mut World, list_kind: String, ip: String) {
    do_add_ip_in_list(&ip, ListKind::from_str(&list_kind).unwrap())
        .await
        .unwrap();
}

#[given(regex = r#"(.+) list without ip (.+)$"#)]
async fn given_list_without_ip(_w: &mut World, list_kind: String, ip: String) {
    do_delete_ip_from_list(&ip, ListKind::from_str(&list_kind).unwrap())
        .await
        .unwrap();
}

#[when(regex = r#"^add ip (.+) to (.+) list$"#)]
async fn add_ip_in_list(w: &mut World, ip: String, list_kind: String) {
    w.status = match do_add_ip_in_list(&ip, ListKind::from_str(&list_kind).unwrap()).await {
        Ok(_) => Status::default(),
        Err(status) => Status::from_grpc(status),
    }
}

#[when(regex = r#"^delete ip (.+) from (.+) list$"#)]
async fn delete_ip_from_list(w: &mut World, ip: String, list_kind: String) {
    w.status = match do_delete_ip_from_list(&ip, ListKind::from_str(&list_kind).unwrap()).await {
        Ok(_) => Status::default(),
        Err(status) => Status::from_grpc(status),
    }
}

#[when(regex = r#"^checking authorization with ip (.+)$"#)]
async fn checking_authorization_with_ip(w: &mut World, ip: String) {
    let req = proto::IsAuthAllowedRequest {
        login: "some_test_login".to_owned(),
        password: "some_test_password".to_owned(),
        ip: ip.to_string(),
    };
    let request = tonic::Request::new(req);

    let mut client = ApiClient::connect(ADDR).await.unwrap();

    w.status = match client.is_auth_allowed(request).await {
        Ok(result) => Status::Ok(result.get_ref().ok.to_string()),
        Err(status) => Status::from_grpc(status),
    }
}

#[then("response status is ok")]
async fn is_response_ok(w: &mut World) {
    assert!(w.status.is_ok());
}

#[then(regex = r#"^(.+) list has ip (.+)"#)]
async fn list_has_ip(w: &mut World, list_kind: String, ip: String) {
    match check_list_has_ip(w, ListKind::from_str(&list_kind).unwrap(), ip).await {
        Ok(response) => {
            assert!(response.get_ref().ok);
        }
        Err(status) => Status::from_grpc(status).panic(),
    }
}

#[then(regex = r#"^(.+) list hasn't ip (.+)"#)]
async fn list_has_not_ip(w: &mut World, list_kind: String, ip: String) {
    match check_list_has_ip(w, ListKind::from_str(&list_kind).unwrap(), ip).await {
        Ok(response) => {
            assert!(!response.get_ref().ok);
        }
        Err(status) => Status::from_grpc(status).panic(),
    }
}

#[then(regex = "authorization is not allowed")]
async fn authorization_is_not_allowed(w: &mut World) {
    w.status.ok_or_panic(|r| assert_eq!(r, "false"));
}

#[then(regex = "authorization is allowed")]
async fn authorization_is_allowed(w: &mut World) {
    w.status.ok_or_panic(|r| assert_eq!(r, "true"));
}

async fn do_add_ip_in_list(
    ip: &str,
    list_kind: ListKind,
) -> Result<tonic::Response<proto::AddIpInListResponse>, tonic::Status> {
    let req = proto::AddIpInListRequest { ip: ip.to_string() };
    let request = tonic::Request::new(req);

    let mut client = ApiClient::connect(ADDR).await.unwrap();

    match list_kind {
        ListKind::White => client.add_ip_in_white_list(request).await,
        ListKind::Black => client.add_ip_in_black_list(request).await,
    }
}

async fn do_delete_ip_from_list(
    ip: &str,
    list_kind: ListKind,
) -> Result<tonic::Response<proto::DeleteIpFromListResponse>, tonic::Status> {
    let req = proto::DeleteIpFromListRequest { ip: ip.to_string() };
    let request = tonic::Request::new(req);

    let mut client = ApiClient::connect(ADDR).await.unwrap();

    match list_kind {
        ListKind::White => client.delete_ip_from_white_list(request).await,
        ListKind::Black => client.delete_ip_from_black_list(request).await,
    }
}

async fn check_list_has_ip(
    w: &mut World,
    list_kind: ListKind,
    ip: String,
) -> Result<tonic::Response<proto::IsIpInListResponse>, tonic::Status> {
    let mut client = ApiClient::connect(ADDR).await.unwrap();

    let req = proto::IsIpInListRequest { ip: ip.to_string() };
    let request = tonic::Request::new(req);

    match list_kind {
        ListKind::White => client.is_ip_in_white_list(request).await,
        ListKind::Black => client.is_ip_in_black_list(request).await,
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    World::run("tests/api/features").await;
    Ok(())
}
