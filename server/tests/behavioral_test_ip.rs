use cucumber::{given, then, when, World as _};
use proto::api_client::ApiClient;
use rand::Rng;
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

#[derive(Debug, Clone, Copy)]
enum CredentialKey {
    Login,
    Password,
    Ip,
}

impl FromStr for CredentialKey {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "login" => Ok(CredentialKey::Login),
            "password" => Ok(CredentialKey::Password),
            "ip" => Ok(CredentialKey::Ip),
            _ => Err(format!("Unknown credential key: {}", s)),
        }
    }
}

// TODO: move port to env var
const ADDR: &str = "http://[::1]:50051";

pub mod proto {
    tonic::include_proto!("api");
}

#[derive(Debug, PartialEq)]
enum Status {
    Ok(String),
    Error(String),
}

impl Default for Status {
    fn default() -> Self {
        Status::Ok("".to_string())
    }
}

impl Status {
    pub fn from_grpc(status: tonic::Status) -> Self {
        Status::Error(format!("grpc status: {:?}", status))
    }

    pub fn panic(&self) {
        panic!("{:?}", self);
    }

    pub fn ok_or_panic(&self, f: impl FnOnce(&str)) {
        match *self {
            Status::Ok(ref s) => f(s),
            Status::Error(ref s) => panic!("{:?}", s),
        }
    }
}

#[derive(cucumber::World, Debug, Default)]
struct World {
    statuses: Vec<Status>,
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

#[given(regex = r#"reset rate limter for (ip|login|password) (.+)$"#)]
async fn reset_rate_limiter(w: &mut World, credential_key: String, credential_val: String) {
    let key = CredentialKey::from_str(&credential_key).unwrap();

    let req = match key {
        CredentialKey::Ip => proto::ResetRateLimiterRequest {
            login: None,
            password: None,
            ip: Some(credential_val),
        },
        CredentialKey::Login => proto::ResetRateLimiterRequest {
            login: Some(credential_val),
            password: None,
            ip: None,
        },
        CredentialKey::Password => proto::ResetRateLimiterRequest {
            login: None,
            password: Some(credential_val),
            ip: None,
        },
    };

    let request = tonic::Request::new(req);

    let mut client = ApiClient::connect(ADDR).await.unwrap();

    w.statuses = vec![match client.reset_rate_limiter(request).await {
        Ok(_) => Status::default(),
        Err(status) => Status::from_grpc(status),
    }];
}

#[when(regex = r#"^add ip (.+) to (.+) list$"#)]
async fn add_ip_in_list(w: &mut World, ip: String, list_kind: String) {
    w.statuses = vec![
        match do_add_ip_in_list(&ip, ListKind::from_str(&list_kind).unwrap()).await {
            Ok(_) => Status::default(),
            Err(status) => Status::from_grpc(status),
        },
    ];
}

#[when(regex = r#"^delete ip (.+) from (.+) list$"#)]
async fn delete_ip_from_list(w: &mut World, ip: String, list_kind: String) {
    w.statuses = vec![
        match do_delete_ip_from_list(&ip, ListKind::from_str(&list_kind).unwrap()).await {
            Ok(_) => Status::default(),
            Err(status) => Status::from_grpc(status),
        },
    ];
}

#[when(regex = r#"^checking authorization with (ip|login|password) (.+?)(?: (.+) times)?$"#)]
async fn checking_authorization_several_times(
    w: &mut World,
    credential_key: String,
    credential_val: String,
    how_much: String,
) {
    let credential_key = CredentialKey::from_str(&credential_key).unwrap();

    let n = if how_much.trim() == "max allowed" {
        // TODO: parse config and extract limit
        match credential_key {
            CredentialKey::Ip => 1000,
            CredentialKey::Login => 10,
            CredentialKey::Password => 100,
        }
    } else {
        1
    };

    w.statuses = Vec::<Status>::with_capacity(n);

    for _ in 0..n {
        w.statuses.push(
            match do_checking_authorization(credential_key, credential_val.clone()).await {
                Ok(result) => Status::Ok(result.get_ref().ok.to_string()),
                Err(status) => Status::from_grpc(status),
            },
        );
    }
}

#[when(regex = r#"^wait for (\d+) minute[s]?$"#)]
async fn wait_for_minutes(_w: &mut World, minutes: u64) {
    tokio::time::sleep(tokio::time::Duration::from_secs(minutes * 60)).await;
}

#[then(regex = r#"^(?:each )?response is Ok\((.*?)\)$"#)]
async fn is_response_ok(w: &mut World, val: String) {
    let expected = &Status::Ok(val);
    w.statuses.iter().enumerate().for_each(|(i, s)| {
        assert_eq!(expected, s, "unexpected response for #{}", i);
    });
}

#[then(regex = r#"^(.+) list has ip (.+)"#)]
async fn list_has_ip(_w: &mut World, list_kind: String, ip: String) {
    match check_list_has_ip(ListKind::from_str(&list_kind).unwrap(), ip).await {
        Ok(response) => {
            assert!(response.get_ref().ok);
        }
        Err(status) => Status::from_grpc(status).panic(),
    }
}

#[then(regex = r#"^(.+) list hasn't ip (.+)"#)]
async fn list_has_not_ip(_w: &mut World, list_kind: String, ip: String) {
    match check_list_has_ip(ListKind::from_str(&list_kind).unwrap(), ip).await {
        Ok(response) => {
            assert!(!response.get_ref().ok);
        }
        Err(status) => Status::from_grpc(status).panic(),
    }
}

#[then(regex = "authorization is not allowed")]
async fn authorization_is_not_allowed(w: &mut World) {
    w.statuses
        .last()
        .unwrap()
        .ok_or_panic(|r| assert_eq!(r, "false"));
}

#[then(regex = "authorization is allowed")]
async fn authorization_is_allowed(w: &mut World) {
    w.statuses
        .last()
        .unwrap()
        .ok_or_panic(|r| assert_eq!(r, "true"));
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

async fn do_checking_authorization(
    credential_key: CredentialKey,
    credential_val: String,
) -> Result<tonic::Response<proto::IsAuthAllowedResponse>, tonic::Status> {
    let req = match credential_key {
        CredentialKey::Ip => proto::IsAuthAllowedRequest {
            login: generate_string(6),
            password: generate_string(8),
            ip: credential_val,
        },
        CredentialKey::Login => proto::IsAuthAllowedRequest {
            login: credential_val,
            password: generate_string(8),
            ip: generate_simple_ip(),
        },
        CredentialKey::Password => proto::IsAuthAllowedRequest {
            login: generate_string(6),
            password: credential_val,
            ip: generate_simple_ip(),
        },
    };

    let request = tonic::Request::new(req);

    let mut client = ApiClient::connect(ADDR).await.unwrap();

    client.is_auth_allowed(request).await
}

fn generate_string(len: usize) -> String {
    let charset = "=+-_*&^%$#@!?abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    random_string::generate(len, charset)
}

fn generate_simple_ip() -> String {
    let mut rng = rand::thread_rng();
    format!(
        "{}.{}.{}.{}",
        rng.gen_range(0..=255),
        rng.gen_range(0..=255),
        rng.gen_range(0..=255),
        rng.gen_range(0..=255),
    )
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    World::run("tests/api/features").await;
    Ok(())
}
