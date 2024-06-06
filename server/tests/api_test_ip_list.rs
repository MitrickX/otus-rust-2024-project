use cucumber::{given, then, when, World as _};
use proto::api_client::ApiClient;

// TODO: move port to env var
const ADDR: &str = "http://[::1]:50051";

pub mod proto {
    tonic::include_proto!("api");
}

#[derive(cucumber::World, Debug, Default)]
struct World {
    status: String,
}

#[given(regex = r#"API Client$"#)]
async fn given_api_client(w: &mut World) {
    // check connection to server
    ApiClient::connect(ADDR).await.unwrap();
}

#[when(regex = r#"^add ip (.+) to (.+) list"#)]
async fn add_ip_in_list(w: &mut World, ip: String, list_kind: String) {
    if list_kind != "black" && list_kind != "white" {
        panic!("Unknown list kind: {}", list_kind)
    }

    let req = proto::AddIpInListRequest { ip };
    let request = tonic::Request::new(req);

    let mut client = ApiClient::connect(ADDR).await.unwrap();

    match client.add_in_black_list(request).await {
        Ok(_) => w.status = "ok".to_string(),
        Err(status) => w.status = format!("grpc status: {:?}", status),
    }
}

#[then("response is ok")]
async fn is_response_ok(w: &mut World) {
    assert_eq!("ok", w.status);
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    World::run("tests/api/ip_list/features").await;

    Ok(())
}
