use cucumber::{given, then, when, World as _};

#[derive(cucumber::World, Debug, Default)]
struct World {
    black_list: Vec<String>,
    white_list: Vec<String>,
    list_kind: String,
}

#[given(regex = r#"(.+) list$"#)]
async fn black_list_is(w: &mut World, list_kind: String) {
    if list_kind == "black" {
        w.black_list = Vec::new();
        w.list_kind = list_kind;
    } else if list_kind == "white" {
        w.white_list = Vec::new();
        w.list_kind = list_kind;
    } else {
        panic!("Unknown list kind: {}", list_kind)
    }
}

#[when(regex = r#"^add ip (.+)"#)]
async fn add_ip_in_list(w: &mut World, ip: String) {
    if w.list_kind == "black" {
        w.black_list.push(ip);
    } else if w.list_kind == "white" {
        w.white_list.push(ip);
    } else {
        panic!("Unknown list kind: {}", w.list_kind)
    }
}

#[then("ok")]
async fn is_ok(w: &mut World) {
    if w.list_kind == "black" {
        assert!(w.black_list.len() > 0, "black list is empty");
    } else if w.list_kind == "white" {
        assert!(w.white_list.len() > 0, "white list is empty");
    } else {
        panic!("Unknown list kind: {}", w.list_kind)
    }
}

#[tokio::main]
async fn main() {
    World::run("tests/api/ip_list/features").await;
}
