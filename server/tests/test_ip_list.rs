use cidr::IpCidr;
use serde::{Deserialize, Serialize};
use serde_yml;
use server::app::{
    config::Db,
    connection::connect,
    ip_list::{ip::Ip, list::List},
    migrations::run_app_migrations,
};
use std::{path::Path, str::FromStr, sync::Arc};
use tokio::sync::Mutex;

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub db: Db,
}

const CONFIG_PATH: &str = "../configs/tests/config.yaml";

impl Config {
    pub fn parse(file_path: &Path) -> Result<Self, Box<serde_yml::Error>> {
        let content = std::fs::read_to_string(file_path).unwrap();
        let config: Config = serde_yml::from_str(&content)?;
        Ok(config)
    }
}

async fn setup(list_kind: &str) -> Config {
    let mut path = std::env::current_dir().unwrap();
    path.push(CONFIG_PATH);

    let config = Config::parse(path.as_path()).unwrap();

    let (mut client, connection) = connect(&config.db).await;

    // The connection object performs the actual communication with the database,
    // so spawn it off to run on its own.
    tokio::spawn(async move {
        connection.await.unwrap();
    });

    run_app_migrations(&mut client).await;

    // clear all records for new test
    client
        .execute(r#"DELETE FROM ip_list WHERE kind = $1"#, &[&list_kind])
        .await
        .unwrap();

    config
}

#[tokio::test]
async fn test_ip_list_simple_crud() {
    let list_kind = "test_ip_list_simple_crud";

    let config = setup(&list_kind).await;

    let (client, connection) = connect(&config.db).await;

    // The connection object performs the actual communication with the database,
    // so spawn it off to run on its own.
    tokio::spawn(async move {
        connection.await.unwrap();
    });

    let client = Arc::new(Mutex::new(client));
    let list = List::new(Arc::clone(&client), &list_kind);
    let ip_v4_with_mask = Ip::from_str("192.168.56.0/24").unwrap();
    let ip_v4_without_mask = Ip::from_str("192.168.56.1").unwrap();
    let ip_v6_with_mask = Ip::from_str("2001:1111:2222:3333::/64").unwrap();
    let ip_v6_without_mask = Ip::from_str("5be8:dde9:7f0b:d5a7:bd01:b3be:9c69:573b").unwrap();

    list.add(&ip_v4_with_mask).await.unwrap();
    list.add(&ip_v4_without_mask).await.unwrap();
    list.add(&ip_v6_with_mask).await.unwrap();
    list.add(&ip_v6_without_mask).await.unwrap();

    // repeating adding should be fine - no panic
    list.add(&ip_v4_with_mask).await.unwrap();
    list.add(&ip_v4_without_mask).await.unwrap();
    list.add(&ip_v6_with_mask).await.unwrap();
    list.add(&ip_v6_without_mask).await.unwrap();

    // total count is 4 records
    let result = Arc::clone(&client)
        .lock()
        .await
        .query_one(
            r#"SELECT COUNT(*) as count FROM ip_list WHERE kind = $1"#,
            &[&list_kind],
        )
        .await
        .unwrap();

    assert_eq!(
        result.get::<_, i64>("count"),
        4,
        "should be 4 records so far"
    );

    assert!(
        list.has(&ip_v4_with_mask).await.unwrap(),
        "should has ip_v4_with_mask"
    );
    assert!(
        list.has(&ip_v4_without_mask).await.unwrap(),
        "should has ip_v4_without_mask"
    );
    assert!(
        list.has(&ip_v6_with_mask).await.unwrap(),
        "should has ip_v6_with_mask"
    );
    assert!(
        list.has(&ip_v6_without_mask).await.unwrap(),
        "should has ip_v6_without_mask"
    );

    assert!(!list.has(&Ip::from_str("1.1.1.1").unwrap()).await.unwrap());
    assert!(!list.has(&Ip::from_str("::1").unwrap()).await.unwrap());
    assert!(!list.has(&Ip::from_str("::1:1:1").unwrap()).await.unwrap());
    assert!(!list
        .has(&Ip::from_str("192.168.56.0").unwrap())
        .await
        .unwrap());

    assert!(
        list.is_conform(&Ip::from_str("192.168.56.0").unwrap())
            .await
            .unwrap(),
        "should be conform because list has 192.168.56.0/24 network"
    );

    assert!(
        list.is_conform(&Ip::from_str("192.168.56.1").unwrap())
            .await
            .unwrap(),
        "should be conform because list has 192.168.56.1 ip address"
    );

    assert!(
        list.is_conform(&Ip::from_str("192.168.56.2").unwrap())
            .await
            .unwrap(),
        "should be conform because list has 192.168.56.0/24 network"
    );

    list.delete(&ip_v4_with_mask).await.unwrap();
    list.delete(&ip_v4_without_mask).await.unwrap();
    list.delete(&ip_v6_with_mask).await.unwrap();
    list.delete(&ip_v6_without_mask).await.unwrap();

    // total count is 4 records
    let result = Arc::clone(&client)
        .lock()
        .await
        .query_one(
            r#"SELECT COUNT(*) as count FROM ip_list WHERE kind = $1"#,
            &[&list_kind],
        )
        .await
        .unwrap();

    assert_eq!(
        result.get::<_, i64>("count"),
        0,
        "should be 4 records after this test"
    );
}

#[tokio::test]
async fn test_conform_ip_v4() {
    let list_kind = "test_conform_ip_v4";
    let config = setup(list_kind).await;

    let (client, connection) = connect(&config.db).await;

    // The connection object performs the actual communication with the database,
    // so spawn it off to run on its own.
    tokio::spawn(async move {
        connection.await.unwrap();
    });

    let client = Arc::new(Mutex::new(client));
    let list = List::new(Arc::clone(&client), &list_kind);

    let ip_str = "192.168.56.0/24";
    list.add(&Ip::from_str(ip_str).unwrap()).await.unwrap();

    for ip_in_network in IpCidr::from_str(ip_str).unwrap().into_iter() {
        let ip_addr = ip_in_network.address();
        assert!(
            list.is_conform(&Ip::from_str(&ip_addr.to_string()).unwrap())
                .await
                .unwrap(),
            "should be conform because list has 192.168.56.0/24 network"
        );
    }

    let ip_net_str = "192.168.33.0/24";
    let ip_str = "192.168.33.124";

    list.add(&Ip::from_str(ip_str).unwrap()).await.unwrap();

    for ip_in_network in IpCidr::from_str(ip_net_str).unwrap().into_iter() {
        let ip_addr = ip_in_network.address();
        let ip_addr_str = ip_addr.to_string();
        if ip_addr_str != ip_str {
            assert!(
                !list
                    .is_conform(&Ip::from_str(&ip_addr_str).unwrap())
                    .await
                    .unwrap(),
                "should NOT be conform because list has NOT 192.168.33.0/24 network"
            );
        } else {
            assert!(
                list.is_conform(&Ip::from_str("192.168.33.124").unwrap())
                    .await
                    .unwrap(),
                "conform because has 192.168.55.124"
            );
        }
    }
}

#[tokio::test]
async fn test_conform_ip_v6() {
    let list_kind = "test_conform_ip_v6";
    let config = setup(list_kind).await;

    let (client, connection) = connect(&config.db).await;

    // The connection object performs the actual communication with the database,
    // so spawn it off to run on its own.
    tokio::spawn(async move {
        connection.await.unwrap();
    });

    let client = Arc::new(Mutex::new(client));
    let list = List::new(Arc::clone(&client), &list_kind);

    let ip_str = "2001:1111:2222:3333::/64";
    list.add(&Ip::from_str(ip_str).unwrap()).await.unwrap();

    // positive cases

    assert!(
        list.is_conform(&Ip::from_str("2001:1111:2222:3333::").unwrap())
            .await
            .unwrap(),
        "should be conform because list has 2001:1111:2222:3333::/64 network"
    );

    assert!(
        list.is_conform(&Ip::from_str("2001:1111:2222:3333::1").unwrap())
            .await
            .unwrap(),
        "should be conform because list has 2001:1111:2222:3333::/64 network"
    );

    assert!(
        list.is_conform(&Ip::from_str("2001:1111:2222:3333::ffff").unwrap())
            .await
            .unwrap(),
        "should be conform because list has 2001:1111:2222:3333::/64 network"
    );

    assert!(
        list.is_conform(&Ip::from_str("2001:1111:2222:3333:ffff:ffff:1234:ffff").unwrap())
            .await
            .unwrap(),
        "should be conform because list has 2001:1111:2222:3333::/64 network"
    );

    assert!(
        list.is_conform(&Ip::from_str("2001:1111:2222:3333:ffff:ffff:1234:1").unwrap())
            .await
            .unwrap(),
        "should be conform because list has 2001:1111:2222:3333::/64 network"
    );

    assert!(
        list.is_conform(&Ip::from_str("2001:1111:2222:3333:ffff:ffff:0001:ffff").unwrap())
            .await
            .unwrap(),
        "should be conform because list has 2001:1111:2222:3333::/64 network"
    );

    assert!(
        list.is_conform(&Ip::from_str("2001:1111:2222:3333::").unwrap())
            .await
            .unwrap(),
        "should be conform because list has 2001:1111:2222:3333::/64 network"
    );

    assert!(
        list.is_conform(&Ip::from_str("2001:1111:2222:3333::1").unwrap())
            .await
            .unwrap(),
        "should be conform because list has 2001:1111:2222:3333::/64 network"
    );

    assert!(
        list.is_conform(&Ip::from_str("2001:1111:2222:3333::ffff").unwrap())
            .await
            .unwrap(),
        "should be conform because list has 2001:1111:2222:3333::/64 network"
    );

    assert!(
        list.is_conform(&Ip::from_str("2001:1111:2222:3333:ffff:ffff:1234:ffff").unwrap())
            .await
            .unwrap(),
        "should be conform because list has 2001:1111:2222:3333::/64 network"
    );

    assert!(
        list.is_conform(&Ip::from_str("2001:1111:2222:3333:ffff:ffff:1234:1").unwrap())
            .await
            .unwrap(),
        "should be conform because list has 2001:1111:2222:3333::/64 network"
    );

    assert!(
        list.is_conform(&Ip::from_str("2001:1111:2222:3333:ffff:ffff:0001:ffff").unwrap())
            .await
            .unwrap(),
        "should be conform because list has 2001:1111:2222:3333::/64 network"
    );

    // negative cases

    assert!(
        !list
            .is_conform(&Ip::from_str("2001:1111:2222:ffcc::").unwrap())
            .await
            .unwrap(),
        "should not be conform because list has not 2001:1111:2222:ffcc::/64 network or this ip"
    );

    assert!(
        !list
            .is_conform(&Ip::from_str("2001:1111:2222:ffcc::1").unwrap())
            .await
            .unwrap(),
        "should not be conform because list has not 2001:1111:2222:ffcc::/64 network or this ip"
    );

    assert!(
        !list
            .is_conform(&Ip::from_str("2001:1111:2222:ffcc::ffff").unwrap())
            .await
            .unwrap(),
        "should not be conform because list has not 2001:1111:2222:ffcc::/64 network or this ip"
    );

    assert!(
        !list
            .is_conform(&Ip::from_str("2001:1111:2222:ffcc:ffff:ffff:1234:ffff").unwrap())
            .await
            .unwrap(),
        "should not be conform because list has not 2001:1111:2222:ffcc::/64 network or this ip"
    );

    assert!(
        !list
            .is_conform(&Ip::from_str("2001:1111:2222:ffcc:ffff:ffff:1234:1").unwrap())
            .await
            .unwrap(),
        "should not be conform because list has not 2001:1111:2222:ffcc::/64 network or this ip"
    );

    // one more positive case

    assert!(
        !list
            .is_conform(&Ip::from_str("2001:1111:2222:ffcc:ffff:ffff:0001:ffff").unwrap())
            .await
            .unwrap(),
        "should not be conform because list has not 2001:1111:2222:ffcc::/64 network or this ip"
    );

    list.add(&Ip::from_str("2001:1111:2222:ffcc:ffff:ffff:0001:ffff").unwrap())
        .await
        .unwrap();

    assert!(
        list.is_conform(&Ip::from_str("2001:1111:2222:ffcc:ffff:ffff:0001:ffff").unwrap())
            .await
            .unwrap(),
        "should be conform because list has exactly this ip"
    );
}
