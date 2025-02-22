use cidr::IpCidr;
use server::app::{
    config::DbConfig,
    connection::connect,
    ip_list::{ip::Ip, list::List},
    migrations::run_app_migrations,
};
use std::{str::FromStr, sync::Arc};
use tokio::sync::OnceCell;

static ONCE_RUN_MIGRATIONS: OnceCell<()> = OnceCell::const_new();

async fn once_run_migrations() {
    ONCE_RUN_MIGRATIONS
        .get_or_init(|| async {
            let db_config = DbConfig::from_env();
            let (mut client, connection) = connect(&db_config).await;

            // The connection object performs the actual communication with the database,
            // so spawn it off to run on its own.
            tokio::spawn(async move {
                connection.await.unwrap();
            });

            run_app_migrations(&mut client).await;
        })
        .await;
}

async fn clear_ip_list(client: &tokio_postgres::Client, list_kind: &str) {
    // clear all records for new test
    client
        .execute(r#"DELETE FROM ip_list WHERE kind = $1"#, &[&list_kind])
        .await
        .unwrap();
}

#[tokio::test]
async fn test_ip_list_simple_crud() {
    once_run_migrations().await;

    let db_config = DbConfig::from_env();
    let (client, connection) = connect(&db_config).await;

    // The connection object performs the actual communication with the database,
    // so spawn it off to run on its own.
    tokio::spawn(async move {
        connection.await.unwrap();
    });

    let list_kind = "test_ip_list_simple_crud";
    clear_ip_list(&client, list_kind).await;

    let client = Arc::new(client);
    let list = List::new(Arc::clone(&client), list_kind);
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
    once_run_migrations().await;

    let db_config = DbConfig::from_env();
    let (client, connection) = connect(&db_config).await;

    // The connection object performs the actual communication with the database,
    // so spawn it off to run on its own.
    tokio::spawn(async move {
        connection.await.unwrap();
    });

    let list_kind = "test_conform_ip_v4";
    clear_ip_list(&client, list_kind).await;

    let client = Arc::new(client);
    let list = List::new(Arc::clone(&client), list_kind);

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
    once_run_migrations().await;

    let db_config = DbConfig::from_env();
    let (client, connection) = connect(&db_config).await;

    // The connection object performs the actual communication with the database,
    // so spawn it off to run on its own.
    tokio::spawn(async move {
        connection.await.unwrap();
    });

    let list_kind = "test_conform_ip_v6";
    clear_ip_list(&client, list_kind).await;

    let client = Arc::new(client);
    let list = List::new(Arc::clone(&client), list_kind);

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
