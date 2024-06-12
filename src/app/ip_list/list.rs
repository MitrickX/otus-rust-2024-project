use super::ip::Ip;
use std::sync::Arc;
use tokio::sync::Mutex;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
type Client = Arc<Mutex<tokio_postgres::Client>>;

#[derive(Debug)]
pub struct List {
    client: Client,
    kind: String,
}

impl List {
    pub fn new(client: Client, kind: &str) -> Self {
        Self {
            client,
            kind: kind.to_owned(),
        }
    }

    pub async fn has(&self, ip: &Ip) -> Result<bool> {
        let row = match ip.network_length() {
            Some(network_length) => {
                Arc::clone(&self.client)
                    .lock()
                    .await
                    .query_one(
                        r#"
SELECT EXISTS(
    SELECT 1 FROM ip_list 
    WHERE kind = $1 AND ip = $2 AND network_length = $3
)"#,
                        &[&self.kind.clone(), &ip.octets(), &(network_length as i16)],
                    )
                    .await
            }
            None => {
                Arc::clone(&self.client)
                    .lock()
                    .await
                    .query_one(
                        r#"
SELECT EXISTS(
    SELECT 1 FROM ip_list 
    WHERE kind = $1 AND ip = $2 AND network_length IS NULL
)"#,
                        &[&self.kind.as_str(), &ip.octets()],
                    )
                    .await
            }
        }?;

        let result: bool = row.try_get(0)?;

        Ok(result)
    }

    pub async fn add(&self, ip: &Ip) -> Result<()> {
        Arc::clone(&self.client)
            .lock()
            .await
            .execute(
                r#"
        INSERT INTO ip_list (ip, mask, ip_str, network_length, is_v6, kind)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT DO NOTHING"#,
                &[
                    &ip.octets(),
                    &ip.mask(),
                    &ip.addr(),
                    &ip.network_length().map(|mask| mask as i16),
                    &ip.is_v6(),
                    &self.kind.clone(),
                ],
            )
            .await?;

        Ok(())
    }

    pub async fn clear(&self) -> Result<()> {
        Arc::clone(&self.client)
            .lock()
            .await
            .execute("DELETE FROM ip_list WHERE kind = $1", &[&self.kind.clone()])
            .await?;

        Ok(())
    }

    pub async fn delete(&self, ip: &Ip) -> Result<()> {
        match ip.network_length() {
            Some(network_length) => {
                Arc::clone(&self.client)
                    .lock()
                    .await
                    .execute(
                        r#"
DELETE FROM ip_list 
WHERE kind = $1 AND ip = $2 AND network_length = $3"#,
                        &[&self.kind.clone(), &ip.octets(), &(network_length as i16)],
                    )
                    .await?;
            }
            None => {
                Arc::clone(&self.client)
                    .lock()
                    .await
                    .execute(
                        r#"
DELETE FROM ip_list 
WHERE kind = $1 AND ip = $2"#,
                        &[&self.kind.clone(), &ip.octets()],
                    )
                    .await?;
            }
        }

        Ok(())
    }

    pub async fn is_conform(&self, ip: &Ip) -> Result<bool> {
        let row = Arc::clone(&self.client)
            .lock()
            .await
            .query_one(
                r#"
SELECT EXISTS(
    SELECT 1 FROM ip_list 
    WHERE (
        -- condition when search pure ip exact as it
        ip = $1 
            OR 
        -- condition when find subnet (network) that contains this pure ip   
        ((ip & mask) = ($1 & mask)) 
    ) AND kind = $2 AND is_v6 = $3
)"#,
                &[&ip.octets(), &self.kind.clone(), &ip.is_v6()],
            )
            .await?;

        let result: bool = row.try_get(0)?;

        Ok(result)
    }
}
