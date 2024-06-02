use super::ip::IP;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub struct List {
    client: tokio_postgres::Client,
    kind: String,
}

impl List {
    pub fn new(client: tokio_postgres::Client, kind: &str) -> Self {
        Self {
            client,
            kind: kind.to_owned(),
        }
    }

    pub async fn has(&self, ip: &IP) -> Result<bool> {
        let row = match ip.network_length() {
            Some(network_length) => {
                self.client
                    .query_one(
                        r#"
SELECT EXISTS(
    SELECT 1 FROM ip_list 
    WHERE kind = $1 AND ip = $2 AND network_length = $3
)"#,
                        &[
                            &self.kind.clone(),
                            &ip.octets(),
                            &network_length.to_string(),
                        ],
                    )
                    .await
            }
            None => {
                self.client
                    .query_one(
                        r#"
SELECT EXISTS(
    SELECT 1 FROM ip_list 
    WHERE kind = $1 AND ip = $2
)"#,
                        &[&self.kind.as_str(), &ip.octets()],
                    )
                    .await
            }
        }?;

        let result: bool = row.try_get(0)?;

        Ok(result)
    }

    pub async fn add(&self, ip: &IP) -> Result<()> {
        self.client
            .execute(
                r#"
INSERT INTO ip_list (ip, mask, ip_str, mask_int, is_v6, kind) 
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT DO NOTHING"#,
                &[
                    &ip.octets(),
                    &ip.mask(),
                    &ip.addr(),
                    &ip.network_length()
                        .map(|mask| mask.to_string())
                        .unwrap_or_default(),
                    &ip.is_v6(),
                    &self.kind.clone(),
                ],
            )
            .await?;

        return Ok(());
    }

    pub async fn delete(&self, ip: IP) -> Result<()> {
        match ip.network_length() {
            Some(network_length) => {
                self.client
                    .execute(
                        r#"
DELETE FROM ip_list 
WHERE kind = $1 AND ip = $2 AND network_length = $3"#,
                        &[
                            &self.kind.clone(),
                            &ip.octets(),
                            &network_length.to_string(),
                        ],
                    )
                    .await?;
            }
            None => {
                self.client
                    .execute(
                        r#"
DELETE FROM ip_list 
WHERE kind = $1 AND ip = $2"#,
                        &[&self.kind.clone(), &ip.octets()],
                    )
                    .await?;
            }
        }

        return Ok(());
    }

    pub async fn is_conform(&self, ip: IP) -> Result<bool> {
        let row = self
            .client
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
