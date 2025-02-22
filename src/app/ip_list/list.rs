use super::ip::Ip;
use std::sync::Arc;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
type Client = Arc<tokio_postgres::Client>;

#[derive(Debug)]
pub struct List {
    client: Client,
    kind: String,
}

impl List {
    /// Create a new `List` instance.
    ///
    /// This function will create a new `List` instance with the given database client and kind.
    ///
    /// # Arguments
    ///
    /// * `client` - The database client to use for querying the `ip_list` table.
    /// * `kind` - The kind of list to create, one of "white" or "black".
    ///
    /// # Returns
    ///
    /// A new `List` instance.
    ///
    /// # Errors
    ///
    /// This function does not return an error.
    pub fn new(client: Client, kind: &str) -> Self {
        Self {
            client,
            kind: kind.to_owned(),
        }
    }

    /// Returns true if the given IP address is in the list, false otherwise.
    ///
    /// This function will return false if there is an error querying the database.
    ///
    /// # Arguments
    ///
    /// * `ip` - The IP address to search for in the list.
    ///
    /// # Errors
    ///
    /// This function will return an error if there is an error querying the database.
    pub async fn has(&self, ip: &Ip) -> Result<bool> {
        let row = match ip.network_length() {
            Some(network_length) => {
                Arc::clone(&self.client)
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

    /// Adds the given IP address to the list.
    ///
    /// This function will return `Ok(())` if the IP address is successfully added
    /// to the list. In case of an error during the addition process,
    /// an appropriate `ApiError` is returned.
    ///
    /// # Arguments
    ///
    /// * `ip` - The IP address to be added to the list.
    ///
    /// # Errors
    ///
    /// This function will return an error if there is an error querying the database.
    pub async fn add(&self, ip: &Ip) -> Result<()> {
        Arc::clone(&self.client)
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

    /// Clears all records from the given list.
    ///
    /// This function will delete all records from the given list.
    ///
    /// # Errors
    ///
    /// This function will return an error if there is an error querying the database.
    pub async fn clear(&self) -> Result<()> {
        Arc::clone(&self.client)
            .execute("DELETE FROM ip_list WHERE kind = $1", &[&self.kind.clone()])
            .await?;

        Ok(())
    }

    /// Removes the given IP address from the list.
    ///
    /// This function will return `Ok(())` if the IP address is successfully removed
    /// from the list. In case of an error during the removal process,
    /// an appropriate `ApiError` is returned.
    ///
    /// # Arguments
    ///
    /// * `ip` - The IP address to be removed from the list.
    ///
    /// # Errors
    ///
    /// This function will return an error if there is an error querying the database.
    pub async fn delete(&self, ip: &Ip) -> Result<()> {
        match ip.network_length() {
            Some(network_length) => {
                Arc::clone(&self.client)
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

    /// Returns true if the given IP address is in the list, false otherwise.
    ///
    /// This function will return false if there is an error querying the database.
    ///
    /// # Arguments
    ///
    /// * `ip` - The IP address to search for in the list.
    ///
    /// # Errors
    ///
    /// This function will return an error if there is an error querying the database.
    pub async fn is_conform(&self, ip: &Ip) -> Result<bool> {
        let row = Arc::clone(&self.client)
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
