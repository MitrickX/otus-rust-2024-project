pub struct Credentials {
    pub login: String,
    pub password: String,
    pub ip: String,
}

#[derive(Debug, Default)]
pub struct Auth {}

impl Auth {
    pub async fn check(&self, credentials: Credentials) -> bool {
        credentials.login == "admin"
            && credentials.password == "1234"
            && credentials.ip == "127.0.0.1"
    }
}
