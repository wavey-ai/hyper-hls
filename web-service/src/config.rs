// h2h3-server/src/config.rs

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub cert_pem_base64: String,
    pub privkey_pem_base64: String,
    pub port: u16,
    pub enable_h2: bool,
    pub enable_h3: bool,
    pub enable_webtransport: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            cert_pem_base64: String::new(),
            privkey_pem_base64: String::new(),
            port: 443,
            enable_h2: true,
            enable_h3: true,
            enable_webtransport: true,
        }
    }
}
