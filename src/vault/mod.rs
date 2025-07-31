pub mod auth;
pub mod client;
pub mod mounts;
pub mod pki;
pub mod wrapper;

use reqwest::Client;
use serde_json::Value;

/// Create a standardized HTTP client with security best practices
pub fn create_http_client() -> Result<Client, reqwest::Error> {
    Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .use_rustls_tls() // Use rustls with system certificate store
        .build()
}

/// Extract string array from Vault API response data.keys field
pub fn extract_keys_array(response: &Value) -> Vec<String> {
    if let Some(data) = response.get("data") {
        if let Some(keys) = data.get("keys") {
            if let Some(array) = keys.as_array() {
                return array
                    .iter()
                    .filter_map(|item| item.as_str())
                    .map(|s| s.to_string())
                    .collect();
            }
        }
    }
    Vec::new()
}
