pub mod auth;
pub mod client;
pub mod mounts;
pub mod oidc;
mod transport;

use serde_json::Value;

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
