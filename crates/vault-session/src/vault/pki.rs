use serde::Deserialize;

/// A PKI role's configuration, as returned by `GET {mount}/roles/{role}`.
///
/// Vault omits fields that were never set on the role rather than sending
/// zero values, so every field defaults rather than failing to deserialize.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RoleConfig {
    #[serde(default)]
    pub use_csr_common_name: bool,
    #[serde(default)]
    pub use_csr_sans: bool,
    #[serde(default)]
    pub ext_key_usage: Vec<String>,
    #[serde(default)]
    pub client_flag: bool,
    #[serde(default)]
    pub server_flag: bool,
    /// Seconds, as recent Vault versions send it - not a duration string.
    #[serde(default)]
    pub ttl: u64,
    #[serde(default)]
    pub max_ttl: u64,
    #[serde(default)]
    pub key_type: String,
    #[serde(default)]
    pub key_bits: u64,
    #[serde(default)]
    pub ou: Vec<String>,
    #[serde(default)]
    pub organization: Vec<String>,
    #[serde(default)]
    pub country: Vec<String>,
    #[serde(default)]
    pub locality: Vec<String>,
    #[serde(default)]
    pub province: Vec<String>,
    #[serde(default)]
    pub street_address: Vec<String>,
    #[serde(default)]
    pub postal_code: Vec<String>,
}
