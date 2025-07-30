use crate::utils::errors::{Result, VaultCliError};
use crate::utils::PROGRAM_NAME;
use aes_gcm::{Aes256Gcm, Key, KeyInit};
use rand::RngCore;
use reqwest::Client;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const DEFAULT_KV_MOUNT: &str = "secret";
const KV_PATH: &str = "vault-rs/encryption-key";

pub struct KeyManager {
    client: Client,
    vault_addr: String,
}

impl KeyManager {
    pub fn new(vault_addr: String) -> Self {
        let client = crate::vault::create_http_client().expect("Failed to create HTTP client");

        Self { client, vault_addr }
    }

    /// Get or create the master encryption key from Vault
    pub async fn get_master_key(&self, vault_token: &str) -> Result<[u8; 32]> {
        // Try to retrieve existing key first
        if let Ok(key) = self.retrieve_key_from_vault(vault_token).await {
            return Ok(key);
        }

        // If key doesn't exist, create and store a new one
        let new_key = self.generate_master_key();
        self.store_key_in_vault(vault_token, &new_key).await?;

        Ok(new_key)
    }

    /// Initialize encryption key in personal vault
    pub async fn init_encryption_key(&self, vault_token: &str) -> Result<()> {
        let key = self.generate_master_key();
        self.store_key_in_vault(vault_token, &key).await?;
        tracing::info!("Encryption key initialized in personal vault");
        Ok(())
    }

    /// Generate a new 256-bit master key
    fn generate_master_key(&self) -> [u8; 32] {
        let mut key = [0u8; 32];
        rand::rng().fill_bytes(&mut key);
        key
    }

    /// Find available KV mounts and return the first one found
    async fn find_kv_mount(&self, vault_token: &str) -> Result<Option<(String, String)>> {
        let mounts_url = format!("{}/v1/sys/mounts", self.vault_addr);
        let response = self
            .client
            .get(&mounts_url)
            .header("X-Vault-Token", vault_token)
            .send()
            .await?;

        if !response.status().is_success() {
            return Ok(None);
        }

        let mounts: Value = response.json().await?;
        if let Some(data) = mounts.get("data").and_then(|d| d.as_object()) {
            // Look for KV mounts
            for (mount_path, mount_info) in data {
                if let Some(mount_type) = mount_info.get("type").and_then(|t| t.as_str()) {
                    if mount_type == "kv" {
                        let clean_mount = mount_path.trim_end_matches('/');
                        let version = mount_info
                            .get("options")
                            .and_then(|opts| opts.get("version"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("1");

                        let path = if version == "2" {
                            format!("{clean_mount}/data/{KV_PATH}")
                        } else {
                            format!("{clean_mount}/{KV_PATH}")
                        };

                        return Ok(Some((clean_mount.to_string(), path)));
                    }
                }
            }
        }

        Ok(None)
    }

    /// Get the appropriate KV path for reading/writing
    async fn get_kv_path(&self, vault_token: &str) -> Result<String> {
        // First check if default "secret" mount exists
        let mounts_url = format!("{}/v1/sys/mounts", self.vault_addr);
        let response = self
            .client
            .get(&mounts_url)
            .header("X-Vault-Token", vault_token)
            .send()
            .await?;

        if response.status().is_success() {
            let mounts: Value = response.json().await?;
            if let Some(secret_mount) = mounts["data"][format!("{DEFAULT_KV_MOUNT}/")].as_object() {
                if let Some(version) = secret_mount
                    .get("options")
                    .and_then(|opts| opts.get("version"))
                    .and_then(|v| v.as_str())
                {
                    if version == "2" {
                        // KV v2 path
                        return Ok(format!("{DEFAULT_KV_MOUNT}/data/{KV_PATH}"));
                    }
                }
                // KV v1 path
                return Ok(format!("{DEFAULT_KV_MOUNT}/{KV_PATH}"));
            }
        }

        // If no "secret" mount, look for any KV mount
        if let Some((mount_name, path)) = self.find_kv_mount(vault_token).await? {
            tracing::info!("Using KV mount '{}' for encryption key storage", mount_name);
            return Ok(path);
        }

        Err(VaultCliError::Storage(
            format!("No KV mount found in Vault.\n\nTo enable encrypted local storage, create a KV mount:\n  {PROGRAM_NAME} secrets enable -path=secret kv-v2\n\nAlternatively, use --no-store with certificate creation to skip local storage.\nUse '{PROGRAM_NAME} auth list-secrets' to see available secret engines.")
        ))
    }

    /// Retrieve key from Vault KV store
    async fn retrieve_key_from_vault(&self, vault_token: &str) -> Result<[u8; 32]> {
        let kv_path = self.get_kv_path(vault_token).await?;
        let url = format!("{}/v1/{}", self.vault_addr, kv_path);

        let response = self
            .client
            .get(&url)
            .header("X-Vault-Token", vault_token)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(VaultCliError::Storage(
                "Encryption key not found in vault".to_string(),
            ));
        }

        let data: Value = response.json().await?;

        // Handle both KV v1 and v2 response formats
        let key_hex = if kv_path.contains("/data/") {
            // KV v2 format: data.data.key
            data["data"]["data"]["key"].as_str()
        } else {
            // KV v1 format: data.key
            data["data"]["key"].as_str()
        }
        .ok_or_else(|| VaultCliError::Storage("Invalid key format in vault".to_string()))?;

        let key_bytes = hex::decode(key_hex)
            .map_err(|_| VaultCliError::Storage("Invalid hex key in vault".to_string()))?;

        if key_bytes.len() != 32 {
            return Err(VaultCliError::Storage(
                "Invalid key length in vault".to_string(),
            ));
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&key_bytes);
        Ok(key)
    }

    /// Store key in Vault KV store
    async fn store_key_in_vault(&self, vault_token: &str, key: &[u8; 32]) -> Result<()> {
        let kv_path = self.get_kv_path(vault_token).await?;
        let url = format!("{}/v1/{}", self.vault_addr, kv_path);
        let key_hex = hex::encode(key);

        let key_data = json!({
            "key": key_hex,
            "created": chrono::Utc::now().to_rfc3339(),
            "description": "vault-rs master encryption key"
        });

        // For KV v2, we need to wrap in "data", for KV v1 we don't
        let payload = if kv_path.contains("/data/") {
            // KV v2 format
            json!({ "data": key_data })
        } else {
            // KV v1 format
            key_data
        };

        let response = self
            .client
            .post(&url)
            .header("X-Vault-Token", vault_token)
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(VaultCliError::Storage(format!(
                "Failed to store key in vault: {status} - {error_text}"
            )));
        }

        Ok(())
    }

    /// Derive a context-specific key from the master key
    pub fn derive_key(&self, master_key: &[u8; 32], context: &str) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(master_key);
        hasher.update(context.as_bytes());
        let result = hasher.finalize();

        let mut derived_key = [0u8; 32];
        derived_key.copy_from_slice(&result);
        derived_key
    }

    /// Create an AES-GCM cipher instance from a key
    pub fn create_cipher(&self, key: &[u8; 32]) -> Aes256Gcm {
        let key = Key::<Aes256Gcm>::from_slice(key);
        Aes256Gcm::new(key)
    }

    /// Generate a random nonce for AES-GCM
    pub fn generate_nonce(&self) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        rand::rng().fill_bytes(&mut nonce);
        nonce
    }
}
