use crate::client::VaultClient;
use crate::utils::errors::{Result, VaultCliError};
use crate::utils::PROGRAM_NAME;
use aes_gcm::{Aes256Gcm, Key, KeyInit};
use rand::RngCore;
use serde_json::json;
use sha2::{Digest, Sha256};

const DEFAULT_KV_MOUNT: &str = "secret";
const KV_PATH: &str = "vault-rs/encryption-key";

pub struct KeyManager {
    client: VaultClient,
}

impl KeyManager {
    pub async fn new() -> Self {
        let client = VaultClient::new().await;
        Self { client }
    }

    /// Get or create the master encryption key from Vault
    pub async fn get_master_key(&self) -> Result<[u8; 32]> {
        // Try to retrieve existing key first
        if let Ok(key) = self.retrieve_key_from_vault().await {
            return Ok(key);
        }

        // If key doesn't exist, create and store a new one
        let new_key = self.generate_master_key();
        self.store_key_in_vault(&new_key).await?;

        Ok(new_key)
    }

    /// Initialize encryption key in personal vault
    pub async fn init_encryption_key(&self) -> Result<()> {
        let key = self.generate_master_key();
        self.store_key_in_vault(&key).await?;
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
    async fn find_kv_mount(&self) -> Result<Option<(String, String)>> {
        let mounts = self.client.list_mounts().await?;

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
    async fn get_kv_path(&self) -> Result<String> {
        // First check if default "secret" mount exists
        let mounts = self.client.list_mounts().await?;

        if let Some(data) = mounts.get("data").and_then(|d| d.as_object()) {
            if let Some(secret_mount) = data.get(&format!("{DEFAULT_KV_MOUNT}/")) {
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
        if let Some((mount_name, path)) = self.find_kv_mount().await? {
            tracing::info!("Using KV mount '{}' for encryption key storage", mount_name);
            return Ok(path);
        }

        Err(VaultCliError::Storage(
            format!("No KV mount found in Vault.\n\nTo enable encrypted local storage, create a KV mount:\n  {PROGRAM_NAME} secrets enable -path=secret kv-v2\n\nAlternatively, use --no-store with certificate creation to skip local storage.\nUse '{PROGRAM_NAME} auth list-secrets' to see available secret engines.")
        ))
    }

    /// Retrieve key from Vault KV store
    async fn retrieve_key_from_vault(&self) -> Result<[u8; 32]> {
        let kv_path = self.get_kv_path().await?;

        let data =
            self.client.get(&kv_path).await.map_err(|_| {
                VaultCliError::Storage("Encryption key not found in vault".to_string())
            })?;

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
    async fn store_key_in_vault(&self, key: &[u8; 32]) -> Result<()> {
        let kv_path = self.get_kv_path().await?;
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

        self.client
            .post(&kv_path, payload)
            .await
            .map_err(|e| VaultCliError::Storage(format!("Failed to store key in vault: {e}")))?;

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
