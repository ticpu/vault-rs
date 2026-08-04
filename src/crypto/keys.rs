use crate::utils::errors::{Result, VaultCliError};
use crate::utils::PROGRAM_NAME;
use crate::vault::client::VaultClient;
use aes_gcm::{Aes256Gcm, Key, KeyInit};
use rand::Rng;
use serde_json::json;
use sha2::{Digest, Sha256};

const DEFAULT_KV_MOUNT: &str = "secret";
const KV_PATH: &str = "vault-rs/encryption-key";

pub struct KeyManager {
    client: VaultClient,
}

impl KeyManager {
    pub async fn new() -> Result<Self> {
        let client = VaultClient::new().await?;
        Ok(Self { client })
    }

    pub fn with_client(client: VaultClient) -> Self {
        Self { client }
    }

    /// Get or create the master encryption key from Vault.
    ///
    /// Minting happens only when the store genuinely holds no key. Treating a
    /// failed read as absence would overwrite the existing key, and every
    /// artifact in the local store is encrypted under it.
    pub async fn get_master_key(&self) -> Result<[u8; 32]> {
        if let Some(key) = self.retrieve_key_from_vault().await? {
            return Ok(key);
        }

        let new_key = self.generate_master_key();
        self.store_key_in_vault(&new_key).await?;

        Ok(new_key)
    }

    /// Initialize encryption key in personal vault. `destroy_existing`
    /// overwrites one that is already there, which is unrecoverable.
    pub async fn init_encryption_key(&self, destroy_existing: bool) -> Result<()> {
        if !destroy_existing && self.retrieve_key_from_vault().await?.is_some() {
            let kv_path = self.get_kv_path().await?;
            return Err(VaultCliError::Storage(format!(
                "An encryption key already exists at '{kv_path}'.\n\n\
                 Overwriting it makes every certificate and private key already in the local store \
                 permanently undecryptable. There is no recovery.\n\n\
                 If that is genuinely what you want: {PROGRAM_NAME} auth init-encryption --destroy-all-my-keys"
            )));
        }

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

        // Look for KV mounts
        for (mount_path, mount_info) in &mounts.data {
            if mount_info.is_kv() {
                let clean_mount = mount_path.trim_end_matches('/');
                let version = mount_info.get_version().unwrap_or("1");

                let path = if version == "2" {
                    format!("{clean_mount}/data/{KV_PATH}")
                } else {
                    format!("{clean_mount}/{KV_PATH}")
                };

                return Ok(Some((clean_mount.to_string(), path)));
            }
        }

        Ok(None)
    }

    /// Get the appropriate KV path for reading/writing
    async fn get_kv_path(&self) -> Result<String> {
        // First check if default "secret" mount exists
        let mounts = self.client.list_mounts().await?;

        if let Some(secret_mount) = mounts.data.get(&format!("{DEFAULT_KV_MOUNT}/")) {
            if secret_mount.is_kv() {
                let version = secret_mount.get_version().unwrap_or("1");
                if version == "2" {
                    // KV v2 path
                    return Ok(format!("{DEFAULT_KV_MOUNT}/data/{KV_PATH}"));
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

    /// The stored key, or `Ok(None)` when the path genuinely holds nothing.
    ///
    /// Every other outcome is an error, including a payload that is present but
    /// malformed: the caller mints on `None`, so anything that cannot be read
    /// with certainty has to stop it rather than look like an empty store.
    async fn retrieve_key_from_vault(&self) -> Result<Option<[u8; 32]>> {
        let kv_path = self.get_kv_path().await?;

        let data = match self.client.get(&kv_path).await {
            Ok(data) => data,
            // Vault answers 404 both for a path never written and for a
            // soft-deleted KV v2 version; either way there is no key here.
            Err(VaultCliError::CertNotFound(_)) => return Ok(None),
            Err(e) => return Err(e),
        };

        // Handle both KV v1 and v2 response formats
        let key_hex = if kv_path.contains("/data/") {
            // KV v2 format: data.data.key
            data["data"]["data"]["key"].as_str()
        } else {
            // KV v1 format: data.key
            data["data"]["key"].as_str()
        }
        .ok_or_else(|| {
            VaultCliError::Storage(format!(
                "'{kv_path}' exists but carries no 'key' field; refusing to read that as an absent key"
            ))
        })?;

        let key_bytes = hex::decode(key_hex).map_err(|e| {
            VaultCliError::Storage(format!(
                "'{kv_path}' holds a key that is not valid hex: {e}"
            ))
        })?;

        if key_bytes.len() != 32 {
            return Err(VaultCliError::Storage(format!(
                "'{kv_path}' holds a {}-byte key; 32 expected",
                key_bytes.len()
            )));
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&key_bytes);
        Ok(Some(key))
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

        self.client.post(&kv_path, payload).await?;

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
        Aes256Gcm::new(&Key::<Aes256Gcm>::from(*key))
    }

    /// Generate a random nonce for AES-GCM
    pub fn generate_nonce(&self) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        rand::rng().fill_bytes(&mut nonce);
        nonce
    }
}

/// Every test here turns on one question: does this code path write to the key
/// path? A write over an existing key makes every artifact in the local store
/// permanently undecryptable, and no round-trip or return-value assertion can
/// see that happen — only counting the POST can. `expect(0)` is verified when
/// the `MockServer` drops.
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const V2_PATH: &str = "/v1/secret/data/vault-rs/encryption-key";
    const V1_PATH: &str = "/v1/secret/vault-rs/encryption-key";

    fn manager(server: &MockServer) -> KeyManager {
        KeyManager::with_client(
            VaultClient::for_test(server.uri(), "test-token".to_string()).expect("test client"),
        )
    }

    /// `sys/mounts` shaped so `get_kv_path` resolves to the `secret` mount.
    async fn mount_kv(server: &MockServer, version: &str) {
        let body = json!({
            "data": { "secret/": { "type": "kv", "options": { "version": version } } }
        });
        Mock::given(method("GET"))
            .and(path("/v1/sys/mounts"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(server)
            .await;
    }

    async fn respond_to_read(server: &MockServer, at: &str, response: ResponseTemplate) {
        Mock::given(method("GET"))
            .and(path(at))
            .respond_with(response)
            .mount(server)
            .await;
    }

    /// Mounts a POST expectation at the key path. `writes` is the number of
    /// writes this test asserts must happen — usually zero.
    async fn expect_writes(server: &MockServer, at: &str, writes: u64) {
        Mock::given(method("POST"))
            .and(path(at))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "data": {} })))
            .expect(writes)
            .mount(server)
            .await;
    }

    fn stored_key(hex_key: &str, v2: bool) -> ResponseTemplate {
        let inner = json!({ "key": hex_key });
        let body: Value = if v2 {
            json!({ "data": { "data": inner } })
        } else {
            json!({ "data": inner })
        };
        ResponseTemplate::new(200).set_body_json(body)
    }

    #[tokio::test]
    async fn a_stored_key_is_read_from_kv_v2_and_nothing_is_written() {
        let server = MockServer::start().await;
        mount_kv(&server, "2").await;
        respond_to_read(&server, V2_PATH, stored_key(&"ab".repeat(32), true)).await;
        expect_writes(&server, V2_PATH, 0).await;

        let key = manager(&server).get_master_key().await.expect("read");
        assert_eq!(key, [0xab; 32]);
    }

    #[tokio::test]
    async fn a_stored_key_is_read_from_kv_v1_and_nothing_is_written() {
        let server = MockServer::start().await;
        mount_kv(&server, "1").await;
        respond_to_read(&server, V1_PATH, stored_key(&"cd".repeat(32), false)).await;
        expect_writes(&server, V1_PATH, 0).await;

        let key = manager(&server).get_master_key().await.expect("read");
        assert_eq!(key, [0xcd; 32]);
    }

    /// 404 is the one answer that means the store genuinely holds no key.
    #[tokio::test]
    async fn a_404_is_absence_and_mints_exactly_one_key() {
        let server = MockServer::start().await;
        mount_kv(&server, "2").await;
        respond_to_read(&server, V2_PATH, ResponseTemplate::new(404)).await;
        expect_writes(&server, V2_PATH, 1).await;

        manager(&server).get_master_key().await.expect("mint");
    }

    /// The defect this step exists to remove: a transient failure used to read
    /// as absence, mint a fresh key and overwrite the real one.
    #[tokio::test]
    async fn a_denied_read_never_writes() {
        let server = MockServer::start().await;
        mount_kv(&server, "2").await;
        respond_to_read(&server, V2_PATH, ResponseTemplate::new(403)).await;
        expect_writes(&server, V2_PATH, 0).await;

        manager(&server)
            .get_master_key()
            .await
            .expect_err("a denied read is not an absent key");
    }

    #[tokio::test]
    async fn a_server_error_never_writes() {
        let server = MockServer::start().await;
        mount_kv(&server, "2").await;
        respond_to_read(&server, V2_PATH, ResponseTemplate::new(500)).await;
        expect_writes(&server, V2_PATH, 0).await;

        manager(&server)
            .get_master_key()
            .await
            .expect_err("a server error is not an absent key");
    }

    /// A payload that is present but unreadable is not an empty store either.
    #[tokio::test]
    async fn a_malformed_stored_key_never_writes() {
        let server = MockServer::start().await;
        mount_kv(&server, "2").await;
        respond_to_read(&server, V2_PATH, stored_key("not-hex", true)).await;
        expect_writes(&server, V2_PATH, 0).await;

        let err = manager(&server)
            .get_master_key()
            .await
            .expect_err("malformed is not absent")
            .to_string();
        assert!(err.contains("not valid hex"), "{err}");
    }

    #[tokio::test]
    async fn init_refuses_when_a_key_already_exists() {
        let server = MockServer::start().await;
        mount_kv(&server, "2").await;
        respond_to_read(&server, V2_PATH, stored_key(&"ab".repeat(32), true)).await;
        expect_writes(&server, V2_PATH, 0).await;

        let err = manager(&server)
            .init_encryption_key(false)
            .await
            .expect_err("a second init must not overwrite")
            .to_string();
        assert!(err.contains("--destroy-all-my-keys"), "{err}");
    }

    /// Not knowing whether a key is there is not the same as knowing there is
    /// none, so `init` refuses on a failed read too.
    #[tokio::test]
    async fn init_refuses_when_the_existence_check_fails() {
        let server = MockServer::start().await;
        mount_kv(&server, "2").await;
        respond_to_read(&server, V2_PATH, ResponseTemplate::new(500)).await;
        expect_writes(&server, V2_PATH, 0).await;

        manager(&server)
            .init_encryption_key(false)
            .await
            .expect_err("an unread store is not an empty one");
    }

    #[tokio::test]
    async fn init_overwrites_only_with_the_flag() {
        let server = MockServer::start().await;
        mount_kv(&server, "2").await;
        respond_to_read(&server, V2_PATH, stored_key(&"ab".repeat(32), true)).await;
        expect_writes(&server, V2_PATH, 1).await;

        manager(&server)
            .init_encryption_key(true)
            .await
            .expect("the flag permits the overwrite");
    }
}
