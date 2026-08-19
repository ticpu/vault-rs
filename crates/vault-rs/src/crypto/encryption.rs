use crate::crypto::keys::KeyManager;
use crate::utils::errors::{Result, VaultCliError};
use aes_gcm::aead::array::typenum::Unsigned;
use aes_gcm::{aead::Aead, Nonce};
use std::fs;
use std::path::Path;

/// Stored artifacts are `nonce || ciphertext+tag`. Changing this would make
/// every already-encrypted artifact in the local store unreadable.
const NONCE_LEN: usize = 12;

/// The length of a stored file whose plaintext is empty: nonce plus tag and
/// nothing between them, since GCM ciphertext is as long as its plaintext.
///
/// `storage remove` grades its hazard on this, so it is computed from the
/// cipher rather than written down: were it a literal, a changed nonce width
/// or tag length would silently reclassify key-bearing artifacts as empty and
/// delete them without ever requiring the option named for the key.
pub const EMPTY_PAYLOAD_LEN: usize =
    NONCE_LEN + <aes_gcm::Aes256Gcm as aes_gcm::AeadCore>::TagSize::USIZE;

pub struct EncryptionManager {
    key_manager: KeyManager,
}

impl EncryptionManager {
    pub async fn new() -> Result<Self> {
        Ok(Self {
            key_manager: KeyManager::new().await?,
        })
    }

    pub fn with_client(client: crate::vault::client::VaultClient) -> Result<Self> {
        Ok(Self {
            key_manager: KeyManager::with_client(client)?,
        })
    }

    /// For a store rooted somewhere other than the default, which is what a
    /// test has: the record of which mount holds the key belongs to that store
    /// and must not be looked up in the real one.
    #[cfg(test)]
    pub fn recording_at(
        client: crate::vault::client::VaultClient,
        record: std::path::PathBuf,
    ) -> Self {
        Self {
            key_manager: KeyManager::recording_at(client, record),
        }
    }

    /// Encrypt data using context-specific derived key
    pub async fn encrypt_data(&self, data: &[u8], context: &str) -> Result<Vec<u8>> {
        let master_key = self.key_manager.get_master_key().await?;
        let context_key = self.key_manager.derive_key(&master_key, context);
        let cipher = self.key_manager.create_cipher(&context_key);

        let nonce = Nonce::from(self.key_manager.generate_nonce());
        let ciphertext = cipher
            .encrypt(&nonce, data)
            .map_err(|e| VaultCliError::Encryption(format!("Encryption failed: {e}")))?;

        // Prepend nonce to ciphertext for storage
        let mut encrypted_data = Vec::with_capacity(nonce.len() + ciphertext.len());
        encrypted_data.extend_from_slice(&nonce);
        encrypted_data.extend_from_slice(&ciphertext);

        Ok(encrypted_data)
    }

    /// Decrypt data using context-specific derived key
    pub async fn decrypt_data(&self, encrypted_data: &[u8], context: &str) -> Result<Vec<u8>> {
        if encrypted_data.len() < NONCE_LEN {
            return Err(VaultCliError::Encryption(
                "Encrypted data too short".to_string(),
            ));
        }

        let master_key = self.key_manager.get_master_key().await?;
        let context_key = self.key_manager.derive_key(&master_key, context);
        let cipher = self.key_manager.create_cipher(&context_key);

        // Extract nonce and ciphertext
        let (nonce_bytes, ciphertext) = encrypted_data.split_at(NONCE_LEN);
        let nonce = Nonce::try_from(nonce_bytes)
            .map_err(|e| VaultCliError::Encryption(format!("Invalid nonce: {e}")))?;

        // An AEAD failure against the local store has one overwhelmingly likely
        // cause and one obvious next step, both of which this code knows and the
        // operator does not. Naming the mechanism alone leaves no route to
        // recovery while the key that would open the artifact sits in Vault.
        let plaintext = match cipher.decrypt(&nonce, ciphertext) {
            Ok(plaintext) => plaintext,
            Err(e) => {
                return Err(VaultCliError::Encryption(format!(
                    "Decryption failed ({e}).\n\n{}",
                    self.key_manager.recovery_hint().await
                )))
            }
        };

        Ok(plaintext)
    }

    /// Encrypt and write data to file
    pub async fn encrypt_to_file<P: AsRef<Path>>(
        &self,
        data: &[u8],
        context: &str,
        file_path: P,
    ) -> Result<()> {
        let encrypted_data = self.encrypt_data(data, context).await?;

        // Ensure parent directory exists
        if let Some(parent) = file_path.as_ref().parent() {
            fs::create_dir_all(parent)?;
        }

        fs::write(&file_path, encrypted_data)?;

        // Set restrictive permissions on encrypted file
        crate::utils::set_secure_file_permissions(&file_path)?;

        Ok(())
    }

    /// Read and decrypt data from file
    pub async fn decrypt_from_file<P: AsRef<Path>>(
        &self,
        context: &str,
        file_path: P,
    ) -> Result<Vec<u8>> {
        let encrypted_data = fs::read(&file_path)?;
        self.decrypt_data(&encrypted_data, context).await
    }

    /// Initialize encryption key in personal vault
    pub async fn init_encryption_key(&self, destroy_existing: bool) -> Result<()> {
        self.key_manager.init_encryption_key(destroy_existing).await
    }

    /// The key-history route out of a decryption failure, for a caller
    /// assembling its own report rather than reading one error at a time.
    pub async fn recovery_hint(&self) -> String {
        self.key_manager.recovery_hint().await
    }

    /// Encrypt string data
    pub async fn encrypt_string(&self, data: &str, context: &str) -> Result<Vec<u8>> {
        self.encrypt_data(data.as_bytes(), context).await
    }

    /// Decrypt to string data
    pub async fn decrypt_string(&self, encrypted_data: &[u8], context: &str) -> Result<String> {
        let decrypted_bytes = self.decrypt_data(encrypted_data, context).await?;
        String::from_utf8(decrypted_bytes)
            .map_err(|e| VaultCliError::Encryption(format!("Invalid UTF-8 in decrypted data: {e}")))
    }

    /// Encrypt YAML data
    pub async fn encrypt_yaml<T: serde::Serialize>(
        &self,
        data: &T,
        context: &str,
    ) -> Result<Vec<u8>> {
        let yaml_string = serde_yaml_ng::to_string(data)?;
        self.encrypt_string(&yaml_string, context).await
    }

    /// Decrypt YAML data
    pub async fn decrypt_yaml<T: serde::de::DeserializeOwned>(
        &self,
        encrypted_data: &[u8],
        context: &str,
    ) -> Result<T> {
        let yaml_string = self.decrypt_string(encrypted_data, context).await?;
        let data = serde_yaml_ng::from_str(&yaml_string)?;
        Ok(data)
    }

    /// Encrypt YAML to file
    pub async fn encrypt_yaml_to_file<T: serde::Serialize, P: AsRef<Path>>(
        &self,
        data: &T,
        context: &str,
        file_path: P,
    ) -> Result<()> {
        let encrypted_data = self.encrypt_yaml(data, context).await?;

        // Ensure parent directory exists
        if let Some(parent) = file_path.as_ref().parent() {
            fs::create_dir_all(parent)?;
        }

        fs::write(&file_path, encrypted_data)?;

        // Set restrictive permissions on encrypted file
        crate::utils::set_secure_file_permissions(&file_path)?;

        Ok(())
    }

    /// Decrypt JSON from file
    pub async fn decrypt_yaml_from_file<T: serde::de::DeserializeOwned, P: AsRef<Path>>(
        &self,
        context: &str,
        file_path: P,
    ) -> Result<T> {
        let encrypted_data = fs::read(&file_path)?;
        self.decrypt_yaml(&encrypted_data, context).await
    }
}

#[cfg(test)]
mod tests {
    use aes_gcm::{aead::Aead, Aes256Gcm, Key, KeyInit, Nonce};
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// `storage remove` decides whether an artifact holds a private key by
    /// comparing this file's length against `EMPTY_PAYLOAD_LEN`, and it has to
    /// decide that for artifacts it cannot decrypt. The assertion goes through
    /// the real encryptor: a synthesized buffer of the expected length would
    /// restate the assumption and survive exactly the change this exists to
    /// catch — a version prefix, another AEAD or a different nonce width, any
    /// of which would reclassify key-bearing artifacts as empty and let them
    /// be deleted without the option that names the key.
    #[tokio::test]
    async fn an_empty_plaintext_encrypts_to_exactly_nonce_plus_tag() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/sys/mounts"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": { "secret/": { "type": "kv", "options": { "version": "2" } } }
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1/secret/data/vault-rs/encryption-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": { "data": { "key": "ab".repeat(32) } }
            })))
            .mount(&server)
            .await;

        let manager = super::EncryptionManager::recording_at(
            crate::vault::client::VaultClient::with_token(server.uri(), "test-token".to_string())
                .expect("test client"),
            crate::storage::test_support::scratch("encryption-empty").join("key-mount.yaml"),
        );

        let empty = manager
            .encrypt_data(b"", "cert-test-empty")
            .await
            .expect("encrypting an empty plaintext");
        assert_eq!(empty.len(), super::EMPTY_PAYLOAD_LEN);

        // Any non-empty plaintext has to land above it, or the comparison has
        // no side to fall on. One byte is the smallest case that must.
        let keyed = manager
            .encrypt_data(b"x", "cert-test-empty")
            .await
            .expect("encrypting a payload");
        assert!(keyed.len() > super::EMPTY_PAYLOAD_LEN, "{}", keyed.len());
    }

    /// Pins the stored ciphertext format against an independent AES-256-GCM
    /// implementation. The local store holds artifacts encrypted by earlier
    /// builds; a crate upgrade that changed nonce length, tag placement or
    /// tag length would make them permanently unreadable, and a round-trip
    /// test would not notice because it would break both directions together.
    #[test]
    fn stored_ciphertext_format_is_unchanged() {
        let key: [u8; 32] = std::array::from_fn(|i| i as u8);
        let nonce: [u8; 12] = std::array::from_fn(|i| i as u8);
        let expected =
            "3163a377b1c8b068ad32e3e4c38c1c4df0b3e446950fbbae6a3bbcbfb3a2a4e3455b8c52c943";

        let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(key));
        let ciphertext = cipher
            .encrypt(&Nonce::from(nonce), b"vault-rs stored secret".as_ref())
            .expect("encryption");

        assert_eq!(hex::encode(&ciphertext), expected);
    }

    /// The split point decryption uses must match what encryption prepends.
    #[test]
    fn nonce_length_matches_the_stored_prefix() {
        let nonce = Nonce::from([0u8; super::NONCE_LEN]);
        assert_eq!(super::NONCE_LEN, nonce.len());
        // The cipher must accept a nonce of exactly that size.
        Aes256Gcm::new(&Key::<Aes256Gcm>::from([0u8; 32]))
            .encrypt(&nonce, b"x".as_ref())
            .expect("nonce size accepted by the cipher");
    }
}
