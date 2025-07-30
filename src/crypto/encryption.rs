use crate::crypto::keys::KeyManager;
use crate::utils::errors::{Result, VaultCliError};
use aes_gcm::{
    aead::{Aead, AeadCore, OsRng},
    Aes256Gcm, Nonce,
};
use std::fs;
use std::path::Path;

pub struct EncryptionManager {
    key_manager: KeyManager,
}

impl EncryptionManager {
    pub async fn new() -> Self {
        Self {
            key_manager: KeyManager::new().await,
        }
    }

    /// Encrypt data using context-specific derived key
    pub async fn encrypt_data(&self, data: &[u8], context: &str) -> Result<Vec<u8>> {
        let master_key = self.key_manager.get_master_key().await?;
        let context_key = self.key_manager.derive_key(&master_key, context);
        let cipher = self.key_manager.create_cipher(&context_key);

        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
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
        if encrypted_data.len() < 12 {
            return Err(VaultCliError::Encryption(
                "Encrypted data too short".to_string(),
            ));
        }

        let master_key = self.key_manager.get_master_key().await?;
        let context_key = self.key_manager.derive_key(&master_key, context);
        let cipher = self.key_manager.create_cipher(&context_key);

        // Extract nonce and ciphertext
        let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| VaultCliError::Encryption(format!("Decryption failed: {e}")))?;

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
    pub async fn init_encryption_key(&self) -> Result<()> {
        self.key_manager.init_encryption_key().await
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
        let yaml_string = serde_yaml::to_string(data)?;
        self.encrypt_string(&yaml_string, context).await
    }

    /// Decrypt YAML data
    pub async fn decrypt_yaml<T: serde::de::DeserializeOwned>(
        &self,
        encrypted_data: &[u8],
        context: &str,
    ) -> Result<T> {
        let yaml_string = self.decrypt_string(encrypted_data, context).await?;
        let data = serde_yaml::from_str(&yaml_string)?;
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
