use crate::crypto::encryption::EncryptionManager;
use crate::storage::metadata::CertificateStorage;
use crate::storage::metadata::{MasterIndex, StorageCertificateMetadata};
use crate::utils::errors::{Result, VaultCliError};
use crate::utils::paths::VaultCliPaths;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;

pub struct CertificateData<'a> {
    pub pki_mount: &'a str,
    pub cn: &'a str,
    pub certificate_pem: &'a str,
    pub private_key_pem: &'a str,
    pub ca_chain_pem: &'a str,
    pub metadata: StorageCertificateMetadata,
}

pub struct LocalStorage {
    encryption_manager: EncryptionManager,
}

impl LocalStorage {
    pub fn new(vault_addr: String) -> Self {
        Self {
            encryption_manager: EncryptionManager::new(vault_addr),
        }
    }

    /// Store certificate data encrypted locally
    pub async fn store_certificate(
        &self,
        vault_token: &str,
        cert_data: CertificateData<'_>,
    ) -> Result<()> {
        let cert_dir = VaultCliPaths::cert_storage_dir(cert_data.pki_mount, cert_data.cn)?;
        VaultCliPaths::ensure_dir_exists(&cert_dir)?;

        // Create unique context for this certificate
        let context = format!("cert-{}-{}", cert_data.pki_mount, cert_data.cn);

        // Store certificate files encrypted
        let cert_file = cert_dir.join("certificate.pem.enc");
        let key_file = cert_dir.join("private_key.pem.enc");
        let ca_file = cert_dir.join("ca_chain.pem.enc");
        let metadata_file = cert_dir.join("metadata.yaml.enc");

        // Encrypt and store certificate
        self.encryption_manager
            .encrypt_to_file(
                vault_token,
                cert_data.certificate_pem.as_bytes(),
                &context,
                &cert_file,
            )
            .await?;

        // Encrypt and store private key
        self.encryption_manager
            .encrypt_to_file(
                vault_token,
                cert_data.private_key_pem.as_bytes(),
                &context,
                &key_file,
            )
            .await?;

        // Encrypt and store CA chain
        self.encryption_manager
            .encrypt_to_file(
                vault_token,
                cert_data.ca_chain_pem.as_bytes(),
                &context,
                &ca_file,
            )
            .await?;

        // Create P12 bundle and store it
        let p12_data = self.create_p12_bundle(
            cert_data.certificate_pem,
            cert_data.private_key_pem,
            cert_data.ca_chain_pem,
        )?;
        let p12_file = cert_dir.join("p12.enc");
        self.encryption_manager
            .encrypt_to_file(vault_token, &p12_data, &context, &p12_file)
            .await?;

        // Create file info map
        use crate::storage::metadata::{CertificateStorage, FileInfo};
        use std::collections::HashMap;

        let mut file_info = HashMap::new();
        file_info.insert(
            "certificate.pem.enc".to_string(),
            FileInfo {
                size: fs::metadata(&cert_file)?.len(),
                created: chrono::Utc::now(),
                checksum: self.calculate_file_checksum(&cert_file)?,
            },
        );
        file_info.insert(
            "private_key.pem.enc".to_string(),
            FileInfo {
                size: fs::metadata(&key_file)?.len(),
                created: chrono::Utc::now(),
                checksum: self.calculate_file_checksum(&key_file)?,
            },
        );
        file_info.insert(
            "ca_chain.pem.enc".to_string(),
            FileInfo {
                size: fs::metadata(&ca_file)?.len(),
                created: chrono::Utc::now(),
                checksum: self.calculate_file_checksum(&ca_file)?,
            },
        );
        file_info.insert(
            "p12.enc".to_string(),
            FileInfo {
                size: fs::metadata(&p12_file)?.len(),
                created: chrono::Utc::now(),
                checksum: self.calculate_file_checksum(&p12_file)?,
            },
        );

        // Create the full CertificateStorage structure
        let cert_storage = CertificateStorage {
            pki_mount: cert_data.pki_mount.to_string(),
            crypto: cert_data.metadata.crypto.clone(),
            created: chrono::Utc::now(),
            storage_path: cert_dir.to_string_lossy().to_string(),
            vault_status: "Active".to_string(),
            last_vault_check: chrono::Utc::now(),
            file_info,
            meta: cert_data.metadata,
        };

        self.encryption_manager
            .encrypt_yaml_to_file(vault_token, &cert_storage, &context, &metadata_file)
            .await?;

        // Update master index
        self.update_master_index(vault_token, cert_storage).await?;

        tracing::info!(
            "Certificate stored encrypted locally: {}",
            cert_dir.display()
        );
        Ok(())
    }

    /// Retrieve certificate data from local storage
    pub async fn get_certificate(
        &self,
        vault_token: &str,
        pki_mount: &str,
        cn: &str,
    ) -> Result<(String, String, String, StorageCertificateMetadata)> {
        let cert_dir = VaultCliPaths::cert_storage_dir(pki_mount, cn)?;
        if !cert_dir.exists() {
            return Err(VaultCliError::CertNotFound(format!(
                "Certificate not found: {pki_mount}/{cn}"
            )));
        }

        let context = format!("cert-{pki_mount}-{cn}");

        // Read encrypted files
        let cert_file = cert_dir.join("certificate.pem.enc");
        let key_file = cert_dir.join("private_key.pem.enc");
        let ca_file = cert_dir.join("ca_chain.pem.enc");
        let metadata_file = cert_dir.join("metadata.json.enc");

        let certificate_pem = String::from_utf8(
            self.encryption_manager
                .decrypt_from_file(vault_token, &context, &cert_file)
                .await?,
        )?;
        let private_key_pem = String::from_utf8(
            self.encryption_manager
                .decrypt_from_file(vault_token, &context, &key_file)
                .await?,
        )?;
        let ca_chain_pem = String::from_utf8(
            self.encryption_manager
                .decrypt_from_file(vault_token, &context, &ca_file)
                .await?,
        )?;
        let metadata: StorageCertificateMetadata = self
            .encryption_manager
            .decrypt_yaml_from_file(vault_token, &context, &metadata_file)
            .await?;

        Ok((certificate_pem, private_key_pem, ca_chain_pem, metadata))
    }

    /// List all locally stored certificates
    pub async fn list_certificates(&self, vault_token: &str) -> Result<Vec<CertificateStorage>> {
        let index = self.get_master_index(vault_token).await?;
        Ok(index.certificates)
    }

    /// Remove certificate from local storage
    pub async fn remove_certificate(
        &self,
        vault_token: &str,
        pki_mount: &str,
        cn: &str,
    ) -> Result<()> {
        let cert_dir = VaultCliPaths::cert_storage_dir(pki_mount, cn)?;

        if cert_dir.exists() {
            fs::remove_dir_all(&cert_dir)?;
            tracing::info!("Removed certificate directory: {}", cert_dir.display());
        }

        // Update master index - find and remove by CN and PKI mount
        let mut index = self.get_master_index(vault_token).await?;
        let serial_to_remove = index
            .certificates
            .iter()
            .find(|cert| cert.meta.cn == cn && cert.pki_mount == pki_mount)
            .map(|cert| cert.meta.serial.clone());

        if let Some(serial) = serial_to_remove {
            index.remove_certificate(&serial);
            self.store_master_index(vault_token, &index).await?;
        }

        Ok(())
    }

    /// Export certificate in various formats
    pub async fn export_certificate(
        &self,
        vault_token: &str,
        pki_mount: &str,
        cn: &str,
        output_dir: &str,
        formats: &[String],
        _decrypt: bool,
    ) -> Result<()> {
        let (cert_pem, key_pem, ca_pem, _metadata) =
            self.get_certificate(vault_token, pki_mount, cn).await?;

        let output_path = PathBuf::from(output_dir);
        fs::create_dir_all(&output_path)?;

        for format in formats {
            match format.as_str() {
                "all" => {
                    // Export all formats
                    let full_pem = format!("{key_pem}{cert_pem}");
                    fs::write(output_path.join(format!("{cn}.pem")), full_pem)?;
                    fs::write(output_path.join(format!("{cn}.crt")), &cert_pem)?;
                    fs::write(output_path.join(format!("{cn}.key")), &key_pem)?;
                    fs::write(output_path.join(format!("{cn}_chain.pem")), &ca_pem)?;

                    let cert_dir = VaultCliPaths::cert_storage_dir(pki_mount, cn)?;
                    let p12_file = cert_dir.join("p12.enc");
                    let context = format!("cert-{pki_mount}-{cn}");
                    let p12_data = self
                        .encryption_manager
                        .decrypt_from_file(vault_token, &context, &p12_file)
                        .await?;
                    fs::write(output_path.join(format!("{cn}.p12")), p12_data)?;

                    // Set restrictive permissions on private key
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let key_file = output_path.join(format!("{cn}.key"));
                        let mut perms = fs::metadata(&key_file)?.permissions();
                        perms.set_mode(0o600);
                        fs::set_permissions(&key_file, perms)?;
                    }
                }
                "pem" => {
                    let full_pem = format!("{key_pem}{cert_pem}");
                    fs::write(output_path.join(format!("{cn}.pem")), full_pem)?;
                }
                "crt" => {
                    fs::write(output_path.join(format!("{cn}.crt")), &cert_pem)?;
                }
                "key" => {
                    fs::write(output_path.join(format!("{cn}.key")), &key_pem)?;
                    // Set restrictive permissions on private key
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let key_file = output_path.join(format!("{cn}.key"));
                        let mut perms = fs::metadata(&key_file)?.permissions();
                        perms.set_mode(0o600);
                        fs::set_permissions(&key_file, perms)?;
                    }
                }
                "chain" => {
                    fs::write(output_path.join(format!("{cn}_chain.pem")), &ca_pem)?;
                }
                "p12" => {
                    let cert_dir = VaultCliPaths::cert_storage_dir(pki_mount, cn)?;
                    let p12_file = cert_dir.join("p12.enc");
                    let context = format!("cert-{pki_mount}-{cn}");
                    let p12_data = self
                        .encryption_manager
                        .decrypt_from_file(vault_token, &context, &p12_file)
                        .await?;
                    fs::write(output_path.join(format!("{cn}.p12")), p12_data)?;
                }
                _ => {
                    return Err(VaultCliError::InvalidInput(format!(
                        "Unknown format: {format}"
                    )))
                }
            }
        }

        tracing::info!("Certificate exported to: {}", output_path.display());
        Ok(())
    }

    /// Get master index
    async fn get_master_index(&self, vault_token: &str) -> Result<MasterIndex> {
        let index_file = VaultCliPaths::master_index()?;

        if !index_file.exists() {
            return Ok(MasterIndex::new());
        }

        let index: MasterIndex = self
            .encryption_manager
            .decrypt_yaml_from_file(vault_token, "master-index", &index_file)
            .await?;

        Ok(index)
    }

    /// Store master index
    async fn store_master_index(&self, vault_token: &str, index: &MasterIndex) -> Result<()> {
        let index_file = VaultCliPaths::master_index()?;
        self.encryption_manager
            .encrypt_yaml_to_file(vault_token, index, "master-index", &index_file)
            .await
    }

    /// Update master index with new certificate
    async fn update_master_index(&self, vault_token: &str, cert: CertificateStorage) -> Result<()> {
        let mut index = self.get_master_index(vault_token).await?;
        index.add_certificate(cert);
        index.update_last_sync();
        self.store_master_index(vault_token, &index).await
    }

    /// Create P12 bundle from PEM files
    fn create_p12_bundle(&self, cert_pem: &str, key_pem: &str, ca_pem: &str) -> Result<Vec<u8>> {
        // For now, return a concatenated version
        // In a real implementation, you'd use openssl or a similar library to create proper P12
        let bundle = format!("{key_pem}\n{cert_pem}\n{ca_pem}");
        Ok(bundle.into_bytes())
    }

    /// Calculate SHA256 checksum of a file
    fn calculate_file_checksum(&self, file_path: &PathBuf) -> Result<String> {
        let data = fs::read(file_path)?;
        let mut hasher = Sha256::new();
        hasher.update(&data);
        Ok(hex::encode(hasher.finalize()))
    }

    /// Clean up expired certificates
    pub async fn cleanup_expired(&self, vault_token: &str) -> Result<usize> {
        let index = self.get_master_index(vault_token).await?;
        let expired_certs = index.get_expired().into_iter().cloned().collect::<Vec<_>>();
        let mut removed_count = 0;

        for cert in expired_certs {
            if let Err(e) = self
                .remove_certificate(vault_token, &cert.pki_mount, &cert.meta.cn)
                .await
            {
                tracing::warn!(
                    "Failed to remove expired certificate {}: {}",
                    cert.meta.cn,
                    e
                );
            } else {
                removed_count += 1;
            }
        }

        Ok(removed_count)
    }

    /// Find certificate by serial number
    pub async fn find_by_serial(
        &self,
        vault_token: &str,
        serial: &str,
    ) -> Result<Option<CertificateStorage>> {
        let index = self.get_master_index(vault_token).await?;
        Ok(index.find_by_serial(serial).cloned())
    }
}
