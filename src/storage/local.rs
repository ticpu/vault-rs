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
    pub async fn new() -> Self {
        Self {
            encryption_manager: EncryptionManager::new().await,
        }
    }

    /// Store certificate data encrypted locally
    pub async fn store_certificate(&self, cert_data: CertificateData<'_>) -> Result<()> {
        let cert_dir = VaultCliPaths::cert_storage_dir(
            cert_data.pki_mount,
            cert_data.cn,
            &cert_data.metadata.serial,
        )?;
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
            .encrypt_to_file(cert_data.certificate_pem.as_bytes(), &context, &cert_file)
            .await?;

        // Encrypt and store private key
        self.encryption_manager
            .encrypt_to_file(cert_data.private_key_pem.as_bytes(), &context, &key_file)
            .await?;

        // Encrypt and store CA chain
        self.encryption_manager
            .encrypt_to_file(cert_data.ca_chain_pem.as_bytes(), &context, &ca_file)
            .await?;

        // Create P12 bundle and store it
        let p12_data = self.create_p12_bundle(
            cert_data.certificate_pem,
            cert_data.private_key_pem,
            cert_data.ca_chain_pem,
        )?;
        let p12_file = cert_dir.join("p12.enc");
        self.encryption_manager
            .encrypt_to_file(&p12_data, &context, &p12_file)
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
            .encrypt_yaml_to_file(&cert_storage, &context, &metadata_file)
            .await?;

        // Update master index
        self.update_master_index(cert_storage).await?;

        tracing::info!(
            "Certificate stored encrypted locally: {}",
            cert_dir.display()
        );
        Ok(())
    }

    /// Retrieve certificate data from local storage (finds latest by expiration)
    pub async fn get_certificate(
        &self,
        pki_mount: &str,
        cn: &str,
    ) -> Result<(String, String, String, StorageCertificateMetadata)> {
        let cn_dir = VaultCliPaths::cert_cn_dir(pki_mount, cn)?;
        if !cn_dir.exists() {
            return Err(VaultCliError::CertNotFound(format!(
                "Certificate not found: {pki_mount}/{cn}"
            )));
        }

        // Check if this is old format (files directly in CN directory)
        let old_cert_file = cn_dir.join("certificate.pem.enc");
        let old_metadata_file = cn_dir.join("metadata.yaml.enc");

        if old_cert_file.exists() && old_metadata_file.exists() {
            // Handle old storage format
            let context = format!("cert-{pki_mount}-{cn}");

            let certificate_pem = String::from_utf8(
                self.encryption_manager
                    .decrypt_from_file(&context, &old_cert_file)
                    .await?,
            )?;
            let private_key_pem = String::from_utf8(
                self.encryption_manager
                    .decrypt_from_file(&context, &cn_dir.join("private_key.pem.enc"))
                    .await?,
            )?;
            let ca_chain_pem = String::from_utf8(
                self.encryption_manager
                    .decrypt_from_file(&context, &cn_dir.join("ca_chain.pem.enc"))
                    .await?,
            )?;
            let metadata: StorageCertificateMetadata = self
                .encryption_manager
                .decrypt_yaml_from_file(&context, &old_metadata_file)
                .await?;

            return Ok((certificate_pem, private_key_pem, ca_chain_pem, metadata));
        }

        // Handle new storage format (serial-based directories)
        let mut cert_dirs = Vec::new();
        let entries = fs::read_dir(&cn_dir)?;
        for entry in entries {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                let serial = entry.file_name().to_string_lossy().to_string();
                cert_dirs.push(serial);
            }
        }

        if cert_dirs.is_empty() {
            return Err(VaultCliError::CertNotFound(format!(
                "No certificate serials found for: {pki_mount}/{cn}"
            )));
        }

        // Load metadata for all certificates to find the latest by expiration
        let mut cert_metadata = Vec::new();
        for serial in &cert_dirs {
            let cert_dir = VaultCliPaths::cert_storage_dir(pki_mount, cn, serial)?;
            let context = format!("cert-{pki_mount}-{cn}");
            let metadata_file = cert_dir.join("metadata.yaml.enc");

            match self
                .encryption_manager
                .decrypt_yaml_from_file(&context, &metadata_file)
                .await
            {
                Ok(metadata) => cert_metadata.push((serial.clone(), metadata)),
                Err(e) => {
                    tracing::warn!(
                        "Failed to read metadata for {}/{}/{}: {}",
                        pki_mount,
                        cn,
                        serial,
                        e
                    );
                    continue;
                }
            }
        }

        if cert_metadata.is_empty() {
            return Err(VaultCliError::CertNotFound(format!(
                "No valid certificate metadata found for: {pki_mount}/{cn}"
            )));
        }

        // Sort by expiration date (latest first) and take the newest
        cert_metadata.sort_by(
            |a: &(String, StorageCertificateMetadata), b: &(String, StorageCertificateMetadata)| {
                b.1.expires.cmp(&a.1.expires)
            },
        );
        let (latest_serial, latest_metadata) = &cert_metadata[0];

        let cert_dir = VaultCliPaths::cert_storage_dir(pki_mount, cn, latest_serial)?;
        let context = format!("cert-{pki_mount}-{cn}");

        // Read encrypted files for the latest certificate
        let cert_file = cert_dir.join("certificate.pem.enc");
        let key_file = cert_dir.join("private_key.pem.enc");
        let ca_file = cert_dir.join("ca_chain.pem.enc");

        let certificate_pem = String::from_utf8(
            self.encryption_manager
                .decrypt_from_file(&context, &cert_file)
                .await?,
        )?;
        let private_key_pem = String::from_utf8(
            self.encryption_manager
                .decrypt_from_file(&context, &key_file)
                .await?,
        )?;
        let ca_chain_pem = String::from_utf8(
            self.encryption_manager
                .decrypt_from_file(&context, &ca_file)
                .await?,
        )?;

        Ok((
            certificate_pem,
            private_key_pem,
            ca_chain_pem,
            latest_metadata.clone(),
        ))
    }

    /// List all locally stored certificates
    pub async fn list_certificates(&self) -> Result<Vec<CertificateStorage>> {
        let index = self.get_master_index().await?;
        Ok(index.certificates)
    }

    /// Remove certificate from local storage
    pub async fn remove_certificate(&self, pki_mount: &str, cn: &str) -> Result<()> {
        let cn_dir = VaultCliPaths::cert_cn_dir(pki_mount, cn)?;

        if cn_dir.exists() {
            fs::remove_dir_all(&cn_dir)?;
            tracing::info!("Removed certificate CN directory: {}", cn_dir.display());
        }

        // Update master index - find and remove all certificates for this CN and PKI mount
        let mut index = self.get_master_index().await?;
        let serials_to_remove: Vec<String> = index
            .certificates
            .iter()
            .filter(|cert| cert.meta.cn == cn && cert.pki_mount == pki_mount)
            .map(|cert| cert.meta.serial.clone())
            .collect();

        for serial in serials_to_remove {
            index.remove_certificate(&serial);
        }

        if !index.certificates.is_empty() {
            self.store_master_index(&index).await?;
        }

        Ok(())
    }

    /// Remove specific certificate by serial from local storage
    pub async fn remove_certificate_by_serial(
        &self,
        pki_mount: &str,
        cn: &str,
        serial: &str,
    ) -> Result<()> {
        let cert_dir = VaultCliPaths::cert_storage_dir(pki_mount, cn, serial)?;

        if cert_dir.exists() {
            fs::remove_dir_all(&cert_dir)?;
            tracing::info!("Removed certificate directory: {}", cert_dir.display());
        }

        // Update master index
        let mut index = self.get_master_index().await?;
        if index.remove_certificate(serial) {
            self.store_master_index(&index).await?;
        }

        Ok(())
    }

    /// Export certificate in various formats
    pub async fn export_certificate(
        &self,
        pki_mount: &str,
        cn: &str,
        output_dir: &str,
        formats: &[String],
        _decrypt: bool,
    ) -> Result<()> {
        let (cert_pem, key_pem, ca_pem, _metadata) = self.get_certificate(pki_mount, cn).await?;

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

                    // Find the latest certificate serial for this CN
                    let (_, _, _, metadata) = self.get_certificate(pki_mount, cn).await?;
                    let cert_dir =
                        VaultCliPaths::cert_storage_dir(pki_mount, cn, &metadata.serial)?;
                    let p12_file = cert_dir.join("p12.enc");
                    let context = format!("cert-{pki_mount}-{cn}");
                    let p12_data = self
                        .encryption_manager
                        .decrypt_from_file(&context, &p12_file)
                        .await?;
                    fs::write(output_path.join(format!("{cn}.p12")), p12_data)?;

                    // Set restrictive permissions on private key
                    let key_file = output_path.join(format!("{cn}.key"));
                    crate::utils::set_secure_file_permissions(&key_file)?;
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
                    let key_file = output_path.join(format!("{cn}.key"));
                    crate::utils::set_secure_file_permissions(&key_file)?;
                }
                "chain" => {
                    fs::write(output_path.join(format!("{cn}_chain.pem")), &ca_pem)?;
                }
                "p12" => {
                    // Find the latest certificate serial for this CN
                    let (_, _, _, metadata) = self.get_certificate(pki_mount, cn).await?;
                    let cert_dir =
                        VaultCliPaths::cert_storage_dir(pki_mount, cn, &metadata.serial)?;
                    let p12_file = cert_dir.join("p12.enc");
                    let context = format!("cert-{pki_mount}-{cn}");
                    let p12_data = self
                        .encryption_manager
                        .decrypt_from_file(&context, &p12_file)
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
    async fn get_master_index(&self) -> Result<MasterIndex> {
        let index_file = VaultCliPaths::master_index()?;

        if !index_file.exists() {
            return Ok(MasterIndex::new());
        }

        let index: MasterIndex = self
            .encryption_manager
            .decrypt_yaml_from_file("master-index", &index_file)
            .await?;

        Ok(index)
    }

    /// Store master index
    async fn store_master_index(&self, index: &MasterIndex) -> Result<()> {
        let index_file = VaultCliPaths::master_index()?;
        self.encryption_manager
            .encrypt_yaml_to_file(index, "master-index", &index_file)
            .await
    }

    /// Update master index with new certificate
    async fn update_master_index(&self, cert: CertificateStorage) -> Result<()> {
        let mut index = self.get_master_index().await?;
        index.add_certificate(cert);
        index.update_last_sync();
        self.store_master_index(&index).await
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
    pub async fn cleanup_expired(&self) -> Result<usize> {
        let index = self.get_master_index().await?;
        let expired_certs = index.get_expired().into_iter().cloned().collect::<Vec<_>>();
        let mut removed_count = 0;

        for cert in expired_certs {
            if let Err(e) = self
                .remove_certificate(&cert.pki_mount, &cert.meta.cn)
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
    /// Decrypt a file for debugging purposes
    pub async fn decrypt_file(
        &self,
        context: &str,
        file_path: &std::path::Path,
    ) -> Result<Vec<u8>> {
        self.encryption_manager
            .decrypt_from_file(context, file_path)
            .await
    }

    pub async fn find_by_serial(&self, serial: &str) -> Result<Option<CertificateStorage>> {
        let index = self.get_master_index().await?;
        Ok(index.find_by_serial(serial).cloned())
    }
}
