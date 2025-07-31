use crate::cert::{CertificateCache, CertificateMetadata, CertificateParser, SerialNumber};
use crate::utils::errors::Result;
use crate::vault::client::VaultClient;
use std::collections::HashMap;

pub struct CertificateService {
    client: VaultClient,
    cache: CertificateCache,
}

impl CertificateService {
    pub async fn new() -> Result<Self> {
        Ok(Self {
            client: VaultClient::new().await,
            cache: CertificateCache::new()?,
        })
    }

    /// List certificates with metadata from all PKI mounts or specific mount
    pub async fn list_certificates_with_metadata(
        &self,
        pki_mount: Option<&str>,
    ) -> Result<Vec<CertificateMetadata>> {
        if let Some(mount) = pki_mount {
            self.list_certificates_single_mount(mount).await
        } else {
            self.list_certificates_all_mounts().await
        }
    }

    /// List certificates with metadata from all PKI mounts
    async fn list_certificates_all_mounts(&self) -> Result<Vec<CertificateMetadata>> {
        let pki_mounts = self.client.list_pki_mounts().await?;
        let mut all_certificates = Vec::new();

        for mount in pki_mounts {
            if let Ok(certs) = self.list_certificates_single_mount(&mount).await {
                all_certificates.extend(certs);
            }
            // Silently skip mounts that fail (might not have permissions)
        }

        // Sort by not_after date (newest first)
        all_certificates.sort_by(|a, b| b.not_after.cmp(&a.not_after));

        Ok(all_certificates)
    }

    /// List certificates with metadata from a single PKI mount, using cache when possible
    async fn list_certificates_single_mount(
        &self,
        pki_mount: &str,
    ) -> Result<Vec<CertificateMetadata>> {
        tracing::debug!("Listing certificates for PKI mount: {}", pki_mount);

        // Get list of certificate serials from Vault
        let serials = self.client.list_certificates(pki_mount).await?;
        tracing::debug!("Found {} certificates in Vault", serials.len());

        let mut results = Vec::new();
        let mut to_fetch = Vec::new();

        // Check cache for each certificate
        for serial in &serials {
            if let Some(metadata) = self.cache.get_metadata(pki_mount, serial)? {
                tracing::trace!("Found cached metadata for serial: {}", serial);
                results.push(metadata);
            } else {
                tracing::trace!("Need to fetch metadata for serial: {}", serial);
                to_fetch.push(serial.clone());
            }
        }

        // Fetch missing certificates from Vault
        if !to_fetch.is_empty() {
            tracing::info!("Fetching {} certificates from Vault", to_fetch.len());
            let mut fetched_metadata = Vec::new();

            for serial in to_fetch.into_iter() {
                match self.fetch_certificate_metadata(pki_mount, &serial).await {
                    Ok(metadata) => {
                        // Update cache
                        if let Err(e) =
                            self.cache
                                .update_entry(pki_mount, &serial, metadata.clone())
                        {
                            tracing::warn!("Failed to cache metadata for {}: {}", serial, e);
                        }
                        fetched_metadata.push(metadata);
                    }
                    Err(e) => {
                        tracing::warn!("Failed to fetch metadata for {}: {}", serial, e);
                        // Continue with other certificates instead of failing completely
                    }
                }
            }

            results.extend(fetched_metadata);
        }

        // Sort by not_after date (newest first)
        results.sort_by(|a, b| b.not_after.cmp(&a.not_after));

        tracing::info!("Retrieved {} certificate metadata entries", results.len());
        Ok(results)
    }

    /// Fetch certificate metadata from Vault and parse it
    async fn fetch_certificate_metadata(
        &self,
        pki_mount: &str,
        serial: &SerialNumber,
    ) -> Result<CertificateMetadata> {
        tracing::debug!("Fetching certificate PEM for serial: {}", serial);

        let cert_data = self.client.get_certificate_pem(pki_mount, serial).await?;
        let mut metadata = CertificateParser::parse_pem(&cert_data.certificate, pki_mount)?;

        // Set revocation time from Vault response
        metadata.revocation_time = cert_data
            .revocation_time
            .map(|t| chrono::DateTime::from_timestamp(t, 0).unwrap_or_else(chrono::Utc::now));

        tracing::debug!(
            "Parsed metadata for CN: {} (serial: {})",
            metadata.cn,
            serial
        );
        Ok(metadata)
    }

    /// Sync cache with Vault for a PKI mount
    pub async fn sync_cache(&self, pki_mount: &str) -> Result<usize> {
        tracing::info!("Syncing cache for PKI mount: {}", pki_mount);

        let serials = self.client.list_certificates(pki_mount).await?;
        let mut synced_count = 0;

        for serial in serials.into_iter() {
            if self.cache.needs_refresh(pki_mount, &serial)? {
                match self.fetch_certificate_metadata(pki_mount, &serial).await {
                    Ok(metadata) => {
                        self.cache.update_entry(pki_mount, &serial, metadata)?;
                        synced_count += 1;
                    }
                    Err(e) => {
                        tracing::warn!("Failed to sync certificate {}: {}", serial, e);
                    }
                }
            }
        }

        tracing::info!(
            "Synced {} certificates for PKI mount: {}",
            synced_count,
            pki_mount
        );
        Ok(synced_count)
    }

    /// Clear cache for a PKI mount
    pub fn clear_cache(&self, pki_mount: &str) -> Result<()> {
        self.cache.clear_cache(pki_mount)
    }

    /// Clear all cache files
    pub fn clear_all_cache(&self) -> Result<usize> {
        self.cache.clear_all_cache()
    }

    /// Get cache statistics
    pub fn get_cache_stats(&self) -> Result<HashMap<String, usize>> {
        self.cache.get_stats()
    }

    /// Rebuild cache from Vault
    pub async fn rebuild_cache(&self, pki_mount: Option<&str>) -> Result<usize> {
        let mut total_rebuilt = 0;

        if let Some(mount) = pki_mount {
            // Rebuild specific mount
            self.clear_cache(mount)?;
            total_rebuilt += self.sync_cache(mount).await?;
        } else {
            // Rebuild all PKI mounts
            let pki_mounts = self.client.list_pki_mounts().await?;

            for mount in pki_mounts {
                self.clear_cache(&mount)?;
                total_rebuilt += self.sync_cache(&mount).await?;
            }
        }

        Ok(total_rebuilt)
    }
}
