use crate::cert::{CertificateCache, CertificateMetadata, CertificateParser, SerialNumber};
use crate::utils::errors::Result;
use crate::utils::partial::{Incomplete, Partial};
use crate::vault::client::VaultClient;
use crate::vault::PkiClient;

pub struct CertificateService {
    client: VaultClient,
    cache: CertificateCache,
}

impl CertificateService {
    pub async fn new() -> Result<Self> {
        Ok(Self {
            client: crate::vault::operator_client().await?,
            cache: CertificateCache::new()?,
        })
    }

    /// List certificates with metadata from all PKI mounts or specific mount.
    ///
    /// Certificates that could not be read come back as failures rather than
    /// silently missing rows; the caller decides whether an incomplete listing
    /// is an answer.
    pub async fn list_certificates_with_metadata(
        &self,
        pki_mount: Option<&str>,
    ) -> Result<Partial<CertificateMetadata>> {
        let mut result = if let Some(mount) = pki_mount {
            self.list_certificates_single_mount(mount).await?
        } else {
            self.list_certificates_all_mounts().await?
        };

        // Soonest expiry first.
        result.items_mut().sort_by_key(|c| c.not_after);

        Ok(result)
    }

    /// List certificates with metadata from all PKI mounts
    async fn list_certificates_all_mounts(&self) -> Result<Partial<CertificateMetadata>> {
        let pki_mounts = self.client.list_pki_mounts().await?;
        let mut all_certificates = Partial::new();

        for mount in pki_mounts {
            // A mount that will not list is recorded as a failure, not an abort.
            match self.list_certificates_single_mount(&mount).await {
                Ok(certs) => all_certificates.absorb(certs),
                Err(e) => all_certificates.fail(Incomplete::record(&mount, e)),
            }
        }

        Ok(all_certificates)
    }

    /// List certificates with metadata from a single PKI mount, using cache when possible
    async fn list_certificates_single_mount(
        &self,
        pki_mount: &str,
    ) -> Result<Partial<CertificateMetadata>> {
        tracing::debug!("Listing certificates for PKI mount: {}", pki_mount);

        // Get list of certificate serials from Vault
        let serials = self.client.list_certificates(pki_mount).await?;
        tracing::debug!("Found {} certificates in Vault", serials.len());

        let mut results = Partial::new();
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
                    Ok(metadata) => fetched_metadata.push(metadata),
                    Err(e) => results.fail(Incomplete::record(serial.to_string(), e)),
                }
            }

            // One rewrite of the mount's cache file for the whole batch,
            // instead of a per-certificate rewrite (O(n^2) file writes on a
            // cold cache).
            results.extend(fetched_metadata.iter().cloned());

            // A failed cache write leaves the answer complete; only the next
            // run is slower.
            if let Err(e) = self.cache.bulk_update(pki_mount, fetched_metadata) {
                tracing::warn!("Failed to cache metadata batch for {}: {}", pki_mount, e);
            }
        }

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
            .map(|t| crate::cert::parser::timestamp(t, "revocation_time"))
            .transpose()?;

        tracing::debug!(
            "Parsed metadata for CN: {} (serial: {})",
            metadata.cn,
            serial
        );
        Ok(metadata)
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
    pub fn get_cache_stats(&self) -> Result<Partial<(String, String)>> {
        self.cache.get_stats()
    }
}
