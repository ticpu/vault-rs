use crate::cert::metadata::CertificateMetadata;
use crate::utils::errors::{Result, VaultCliError};
use crate::utils::paths::VaultCliPaths;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize)]
pub struct CacheEntry {
    pub metadata: CertificateMetadata,
    pub last_verified: chrono::DateTime<chrono::Utc>,
}

pub struct CertificateCache {
    cache_dir: PathBuf,
}

impl CertificateCache {
    pub fn new() -> Result<Self> {
        let cache_dir = VaultCliPaths::cert_cache()?;
        fs::create_dir_all(&cache_dir)?;

        Ok(Self { cache_dir })
    }

    /// Get cache file path for a PKI mount
    fn cache_file_path(&self, pki_mount: &str) -> PathBuf {
        self.cache_dir.join(format!("{pki_mount}.json"))
    }

    /// Load cached certificates for a PKI mount
    pub fn load_cache(&self, pki_mount: &str) -> Result<HashMap<String, CacheEntry>> {
        let cache_file = self.cache_file_path(pki_mount);

        if !cache_file.exists() {
            return Ok(HashMap::new());
        }

        let content = fs::read_to_string(&cache_file)?;
        match serde_json::from_str::<HashMap<String, CacheEntry>>(&content) {
            Ok(cache) => Ok(cache),
            Err(e) => {
                tracing::warn!(
                    "Cache parsing error for '{}': {}. Clearing corrupted cache.",
                    pki_mount,
                    e
                );
                // Auto-clear corrupted cache file
                if let Err(remove_err) = fs::remove_file(&cache_file) {
                    tracing::error!("Failed to remove corrupted cache file: {}", remove_err);
                }
                // Return empty cache so the system can continue
                Ok(HashMap::new())
            }
        }
    }

    /// Save cache for a PKI mount
    pub fn save_cache(&self, pki_mount: &str, cache: &HashMap<String, CacheEntry>) -> Result<()> {
        let cache_file = self.cache_file_path(pki_mount);

        let content = serde_json::to_string_pretty(cache)
            .map_err(|e| VaultCliError::Storage(format!("Cache serialization error: {e}")))?;

        fs::write(&cache_file, content)?;
        tracing::debug!(
            "Saved cache for PKI mount '{}' with {} entries",
            pki_mount,
            cache.len()
        );

        Ok(())
    }

    /// Update cache entry for a certificate
    pub fn update_entry(
        &self,
        pki_mount: &str,
        serial: &str,
        metadata: CertificateMetadata,
    ) -> Result<()> {
        let mut cache = self.load_cache(pki_mount)?;

        cache.insert(
            serial.to_string(),
            CacheEntry {
                metadata,
                last_verified: chrono::Utc::now(),
            },
        );

        self.save_cache(pki_mount, &cache)
    }

    /// Get certificate metadata from cache
    pub fn get_metadata(
        &self,
        pki_mount: &str,
        serial: &str,
    ) -> Result<Option<CertificateMetadata>> {
        let cache = self.load_cache(pki_mount)?;

        Ok(cache.get(serial).map(|entry| entry.metadata.clone()))
    }

    /// Get all cached certificates for a PKI mount
    pub fn get_all_metadata(&self, pki_mount: &str) -> Result<Vec<CertificateMetadata>> {
        let cache = self.load_cache(pki_mount)?;

        Ok(cache.into_values().map(|entry| entry.metadata).collect())
    }

    /// Remove certificate from cache
    pub fn remove_entry(&self, pki_mount: &str, serial: &str) -> Result<()> {
        let mut cache = self.load_cache(pki_mount)?;
        cache.remove(serial);
        self.save_cache(pki_mount, &cache)
    }

    /// Clear entire cache for a PKI mount
    pub fn clear_cache(&self, pki_mount: &str) -> Result<()> {
        let cache_file = self.cache_file_path(pki_mount);
        if cache_file.exists() {
            fs::remove_file(&cache_file)?;
            tracing::info!("Cleared cache for PKI mount '{}'", pki_mount);
        } else {
            tracing::debug!("Cache file for PKI mount '{}' does not exist", pki_mount);
        }
        Ok(())
    }

    /// Clear all cache files
    pub fn clear_all_cache(&self) -> Result<usize> {
        let mut cleared_count = 0;

        if !self.cache_dir.exists() {
            return Ok(0);
        }

        for entry in fs::read_dir(&self.cache_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("json") {
                fs::remove_file(&path)?;
                cleared_count += 1;
                tracing::debug!("Removed cache file: {}", path.display());
            }
        }

        tracing::info!("Cleared {} cache files", cleared_count);
        Ok(cleared_count)
    }

    /// Get cache statistics
    pub fn get_stats(&self) -> Result<HashMap<String, usize>> {
        let mut stats = HashMap::new();

        if let Ok(entries) = fs::read_dir(&self.cache_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("json") {
                    if let Some(mount_name) = path.file_stem().and_then(|s| s.to_str()) {
                        if let Ok(cache) = self.load_cache(mount_name) {
                            stats.insert(mount_name.to_string(), cache.len());
                        }
                    }
                }
            }
        }

        Ok(stats)
    }

    /// Check if cache entry needs refresh (certificates are immutable, so only check if missing)
    pub fn needs_refresh(&self, pki_mount: &str, serial: &str) -> Result<bool> {
        let cache = self.load_cache(pki_mount)?;
        Ok(!cache.contains_key(serial))
    }

    /// Bulk update cache with multiple certificates
    pub fn bulk_update(
        &self,
        pki_mount: &str,
        certificates: Vec<CertificateMetadata>,
    ) -> Result<()> {
        let mut cache = self.load_cache(pki_mount)?;

        let now = chrono::Utc::now();
        for cert in certificates {
            cache.insert(
                cert.serial.clone(),
                CacheEntry {
                    metadata: cert,
                    last_verified: now,
                },
            );
        }

        self.save_cache(pki_mount, &cache)
    }
}
