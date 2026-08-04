use crate::cert::metadata::CertificateMetadata;
use crate::cert::SerialNumber;
use crate::utils::errors::{Result, VaultCliError};
use crate::utils::partial::{Incomplete, Partial};
use crate::utils::paths::VaultCliPaths;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

/// Bump whenever a change alters what is derived from a certificate — a parsed
/// field, a computed one, or the meaning of an existing value.
///
/// The cache holds derived metadata, not the certificate, so a parser fix
/// reaches nobody who already has a cached mount: the new binary deserializes
/// the old conclusions and renders them faithfully. Nothing about a stale entry
/// looks stale, and the test suite cannot see it, because fixtures go through
/// the parser and never through the cache. This number is what makes such a fix
/// self-invalidating instead of dependent on someone being told to clear it.
const CACHE_SCHEMA_VERSION: u32 = 2;

#[derive(Debug, Serialize, Deserialize)]
pub struct CacheEntry {
    pub metadata: CertificateMetadata,
    /// Written on every insert; nothing reads it.
    pub last_verified: chrono::DateTime<chrono::Utc>,
}

/// On-disk shape. Entries are keyed by serial as a string; `SerialNumber` is
/// reconstructed on load.
#[derive(Debug, Deserialize)]
struct CacheFile {
    version: u32,
    entries: HashMap<String, CacheEntry>,
}

/// Writing side, borrowing the live entries rather than cloning them.
#[derive(Serialize)]
struct CacheFileRef<'a> {
    version: u32,
    entries: HashMap<String, &'a CacheEntry>,
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

    #[cfg(test)]
    fn with_dir(cache_dir: PathBuf) -> Result<Self> {
        fs::create_dir_all(&cache_dir)?;
        Ok(Self { cache_dir })
    }

    /// Get cache file path for a PKI mount
    fn cache_file_path(&self, pki_mount: &str) -> PathBuf {
        self.cache_dir.join(format!("{pki_mount}.json"))
    }

    /// Load cached certificates for a PKI mount
    pub fn load_cache(&self, pki_mount: &str) -> Result<HashMap<SerialNumber, CacheEntry>> {
        let cache_file = self.cache_file_path(pki_mount);

        if !cache_file.exists() {
            return Ok(HashMap::new());
        }

        let content = fs::read_to_string(&cache_file)?;
        let parsed = serde_json::from_str::<CacheFile>(&content);

        // A file this binary cannot read, or one written before the current
        // schema, is discarded rather than trusted. Both cases mean the same
        // thing: its conclusions were drawn by different code.
        let file = match parsed {
            Ok(file) if file.version == CACHE_SCHEMA_VERSION => file,
            Ok(file) => {
                tracing::info!(
                    "Cache for '{pki_mount}' was written by schema v{} (current v{CACHE_SCHEMA_VERSION}); refetching.",
                    file.version
                );
                return self.discard(&cache_file);
            }
            Err(e) => {
                tracing::info!("Cache for '{pki_mount}' is unreadable ({e}); refetching.");
                return self.discard(&cache_file);
            }
        };

        let mut cache = HashMap::with_capacity(file.entries.len());
        for (key, entry) in file.entries {
            let serial =
                SerialNumber::parse(&key).map_err(|e| VaultCliError::SerialNumberParse {
                    key: key.clone(),
                    source: e,
                })?;
            cache.insert(serial, entry);
        }

        Ok(cache)
    }

    /// Remove a cache file that must not be trusted, and report an empty cache
    /// so the caller refetches from Vault.
    fn discard(&self, cache_file: &std::path::Path) -> Result<HashMap<SerialNumber, CacheEntry>> {
        if let Err(e) = fs::remove_file(cache_file) {
            tracing::error!("Failed to remove cache file {}: {e}", cache_file.display());
        }

        Ok(HashMap::new())
    }

    /// Save cache for a PKI mount
    pub fn save_cache(
        &self,
        pki_mount: &str,
        cache: &HashMap<SerialNumber, CacheEntry>,
    ) -> Result<()> {
        let cache_file = self.cache_file_path(pki_mount);

        let file = CacheFileRef {
            version: CACHE_SCHEMA_VERSION,
            entries: cache
                .iter()
                .map(|(serial, entry)| (serial.to_string(), entry))
                .collect(),
        };

        let content = serde_json::to_string_pretty(&file)
            .map_err(|e| VaultCliError::Storage(format!("Cache serialization error: {e}")))?;

        fs::write(&cache_file, content)?;
        tracing::debug!(
            "Saved cache for PKI mount '{}' with {} entries",
            pki_mount,
            cache.len()
        );

        Ok(())
    }

    /// Get certificate metadata from cache
    pub fn get_metadata(
        &self,
        pki_mount: &str,
        serial: &SerialNumber,
    ) -> Result<Option<CertificateMetadata>> {
        let cache = self.load_cache(pki_mount)?;

        Ok(cache.get(serial).map(|entry| entry.metadata.clone()))
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

    /// Per-mount entry counts.
    ///
    /// A mount whose file will not load keeps its row with no count: the name
    /// came from the filename and read fine. Failing to read the directory at
    /// all is different — that is not a partial answer, it is none, so it
    /// propagates rather than reporting an empty cache.
    pub fn get_stats(&self) -> Result<Partial<(String, String)>> {
        let mut stats = Partial::new();

        if !self.cache_dir.exists() {
            return Ok(stats);
        }

        for entry in fs::read_dir(&self.cache_dir)? {
            let path = entry?.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            let Some(mount) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };

            match self.load_cache(mount) {
                Ok(cache) => stats.push((mount.to_string(), cache.len().to_string())),
                Err(e) => {
                    stats.fail(Incomplete::unread_field(mount, "entry count", e));
                    stats.push((mount.to_string(), String::new()));
                }
            }
        }

        Ok(stats)
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn scratch(name: &str) -> PathBuf {
        let dir =
            PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/target/cache-tests")).join(name);
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    fn metadata(extended_key_usage: &[&str]) -> CertificateMetadata {
        CertificateMetadata {
            serial: SerialNumber::new("0a0b"),
            cn: "leaf".to_string(),
            not_before: Utc::now(),
            not_after: Utc::now(),
            sans: vec!["leaf.example.test".to_string()],
            key_usage: vec!["DigitalSignature".to_string()],
            extended_key_usage: extended_key_usage.iter().map(|s| s.to_string()).collect(),
            is_ca: false,
            issuer: "issuer".to_string(),
            pki_mount: "mount".to_string(),
            cached_at: Utc::now(),
            revocation_time: None,
        }
    }

    /// The suite otherwise only exercises the parser, so a derived field could
    /// survive a round trip wrong and nothing would notice.
    #[test]
    fn derived_metadata_survives_a_round_trip() {
        let cache = CertificateCache::with_dir(scratch("roundtrip")).unwrap();
        let serial = SerialNumber::new("0a0b");

        cache
            .bulk_update("mount", vec![metadata(&["ClientAuth"])])
            .unwrap();

        let read = cache.get_metadata("mount", &serial).unwrap().unwrap();
        assert_eq!(read.extended_key_usage, ["ClientAuth"]);
        assert_eq!(read.cn, "leaf");
    }

    /// A file written by a previous schema is discarded, not deserialized.
    /// Otherwise a parser fix ships inert for every already-cached mount.
    #[test]
    fn a_file_from_an_older_schema_is_discarded() {
        let dir = scratch("older-schema");
        let cache = CertificateCache::with_dir(dir.clone()).unwrap();

        cache
            .bulk_update("mount", vec![metadata(&["ClientAuth"])])
            .unwrap();

        let path = dir.join("mount.json");
        let content = fs::read_to_string(&path).unwrap();
        fs::write(
            &path,
            content.replace(
                &format!("\"version\": {CACHE_SCHEMA_VERSION}"),
                "\"version\": 0",
            ),
        )
        .unwrap();

        assert!(cache.load_cache("mount").unwrap().is_empty());
        assert!(!path.exists(), "stale file should be removed, not reused");
    }

    /// The pre-versioning format was a bare map of serial to entry. Reading one
    /// as if it were current is exactly how stale conclusions were served.
    #[test]
    fn a_file_from_before_versioning_is_discarded() {
        let dir = scratch("unversioned");
        let cache = CertificateCache::with_dir(dir.clone()).unwrap();
        let path = dir.join("mount.json");
        fs::write(
            &path,
            r#"{"0a:0b":{"metadata":{"serial":"0a:0b","cn":"leaf","not_before":"2026-01-01T00:00:00Z","not_after":"2031-01-01T00:00:00Z","sans":[],"key_usage":[],"extended_key_usage":[],"is_ca":false,"issuer":"i","pki_mount":"mount","cached_at":"2026-01-01T00:00:00Z","revocation_time":null},"last_verified":"2026-01-01T00:00:00Z"}}"#,
        )
        .unwrap();

        assert!(cache.load_cache("mount").unwrap().is_empty());
        assert!(!path.exists());
    }
}
