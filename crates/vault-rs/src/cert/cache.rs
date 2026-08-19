use crate::cert::metadata::CertificateMetadata;
use crate::cert::SerialNumber;
use crate::utils::cli_paths::CliPaths;
use crate::utils::errors::{Result, VaultCliError};
use crate::utils::partial::{Incomplete, Partial};
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
        let cache_dir = CliPaths::cert_cache()?;
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

        cleared_count += self.clear_orphaned_index()?;

        tracing::info!("Cleared {} cache files", cleared_count);
        Ok(cleared_count)
    }

    /// Remove the master index. Nothing reads it — the artifact directory is
    /// the store — so a leftover copy only misleads a hand decryption.
    fn clear_orphaned_index(&self) -> Result<usize> {
        let Some(cache_root) = self.cache_dir.parent() else {
            return Ok(0);
        };
        let index = cache_root.join("index.yaml.enc");
        match fs::remove_file(&index) {
            Ok(()) => {
                tracing::debug!("Removed orphaned master index: {}", index.display());
                Ok(1)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
            Err(e) => Err(e.into()),
        }
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
    use crate::cert::{CertificateColumn, CertificateParser};
    use chrono::Utc;

    fn scratch(name: &str) -> PathBuf {
        let dir = landlock_test_confine::scratch_dir("cache-tests").join(name);
        // discard-ok: test scratch; the directory usually does not exist yet
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

    /// Every fixture, so a new one is covered without anyone remembering to
    /// add it here.
    fn fixtures() -> Vec<(String, CertificateMetadata)> {
        let dir = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/src/cert/testdata"));
        let mut parsed: Vec<_> = fs::read_dir(&dir)
            .expect("testdata directory")
            .map(|entry| entry.expect("directory entry").path())
            .filter(|path| path.extension().and_then(|e| e.to_str()) == Some("pem"))
            .map(|path| {
                let name = path.file_stem().unwrap().to_str().unwrap().to_string();
                let pem = fs::read_to_string(&path).expect("fixture");
                let metadata =
                    CertificateParser::parse_pem(&pem, "test-mount").expect("fixture parses");
                (name, metadata)
            })
            .collect();
        parsed.sort_by(|a, b| a.0.cmp(&b.0));
        assert!(!parsed.is_empty(), "no fixtures found");
        parsed
    }

    /// The suite otherwise stops at the parser, and `cache.rs`'s own tests use
    /// a hand-built struct, so nothing real ever went through the cache. A
    /// computed column reading differently from a cached entry than from a
    /// fresh parse would have shipped with a green suite.
    #[test]
    fn every_fixture_survives_the_cache_unchanged() {
        use crate::utils::output::GetColumnValue;

        let columns = [
            CertificateColumn::Cn,
            CertificateColumn::Serial,
            CertificateColumn::NotBefore,
            CertificateColumn::NotAfter,
            CertificateColumn::Sans,
            CertificateColumn::KeyUsage,
            CertificateColumn::ExtendedKeyUsage,
            CertificateColumn::Issuer,
            CertificateColumn::PkiMount,
            CertificateColumn::Revoked,
            CertificateColumn::Expired,
        ];

        for (name, parsed) in fixtures() {
            let cache = CertificateCache::with_dir(scratch(&format!("roundtrip-{name}"))).unwrap();
            cache.bulk_update("mount", vec![parsed.clone()]).unwrap();

            let cached = cache
                .get_metadata("mount", &parsed.serial)
                .unwrap()
                .unwrap_or_else(|| panic!("{name} did not come back out of the cache"));

            assert_eq!(cached, parsed, "{name} changed across the cache");
            for column in &columns {
                assert_eq!(
                    cached.get_column_value(column),
                    parsed.get_column_value(column),
                    "{name} renders {column:?} differently from the cache"
                );
            }
        }
    }

    /// Pinned per fixture, not one hash over the set: a new fixture then adds
    /// an entry instead of breaking every pin, and only a changed derivation
    /// fails one. A single hash would fail on both and train reflexive
    /// repinning, which is how a pin stops guarding anything.
    ///
    /// `cached_at` is normalised because it is wall-clock, not derived. A
    /// column computed at render time from stored fields is deliberately not
    /// covered: the new binary recomputes it from the cached raw values, so it
    /// cannot go stale and needs no bump. Only what the cache stores can.
    const FIXTURE_FINGERPRINTS: &[(&str, &str)] = &[
        (
            "ca-intermediate",
            "60bccabc7c84e176ccdb57a204bdf010c397b551e5f04ffa132727a8f7091690",
        ),
        (
            "ca-other-root",
            "f51220a9dcbcab571d7f3fd94a9f7da0e97aa133813c0a3239aa281895635ee5",
        ),
        (
            "ca-root",
            "3b2c17f8aa72555f33e9031c8d04335d1b46b586c22e9b3c07a9579a0b11769e",
        ),
        (
            "chain-no-root",
            "125850594bd05e0c48b33a6353973d9248bb91e4390eefc0e13257509058a698",
        ),
        (
            "chain-with-root",
            "125850594bd05e0c48b33a6353973d9248bb91e4390eefc0e13257509058a698",
        ),
        (
            "eku-client",
            "99add85a3bf9a74387a3a18df25243363661e6d22eeb8258637c119e6cbc6655",
        ),
        (
            "eku-client-server",
            "547496fe9be8ace5be95de5aa3134440ad534c1689847fca70137eb417622a3e",
        ),
        (
            "eku-none",
            "6b9e65d87d50783da88be38ba25fb0a5adc205ba3bfe15118f1e319ea16fb561",
        ),
        (
            "eku-server",
            "1f7ac1a9f076912ee1888f5ad3a151bf123a0619259a8fe95dbd580466cfa609",
        ),
        (
            "eku-unknown",
            "9675da0e8dcc7402a654616ae899768b5cfa7e2477f0ff1e511241638264a061",
        ),
        (
            "leaf-client",
            "125850594bd05e0c48b33a6353973d9248bb91e4390eefc0e13257509058a698",
        ),
        (
            "leaf-noeku",
            "987959ecbbc677d278ef73969e557f4848464f6e963eb30aa0517aaa4fc3836a",
        ),
        (
            "leaf-server",
            "69c95abaa35df18cc7314bdaff1a21901053429bcd1b1f9fdf70bdcb0e6430b7",
        ),
    ];

    fn fingerprint(metadata: &CertificateMetadata) -> String {
        use sha2::{Digest, Sha256};
        let mut normalised = metadata.clone();
        normalised.cached_at = chrono::DateTime::from_timestamp(0, 0).unwrap();
        let json = serde_json::to_string(&normalised).expect("metadata serializes");
        hex::encode(Sha256::digest(json.as_bytes()))
    }

    #[test]
    fn what_the_parser_derives_is_pinned_per_fixture() {
        let pinned: HashMap<&str, &str> = FIXTURE_FINGERPRINTS.iter().copied().collect();

        for (name, metadata) in fixtures() {
            let actual = fingerprint(&metadata);
            match pinned.get(name.as_str()) {
                None => panic!(
                    "fixture '{name}' has no pinned fingerprint; add (\"{name}\", \"{actual}\") \
                     to FIXTURE_FINGERPRINTS"
                ),
                Some(expected) => assert_eq!(
                    &actual, expected,
                    "what the parser derives from '{name}' changed. If that is intended, bump \
                     CACHE_SCHEMA_VERSION so already-cached mounts refetch, then repin this to \
                     {actual}"
                ),
            }
        }
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
