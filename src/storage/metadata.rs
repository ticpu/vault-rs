use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateStorage {
    pub pki_mount: String,
    pub crypto: String,
    pub created: DateTime<Utc>,
    pub storage_path: String,
    pub vault_status: String,
    pub last_vault_check: DateTime<Utc>,
    pub file_info: HashMap<String, FileInfo>,
    pub meta: StorageCertificateMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageCertificateMetadata {
    pub serial: String,
    pub cn: String,
    pub role: String,
    pub crypto: String,
    pub created: DateTime<Utc>,
    pub expires: DateTime<Utc>,
    pub status: CertStatus,
    pub sans: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInfo {
    pub size: u64,
    pub created: DateTime<Utc>,
    pub checksum: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CertStatus {
    Active,
    Expired,
    Revoked,
    Unknown,
}

impl StorageCertificateMetadata {
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires
    }

    pub fn expires_soon(&self, days: u32) -> bool {
        let threshold = Utc::now() + chrono::Duration::days(days as i64);
        self.expires < threshold
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MasterIndex {
    pub certificates: Vec<CertificateStorage>,
    pub last_full_sync: DateTime<Utc>,
    pub cache_version: String,
}

impl MasterIndex {
    pub fn new() -> Self {
        Self {
            certificates: Vec::new(),
            last_full_sync: Utc::now(),
            cache_version: "1.0".to_string(),
        }
    }

    pub fn add_certificate(&mut self, cert: CertificateStorage) {
        // Remove existing entry with same serial if it exists
        self.certificates
            .retain(|c| c.meta.serial != cert.meta.serial);
        self.certificates.push(cert);
        self.sort_by_expiry();
    }

    pub fn remove_certificate(&mut self, serial: &str) -> bool {
        let before_count = self.certificates.len();
        self.certificates.retain(|c| c.meta.serial != serial);
        self.certificates.len() != before_count
    }

    pub fn find_by_serial(&self, serial: &str) -> Option<&CertificateStorage> {
        self.certificates.iter().find(|c| c.meta.serial == serial)
    }

    pub fn find_by_cn(&self, cn: &str) -> Vec<&CertificateStorage> {
        self.certificates
            .iter()
            .filter(|c| c.meta.cn == cn)
            .collect()
    }

    pub fn find_by_pki_mount(&self, pki_mount: &str) -> Vec<&CertificateStorage> {
        self.certificates
            .iter()
            .filter(|c| c.pki_mount == pki_mount)
            .collect()
    }

    pub fn get_expired(&self) -> Vec<&CertificateStorage> {
        self.certificates
            .iter()
            .filter(|c| c.meta.is_expired())
            .collect()
    }

    pub fn get_expiring_soon(&self, days: u32) -> Vec<&CertificateStorage> {
        self.certificates
            .iter()
            .filter(|c| c.meta.expires_soon(days))
            .collect()
    }

    pub fn sort_by_expiry(&mut self) {
        self.certificates
            .sort_by(|a, b| a.meta.expires.cmp(&b.meta.expires));
    }

    pub fn update_last_sync(&mut self) {
        self.last_full_sync = Utc::now();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerialCacheEntry {
    pub serial: String,
    pub cn: String,
    pub pki_mount: String,
    pub storage_path: String,
    pub vault_metadata: VaultCertMetadata,
    pub local_metadata: LocalCertMetadata,
    pub last_updated: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultCertMetadata {
    pub subject: String,
    pub issuer: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub key_usage: Vec<String>,
    pub sans: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalCertMetadata {
    pub created: DateTime<Utc>,
    pub files: Vec<String>,
    pub file_sizes: HashMap<String, u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PKICache {
    pub pki_mount: String,
    pub ca_info: CAInfo,
    pub roles: Vec<String>,
    pub last_certificate_list: Vec<String>,
    pub last_sync: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CAInfo {
    pub issuer: String,
    pub serial: String,
    pub not_after: DateTime<Utc>,
}

impl Default for MasterIndex {
    fn default() -> Self {
        Self::new()
    }
}
