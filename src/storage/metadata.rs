use crate::utils::output::GetColumnValue;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

fn normalize_serial(serial: &str) -> String {
    serial.replace(':', "").to_lowercase()
}

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

impl GetColumnValue for CertificateStorage {
    /// Get column value for storage certificates using the same system as CertificateMetadata
    fn get_column_value(&self, column: &crate::cert::CertificateColumn) -> String {
        use crate::cert::CertificateColumn;
        match column {
            CertificateColumn::PkiMount => self.pki_mount.clone(),
            _ => self.meta.get_column_value(column),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageCertificateMetadata {
    #[serde(default = "default_serial")]
    pub serial: String,
    #[serde(default = "default_cn")]
    pub cn: String,
    #[serde(default = "default_role")]
    pub role: String,
    #[serde(default = "default_crypto")]
    pub crypto: String,
    #[serde(default = "default_created")]
    pub created: DateTime<Utc>,
    #[serde(default = "default_expires")]
    pub expires: DateTime<Utc>,
    #[serde(default)]
    pub status: CertStatus,
    #[serde(default)]
    pub sans: Vec<String>,
}

fn default_serial() -> String {
    "unknown".to_string()
}

fn default_cn() -> String {
    "unknown".to_string()
}

fn default_role() -> String {
    "unknown".to_string()
}

fn default_crypto() -> String {
    "unknown".to_string()
}

fn default_created() -> DateTime<Utc> {
    Utc::now()
}

fn default_expires() -> DateTime<Utc> {
    Utc::now() + chrono::Duration::days(365)
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

impl Default for CertStatus {
    fn default() -> Self {
        Self::Unknown
    }
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

impl GetColumnValue for StorageCertificateMetadata {
    /// Get column value using the same system as CertificateMetadata
    fn get_column_value(&self, column: &crate::cert::CertificateColumn) -> String {
        use crate::cert::CertificateColumn;
        match column {
            CertificateColumn::Cn => self.cn.clone(),
            CertificateColumn::Serial => normalize_serial(&self.serial),
            CertificateColumn::NotBefore => self.created.format("%Y-%m-%d %H:%M").to_string(),
            CertificateColumn::NotAfter => self.expires.format("%Y-%m-%d %H:%M").to_string(),
            CertificateColumn::Sans => self.sans.join(","),
            CertificateColumn::KeyUsage => "".to_string(), // Not available in storage metadata
            CertificateColumn::ExtendedKeyUsage => {
                let status = if self.is_expired() {
                    "EXPIRED"
                } else {
                    "ACTIVE"
                };
                format!(
                    "{}{}",
                    self.role,
                    if status == "EXPIRED" {
                        " (EXPIRED)"
                    } else {
                        ""
                    }
                )
            }
            CertificateColumn::Issuer => "".to_string(), // Not available in storage metadata
            CertificateColumn::PkiMount => "".to_string(), // This comes from the parent struct
            CertificateColumn::Revoked => " ".to_string(), // Local storage doesn't track revocation
            CertificateColumn::Expired => {
                if self.is_expired() {
                    "✗".to_string()
                } else {
                    " ".to_string()
                }
            }
        }
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
