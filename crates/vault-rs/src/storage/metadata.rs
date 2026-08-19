use crate::utils::output::GetColumnValue;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub(crate) fn normalize_serial(serial: &str) -> String {
    serial.replace(':', "").to_lowercase()
}

/// What `metadata.yaml.enc` holds: only what the stored certificate cannot
/// yield. Anything readable from the certificate is read from it on every
/// listing instead, so no second copy of it can go stale on disk.
///
/// Keys and nesting stay a strict subset of the on-disk shape, so one parse
/// path reads every artifact and none needs a migration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredMetadata {
    /// What the issuance was asked for. No certificate records the request,
    /// only its result, so an artifact that arrived without this has none.
    pub crypto: Option<String>,
    /// When the artifact was written, not the certificate's `notBefore`.
    pub created: DateTime<Utc>,
    pub file_info: HashMap<String, FileInfo>,
    pub meta: StoredIdentity,
}

/// The part of the issuance no certificate records.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredIdentity {
    /// The PKI has no record of which role issued a certificate, so the store
    /// is the only place this exists — and an artifact imported without it
    /// genuinely has none. Absent rather than invented: a fabricated value
    /// here is unfalsifiable, since nothing else holds the field.
    pub role: Option<String>,
    pub status: CertStatus,
}

/// Which Vault sealed an artifact, kept in the clear beside it: the moment it
/// is wanted is the moment nothing in that directory decrypts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedBy {
    pub cluster_id: String,
    /// A hint only, never the identity.
    pub address: String,
}

/// One stored artifact, assembled by the walk. Never deserialized: the
/// certificate-derived fields come from the certificate itself.
#[derive(Debug, Clone, Serialize)]
pub struct CertificateStorage {
    pub pki_mount: String,
    pub crypto: Option<String>,
    pub created: DateTime<Utc>,
    pub storage_path: String,
    pub sealed_by: Option<SealedBy>,
    pub file_info: HashMap<String, FileInfo>,
    pub meta: StorageCertificateMetadata,
}

impl GetColumnValue for CertificateStorage {
    fn get_column_value(&self, column: &crate::cert::CertificateColumn) -> String {
        use crate::cert::CertificateColumn;
        match column {
            CertificateColumn::PkiMount => self.pki_mount.clone(),
            _ => self.meta.get_column_value(column),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct StorageCertificateMetadata {
    pub serial: String,
    pub cn: String,
    pub role: Option<String>,
    pub crypto: Option<String>,
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

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub enum CertStatus {
    Active,
    Expired,
    Revoked,
    #[default]
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

impl GetColumnValue for StorageCertificateMetadata {
    fn get_column_value(&self, column: &crate::cert::CertificateColumn) -> String {
        use crate::cert::CertificateColumn;
        match column {
            CertificateColumn::Cn => self.cn.clone(),
            CertificateColumn::Serial => normalize_serial(&self.serial),
            CertificateColumn::NotBefore => self.created.format("%Y-%m-%d %H:%M").to_string(),
            CertificateColumn::NotAfter => self.expires.format("%Y-%m-%d %H:%M").to_string(),
            CertificateColumn::Sans => self.sans.join(","),
            CertificateColumn::KeyUsage => "".to_string(), // Not available in storage metadata
            CertificateColumn::ExtendedKeyUsage => "".to_string(), // Not available in storage metadata
            CertificateColumn::Issuer => "".to_string(), // Not available in storage metadata
            CertificateColumn::PkiMount => "".to_string(), // This comes from the parent struct
            CertificateColumn::Revoked => String::new(), // Local storage doesn't track revocation
            CertificateColumn::Expired => match self.is_expired() {
                true => "✗".to_string(),
                false => String::new(),
            },
            CertificateColumn::Role => self.role.clone().unwrap_or_default(),
        }
    }
}
