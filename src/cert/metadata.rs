use crate::cert::SerialNumber;
use crate::utils::output::GetColumnValue;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateMetadata {
    pub serial: SerialNumber,
    pub cn: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub sans: Vec<String>,
    pub key_usage: Vec<String>,
    pub extended_key_usage: Vec<String>,
    pub is_ca: bool,
    pub issuer: String,
    pub pki_mount: String,
    pub cached_at: DateTime<Utc>,
    pub revocation_time: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub enum CertificateColumn {
    Cn,
    Serial,
    NotBefore,
    NotAfter,
    Sans,
    KeyUsage,
    ExtendedKeyUsage,
    Issuer,
    PkiMount,
    Revoked,
    Expired,
}

impl FromStr for CertificateColumn {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "cn" => Ok(Self::Cn),
            "serial" => Ok(Self::Serial),
            "not_before" => Ok(Self::NotBefore),
            "not_after" => Ok(Self::NotAfter),
            "sans" => Ok(Self::Sans),
            "key_usage" => Ok(Self::KeyUsage),
            "extended_key_usage" | "ext_key_usage" => Ok(Self::ExtendedKeyUsage),
            "issuer" => Ok(Self::Issuer),
            "pki_mount" | "mount" => Ok(Self::PkiMount),
            "revoked" | "r" => Ok(Self::Revoked),
            "expired" | "e" => Ok(Self::Expired),
            _ => Err(format!("Invalid column: {s}")),
        }
    }
}

impl CertificateColumn {
    pub fn header(&self) -> &'static str {
        match self {
            Self::Cn => "CN",
            Self::Serial => "Serial",
            Self::NotBefore => "Not Before",
            Self::NotAfter => "Not After",
            Self::Sans => "SANs",
            Self::KeyUsage => "Key Usage",
            Self::ExtendedKeyUsage => "Ext Key Usage",
            Self::Issuer => "Issuer",
            Self::PkiMount => "PKI Mount",
            Self::Revoked => "R",
            Self::Expired => "E",
        }
    }

    pub fn width(&self) -> usize {
        match self {
            Self::Cn => 30,
            Self::Serial => 20,
            Self::NotBefore => 19,
            Self::NotAfter => 19,
            Self::Sans => 40,
            Self::KeyUsage => 20,
            Self::ExtendedKeyUsage => 25,
            Self::Issuer => 30,
            Self::PkiMount => 15,
            Self::Revoked => 1,
            Self::Expired => 1,
        }
    }
}

impl GetColumnValue for CertificateMetadata {
    fn get_column_value(&self, column: &CertificateColumn) -> String {
        match column {
            CertificateColumn::Cn => self.cn.clone(),
            CertificateColumn::Serial => self.serial.to_string(),
            CertificateColumn::NotBefore => self.not_before.format("%Y-%m-%d %H:%M").to_string(),
            CertificateColumn::NotAfter => self.not_after.format("%Y-%m-%d %H:%M").to_string(),
            CertificateColumn::Sans => self.sans.join(","),
            CertificateColumn::KeyUsage => self.key_usage.join(","),
            CertificateColumn::ExtendedKeyUsage => {
                // Combine CA status with usage type
                let ca_prefix = if self.is_ca { "CA:" } else { "" };

                // Simplify extended key usage to client/server/both
                let has_client = self
                    .extended_key_usage
                    .iter()
                    .any(|eku| eku.contains("ClientAuth"));
                let has_server = self
                    .extended_key_usage
                    .iter()
                    .any(|eku| eku.contains("ServerAuth"));

                let usage = match (has_client, has_server) {
                    (true, true) => "Client+Server",
                    (true, false) => "Client",
                    (false, true) => "Server",
                    (false, false) => {
                        // Fallback: if no Extended Key Usage, infer from Key Usage and SANs
                        if self.extended_key_usage.is_empty() {
                            let has_digital_sig = self
                                .key_usage
                                .iter()
                                .any(|ku| ku.contains("DigitalSignature"));
                            let has_key_encipherment = self
                                .key_usage
                                .iter()
                                .any(|ku| ku.contains("KeyEncipherment"));
                            let has_sans = !self.sans.is_empty();

                            // Common heuristic: DigitalSignature + KeyEncipherment + SANs = Server cert
                            if has_digital_sig && has_key_encipherment && has_sans {
                                "Server"
                            } else if has_digital_sig && has_key_encipherment {
                                "Client+Server"
                            } else {
                                "Unknown"
                            }
                        } else {
                            return self.extended_key_usage.join(",");
                        }
                    }
                };

                format!("{ca_prefix}{usage}")
            }
            CertificateColumn::Issuer => self.issuer.clone(),
            CertificateColumn::PkiMount => self.pki_mount.clone(),
            CertificateColumn::Revoked => {
                if let Some(revoke_time) = self.revocation_time {
                    // Only show as revoked if revocation time is actually set (> 0)
                    // Vault returns 0 for non-revoked certificates
                    if revoke_time.timestamp() > 0 {
                        "✗".to_string()
                    } else {
                        " ".to_string()
                    }
                } else {
                    " ".to_string()
                }
            }
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

impl CertificateMetadata {
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.not_after
    }

    pub fn expires_soon(&self, days: u32) -> bool {
        let threshold = Utc::now() + chrono::Duration::days(days as i64);
        self.not_after <= threshold
    }
}

impl fmt::Display for CertificateMetadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CN: {}, Serial: {}, Expires: {}",
            self.cn,
            self.serial,
            self.not_after.format("%Y-%m-%d %H:%M")
        )
    }
}
