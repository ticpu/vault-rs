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

#[derive(Debug, Clone, PartialEq, Eq)]
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

/// Canonical column names, for help text and parse errors. Kept beside the
/// `FromStr` arms below so the two cannot drift.
pub const COLUMN_NAMES: &str = "cn, serial, not_before, not_after, sans, key_usage, \
     extended_key_usage, issuer, pki_mount, revoked, expired";

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
                let ca_prefix = if self.is_ca { "CA:" } else { "" };

                format!("{ca_prefix}{}", self.summarize_extended_key_usage())
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
    /// Abbreviates the TLS authentication usages, which is the distinction the
    /// column exists to show, and passes anything else through verbatim so a
    /// certificate that is also a code-signing cert does not read as only a
    /// client one. An absent extension is reported as such: RFC 5280 leaves
    /// such a certificate unconstrained, so narrowing it here would be an
    /// opinion printed in the same shape as a reading.
    fn summarize_extended_key_usage(&self) -> String {
        if self.extended_key_usage.is_empty() {
            return "None".to_string();
        }

        let (mut client, mut server) = (false, false);
        let mut rest = Vec::new();
        for usage in &self.extended_key_usage {
            match usage.as_str() {
                "ClientAuth" => client = true,
                "ServerAuth" => server = true,
                other => rest.push(other),
            }
        }

        let tls = match (client, server) {
            (true, true) => Some("Client+Server"),
            (true, false) => Some("Client"),
            (false, true) => Some("Server"),
            (false, false) => None,
        };

        tls.into_iter().chain(rest).collect::<Vec<_>>().join(",")
    }

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::output::GetColumnValue;

    fn cert(extended_key_usage: &[&str]) -> CertificateMetadata {
        CertificateMetadata {
            serial: crate::cert::SerialNumber::new("00"),
            cn: "test".to_string(),
            not_before: Utc::now(),
            not_after: Utc::now(),
            sans: vec!["test.example.test".to_string()],
            // The shape the removed heuristic read as "Server".
            key_usage: vec![
                "DigitalSignature".to_string(),
                "KeyEncipherment".to_string(),
            ],
            extended_key_usage: extended_key_usage.iter().map(|s| s.to_string()).collect(),
            is_ca: false,
            issuer: "issuer".to_string(),
            pki_mount: "mount".to_string(),
            cached_at: Utc::now(),
            revocation_time: None,
        }
    }

    fn eku_column(cert: &CertificateMetadata) -> String {
        cert.get_column_value(&CertificateColumn::ExtendedKeyUsage)
    }

    #[test]
    fn absent_eku_is_reported_not_inferred() {
        assert_eq!(eku_column(&cert(&[])), "None");
    }

    #[test]
    fn tls_usages_are_abbreviated() {
        assert_eq!(eku_column(&cert(&["ClientAuth"])), "Client");
        assert_eq!(eku_column(&cert(&["ServerAuth"])), "Server");
        assert_eq!(
            eku_column(&cert(&["ServerAuth", "ClientAuth"])),
            "Client+Server"
        );
    }

    #[test]
    fn other_usages_are_passed_through_alongside() {
        assert_eq!(
            eku_column(&cert(&["ClientAuth", "CodeSigning"])),
            "Client,CodeSigning"
        );
        assert_eq!(eku_column(&cert(&["1.2.3.4"])), "1.2.3.4");
    }

    /// Previously an unrecognised EKU returned early and lost the marker.
    #[test]
    fn ca_prefix_survives_every_branch() {
        let ca = |ekus: &[&str]| {
            let mut c = cert(ekus);
            c.is_ca = true;
            eku_column(&c)
        };
        assert_eq!(ca(&[]), "CA:None");
        assert_eq!(ca(&["ServerAuth"]), "CA:Server");
        assert_eq!(ca(&["1.2.3.4"]), "CA:1.2.3.4");
    }
}
