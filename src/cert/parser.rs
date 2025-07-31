use crate::cert::metadata::CertificateMetadata;
use crate::cert::SerialNumber;
use crate::utils::errors::{Result, VaultCliError};
use base64::{engine::general_purpose, Engine as _};
use chrono::{DateTime, Utc};
use x509_parser::der_parser::oid;
use x509_parser::prelude::*;

// X.509 Extension OIDs
const SUBJECT_ALT_NAME_OID: oid::Oid = oid!(2.5.29 .17);
const KEY_USAGE_OID: oid::Oid = oid!(2.5.29 .15);
const EXTENDED_KEY_USAGE_OID: oid::Oid = oid!(2.5.29 .37);
const BASIC_CONSTRAINTS_OID: oid::Oid = oid!(2.5.29 .19);

// Extended Key Usage OIDs
const EKU_SERVER_AUTH: &str = "1.3.6.1.5.5.7.3.1";
const EKU_CLIENT_AUTH: &str = "1.3.6.1.5.5.7.3.2";
const EKU_CODE_SIGNING: &str = "1.3.6.1.5.5.7.3.3";
const EKU_EMAIL_PROTECTION: &str = "1.3.6.1.5.5.7.3.4";
const EKU_TIME_STAMPING: &str = "1.3.6.1.5.5.7.3.8";
const EKU_OCSP_SIGNING: &str = "1.3.6.1.5.5.7.3.9";

pub struct CertificateParser;

impl CertificateParser {
    /// Parse certificate PEM data into metadata
    pub fn parse_pem(pem_data: &str, pki_mount: &str) -> Result<CertificateMetadata> {
        // Extract the base64 content from PEM
        let cert_data = Self::extract_cert_from_pem(pem_data)?;

        // Decode base64
        let der_bytes = general_purpose::STANDARD
            .decode(&cert_data)
            .map_err(|e| VaultCliError::CertParsing(format!("Base64 decode error: {e}")))?;

        // Parse DER certificate
        let (_, cert) = X509Certificate::from_der(&der_bytes)
            .map_err(|e| VaultCliError::CertParsing(format!("DER parsing error: {e}")))?;

        Self::extract_metadata(&cert, pki_mount)
    }

    /// Extract certificate data from PEM format
    fn extract_cert_from_pem(pem_data: &str) -> Result<String> {
        let mut in_cert = false;
        let mut cert_lines = Vec::new();

        for line in pem_data.lines() {
            let line = line.trim();
            if line == "-----BEGIN CERTIFICATE-----" {
                in_cert = true;
                continue;
            } else if line == "-----END CERTIFICATE-----" {
                break;
            } else if in_cert {
                cert_lines.push(line);
            }
        }

        if cert_lines.is_empty() {
            return Err(VaultCliError::CertParsing(
                "No certificate data found in PEM".to_string(),
            ));
        }

        Ok(cert_lines.join(""))
    }

    /// Extract metadata from X509 certificate
    fn extract_metadata(cert: &X509Certificate, pki_mount: &str) -> Result<CertificateMetadata> {
        // Extract serial number - normalize to continuous hex format
        let serial = SerialNumber::new(&hex::encode(cert.serial.to_bytes_be()));

        // Extract subject CN
        let cn = cert
            .subject()
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok())
            .unwrap_or("Unknown")
            .to_string();

        // Extract issuer
        let issuer = cert
            .issuer()
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok())
            .unwrap_or("Unknown")
            .to_string();

        // Extract validity dates
        let not_before = DateTime::from_timestamp(cert.validity().not_before.timestamp(), 0)
            .unwrap_or_else(Utc::now);
        let not_after = DateTime::from_timestamp(cert.validity().not_after.timestamp(), 0)
            .unwrap_or_else(Utc::now);

        // Extract SANs
        let mut sans = Vec::new();
        for ext in cert.extensions() {
            if ext.oid == SUBJECT_ALT_NAME_OID {
                if let Ok((_rem, san)) = SubjectAlternativeName::from_der(ext.value) {
                    for name in &san.general_names {
                        match name {
                            GeneralName::DNSName(dns) => sans.push(dns.to_string()),
                            GeneralName::IPAddress(ip) => {
                                if ip.len() == 4 {
                                    sans.push(format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]));
                                } else if ip.len() == 16 {
                                    let mut ipv6_parts = Vec::new();
                                    for chunk in ip.chunks(2) {
                                        ipv6_parts.push(format!(
                                            "{:02x}{:02x}",
                                            chunk[0],
                                            chunk.get(1).unwrap_or(&0)
                                        ));
                                    }
                                    sans.push(ipv6_parts.join(":"));
                                }
                            }
                            _ => {} // Skip other name types for now
                        }
                    }
                }
                break;
            }
        }

        // Extract key usage
        let mut key_usage = Vec::new();
        for ext in cert.extensions() {
            if ext.oid == KEY_USAGE_OID {
                if let Ok((_rem, ku)) = KeyUsage::from_der(ext.value) {
                    if ku.digital_signature() {
                        key_usage.push("DigitalSignature".to_string());
                    }
                    if ku.key_encipherment() {
                        key_usage.push("KeyEncipherment".to_string());
                    }
                    if ku.key_cert_sign() {
                        key_usage.push("KeyCertSign".to_string());
                    }
                    if ku.crl_sign() {
                        key_usage.push("CRLSign".to_string());
                    }
                    if ku.data_encipherment() {
                        key_usage.push("DataEncipherment".to_string());
                    }
                    if ku.key_agreement() {
                        key_usage.push("KeyAgreement".to_string());
                    }
                    if ku.non_repudiation() {
                        key_usage.push("NonRepudiation".to_string());
                    }
                    if ku.encipher_only() {
                        key_usage.push("EncipherOnly".to_string());
                    }
                    if ku.decipher_only() {
                        key_usage.push("DecipherOnly".to_string());
                    }
                }
                break;
            }
        }

        // Extract extended key usage
        let mut extended_key_usage = Vec::new();
        for ext in cert.extensions() {
            if ext.oid == EXTENDED_KEY_USAGE_OID {
                if let Ok((_rem, eku)) = ExtendedKeyUsage::from_der(ext.value) {
                    for oid in &eku.other {
                        // Convert common EKU OIDs to readable names
                        match oid.to_string().as_str() {
                            EKU_SERVER_AUTH => extended_key_usage.push("ServerAuth".to_string()),
                            EKU_CLIENT_AUTH => extended_key_usage.push("ClientAuth".to_string()),
                            EKU_CODE_SIGNING => extended_key_usage.push("CodeSigning".to_string()),
                            EKU_EMAIL_PROTECTION => {
                                extended_key_usage.push("EmailProtection".to_string())
                            }
                            EKU_TIME_STAMPING => {
                                extended_key_usage.push("TimeStamping".to_string())
                            }
                            EKU_OCSP_SIGNING => extended_key_usage.push("OCSPSigning".to_string()),
                            _ => extended_key_usage.push(oid.to_string()),
                        }
                    }
                }
                break;
            }
        }

        // Check if this is a CA certificate
        let mut is_ca = false;
        for ext in cert.extensions() {
            if ext.oid == BASIC_CONSTRAINTS_OID {
                if let Ok((_rem, bc)) = BasicConstraints::from_der(ext.value) {
                    is_ca = bc.ca;
                }
                break;
            }
        }

        Ok(CertificateMetadata {
            serial,
            cn,
            not_before,
            not_after,
            sans,
            key_usage,
            extended_key_usage,
            is_ca,
            issuer,
            pki_mount: pki_mount.to_string(),
            cached_at: Utc::now(),
            revocation_time: None, // Will be set by the service from Vault API response
        })
    }
}
