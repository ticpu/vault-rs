//! PKI reads over a `VaultClient` that stay out of the published library:
//! crypto-type detection parses a certificate rather than reading a plain
//! Vault field, and the certificate-by-serial calls are CA management, not
//! session or KV work. Rust has no cross-crate inherent impls, so these
//! arrive as an extension trait implemented for the library's `VaultClient`.

use crate::cert::SerialNumber;
use crate::utils::errors::{Result, VaultCliError};
use crate::vault::certificates::{CertificateData, CertificateResponse};
use crate::vault::client::VaultClient;
use crate::vault::extract_keys_array;
use serde_json::Value;
use std::future::Future;

const OID_RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
const OID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
const OID_ECDSA_WITH_SHA256: &str = "1.2.840.10045.4.3.2";
const OID_ECDSA_WITH_SHA384: &str = "1.2.840.10045.4.3.3";
const OID_ECDSA_WITH_SHA512: &str = "1.2.840.10045.4.3.4";

pub trait PkiClient {
    /// Detect crypto type for a PKI mount based on its first issuer
    fn detect_crypto_type(&self, pki_mount: &str) -> impl Future<Output = Result<String>> + Send;

    /// Get certificate details by serial number
    fn get_certificate_info(
        &self,
        pki_mount: &str,
        serial: &str,
    ) -> impl Future<Output = Result<Value>> + Send;

    /// Get certificate PEM data with revocation info
    fn get_certificate_pem(
        &self,
        pki_mount: &str,
        serial: &SerialNumber,
    ) -> impl Future<Output = Result<CertificateData>> + Send;

    /// List certificates for a PKI mount
    fn list_certificates(
        &self,
        pki_mount: &str,
    ) -> impl Future<Output = Result<Vec<SerialNumber>>> + Send;

    /// Revoke certificate by serial number
    fn revoke_certificate(
        &self,
        pki_mount: &str,
        serial: &SerialNumber,
    ) -> impl Future<Output = Result<Value>> + Send;
}

impl PkiClient for VaultClient {
    async fn detect_crypto_type(&self, pki_mount: &str) -> Result<String> {
        tracing::debug!("Detecting crypto type for PKI mount: {pki_mount}");

        let issuer_config = self.get_pki_issuer_info(pki_mount).await?;

        if let Some(data) = issuer_config.get("data") {
            if let Some(default_issuer_id) = data.get("default") {
                if let Some(issuer_id) = default_issuer_id.as_str() {
                    tracing::debug!("Found default issuer: {issuer_id}");

                    // Get the issuer certificate details
                    let issuer_path = format!("{pki_mount}/issuer/{issuer_id}/json");
                    match self.get(&issuer_path).await {
                        Ok(issuer_info) => {
                            if let Some(issuer_data) = issuer_info.get("data") {
                                if let Some(certificate) = issuer_data.get("certificate") {
                                    if let Some(cert_pem) = certificate.as_str() {
                                        return parse_crypto_type_from_pem(cert_pem);
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            tracing::debug!("Failed to get issuer details: {e}");
                        }
                    }
                }
            }
        }

        // Fail if we can't detect crypto type - don't risk creating wrong certificate type
        Err(VaultCliError::Storage(format!(
            "Could not detect crypto type for PKI mount '{pki_mount}'. Please specify --crypto explicitly."
        )))
    }

    async fn get_certificate_info(&self, pki_mount: &str, serial: &str) -> Result<Value> {
        let path = format!("{pki_mount}/cert/{serial}");
        Ok(self.get(&path).await?)
    }

    async fn get_certificate_pem(
        &self,
        pki_mount: &str,
        serial: &SerialNumber,
    ) -> Result<CertificateData> {
        let cert_info = self
            .get_certificate_info(pki_mount, &serial.as_colon_hex())
            .await?;

        let cert_response: CertificateResponse = serde_json::from_value(cert_info)?;
        Ok(cert_response.data)
    }

    async fn list_certificates(&self, pki_mount: &str) -> Result<Vec<SerialNumber>> {
        let path = format!("{pki_mount}/certs");
        let response = self.list(&path).await?;

        let serials = extract_keys_array(&response);
        Ok(serials.into_iter().map(|s| SerialNumber::new(&s)).collect())
    }

    async fn revoke_certificate(&self, pki_mount: &str, serial: &SerialNumber) -> Result<Value> {
        let payload = serde_json::json!({
            "serial_number": serial
        });

        let path = format!("{pki_mount}/revoke");
        Ok(self.post(&path, payload).await?)
    }
}

/// Parse crypto type from certificate PEM
fn parse_crypto_type_from_pem(cert_pem: &str) -> Result<String> {
    use x509_parser::prelude::*;

    // Parse PEM certificate
    let (_, pem) = parse_x509_pem(cert_pem.as_bytes())
        .map_err(|e| VaultCliError::Storage(format!("Failed to parse PEM certificate: {e}")))?;

    // Parse X.509 certificate from PEM
    let (_, cert) = parse_x509_certificate(&pem.contents)
        .map_err(|e| VaultCliError::Storage(format!("Failed to parse X.509 certificate: {e}")))?;

    // Get the subject public key info
    let public_key_info = &cert.public_key();
    let algorithm_oid = &public_key_info.algorithm.algorithm;

    // Check the algorithm OID to determine crypto type
    match algorithm_oid.to_string().as_str() {
        OID_RSA_ENCRYPTION => Ok("rsa".to_string()),
        OID_EC_PUBLIC_KEY
        | OID_ECDSA_WITH_SHA256
        | OID_ECDSA_WITH_SHA384
        | OID_ECDSA_WITH_SHA512 => Ok("ec".to_string()),
        oid => Err(VaultCliError::Storage(format!(
            "Unknown algorithm OID: {oid}. Cannot determine crypto type."
        ))),
    }
}
