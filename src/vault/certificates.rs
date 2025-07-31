use crate::cert::SerialNumber;
use crate::utils::errors::Result;
use crate::vault::client::VaultClient;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateData {
    pub certificate: String,
    pub revocation_time: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateResponse {
    pub data: CertificateData,
}

impl CertificateData {
    pub fn is_revoked(&self) -> bool {
        self.revocation_time.is_some_and(|t| t > 0)
    }
}

impl VaultClient {
    /// Get certificate details by serial number
    pub async fn get_certificate_info(&self, pki_mount: &str, serial: &str) -> Result<Value> {
        let path = format!("{pki_mount}/cert/{serial}");
        self.get(&path).await
    }

    /// Get certificate PEM data with revocation info
    pub async fn get_certificate_pem(
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

    /// List certificates for a PKI mount
    pub async fn list_certificates(&self, pki_mount: &str) -> Result<Vec<SerialNumber>> {
        let path = format!("{pki_mount}/certs");
        let response = self.list(&path).await?;

        let serials = crate::vault::extract_keys_array(&response);
        Ok(serials.into_iter().map(|s| SerialNumber::new(&s)).collect())
    }

    /// Revoke certificate by serial number
    pub async fn revoke_certificate(
        &self,
        pki_mount: &str,
        serial: &SerialNumber,
    ) -> Result<Value> {
        let payload = serde_json::json!({
            "serial_number": serial
        });

        let path = format!("{pki_mount}/revoke");
        self.post(&path, payload).await
    }
}
