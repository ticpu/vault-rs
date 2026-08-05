use crate::utils::errors::{Result, VaultCliError};
use crate::utils::get_vault_addr;
use crate::vault::mounts::MountsResponse;
use crate::vault::pki::RoleConfig;
use reqwest::{Client, Response};
use serde_json::{json, Value};

const OID_RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
const OID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
const OID_ECDSA_WITH_SHA256: &str = "1.2.840.10045.4.3.2";
const OID_ECDSA_WITH_SHA384: &str = "1.2.840.10045.4.3.3";
const OID_ECDSA_WITH_SHA512: &str = "1.2.840.10045.4.3.4";

/// Vault's non-standard `LIST` verb, shared by every LIST-style request
/// rather than unwrapped inline at each call site.
fn list_method() -> Result<reqwest::Method> {
    reqwest::Method::from_bytes(b"LIST")
        .map_err(|e| VaultCliError::Storage(format!("invalid HTTP method: {e}")))
}

pub struct SignCertificateRequest<'a> {
    pub pki_mount: &'a str,
    pub role: &'a str,
    pub common_name: &'a str,
    pub csr_content: &'a str,
    pub alt_names: Option<Vec<String>>,
    pub ip_sans: Option<Vec<String>>,
    pub ttl: Option<&'a str>,
}

pub struct IssueCertificateRequest<'a> {
    pub pki_mount: &'a str,
    pub role: &'a str,
    pub common_name: &'a str,
    pub alt_names: Option<Vec<String>>,
    pub ip_sans: Option<Vec<String>>,
    pub ttl: Option<&'a str>,
}

#[derive(Clone)]
pub struct VaultClient {
    client: Client,
    vault_addr: String,
    token: String,
}

impl VaultClient {
    pub async fn new() -> Result<Self> {
        let client = super::create_http_client()?;
        let vault_addr = get_vault_addr().await?;
        let auth = crate::vault::auth::VaultAuth::new(vault_addr.clone());
        let token = auth.get_token().await?;
        // Char boundaries, not bytes: a short or non-ASCII token panicked here.
        let prefix: String = token.chars().take(8).collect();
        tracing::debug!("Using {vault_addr} with token: {prefix}***");

        Ok(Self {
            client,
            vault_addr,
            token,
        })
    }

    /// A client against an explicit address, for tests that stand up a stub
    /// Vault. Production goes through `new`, which resolves both fields.
    #[cfg(test)]
    pub fn for_test(vault_addr: String, token: String) -> Result<Self> {
        Ok(Self {
            client: super::create_http_client()?,
            vault_addr,
            token,
        })
    }

    /// Where this client is pointed, for recording which Vault sealed an
    /// artifact and for telling an operator where to point back.
    pub fn vault_addr(&self) -> &str {
        &self.vault_addr
    }

    /// Health check
    pub async fn health(&self) -> Result<Value> {
        let url = format!("{}/v1/sys/health", self.vault_addr);
        let response = self.client.get(&url).send().await?;

        if response.status().is_success() {
            Ok(response.json().await?)
        } else {
            Err(VaultCliError::VaultApi(
                response.error_for_status().unwrap_err(),
            ))
        }
    }

    /// Generic GET request to Vault API
    pub async fn get(&self, path: &str) -> Result<Value> {
        let url = format!("{}/v1/{}", self.vault_addr, path);
        let response = self
            .client
            .get(&url)
            .header("X-Vault-Token", &self.token)
            .send()
            .await?;

        self.handle_response(response).await
    }

    /// Generic POST request to Vault API
    pub async fn post(&self, path: &str, data: Value) -> Result<Value> {
        let url = format!("{}/v1/{}", self.vault_addr, path);
        let response = self
            .client
            .post(&url)
            .header("X-Vault-Token", &self.token)
            .header("Content-Type", "application/json")
            .json(&data)
            .send()
            .await?;

        self.handle_response(response).await
    }

    /// Generic LIST request to Vault API
    pub async fn list(&self, path: &str) -> Result<Value> {
        let url = format!("{}/v1/{}", self.vault_addr, path);
        let response = self
            .client
            .request(list_method()?, &url)
            .header("X-Vault-Token", &self.token)
            .send()
            .await?;

        self.handle_response(response).await
    }

    /// List all secret engines (mounts)
    pub async fn list_mounts(&self) -> Result<MountsResponse> {
        let response = self.get("sys/mounts").await?;

        serde_json::from_value(response)
            .map_err(|e| VaultCliError::Storage(format!("Failed to parse mounts response: {e}")))
    }

    /// List PKI mounts only
    pub async fn list_pki_mounts(&self) -> Result<Vec<String>> {
        let mounts = self.list_mounts().await?;
        Ok(mounts.pki_mounts())
    }

    /// Issue a new certificate
    pub async fn issue_certificate(&self, request: IssueCertificateRequest<'_>) -> Result<Value> {
        let mut payload = json!({
            "common_name": request.common_name,
        });

        if let Some(sans) = request.alt_names {
            payload["alt_names"] = json!(sans.join(","));
        }

        if let Some(ips) = request.ip_sans {
            payload["ip_sans"] = json!(ips.join(","));
        }

        if let Some(ttl_val) = request.ttl {
            payload["ttl"] = json!(ttl_val);
        }

        let path = format!("{}/issue/{}", request.pki_mount, request.role);
        self.post(&path, payload).await
    }

    /// Get CA chain for a PKI mount (returns raw PEM data)
    pub async fn get_ca_chain(&self, pki_mount: &str) -> Result<String> {
        let url = format!("{}/v1/{}/ca_chain", self.vault_addr, pki_mount);
        let response = self
            .client
            .get(&url)
            .header("X-Vault-Token", &self.token)
            .send()
            .await?;

        if response.status().is_success() {
            let pem_data = response.text().await?;
            Ok(pem_data)
        } else {
            Err(VaultCliError::VaultApi(
                response.error_for_status().unwrap_err(),
            ))
        }
    }

    /// Get the (single) CA certificate for a PKI mount (returns raw PEM data).
    ///
    /// `/ca/pem`, not `/cert/ca`: the latter wraps the certificate in a JSON
    /// envelope, so reading it as text yields a body no PEM parser accepts.
    pub async fn get_ca_certificate(&self, pki_mount: &str) -> Result<String> {
        let url = format!("{}/v1/{}/ca/pem", self.vault_addr, pki_mount);
        let response = self
            .client
            .get(&url)
            .header("X-Vault-Token", &self.token)
            .send()
            .await?;

        if response.status().is_success() {
            let pem_data = response.text().await?;
            Ok(pem_data)
        } else {
            Err(VaultCliError::VaultApi(
                response.error_for_status().unwrap_err(),
            ))
        }
    }

    /// List roles for a PKI mount
    pub async fn list_roles(&self, pki_mount: &str) -> Result<Vec<String>> {
        let url = format!("{}/v1/{}/roles", self.vault_addr, pki_mount);
        let response = self
            .client
            .request(list_method()?, &url)
            .header("X-Vault-Token", &self.token)
            .send()
            .await?;

        let response = self.handle_response(response).await?;

        Ok(super::extract_keys_array(&response))
    }

    /// Read a role's configuration for a PKI mount
    pub async fn read_role(&self, mount: &str, role: &str) -> Result<RoleConfig> {
        let path = format!("{mount}/roles/{role}");
        let response = self.get(&path).await?;

        let data = response.get("data").cloned().unwrap_or(Value::Null);
        serde_json::from_value(data)
            .map_err(|e| VaultCliError::Storage(format!("Failed to parse role response: {e}")))
    }

    /// Get PKI mount issuer configuration to determine crypto type
    pub async fn get_pki_issuer_info(&self, pki_mount: &str) -> Result<Value> {
        let path = format!("{pki_mount}/config/issuers");
        self.get(&path).await
    }

    /// Detect crypto type for a PKI mount based on its first issuer
    pub async fn detect_crypto_type(&self, pki_mount: &str) -> Result<String> {
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
                                        return self.parse_crypto_type_from_pem(cert_pem);
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

    /// Parse crypto type from certificate PEM
    fn parse_crypto_type_from_pem(&self, cert_pem: &str) -> Result<String> {
        use x509_parser::prelude::*;

        // Parse PEM certificate
        let (_, pem) = parse_x509_pem(cert_pem.as_bytes())
            .map_err(|e| VaultCliError::Storage(format!("Failed to parse PEM certificate: {e}")))?;

        // Parse X.509 certificate from PEM
        let (_, cert) = parse_x509_certificate(&pem.contents).map_err(|e| {
            VaultCliError::Storage(format!("Failed to parse X.509 certificate: {e}"))
        })?;

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

    /// Sign a certificate from CSR
    pub async fn sign_certificate(&self, request: SignCertificateRequest<'_>) -> Result<Value> {
        let mut payload = json!({
            "common_name": request.common_name,
            "csr": request.csr_content,
        });

        if let Some(sans) = request.alt_names {
            payload["alt_names"] = json!(sans.join(","));
        }

        if let Some(ips) = request.ip_sans {
            payload["ip_sans"] = json!(ips.join(","));
        }

        if let Some(ttl_val) = request.ttl {
            payload["ttl"] = json!(ttl_val);
        }

        let path = format!("{}/sign/{}", request.pki_mount, request.role);
        self.post(&path, payload).await
    }

    /// Handle HTTP response from Vault
    async fn handle_response(&self, response: Response) -> Result<Value> {
        let status = response.status();

        if status.is_success() {
            Ok(response.json().await?)
        } else if status == 404 {
            Err(VaultCliError::CertNotFound(
                "Resource not found".to_string(),
            ))
        } else if status == 403 {
            Err(VaultCliError::Auth(
                "Access denied - token may be invalid, expired, or lack required permissions"
                    .to_string(),
            ))
        } else {
            let error_text = response
                .text()
                .await
                // discard-ok: building a message from an already-failed response;
                // the status above is the signal, the body is a courtesy
                .unwrap_or_else(|_| "Unknown error".to_string());
            Err(VaultCliError::Storage(format!(
                "Vault API error: {error_text}"
            )))
        }
    }
}
