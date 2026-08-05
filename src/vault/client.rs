use crate::utils::errors::{Result, VaultCliError};
use crate::utils::get_vault_addr;
use crate::vault::mounts::MountsResponse;
use crate::vault::pki::RoleConfig;
use reqwest::{Client, Response};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

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

/// Which storage layout a mount uses, as the mount itself reported it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MountVersion {
    /// The mount answering for the path, with its trailing separator kept as
    /// Vault reports it.
    pub mount: String,
    pub version: u8,
}

#[derive(Clone)]
pub struct VaultClient {
    client: Client,
    vault_addr: String,
    token: String,
    namespace: Option<String>,
    /// Answers already had from the version probe. Guards a lookup table and
    /// nothing else: the lock is never held across a request.
    mount_versions: Arc<Mutex<HashMap<String, MountVersion>>>,
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
            // discard-ok: an unset namespace is the ordinary single-tenant case
            namespace: std::env::var("VAULT_NAMESPACE")
                .ok()
                .filter(|n| !n.is_empty()),
            mount_versions: Arc::new(Mutex::new(HashMap::new())),
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
            namespace: None,
            mount_versions: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Every request carries the token and, where the session names one, the
    /// namespace. Building requests anywhere else drops both.
    fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        let mut builder = self
            .client
            .request(method, format!("{}/v1/{}", self.vault_addr, path))
            .header("X-Vault-Token", &self.token);

        if let Some(namespace) = &self.namespace {
            builder = builder.header("X-Vault-Namespace", namespace);
        }

        builder
    }

    /// Where this client is pointed, for recording which Vault sealed an
    /// artifact and for telling an operator where to point back.
    pub fn vault_addr(&self) -> &str {
        &self.vault_addr
    }

    /// Health check
    pub async fn health(&self) -> Result<Value> {
        self.get("sys/health").await
    }

    /// The cluster this client is addressing.
    ///
    /// A failed read propagates: a caller comparing which cluster sealed an
    /// artifact demotes it to best-effort at its own call site, where the
    /// choice is visible, and one reporting server status must not print an
    /// unreachable Vault as an absent field.
    pub async fn cluster_id(&self) -> Result<Option<String>> {
        Ok(self
            .health()
            .await?
            .get("cluster_id")
            .and_then(|v| v.as_str())
            .map(str::to_string))
    }

    /// Generic GET request to Vault API
    pub async fn get(&self, path: &str) -> Result<Value> {
        let response = self.request(reqwest::Method::GET, path).send().await?;

        self.handle_response(path, response).await
    }

    /// Generic POST request to Vault API
    pub async fn post(&self, path: &str, data: Value) -> Result<Value> {
        let response = self
            .request(reqwest::Method::POST, path)
            .header("Content-Type", "application/json")
            .json(&data)
            .send()
            .await?;

        self.handle_response(path, response).await
    }

    /// Generic DELETE request to Vault API
    pub async fn delete(&self, path: &str) -> Result<Value> {
        let response = self.request(reqwest::Method::DELETE, path).send().await?;

        self.handle_response(path, response).await
    }

    /// Generic LIST request to Vault API
    pub async fn list(&self, path: &str) -> Result<Value> {
        let response = self.request(list_method()?, path).send().await?;

        self.handle_response(path, response).await
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
        self.get_pem(&format!("{pki_mount}/ca_chain")).await
    }

    /// A response whose body is a certificate rather than a JSON envelope.
    /// Refusals still carry their status, so a denied read is not reported as
    /// an empty chain.
    async fn get_pem(&self, path: &str) -> Result<String> {
        let response = self.request(reqwest::Method::GET, path).send().await?;

        let status = response.status();
        match status.is_success() {
            true => Ok(response.text().await?),
            false => Err(Self::refusal(path, status.as_u16(), response).await),
        }
    }

    /// Get the (single) CA certificate for a PKI mount (returns raw PEM data).
    ///
    /// `/ca/pem`, not `/cert/ca`: the latter wraps the certificate in a JSON
    /// envelope, so reading it as text yields a body no PEM parser accepts.
    pub async fn get_ca_certificate(&self, pki_mount: &str) -> Result<String> {
        self.get_pem(&format!("{pki_mount}/ca/pem")).await
    }

    /// List roles for a PKI mount
    pub async fn list_roles(&self, pki_mount: &str) -> Result<Vec<String>> {
        let response = self.list(&format!("{pki_mount}/roles")).await?;

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
    async fn handle_response(&self, path: &str, response: Response) -> Result<Value> {
        let status = response.status();

        if !status.is_success() {
            return Err(Self::refusal(path, status.as_u16(), response).await);
        }

        // A write that stores nothing back answers with no content at all, and
        // decoding that as JSON fails after the write already happened.
        let body = response.text().await?;
        match body.trim().is_empty() {
            true => Ok(Value::Null),
            false => Ok(serde_json::from_str(&body)?),
        }
    }

    /// A refusal, with whatever the server said about it. Vault reports these
    /// in an envelope; a body in any other shape is kept whole rather than
    /// discarded for not matching.
    async fn refusal(path: &str, status: u16, response: Response) -> VaultCliError {
        let body = response
            .text()
            .await
            // discard-ok: building a message from an already-failed response;
            // the status is the signal, the body is a courtesy
            .unwrap_or_default();

        let errors = match serde_json::from_str::<Value>(&body) {
            Ok(envelope) => match envelope.get("errors").and_then(|e| e.as_array()) {
                Some(reported) => reported
                    .iter()
                    .filter_map(|e| e.as_str().map(str::to_string))
                    .collect(),
                None => vec![body],
            },
            // discard-ok: a body that is not JSON is still what the server said
            Err(_) => match body.trim().is_empty() {
                true => Vec::new(),
                false => vec![body],
            },
        };

        VaultCliError::VaultStatus {
            status,
            path: path.to_string(),
            errors,
        }
    }

    /// Which storage layout the mount answering for `path` uses.
    ///
    /// Asked of that mount rather than derived from the path's shape, and
    /// rather than found by listing every mount — the listing needs a
    /// permission the operation itself does not, and answers for a mount the
    /// caller never named. A server too old to answer has only the one layout.
    pub async fn mount_version(&self, path: &str) -> Result<MountVersion> {
        let path = path.trim_start_matches('/').to_string();
        if let Some(known) = self.cached_mount_version(&path) {
            return Ok(known);
        }

        let probe = format!("sys/internal/ui/mounts/{path}");
        let resolved = match self.get(&probe).await {
            Ok(answer) => MountVersion {
                mount: answer["data"]["path"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
                version: match answer["data"]["options"]["version"].as_str() {
                    Some("2") => 2,
                    _ => 1,
                },
            },
            // A Vault without this endpoint predates the versioned layout.
            Err(e) if e.is_not_found() => MountVersion {
                mount: String::new(),
                version: 1,
            },
            Err(e) => return Err(e),
        };

        // discard-ok: a poisoned memo table costs a repeat request, nothing more
        if let Ok(mut cache) = self.mount_versions.lock() {
            cache.insert(path, resolved.clone());
        }
        Ok(resolved)
    }

    fn cached_mount_version(&self, path: &str) -> Option<MountVersion> {
        // discard-ok: see mount_version; a failed lock just misses the cache
        self.mount_versions.lock().ok()?.get(path).cloned()
    }
}

/// Every test here asks what the caller is told. A refusal that arrives as
/// prose cannot be told apart from another refusal with the same wording, and
/// a body that is absent because nothing was stored is not a malformed one.
#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn client(server: &MockServer) -> VaultClient {
        VaultClient::for_test(server.uri(), "test-token".to_string()).expect("test client")
    }

    async fn answer(server: &MockServer, verb: &str, at: &str, response: ResponseTemplate) {
        Mock::given(method(verb))
            .and(path(at))
            .respond_with(response)
            .mount(server)
            .await;
    }

    /// A write to an unversioned mount stores nothing back and answers with no
    /// content; reading that as JSON failed after the write had happened.
    #[tokio::test]
    async fn a_write_answered_with_no_content_is_not_a_parse_failure() {
        let server = MockServer::start().await;
        answer(
            &server,
            "POST",
            "/v1/secret/thing",
            ResponseTemplate::new(204),
        )
        .await;

        let written = client(&server)
            .post("secret/thing", json!({ "key": "value" }))
            .await
            .expect("a 204 is a successful write");
        assert_eq!(written, Value::Null);
    }

    #[tokio::test]
    async fn a_refusal_carries_its_status_and_the_path_it_was_for() {
        let server = MockServer::start().await;
        answer(
            &server,
            "GET",
            "/v1/secret/data/x",
            ResponseTemplate::new(403),
        )
        .await;

        let err = client(&server)
            .get("secret/data/x")
            .await
            .expect_err("denied");
        assert!(!err.is_not_found(), "a refusal is not an absence");
        let rendered = err.to_string();
        assert!(rendered.contains("403"), "{rendered}");
        assert!(rendered.contains("secret/data/x"), "{rendered}");
    }

    /// The server's own reason beats anything this side can infer from a status.
    #[tokio::test]
    async fn a_refusal_reports_what_the_server_said() {
        let server = MockServer::start().await;
        answer(
            &server,
            "GET",
            "/v1/secret/data/x",
            ResponseTemplate::new(403).set_body_json(json!({ "errors": ["permission denied"] })),
        )
        .await;

        let err = client(&server)
            .get("secret/data/x")
            .await
            .expect_err("denied")
            .to_string();
        assert!(err.contains("permission denied"), "{err}");
    }

    #[tokio::test]
    async fn an_absent_path_is_distinguishable_from_every_other_refusal() {
        let server = MockServer::start().await;
        answer(
            &server,
            "GET",
            "/v1/secret/data/gone",
            ResponseTemplate::new(404),
        )
        .await;
        answer(
            &server,
            "GET",
            "/v1/secret/data/sealed",
            ResponseTemplate::new(503),
        )
        .await;

        let client = client(&server);
        assert!(client
            .get("secret/data/gone")
            .await
            .expect_err("absent")
            .is_not_found());
        assert!(!client
            .get("secret/data/sealed")
            .await
            .expect_err("sealed")
            .is_not_found());
    }

    async fn probe_answers(server: &MockServer, at: &str, body: Value) {
        answer(
            server,
            "GET",
            &format!("/v1/sys/internal/ui/mounts/{at}"),
            ResponseTemplate::new(200).set_body_json(body),
        )
        .await;
    }

    #[tokio::test]
    async fn the_mount_reports_its_own_storage_version() {
        let server = MockServer::start().await;
        probe_answers(
            &server,
            "versioned/thing",
            json!({ "data": { "path": "versioned/", "options": { "version": "2" } } }),
        )
        .await;
        probe_answers(
            &server,
            "flat/thing",
            json!({ "data": { "path": "flat/", "options": null } }),
        )
        .await;

        let client = client(&server);
        assert_eq!(
            client
                .mount_version("versioned/thing")
                .await
                .expect("probe"),
            MountVersion {
                mount: "versioned/".to_string(),
                version: 2
            }
        );
        assert_eq!(
            client.mount_version("flat/thing").await.expect("probe"),
            MountVersion {
                mount: "flat/".to_string(),
                version: 1
            }
        );
    }

    /// A server without the endpoint predates the versioned layout, so it has
    /// only the one. Every other refusal is reported.
    #[tokio::test]
    async fn an_absent_probe_endpoint_means_the_older_layout_but_a_refusal_does_not() {
        let server = MockServer::start().await;
        answer(
            &server,
            "GET",
            "/v1/sys/internal/ui/mounts/old/thing",
            ResponseTemplate::new(404),
        )
        .await;
        answer(
            &server,
            "GET",
            "/v1/sys/internal/ui/mounts/denied/thing",
            ResponseTemplate::new(403),
        )
        .await;

        let client = client(&server);
        assert_eq!(
            client
                .mount_version("old/thing")
                .await
                .expect("older")
                .version,
            1
        );
        client
            .mount_version("denied/thing")
            .await
            .expect_err("a refusal is not an answer");
    }

    /// The same path is asked once; a second call is served from what the mount
    /// already said.
    #[tokio::test]
    async fn a_mount_version_is_asked_once() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/sys/internal/ui/mounts/versioned/thing"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                json!({ "data": { "path": "versioned/", "options": { "version": "2" } } }),
            ))
            .expect(1)
            .mount(&server)
            .await;

        let client = client(&server);
        client
            .mount_version("versioned/thing")
            .await
            .expect("probe");
        client
            .mount_version("versioned/thing")
            .await
            .expect("cached");
    }
}
