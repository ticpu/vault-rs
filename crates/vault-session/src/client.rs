use crate::error::{Error, Result};
use crate::mounts::MountsResponse;
use crate::session::Session;
use crate::transport::{Transport, TransportSettings};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

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
    transport: Transport,
    /// Answers already had from the version probe. Guards a lookup table and
    /// nothing else: the lock is never held across a request.
    mount_versions: Arc<Mutex<HashMap<String, MountVersion>>>,
}

impl VaultClient {
    /// A client resolving through the session it is given.
    ///
    /// The token is read once here and sent unchanged from then on; nothing
    /// re-reads the file or renews it, so a program outliving its token builds
    /// another client from the same session. That is why this borrows.
    pub async fn for_session(session: &Session) -> Result<Self> {
        let token = session.get_token().await?;
        // Char boundaries, not bytes: a short or non-ASCII token panicked here.
        let prefix: String = token.chars().take(8).collect();
        tracing::debug!("Using {} with token: {prefix}***", session.vault_addr());

        Ok(Self::build(session.transport().with_token(&token)))
    }

    /// A client over the session's address and namespace that sends no token.
    ///
    /// For the endpoints that answer without one. Reporting a seal state is the
    /// case that needs it: a sealed Vault cannot mint or validate a token, so
    /// requiring one would fail exactly where the report is wanted.
    pub fn unauthenticated(session: &Session) -> Self {
        Self::build(session.transport().clone())
    }

    fn build(transport: Transport) -> Self {
        Self {
            transport,
            mount_versions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// A client against an address and token given directly: it consults
    /// neither the environment nor discovery.
    pub fn with_token(vault_addr: String, token: String) -> Result<Self> {
        let transport = Transport::build(TransportSettings::new(vault_addr, token))?;
        Ok(Self::build(transport))
    }

    /// Where this client is pointed, for recording which Vault sealed an
    /// artifact and for telling an operator where to point back.
    pub fn vault_addr(&self) -> &str {
        self.transport.vault_addr()
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
        self.transport.get(path).await
    }

    /// A read whose answer is not JSON, returned as the server sent it.
    ///
    /// Some endpoints answer with PEM rather than an envelope, and the ones
    /// that do have a sibling that wraps the same bytes in JSON — reading the
    /// wrong one yields a body no parser downstream accepts.
    pub async fn get_text(&self, path: &str) -> Result<String> {
        self.transport.get_text(path).await
    }

    /// Generic POST request to Vault API
    pub async fn post(&self, path: &str, data: Value) -> Result<Value> {
        self.transport.post(path, data).await
    }

    /// A read where a refusal may still be carrying the record.
    ///
    /// The versioned KV layout reports a withdrawn version as "nothing here"
    /// while still returning that version's metadata, so a caller that has to
    /// tell a version someone deleted from one that never existed cannot let
    /// the status alone decide. A refusal with nothing in it is still a
    /// refusal.
    pub async fn get_even_if_withdrawn(&self, path: &str) -> Result<Value> {
        self.transport.get_even_if_withdrawn(path).await
    }

    /// As `get_even_if_withdrawn`, at a specific version. `version` travels
    /// as a real query parameter rather than appended to `path`, so a key
    /// containing `?` cannot collide with it.
    pub async fn get_even_if_withdrawn_at_version(
        &self,
        path: &str,
        version: u64,
    ) -> Result<Value> {
        self.transport
            .get_even_if_withdrawn_with_query(path, Some(format!("version={version}")))
            .await
    }

    /// Generic DELETE request to Vault API
    pub async fn delete(&self, path: &str) -> Result<Value> {
        self.transport.delete(path).await
    }

    /// Generic LIST request to Vault API
    pub async fn list(&self, path: &str) -> Result<Value> {
        self.transport.list(path).await
    }

    /// The keys a LIST answered with.
    ///
    /// An answer carrying no `keys` at all is an empty listing. One whose
    /// `keys` is not an array of strings is refused rather than read as empty,
    /// which is indistinguishable from a mount holding nothing.
    pub async fn list_keys(&self, path: &str) -> Result<Vec<String>> {
        let response = self.list(path).await?;

        let Some(keys) = response.get("data").and_then(|data| data.get("keys")) else {
            return Ok(Vec::new());
        };

        match keys.as_array() {
            Some(entries) => entries
                .iter()
                .map(|entry| {
                    entry.as_str().map(str::to_string).ok_or_else(|| {
                        Error::InvalidInput(format!(
                            "'{path}' listed an entry that is not a name: {entry}"
                        ))
                    })
                })
                .collect(),
            None => Err(Error::InvalidInput(format!(
                "'{path}' answered with a 'keys' that is not a list"
            ))),
        }
    }

    /// List all secret engines (mounts)
    pub async fn list_mounts(&self) -> Result<MountsResponse> {
        let response = self.get("sys/mounts").await?;

        serde_json::from_value(response).map_err(|e| Error::Decode {
            path: "sys/mounts".to_string(),
            source: e,
        })
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
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn client(server: &MockServer) -> VaultClient {
        VaultClient::with_token(server.uri(), "test-token".to_string()).expect("test client")
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
