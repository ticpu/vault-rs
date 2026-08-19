//! Requests against a Vault, over a session's address and token.
//!
//! The generic verbs take a path and answer with `serde_json::Value`, so an
//! endpoint this crate does not model is still reachable without waiting for a
//! wrapper. What a mount reports about itself — its KV layout — is asked of the
//! mount and memoised for the client's life.

use crate::error::{Error, Result};
use crate::mounts::{MountsResponse, VisibleMounts};
use crate::session::Session;
use crate::transport::{Transport, TransportSettings};
use rustify::enums::RequestMethod;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// How a KV mount addresses a secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum KvLayout {
    /// The value at its own path and nothing else.
    Flat,
    /// The value, its metadata and the verbs that withdraw or restore a
    /// version, each under a separate prefix.
    Versioned,
}

impl KvLayout {
    pub fn is_versioned(self) -> bool {
        matches!(self, Self::Versioned)
    }
}

/// Which storage layout a mount uses, as the mount itself reported it.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct MountLayout {
    /// The mount answering for the path, with its trailing separator kept as
    /// Vault reports it.
    pub mount: String,
    pub layout: KvLayout,
}

/// What `sys/health` answered, whatever status it answered with.
///
/// Vault gives a sealed, uninitialized or standby server a non-200 status, so
/// a reader that lets the status decide cannot report the state it was asked
/// for — sealed being the state the report is usually wanted for. A field
/// Vault did not send stays absent rather than reading as false.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[non_exhaustive]
pub struct HealthStatus {
    pub initialized: Option<bool>,
    pub sealed: Option<bool>,
    pub standby: Option<bool>,
    pub version: Option<String>,
    pub cluster_id: Option<String>,
    pub cluster_name: Option<String>,
    /// The status the answer carried, for a caller that wants Vault's own
    /// verdict rather than one derived from the fields.
    #[serde(skip)]
    pub status: u16,
}

/// What a token may do at one path, as `sys/capabilities-self` reports it.
#[derive(Clone, Debug, Serialize)]
#[non_exhaustive]
pub struct Capabilities {
    pub path: String,
    pub granted: Vec<String>,
}

impl Capabilities {
    /// Whether the token holds a named capability here. A root token holds
    /// every one; an explicit denial overrides whatever else was granted.
    pub fn can(&self, capability: &str) -> bool {
        let holds = |wanted: &str| self.granted.iter().any(|held| held == wanted);
        !holds("deny") && (holds(capability) || holds("root"))
    }

    pub fn can_read(&self) -> bool {
        self.can("read")
    }

    /// Vault splits writing into creating a path and updating one that is
    /// already there; a caller that writes needs whichever applies.
    pub fn can_write(&self) -> bool {
        self.can("create") || self.can("update")
    }

    pub fn can_list(&self) -> bool {
        self.can("list")
    }
}

#[derive(Clone)]
pub struct VaultClient {
    transport: Transport,
    /// Answers already had from the version probe. Guards a lookup table and
    /// nothing else: the lock is never held across a request.
    mount_layouts: Arc<Mutex<HashMap<String, MountLayout>>>,
}

impl VaultClient {
    /// A client resolving through the session it is given.
    ///
    /// The token is read once here and sent unchanged from then on; nothing
    /// re-reads the file or renews it, so a program outliving its token builds
    /// another client from the same session. That is why this borrows.
    pub async fn for_session(session: &Session) -> Result<Self> {
        let token = session.get_token().await?;
        // Chars, not bytes: a byte offset can land mid-codepoint.
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
            mount_layouts: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// A client against an address and token given directly: it consults
    /// neither the environment nor discovery.
    pub fn with_token(vault_addr: impl Into<String>, token: impl Into<String>) -> Result<Self> {
        let transport = Transport::build(TransportSettings::new(vault_addr.into(), token.into()))?;
        Ok(Self::build(transport))
    }

    /// Where this client is pointed.
    pub fn vault_addr(&self) -> &str {
        self.transport.vault_addr()
    }

    /// What the server says about itself. Only a request that never reached an
    /// answer, or one whose body is not a health report, is an error.
    pub async fn health(&self) -> Result<HealthStatus> {
        const PATH: &str = "sys/health";

        let (status, body) = self
            .transport
            .call(RequestMethod::GET, PATH, None, None)
            .await?;

        let mut health: HealthStatus =
            serde_json::from_slice(&body).map_err(|source| Error::Decode {
                path: PATH.to_string(),
                source,
            })?;
        health.status = status;
        Ok(health)
    }

    /// The cluster this client is addressing.
    ///
    /// A failed read propagates rather than reading as absent: a caller wanting
    /// it best-effort demotes it at its own call site, where that is visible.
    pub async fn cluster_id(&self) -> Result<Option<String>> {
        Ok(self.health().await?.cluster_id)
    }

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

    pub async fn delete(&self, path: &str) -> Result<Value> {
        self.transport.delete(path).await
    }

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

    /// What this token may do at each path, asked of Vault rather than
    /// derived from a policy document.
    ///
    /// The paths are the ones the caller will actually address: a KV mount's
    /// two layouts reach a secret through different prefixes, so asking about
    /// the wrong one answers about a path nothing will ever read.
    pub async fn capabilities(&self, paths: &[&str]) -> Result<Vec<Capabilities>> {
        const PATH: &str = "sys/capabilities-self";

        let answer = self.post(PATH, json!({ "paths": paths })).await?;

        paths
            .iter()
            .map(|path| {
                let granted =
                    answer
                        .get(*path)
                        .and_then(Value::as_array)
                        .ok_or_else(|| Error::Decode {
                            path: PATH.to_string(),
                            source: serde::de::Error::custom(format!(
                                "no capabilities reported for '{path}'"
                            )),
                        })?;

                Ok(Capabilities {
                    path: (*path).to_string(),
                    granted: granted
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect(),
                })
            })
            .collect()
    }

    /// The policies attached to this token.
    ///
    /// Vault drops a policy name an auth role gives it but does not know,
    /// rather than refusing the login, so the first sign is a read that fails
    /// long after the login succeeded.
    pub async fn token_policies(&self) -> Result<Vec<String>> {
        const PATH: &str = "auth/token/lookup-self";

        let answer = self.get(PATH).await?;
        let mut policies: Vec<String> = ["policies", "identity_policies"]
            .iter()
            .filter_map(|key| answer["data"][key].as_array())
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect();

        policies.sort();
        policies.dedup();
        Ok(policies)
    }

    /// The mounts this token can see. See `VisibleMounts`.
    pub async fn visible_mounts(&self) -> Result<VisibleMounts> {
        const PATH: &str = "sys/internal/ui/mounts";

        let answer = self.get(PATH).await?;
        serde_json::from_value(answer["data"].clone()).map_err(|source| Error::Decode {
            path: PATH.to_string(),
            source,
        })
    }

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
    pub async fn mount_layout(&self, path: &str) -> Result<MountLayout> {
        let path = path.trim_start_matches('/').to_string();
        if let Some(known) = self.cached_mount_layout(&path) {
            return Ok(known);
        }

        let probe = format!("sys/internal/ui/mounts/{path}");
        let resolved = match self.get(&probe).await {
            Ok(answer) => MountLayout {
                // Read as an empty mount name, the whole path stays on the key
                // and the secret is looked for somewhere it was never written.
                mount: match answer["data"]["path"].as_str() {
                    Some(mount) => mount.to_string(),
                    None => {
                        return Err(Error::decode(
                            &probe,
                            <serde_json::Error as serde::de::Error>::custom(
                                "the mount probe answered without a 'data.path' string",
                            ),
                        ))
                    }
                },
                layout: match answer["data"]["options"]["version"].as_str() {
                    Some("2") => KvLayout::Versioned,
                    _ => KvLayout::Flat,
                },
            },
            // A Vault without this endpoint predates the versioned layout.
            Err(e) if e.is_not_found() => MountLayout {
                mount: String::new(),
                layout: KvLayout::Flat,
            },
            Err(e) => return Err(e),
        };

        // discard-ok: a poisoned memo table costs a repeat request, nothing more
        if let Ok(mut cache) = self.mount_layouts.lock() {
            cache.insert(path, resolved.clone());
        }
        Ok(resolved)
    }

    fn cached_mount_layout(&self, path: &str) -> Option<MountLayout> {
        // discard-ok: see mount_layout; a failed lock just misses the cache
        self.mount_layouts.lock().ok()?.get(path).cloned()
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

    /// Vault answers a sealed server with 503. Letting the status decide
    /// reports an unreachable Vault for the one state a health read is usually
    /// wanted for.
    #[tokio::test]
    async fn a_sealed_vault_reports_that_it_is_sealed() {
        let server = MockServer::start().await;
        answer(
            &server,
            "GET",
            "/v1/sys/health",
            ResponseTemplate::new(503)
                .set_body_json(json!({ "initialized": true, "sealed": true, "version": "1.20.0" })),
        )
        .await;

        let health = client(&server)
            .health()
            .await
            .expect("a sealed server still answers");
        assert_eq!(health.sealed, Some(true));
        assert_eq!(health.status, 503);
    }

    /// A state the server did not report is absent, not false: reading it as
    /// unsealed asserts the safe answer on the strength of a missing field.
    #[tokio::test]
    async fn a_seal_state_that_was_not_reported_is_not_unsealed() {
        let server = MockServer::start().await;
        answer(
            &server,
            "GET",
            "/v1/sys/health",
            ResponseTemplate::new(200).set_body_json(json!({ "version": "1.20.0" })),
        )
        .await;

        assert_eq!(
            client(&server).health().await.expect("answered").sealed,
            None
        );
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

    /// An explicit denial in a policy overrides everything else granted at the
    /// path, so a reader that only looks for the capability it wants reports a
    /// read that Vault will refuse.
    #[test]
    fn a_denial_beats_every_other_capability() {
        let denied = Capabilities {
            path: "secret/data/app".to_string(),
            granted: ["read", "list", "deny"].map(str::to_string).to_vec(),
        };
        assert!(!denied.can_read());

        let root = Capabilities {
            path: "secret/data/app".to_string(),
            granted: vec!["root".to_string()],
        };
        assert!(root.can_read() && root.can_write() && root.can_list());
    }

    /// One request covers every path, and each answer comes back against the
    /// path it was asked about rather than in whatever order Vault replies.
    #[tokio::test]
    async fn capabilities_are_reported_per_path() {
        let server = MockServer::start().await;
        answer(
            &server,
            "POST",
            "/v1/sys/capabilities-self",
            ResponseTemplate::new(200).set_body_json(json!({
                "secret/data/app": ["read"],
                "secret/data/other": ["deny"],
            })),
        )
        .await;

        let reported = client(&server)
            .capabilities(&["secret/data/app", "secret/data/other"])
            .await
            .expect("capabilities");

        assert_eq!(reported[0].path, "secret/data/app");
        assert!(reported[0].can_read());
        assert_eq!(reported[1].path, "secret/data/other");
        assert!(!reported[1].can_read());
    }

    /// A path Vault said nothing about is not a path with no capabilities:
    /// reading it as denied would report a policy problem where the answer was
    /// malformed.
    #[tokio::test]
    async fn a_path_the_answer_skipped_is_not_a_denial() {
        let server = MockServer::start().await;
        answer(
            &server,
            "POST",
            "/v1/sys/capabilities-self",
            ResponseTemplate::new(200).set_body_json(json!({ "secret/data/app": ["read"] })),
        )
        .await;

        client(&server)
            .capabilities(&["secret/data/app", "secret/data/missing"])
            .await
            .expect_err("an answer that skipped a path is malformed");
    }

    /// The identity's policies count as attached: a role that grants through
    /// an entity rather than the token itself is otherwise reported as
    /// carrying nothing.
    #[tokio::test]
    async fn token_policies_include_the_identity_s() {
        let server = MockServer::start().await;
        answer(
            &server,
            "GET",
            "/v1/auth/token/lookup-self",
            ResponseTemplate::new(200).set_body_json(json!({
                "data": {
                    "policies": ["default", "fsa-read"],
                    "identity_policies": ["fsa-read", "team"],
                }
            })),
        )
        .await;

        assert_eq!(
            client(&server).token_policies().await.expect("policies"),
            ["default", "fsa-read", "team"]
        );
    }

    #[tokio::test]
    async fn visible_mounts_report_each_kv_mount_s_layout() {
        let server = MockServer::start().await;
        answer(
            &server,
            "GET",
            "/v1/sys/internal/ui/mounts",
            ResponseTemplate::new(200).set_body_json(json!({
                "data": {
                    "secret": {
                        "versioned/": { "type": "kv", "options": { "version": "2" } },
                        "flat/": { "type": "kv", "options": null },
                        "pki/": { "type": "pki" },
                    },
                    "auth": { "oidc/": { "type": "oidc" } },
                }
            })),
        )
        .await;

        let visible = client(&server).visible_mounts().await.expect("mounts");
        let mut kv = visible.kv_mounts();
        kv.sort_by(|a, b| a.0.cmp(&b.0));

        assert_eq!(
            kv,
            [
                ("flat".to_string(), KvLayout::Flat),
                ("versioned".to_string(), KvLayout::Versioned)
            ]
        );
        assert_eq!(
            visible.auth_mounts(),
            [("oidc".to_string(), "oidc".to_string())]
        );
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
            client.mount_layout("versioned/thing").await.expect("probe"),
            MountLayout {
                mount: "versioned/".to_string(),
                layout: KvLayout::Versioned
            }
        );
        assert_eq!(
            client.mount_layout("flat/thing").await.expect("probe"),
            MountLayout {
                mount: "flat/".to_string(),
                layout: KvLayout::Flat
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
                .mount_layout("old/thing")
                .await
                .expect("older")
                .layout,
            KvLayout::Flat
        );
        client
            .mount_layout("denied/thing")
            .await
            .expect_err("a refusal is not an answer");
    }

    /// The same path is asked once; a second call is served from what the mount
    /// already said.
    #[tokio::test]
    async fn a_mount_layout_is_asked_once() {
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
        client.mount_layout("versioned/thing").await.expect("probe");
        client
            .mount_layout("versioned/thing")
            .await
            .expect("cached");
    }
}
