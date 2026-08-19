//! Everything about talking to Vault: building the client vaultrs wraps, and
//! the one generic endpoint every verb this crate does not model itself goes
//! through.
//!
//! vaultrs' own `api::exec_with_*` helpers strip the response envelope and
//! reject a body that parses to nothing, which loses two things this crate's
//! callers depend on: a write answered with no content decoding as `Null`
//! rather than a parse failure, and `get_even_if_withdrawn` reading the
//! `data`/`warnings` fields of a 404 body. Both need the raw status and body
//! before any interpretation, so requests are driven at the `rustify::client`
//! level directly rather than through those helpers; `vaultrs::error::ClientError`
//! is still what a failed client *construction* returns, and is mapped below.

use crate::error::Error;
use rustify::client::Client as HttpClientTrait;
use rustify::endpoint::{Endpoint, MiddleWare};
use rustify::enums::{RequestMethod, RequestType, ResponseType};
use rustify::errors::ClientError as RustifyError;
use serde_json::Value;
use std::path::PathBuf;
use std::time::Duration;
use vaultrs::client::{
    Client as VaultClientTrait, VaultClient as InnerClient, VaultClientSettings,
};

/// Reached with whichever verb this crate does not model itself. `path` is
/// handed to rustify's URL builder, which splits it on `/` and
/// percent-encodes each segment before appending it — so a key containing `?`
/// or `&` cannot collide with a query parameter the way a hand-built URL
/// string could, and nothing here needs to escape it a second time.
struct PassthroughEndpoint {
    path: String,
    method: RequestMethod,
    query: Option<String>,
    body: Option<Vec<u8>>,
}

impl Endpoint for PassthroughEndpoint {
    type Response = ();
    const REQUEST_BODY_TYPE: RequestType = RequestType::JSON;
    const RESPONSE_BODY_TYPE: ResponseType = ResponseType::JSON;

    fn path(&self) -> String {
        self.path.clone()
    }

    fn method(&self) -> RequestMethod {
        self.method.clone()
    }

    fn query(&self) -> Result<Option<String>, RustifyError> {
        Ok(self.query.clone())
    }

    fn body(&self) -> Result<Option<Vec<u8>>, RustifyError> {
        Ok(self.body.clone())
    }
}

/// A client certificate and key, read from disk when the transport is built.
pub(crate) struct ClientIdentity {
    pub cert: PathBuf,
    pub key: PathBuf,
}

impl ClientIdentity {
    fn load(&self) -> Result<reqwest::Identity, Error> {
        let mut pem = std::fs::read(&self.cert)?;
        let mut key = std::fs::read(&self.key)?;
        pem.append(&mut key);
        reqwest::Identity::from_pem(&pem).map_err(|e| Error::Transport(Box::new(e)))
    }
}

/// The knobs `vaultrs::client::VaultClientSettings` exposes, at the defaults
/// `Transport::build` applies. Not public: a caller-set CA bundle, identity or
/// timeout would put vaultrs' own settings shape in this crate's API.
pub(crate) struct TransportSettings {
    pub address: String,
    pub token: String,
    pub namespace: Option<String>,
    pub timeout: Option<Duration>,
    pub ca_certs: Vec<String>,
    pub identity: Option<ClientIdentity>,
    pub verify: bool,
    pub proxy: Option<String>,
}

impl TransportSettings {
    pub fn new(address: String, token: String) -> Self {
        Self {
            address,
            token,
            namespace: None,
            timeout: Some(Duration::from_secs(30)),
            ca_certs: Vec::new(),
            identity: None,
            verify: true,
            proxy: None,
        }
    }
}

/// `rustls-ring` leaves the process to install its own `CryptoProvider`;
/// reqwest panics at client construction when none is installed. Checked here
/// so that condition is reported rather than left to abort the host process.
#[cfg(feature = "rustls-ring")]
fn ensure_tls_provider_installed() -> Result<(), Error> {
    match rustls::crypto::CryptoProvider::get_default() {
        Some(_) => Ok(()),
        None => Err(Error::NoTlsProvider),
    }
}

#[cfg(not(feature = "rustls-ring"))]
fn ensure_tls_provider_installed() -> Result<(), Error> {
    Ok(())
}

pub(crate) struct Transport {
    inner: InnerClient,
}

impl Transport {
    /// Builds the underlying `vaultrs` client. The address and proxy are
    /// validated here rather than handed to vaultrs' own builder: both of its
    /// setters `Url::parse().unwrap()` internally and panic on bad input, so
    /// this constructs `VaultClientSettings` directly (every field is `pub`)
    /// instead of going through that builder at all.
    pub fn build(settings: TransportSettings) -> Result<Self, Error> {
        ensure_tls_provider_installed()?;

        let address = url::Url::parse(&settings.address).map_err(|e| {
            Error::InvalidInput(format!(
                "'{}' is not a valid Vault address: {e}",
                settings.address
            ))
        })?;
        let proxy = settings
            .proxy
            .as_deref()
            .map(|p| {
                url::Url::parse(p).map_err(|e| {
                    Error::InvalidInput(format!("'{p}' is not a valid proxy address: {e}"))
                })
            })
            .transpose()?;
        let identity = settings
            .identity
            .as_ref()
            .map(ClientIdentity::load)
            .transpose()?;

        let vaultrs_settings = VaultClientSettings {
            address,
            ca_certs: settings.ca_certs,
            identity,
            timeout: settings.timeout,
            token: settings.token,
            verify: settings.verify,
            version: 1,
            // Declared by vaultrs and never read by it; nothing here builds on it.
            wrapping: false,
            namespace: settings.namespace,
            proxy,
        };

        let inner =
            InnerClient::new(vaultrs_settings).map_err(|e| Error::Transport(Box::new(e)))?;
        Ok(Self { inner })
    }

    pub fn vault_addr(&self) -> &str {
        self.inner.settings.address.as_str()
    }

    /// A transport for the same address and connection pool, authenticated
    /// with a token of its own. Built fresh rather than mutated in place, so
    /// a concurrent caller holding the original transport never observes
    /// another operation's token.
    pub fn with_token(&self, token: &str) -> Self {
        let mut cloned = self.clone();
        cloned.inner.set_token(token);
        cloned
    }

    async fn raw(&self, endpoint: PassthroughEndpoint) -> Result<(u16, Vec<u8>), Error> {
        let mut request = endpoint
            .request(self.inner.http.base())
            .map_err(|e| Error::Transport(Box::new(e)))?;
        self.inner
            .middle
            .request(&endpoint, &mut request)
            .map_err(|e| Error::Transport(Box::new(e)))?;
        let response = self
            .inner
            .http
            .send(request)
            .await
            .map_err(|e| Error::Transport(Box::new(e)))?;
        Ok((response.status().as_u16(), response.into_body()))
    }

    /// The status and body Vault answered with, whatever the status was: a
    /// non-2xx here is data, not an error. Only a transport failure — the
    /// request never producing a response — is `Err`. `get`/`post`/`delete`/
    /// `list` interpret the status as a refusal on the caller's behalf;
    /// checking a token's own validity must not turn a rejection into a
    /// propagated error, so that path reads the status itself.
    pub(crate) async fn call(
        &self,
        method: RequestMethod,
        path: &str,
        query: Option<String>,
        body: Option<Vec<u8>>,
    ) -> Result<(u16, Vec<u8>), Error> {
        self.raw(PassthroughEndpoint {
            path: path.trim_start_matches('/').to_string(),
            method,
            query,
            body,
        })
        .await
    }

    fn interpret_json(path: &str, status: u16, body: Vec<u8>) -> Result<Value, Error> {
        if !(200..300).contains(&status) {
            return Err(Error::refusal(path, status, lossy(&body)));
        }

        // A write that stores nothing back answers with no content at all,
        // and decoding that as JSON fails after the write already happened.
        if body.iter().all(u8::is_ascii_whitespace) {
            return Ok(Value::Null);
        }

        serde_json::from_slice(&body).map_err(|e| Error::Decode {
            path: path.to_string(),
            source: e,
        })
    }

    pub async fn get(&self, path: &str) -> Result<Value, Error> {
        let (status, body) = self.call(RequestMethod::GET, path, None, None).await?;
        Self::interpret_json(path, status, body)
    }

    /// As `get`, with a raw, already-encoded query string appended verbatim —
    /// for the one caller (the OIDC callback) whose query carries values this
    /// crate did not URL-encode itself.
    pub async fn get_with_query(&self, path: &str, query: String) -> Result<Value, Error> {
        let (status, body) = self
            .call(RequestMethod::GET, path, Some(query), None)
            .await?;
        Self::interpret_json(path, status, body)
    }

    pub async fn post(&self, path: &str, data: Value) -> Result<Value, Error> {
        let body = serde_json::to_vec(&data).map_err(Error::Encode)?;
        let (status, resp_body) = self
            .call(RequestMethod::POST, path, None, Some(body))
            .await?;
        Self::interpret_json(path, status, resp_body)
    }

    /// A POST carrying no body: Vault does not require a `{}` body for an
    /// endpoint that takes no parameters, and sending nothing matches what
    /// this crate has always sent to them.
    pub async fn post_empty(&self, path: &str) -> Result<Value, Error> {
        let (status, body) = self.call(RequestMethod::POST, path, None, None).await?;
        Self::interpret_json(path, status, body)
    }

    pub async fn delete(&self, path: &str) -> Result<Value, Error> {
        let (status, body) = self.call(RequestMethod::DELETE, path, None, None).await?;
        Self::interpret_json(path, status, body)
    }

    pub async fn list(&self, path: &str) -> Result<Value, Error> {
        let (status, body) = self.call(RequestMethod::LIST, path, None, None).await?;
        Self::interpret_json(path, status, body)
    }

    /// A response whose body is not a JSON envelope. Refusals still carry their
    /// status, so a denied read is not reported as an empty body.
    pub async fn get_text(&self, path: &str) -> Result<String, Error> {
        let (status, body) = self.call(RequestMethod::GET, path, None, None).await?;
        if !(200..300).contains(&status) {
            return Err(Error::refusal(path, status, lossy(&body)));
        }
        Ok(lossy(&body))
    }

    /// A read where a refusal may still be carrying the record.
    ///
    /// The versioned KV layout reports a withdrawn version as "nothing here"
    /// while still returning that version's metadata, so a caller that has to
    /// tell a version someone deleted from one that never existed cannot let
    /// the status alone decide. A refusal with nothing in it is still a
    /// refusal.
    pub async fn get_even_if_withdrawn(&self, path: &str) -> Result<Value, Error> {
        self.get_even_if_withdrawn_with_query(path, None).await
    }

    /// As `get_even_if_withdrawn`, with a raw, already-encoded query string —
    /// for reading a specific KV version, where the version has to travel as
    /// a real query parameter rather than appended to `path`: a key
    /// containing `?` would otherwise collide with it.
    pub async fn get_even_if_withdrawn_with_query(
        &self,
        path: &str,
        query: Option<String>,
    ) -> Result<Value, Error> {
        let (status, body) = self.call(RequestMethod::GET, path, query, None).await?;
        if (200..300).contains(&status) {
            return Self::interpret_json(path, status, body);
        }

        if status == 404 {
            // discard-ok: a body that is not JSON carries no record, which is
            // the refusal reported below
            if let Ok(record) = serde_json::from_slice::<Value>(&body) {
                let carries_something = record.get("data").is_some_and(|d| !d.is_null())
                    || record.get("warnings").is_some_and(|w| !w.is_null());
                if carries_something {
                    return Ok(record);
                }
            }
        }

        Err(Error::refusal(path, status, lossy(&body)))
    }

    /// Whether a request against this token status-succeeded. A rejection is
    /// not an error here — only a transport failure propagates — so this is
    /// what a caller checking a token's own validity reads instead of `get`.
    pub async fn succeeds(&self, method: RequestMethod, path: &str) -> Result<bool, Error> {
        let (status, _) = self.call(method, path, None, None).await?;
        Ok((200..300).contains(&status))
    }
}

impl Clone for Transport {
    /// Shares the underlying connection pool and TLS setup rather than
    /// rebuilding them: a program resolving through a session should not open
    /// a second pool and repeat the TLS handshake setup for every client it
    /// derives from the same transport.
    fn clone(&self) -> Self {
        Self {
            inner: InnerClient {
                http: rustify::clients::reqwest::Client::new(
                    self.inner.http.base(),
                    self.inner.http.http.clone(),
                ),
                middle: self.inner.middle.clone(),
                settings: self.inner.settings.clone(),
            },
        }
    }
}

fn lossy(body: &[u8]) -> String {
    String::from_utf8_lossy(body).into_owned()
}
