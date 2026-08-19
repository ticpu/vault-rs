use crate::utils::errors::{Error, Result};
use crate::utils::paths::VaultCliPaths;
use crate::utils::PROGRAM_NAME;
use crate::vault::oidc::CallbackListener;
use crate::vault::transport::{Transport, TransportSettings};
use rustify::enums::RequestMethod;
use serde_json::{json, Value};
use std::env;
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

/// What `auth status` found, as opposed to what `get_token` needs.
///
/// `get_token` collapses all of these into "a usable token or an error",
/// which is right for its callers and wrong for a status report: "there is
/// no token", "the server rejected the one there is" and "I could not find
/// out" are three different answers, and the third is not a status at all.
pub enum TokenState {
    Absent,
    Rejected,
    Valid(String),
}

/// What `logout` found to act on, so the report names what happened rather
/// than asserting a revocation that had no token to revoke.
#[derive(Debug)]
pub enum LogoutOutcome {
    NoToken,
    Revoked,
}

/// The port the official client uses, and so the one a role's allowed redirect
/// URIs are most likely already written for.
pub const OIDC_REDIRECT_PORT: u16 = 8250;

/// What an OIDC login needs beyond the auth mount.
pub struct OidcLogin<'a> {
    pub mount: &'a str,
    pub role: Option<&'a str>,
    /// Has to match a port in the role's allowed redirect URIs.
    pub port: u16,
    pub open_browser: bool,
}

impl<'a> OidcLogin<'a> {
    pub fn new(mount: &'a str) -> Self {
        Self {
            mount,
            role: None,
            port: OIDC_REDIRECT_PORT,
            open_browser: true,
        }
    }
}

/// The variable the tool's own session answers to.
pub const DEFAULT_TOKEN_ENV: &str = "VAULT_TOKEN";

/// A session belonging to the program that named it, rather than to the
/// operator: its own token file, and nothing taken from the environment unless
/// it is named here.
pub struct CallerSession {
    pub token_file: PathBuf,
    /// Read before the file when named.
    pub token_env: Option<String>,
    pub namespace: Option<String>,
}

impl CallerSession {
    pub fn new(token_file: PathBuf) -> Self {
        Self {
            token_file,
            token_env: None,
            namespace: None,
        }
    }
}

pub struct VaultAuth {
    transport: Transport,
    vault_addr: String,
    /// Where the token lives, when it is not the resolved default. The tool's
    /// own session resolves the path per call, so one with no runtime directory
    /// fails where the token is used rather than wherever a client was built.
    token_file: Option<PathBuf>,
    /// The variable consulted before the file, where a session has one.
    token_env: Option<String>,
    namespace: Option<String>,
}

impl VaultAuth {
    pub fn new(vault_addr: String) -> Result<Self> {
        // discard-ok: an unset namespace is the ordinary single-tenant case
        let namespace = env::var("VAULT_NAMESPACE").ok().filter(|n| !n.is_empty());
        let transport = Self::build_transport(&vault_addr, namespace.clone())?;

        Ok(Self {
            transport,
            vault_addr,
            token_file: None,
            token_env: Some(DEFAULT_TOKEN_ENV.to_string()),
            namespace,
        })
    }

    /// A session reading the named file and no environment variable.
    pub fn with_token_file(vault_addr: String, token_file: PathBuf) -> Result<Self> {
        Self::for_session(vault_addr, CallerSession::new(token_file))
    }

    /// As `with_token_file`, where the caller also names the variable its token
    /// may arrive in and the namespace it works under.
    pub fn for_session(vault_addr: String, session: CallerSession) -> Result<Self> {
        let transport = Self::build_transport(&vault_addr, session.namespace.clone())?;

        Ok(Self {
            transport,
            vault_addr,
            token_file: Some(session.token_file),
            token_env: session.token_env,
            namespace: session.namespace,
        })
    }

    /// This session's own transport is built without a token: every method
    /// below either does not need one (`login_*`) or names the one it needs
    /// (`renew_token`, `validate_token`, `get_token_info`, `revoke_self`)
    /// through `Transport::with_token`, rather than one stored on `self`.
    fn build_transport(vault_addr: &str, namespace: Option<String>) -> Result<Transport> {
        let mut settings = TransportSettings::new(vault_addr.to_string(), String::new());
        settings.namespace = namespace;
        Transport::build(settings)
    }

    pub fn vault_addr(&self) -> &str {
        &self.vault_addr
    }

    pub fn namespace(&self) -> Option<&str> {
        self.namespace.as_deref()
    }

    /// Shared rather than rebuilt, so a client resolving through this session
    /// does not open a second connection pool and repeat the TLS setup.
    pub(crate) fn transport(&self) -> &Transport {
        &self.transport
    }

    fn token_file(&self) -> Result<PathBuf> {
        match &self.token_file {
            Some(path) => Ok(path.clone()),
            None => VaultCliPaths::vault_token(),
        }
    }

    /// The token this session's variable holds, where it names one.
    fn token_from_env(&self) -> Option<String> {
        self.token_env
            .as_deref()
            // discard-ok: an unset variable falls through to the stored token
            .and_then(|name| env::var(name).ok())
            .filter(|token| !token.is_empty())
    }

    /// The stored token's state. Only a genuine absence is `Absent`; an
    /// unreadable file or an unreachable Vault is an error, not a report that
    /// there is no token.
    pub async fn token_state(&self) -> Result<TokenState> {
        let token = match self.token_from_env() {
            Some(token) => token,
            None => {
                let token_file = self.token_file()?;
                if !token_file.exists() {
                    return Ok(TokenState::Absent);
                }
                let token = fs::read_to_string(&token_file)?.trim().to_string();
                if token.is_empty() {
                    return Ok(TokenState::Absent);
                }
                token
            }
        };

        match self.validate_token(&token).await? {
            true => Ok(TokenState::Valid(token)),
            false => Ok(TokenState::Rejected),
        }
    }

    /// Get Vault token from environment or stored token file
    pub async fn get_token(&self) -> Result<String> {
        // Check environment variable first
        if let Some(token) = self.token_from_env() {
            tracing::debug!("Found a token in the environment");
            // Validate environment token
            if self.validate_token(&token).await? {
                tracing::debug!("Environment token is valid");
                return Ok(token);
            } else {
                tracing::warn!("Environment token is invalid/expired, trying stored token");
            }
        }

        // Check stored token file
        tracing::trace!("Checking stored token file");
        self.read_stored_token().await
    }

    /// Authenticate with LDAP and store token
    pub async fn login_ldap(&self, username: &str, password: &str) -> Result<String> {
        let path = format!("auth/ldap/login/{username}");
        let response = self
            .transport
            .post(&path, json!({ "password": password }))
            .await?;
        self.accept_login("LDAP", &response).await
    }

    /// Authenticate with username/password auth method
    pub async fn login_userpass(&self, username: &str, password: &str) -> Result<String> {
        let path = format!("auth/userpass/login/{username}");
        let response = self
            .transport
            .post(&path, json!({ "password": password }))
            .await?;
        self.accept_login("Userpass", &response).await
    }

    /// Take the minted token out of a login answer and store it. Every method
    /// ends here, so a credential never lands in a second place.
    async fn accept_login(&self, method: &str, auth_response: &Value) -> Result<String> {
        let token = auth_response["auth"]["client_token"]
            .as_str()
            .ok_or_else(|| {
                Error::Auth(format!(
                    "{method} authentication answered without a token; \
                     Vault reported: {auth_response}"
                ))
            })?;

        self.store_token(token).await?;
        tracing::info!("Successfully authenticated with {method}");
        Ok(token.to_string())
    }

    /// Authenticate through an identity provider and store the token.
    ///
    /// `mount` is the auth mount's path, not the provider; a role left absent
    /// lets the mount's own default answer.
    pub async fn login_oidc(&self, mount: &str, role: Option<&str>) -> Result<String> {
        self.login_oidc_with(OidcLogin {
            role,
            ..OidcLogin::new(mount)
        })
        .await
    }

    /// As `login_oidc`, where the caller also decides the redirect port and
    /// whether a browser is launched.
    pub async fn login_oidc_with(&self, login: OidcLogin<'_>) -> Result<String> {
        // Bound before Vault is asked for a URL: a port already taken is the
        // caller's to fix, and finding out first leaves no request outstanding.
        let listener = CallbackListener::bind(login.port).await?;
        let nonce = client_nonce()?;
        let auth_url = self
            .oidc_auth_url(&login, &listener.redirect_uri(), &nonce)
            .await?;

        // Printed whether or not a browser is launched, so a session that has
        // none is an ordinary case rather than a failure.
        eprintln!("Open this URL to authenticate:\n\n{auth_url}\n");
        if login.open_browser {
            open_in_browser(&auth_url);
        }

        let callback = listener.accept().await?;
        // Scoped: the serializer is not `Send`, and holding one across the
        // request below makes this future unusable to a caller that spawns it.
        let query = {
            let mut query = form_urlencoded::Serializer::new(String::new());
            query.append_pair("state", &callback.state);
            query.append_pair("code", &callback.code);
            query.append_pair("client_nonce", &nonce);
            if let Some(id_token) = &callback.id_token {
                query.append_pair("id_token", id_token);
            }
            query.finish()
        };

        let path = format!("auth/{}/oidc/callback", login.mount);
        let response = self.transport.get_with_query(&path, query).await?;
        self.accept_login("OIDC", &response).await
    }

    /// The provider's authorization URL, as the mount builds it for this role
    /// and this redirect.
    async fn oidc_auth_url(
        &self,
        login: &OidcLogin<'_>,
        redirect_uri: &str,
        nonce: &str,
    ) -> Result<String> {
        let path = format!("auth/{}/oidc/auth_url", login.mount);
        let mut payload = json!({ "redirect_uri": redirect_uri, "client_nonce": nonce });
        if let Some(role) = login.role {
            payload["role"] = json!(role);
        }

        let answer = self.transport.post(&path, payload).await?;

        // A role that does not allow this redirect is answered with an empty
        // URL and no error, which opens a browser at nothing.
        match answer["data"]["auth_url"].as_str().unwrap_or_default() {
            "" => Err(Error::Auth(format!(
                "The '{}' mount returned no authorization URL for {redirect_uri}. The role's \
                 allowed_redirect_uris has to name it; --port changes the port this asks for.",
                login.mount
            ))),
            auth_url => Ok(auth_url.to_string()),
        }
    }

    /// Renew the current token
    pub async fn renew_token(&self, token: &str) -> Result<String> {
        let renew_response = self
            .transport
            .with_token(token)
            .post_empty("auth/token/renew-self")
            .await?;

        if let Some(auth) = renew_response.get("auth") {
            if let Some(client_token) = auth.get("client_token") {
                if let Some(new_token) = client_token.as_str() {
                    // Store renewed token
                    self.store_token(new_token).await?;
                    tracing::info!("Successfully renewed token");
                    return Ok(new_token.to_string());
                }
            }
        }

        // If no new token in response, the current token is still valid
        Ok(token.to_string())
    }

    /// Check if token is valid
    pub async fn validate_token(&self, token: &str) -> Result<bool> {
        self.transport
            .with_token(token)
            .succeeds(RequestMethod::GET, "auth/token/lookup-self")
            .await
    }

    /// Get token info
    pub async fn get_token_info(&self, token: &str) -> Result<Value> {
        self.transport
            .with_token(token)
            .get("auth/token/lookup-self")
            .await
    }

    /// Store the token at this session's path, owner-only.
    async fn store_token(&self, token: &str) -> Result<()> {
        let token_file = self.token_file()?;

        // An empty parent is a bare relative filename: the directory is the one
        // the process is already in, and there is nothing to create.
        match token_file
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            // A directory the caller named is theirs; only the one this tool
            // resolves for itself is tightened.
            Some(parent) if self.token_file.is_some() => {
                VaultCliPaths::create_owner_only_dir(parent)?
            }
            Some(parent) => VaultCliPaths::ensure_dir_exists(parent)?,
            None => {}
        }

        // Created owner-only rather than written and then tightened, which
        // leaves the token at the umask in between.
        fs::OpenOptions::new()
            .mode(0o600)
            .create(true)
            .truncate(true)
            .write(true)
            .open(&token_file)?
            .write_all(token.as_bytes())?;
        // The mode on open does not reach a file that was already there.
        crate::utils::paths::set_secure_file_permissions(&token_file)?;

        tracing::debug!("Token stored at: {}", token_file.display());
        Ok(())
    }

    /// Read stored token from file
    async fn read_stored_token(&self) -> Result<String> {
        let token_file = self.token_file()?;

        if !token_file.exists() {
            return Err(Error::Auth(
                "No stored token found. Please login first.".to_string(),
            ));
        }

        let token = fs::read_to_string(&token_file)?;
        let token = token.trim().to_string();

        if token.is_empty() {
            return Err(Error::Auth(
                "Empty token file. Please login again.".to_string(),
            ));
        }

        // Validate token is still valid
        if !self.validate_token(&token).await? {
            // Try to renew token
            let renewal_error = match self.renew_token(&token).await {
                Ok(renewed_token) => return Ok(renewed_token),
                // Discarding this reported an unreachable Vault during renewal
                // as a rejected token, sending the operator to log in again
                // when logging in would fail the same way.
                Err(e) => e,
            };
            // Nothing else expires this file, and it outlives the session when
            // the fallback state directory is in use.
            if let Err(e) = fs::remove_file(&token_file) {
                tracing::warn!(
                    "Failed to remove the expired token at {}: {e}",
                    token_file.display()
                );
            }
            // Renewal is how this path tried to recover, not why it failed:
            // the token was already rejected before renewal was attempted, and
            // naming only the renewal sends the operator to look at a lease
            // when what they need is to log in again.
            return Err(Error::Rejected {
                program: PROGRAM_NAME,
                source: Box::new(renewal_error),
            });
        }

        Ok(token)
    }

    /// Revoke the token server-side.
    ///
    /// Separate from `logout` so the caller decides what a failure means; a
    /// token already past its expiry and an unreachable server both land here.
    pub async fn revoke_self(&self, token: &str) -> Result<()> {
        self.transport
            .with_token(token)
            .post_empty("auth/token/revoke-self")
            .await?;
        Ok(())
    }

    /// Revoke the stored token, then remove it whether or not that succeeded.
    ///
    /// The token is read from its file rather than through `get_token`, which
    /// renews an invalid one before returning it — extending a credential in
    /// order to destroy it. A token supplied through the environment belongs to
    /// the caller's shell and is theirs to revoke; this removes what the tool
    /// stored.
    pub async fn logout(&self) -> Result<LogoutOutcome> {
        let token_file = self.token_file()?;

        if !token_file.exists() {
            return Ok(LogoutOutcome::NoToken);
        }

        let token = fs::read_to_string(&token_file)?.trim().to_string();
        let revocation = match token.is_empty() {
            true => Ok(()),
            false => self.revoke_self(&token).await,
        };

        // Unconditional: a revocation that could not reach Vault must not leave
        // the credential sitting on disk.
        if let Err(removal) = fs::remove_file(&token_file) {
            if let Err(e) = &revocation {
                tracing::error!("Revoking the token also failed: {e}");
            }
            return Err(removal.into());
        }
        tracing::info!("Token removed from {}", token_file.display());

        revocation.map(|()| match token.is_empty() {
            true => LogoutOutcome::NoToken,
            false => LogoutOutcome::Revoked,
        })
    }
}

/// Binds the callback to this login, so a redirect belonging to another one is
/// refused by Vault rather than exchanged here.
fn client_nonce() -> Result<String> {
    let mut bytes = [0u8; 20];
    getrandom::fill(&mut bytes).map_err(|e| Error::Random(Box::new(std::io::Error::from(e))))?;

    Ok(bytes.iter().fold(String::new(), |mut nonce, byte| {
        use std::fmt::Write;
        // discard-ok: writing to a String cannot fail
        let _ = write!(nonce, "{byte:02x}");
        nonce
    }))
}

/// Launch a browser at the authorization URL, which is already on stderr — a
/// launcher that is absent or refuses costs nothing.
fn open_in_browser(url: &str) {
    // Without a display `xdg-open` reaches for a terminal browser, which takes
    // over the terminal this login is reporting to.
    if env::var_os("DISPLAY").is_none() && env::var_os("WAYLAND_DISPLAY").is_none() {
        eprintln!("No display session; open the URL above yourself.");
        return;
    }

    if let Err(e) = std::process::Command::new("xdg-open").arg(url).spawn() {
        eprintln!("Could not launch a browser with xdg-open ({e}); open the URL above yourself.");
    }
}

/// Every test here turns on the same question: is the credential off this
/// machine when the command returns? A revocation that fails for an ordinary
/// reason must not leave the token on disk, and nothing on this path may renew
/// the token it is about to destroy — `expect(0)` on the renewal and lookup
/// mocks is verified when the `MockServer` drops.
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const REVOKE: &str = "/v1/auth/token/revoke-self";
    const RENEW: &str = "/v1/auth/token/renew-self";
    const LOOKUP: &str = "/v1/auth/token/lookup-self";

    fn token_at(name: &str) -> PathBuf {
        let dir = test_confine::scratch_dir("auth-tests").join(name);
        // discard-ok: test scratch; the directory usually does not exist yet
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("scratch");
        dir.join("token")
    }

    async fn respond_to_revoke(server: &MockServer, response: ResponseTemplate) {
        Mock::given(method("POST"))
            .and(path(REVOKE))
            .respond_with(response)
            .expect(1)
            .mount(server)
            .await;
    }

    /// Renewing a token in order to destroy it extends the credential the
    /// operator asked to be gone, and reports an expired one as unrenewable
    /// rather than as expired.
    async fn expect_no_renewal(server: &MockServer) {
        for at in [RENEW, LOOKUP] {
            Mock::given(method("POST"))
                .and(path(at))
                .respond_with(ResponseTemplate::new(200))
                .expect(0)
                .mount(server)
                .await;
            Mock::given(method("GET"))
                .and(path(at))
                .respond_with(ResponseTemplate::new(200))
                .expect(0)
                .mount(server)
                .await;
        }
    }

    #[tokio::test]
    async fn logout_revokes_the_stored_token_and_removes_it() {
        let server = MockServer::start().await;
        respond_to_revoke(&server, ResponseTemplate::new(204)).await;
        expect_no_renewal(&server).await;

        let token_file = token_at("revokes");
        fs::write(&token_file, "s.stored-token").expect("token");
        let auth = VaultAuth::with_token_file(server.uri(), token_file.clone()).expect("session");

        assert!(matches!(
            auth.logout().await.expect("logout"),
            LogoutOutcome::Revoked
        ));
        assert!(!token_file.exists(), "the token file must be gone");
    }

    /// The defect this step exists to remove: a revocation that cannot reach
    /// Vault used to leave nothing behind to revoke and no error either.
    #[tokio::test]
    async fn a_refused_revocation_still_removes_the_token() {
        let server = MockServer::start().await;
        respond_to_revoke(&server, ResponseTemplate::new(403)).await;
        expect_no_renewal(&server).await;

        let token_file = token_at("refused");
        fs::write(&token_file, "s.expired-token").expect("token");
        let auth = VaultAuth::with_token_file(server.uri(), token_file.clone()).expect("session");

        let err = auth
            .logout()
            .await
            .expect_err("a refused revocation is reported")
            .to_string();
        assert!(err.contains("403"), "{err}");
        assert!(err.contains("auth/token/revoke-self"), "{err}");
        assert!(!token_file.exists(), "the token file must be gone anyway");
    }

    /// An unreachable Vault is the same case as a refusal: the operator asked
    /// for the credential to be gone from this machine.
    #[tokio::test]
    async fn an_unreachable_vault_still_removes_the_token() {
        let token_file = token_at("unreachable");
        fs::write(&token_file, "s.stored-token").expect("token");
        // A port nothing is listening on; the request fails to connect.
        let auth = VaultAuth::with_token_file("http://127.0.0.1:1".to_string(), token_file.clone())
            .expect("session");

        auth.logout()
            .await
            .expect_err("an unreachable server is reported");
        assert!(!token_file.exists(), "the token file must be gone anyway");
    }

    const AUTH_URL: &str = "/v1/auth/oidc/oidc/auth_url";
    const CALLBACK: &str = "/v1/auth/oidc/oidc/callback";

    fn oidc_at(port: u16) -> OidcLogin<'static> {
        OidcLogin {
            port,
            open_browser: false,
            ..OidcLogin::new("oidc")
        }
    }

    /// Vault answers a redirect the role does not allow with an empty URL and
    /// a success status, which would otherwise send a browser to nothing and
    /// leave the login waiting out its timeout.
    #[tokio::test]
    async fn a_redirect_the_role_does_not_allow_is_refused() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(AUTH_URL))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "auth_url": "" }
            })))
            .mount(&server)
            .await;

        let auth =
            VaultAuth::with_token_file(server.uri(), token_at("oidc-refused")).expect("session");
        let err = auth
            .login_oidc_with(oidc_at(18251))
            .await
            .expect_err("no URL to open")
            .to_string();
        assert!(err.contains("allowed_redirect_uris"), "{err}");
    }

    /// The whole flow: the mount builds a URL, the provider redirects to the
    /// listener, and the code is exchanged for a token that lands in the one
    /// file every other method writes.
    #[tokio::test]
    async fn a_completed_redirect_stores_the_token() {
        let port = 18252;
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(AUTH_URL))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "auth_url": "https://idp.example/authorize?state=st" }
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(CALLBACK))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "auth": { "client_token": "s.oidc-token" }
            })))
            .expect(1)
            .mount(&server)
            .await;

        // Under a directory of its own that does not exist yet, so the login
        // has to create the one it was told to write into.
        let token_file = token_at("oidc-complete")
            .parent()
            .expect("scratch")
            .join("session/token");
        let auth = VaultAuth::with_token_file(server.uri(), token_file.clone()).expect("session");
        let login = tokio::spawn(async move { auth.login_oidc_with(oidc_at(port)).await });

        redirect_to(port, "/oidc/callback?state=st&code=xyz").await;

        let token = login.await.expect("joined").expect("the login");
        assert_eq!(token, "s.oidc-token");
        assert_eq!(
            fs::read_to_string(&token_file).expect("stored"),
            "s.oidc-token"
        );
        assert_eq!(mode_of(&token_file), 0o600);
        assert_eq!(mode_of(token_file.parent().expect("its directory")), 0o700);
    }

    fn mode_of(path: &std::path::Path) -> u32 {
        fs::metadata(path).expect("stored").permissions().mode() & 0o777
    }

    /// Stand in for the browser, once the login has had time to bind.
    async fn redirect_to(port: u16, target: &str) {
        use tokio::io::AsyncWriteExt;

        for attempt in 0..100 {
            match tokio::net::TcpStream::connect(("127.0.0.1", port)).await {
                Ok(mut stream) => {
                    stream
                        .write_all(
                            format!("GET {target} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes(),
                        )
                        .await
                        .expect("redirect");
                    return;
                }
                Err(e) => {
                    assert!(attempt < 99, "the listener never came up: {e}");
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
            }
        }
    }

    #[tokio::test]
    async fn logout_with_no_stored_token_revokes_nothing() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(REVOKE))
            .respond_with(ResponseTemplate::new(204))
            .expect(0)
            .mount(&server)
            .await;
        expect_no_renewal(&server).await;

        let token_file = token_at("absent");
        let auth = VaultAuth::with_token_file(server.uri(), token_file).expect("session");

        assert!(matches!(
            auth.logout().await.expect("logout"),
            LogoutOutcome::NoToken
        ));
    }
}
