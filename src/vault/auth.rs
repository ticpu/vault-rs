use crate::utils::errors::{Result, VaultCliError};
use crate::utils::paths::VaultCliPaths;
use crate::utils::PROGRAM_NAME;
use reqwest::Client;
use serde_json::{json, Value};
use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
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

pub struct VaultAuth {
    client: Client,
    vault_addr: String,
    /// Where the token lives, when it is not the resolved default. Production
    /// resolves the path per call so a session with no runtime directory fails
    /// where the token is used rather than wherever a client was built; tests
    /// point this at a scratch file.
    token_file: Option<PathBuf>,
}

impl VaultAuth {
    pub fn new(vault_addr: String) -> Self {
        let client = super::create_http_client().expect("Failed to create HTTP client");

        Self {
            client,
            vault_addr,
            token_file: None,
        }
    }

    #[cfg(test)]
    pub fn for_test(vault_addr: String, token_file: PathBuf) -> Self {
        Self {
            client: super::create_http_client().expect("test client"),
            vault_addr,
            token_file: Some(token_file),
        }
    }

    fn token_file(&self) -> Result<PathBuf> {
        match &self.token_file {
            Some(path) => Ok(path.clone()),
            None => VaultCliPaths::vault_token(),
        }
    }

    /// The stored token's state. Only a genuine absence is `Absent`; an
    /// unreadable file or an unreachable Vault is an error, not a report that
    /// there is no token.
    pub async fn token_state(&self) -> Result<TokenState> {
        let token = match env::var("VAULT_TOKEN") {
            Ok(token) if !token.is_empty() => token,
            _ => {
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
        // discard-ok: an unset variable falls through to the stored token
        if let Ok(token) = env::var("VAULT_TOKEN") {
            if !token.is_empty() {
                tracing::debug!("Found VAULT_TOKEN in environment");
                // Validate environment token
                if self.validate_token(&token).await? {
                    tracing::debug!("Environment token is valid");
                    return Ok(token);
                } else {
                    tracing::warn!("Environment token is invalid/expired, trying stored token");
                }
            }
        }

        // Check stored token file
        tracing::trace!("Checking stored token file");
        self.read_stored_token().await
    }

    /// Authenticate with LDAP and store token
    pub async fn login_ldap(&self, username: &str, password: &str) -> Result<String> {
        let url = format!("{}/v1/auth/ldap/login/{}", self.vault_addr, username);

        let payload = json!({
            "password": password
        });

        let response = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response
                .text()
                .await
                // discard-ok: building a message from an already-failed response;
                // the status above is the signal, the body is a courtesy
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(VaultCliError::Auth(format!(
                "LDAP authentication failed: {status} - {error_text}"
            )));
        }

        let auth_response: Value = response.json().await?;

        if let Some(auth) = auth_response.get("auth") {
            if let Some(client_token) = auth.get("client_token") {
                if let Some(token) = client_token.as_str() {
                    // Store token securely
                    self.store_token(token).await?;
                    tracing::info!("Successfully authenticated with LDAP");
                    return Ok(token.to_string());
                }
            }
        }

        Err(VaultCliError::Auth(
            "Invalid response from Vault authentication".to_string(),
        ))
    }

    /// Authenticate with username/password auth method
    pub async fn login_userpass(&self, username: &str, password: &str) -> Result<String> {
        let url = format!("{}/v1/auth/userpass/login/{}", self.vault_addr, username);

        let payload = json!({
            "password": password
        });

        let response = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response
                .text()
                .await
                // discard-ok: building a message from an already-failed response;
                // the status above is the signal, the body is a courtesy
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(VaultCliError::Auth(format!(
                "Userpass authentication failed: {status} - {error_text}"
            )));
        }

        let auth_response: Value = response.json().await?;

        if let Some(auth) = auth_response.get("auth") {
            if let Some(client_token) = auth.get("client_token") {
                if let Some(token) = client_token.as_str() {
                    // Store token securely
                    self.store_token(token).await?;
                    tracing::info!("Successfully authenticated with userpass");
                    return Ok(token.to_string());
                }
            }
        }

        Err(VaultCliError::Auth(
            "Invalid response from Vault authentication".to_string(),
        ))
    }

    /// Renew the current token
    pub async fn renew_token(&self, token: &str) -> Result<String> {
        let url = format!("{}/v1/auth/token/renew-self", self.vault_addr);

        let response = self
            .client
            .post(&url)
            .header("X-Vault-Token", token)
            .header("Content-Type", "application/json")
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response
                .text()
                .await
                // discard-ok: building a message from an already-failed response;
                // the status above is the signal, the body is a courtesy
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(VaultCliError::Auth(format!(
                "Token renewal failed: {status} - {error_text}"
            )));
        }

        let renew_response: Value = response.json().await?;

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
        let url = format!("{}/v1/auth/token/lookup-self", self.vault_addr);

        let response = self
            .client
            .get(&url)
            .header("X-Vault-Token", token)
            .send()
            .await?;

        Ok(response.status().is_success())
    }

    /// Get token info
    pub async fn get_token_info(&self, token: &str) -> Result<Value> {
        let url = format!("{}/v1/auth/token/lookup-self", self.vault_addr);

        let response = self
            .client
            .get(&url)
            .header("X-Vault-Token", token)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            return Err(VaultCliError::Auth(format!(
                "Failed to get token info: {status}"
            )));
        }

        Ok(response.json().await?)
    }

    /// Store token securely in XDG runtime directory
    async fn store_token(&self, token: &str) -> Result<()> {
        let token_file = self.token_file()?;

        // Ensure parent directory exists
        if let Some(parent) = token_file.parent() {
            fs::create_dir_all(parent)?;
        }

        // Write token to file
        fs::write(&token_file, token)?;

        // Set restrictive permissions (owner read/write only)
        let mut perms = fs::metadata(&token_file)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&token_file, perms)?;

        tracing::debug!("Token stored at: {}", token_file.display());
        Ok(())
    }

    /// Read stored token from file
    async fn read_stored_token(&self) -> Result<String> {
        let token_file = self.token_file()?;

        if !token_file.exists() {
            return Err(VaultCliError::Auth(
                "No stored token found. Please login first.".to_string(),
            ));
        }

        let token = fs::read_to_string(&token_file)?;
        let token = token.trim().to_string();

        if token.is_empty() {
            return Err(VaultCliError::Auth(
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
            return Err(VaultCliError::Auth(format!(
                "The stored token was rejected by Vault, and renewing it did not help \
                 ({renewal_error}). It has been removed; log in again with \
                 `{PROGRAM_NAME} session login`."
            )));
        }

        Ok(token)
    }

    /// Revoke the token server-side.
    ///
    /// Separate from `logout` so the caller decides what a failure means; a
    /// token already past its expiry and an unreachable server both land here.
    pub async fn revoke_self(&self, token: &str) -> Result<()> {
        let url = format!("{}/v1/auth/token/revoke-self", self.vault_addr);

        let response = self
            .client
            .post(&url)
            .header("X-Vault-Token", token)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response
                .text()
                .await
                // discard-ok: building a message from an already-failed response;
                // the status above is the signal, the body is a courtesy
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(VaultCliError::Auth(format!(
                "Token revocation failed: {status} - {error_text}"
            )));
        }

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

    /// Interactive login - prompts for username and password
    pub async fn interactive_login(&self, auth_method: Option<String>) -> Result<String> {
        let method = auth_method.unwrap_or_else(|| "ldap".to_string());

        // Get username
        print!("Username: ");
        use std::io::{self, Write};
        io::stdout().flush()?;

        let mut username = String::new();
        io::stdin().read_line(&mut username)?;
        let username = username.trim();

        // Get password securely
        let password = rpassword::prompt_password("Password: ")
            .map_err(|e| VaultCliError::Auth(format!("Failed to read password: {e}")))?;

        match method.as_str() {
            "ldap" => self.login_ldap(username, &password).await,
            "userpass" => self.login_userpass(username, &password).await,
            _ => Err(VaultCliError::Auth(format!(
                "Unsupported auth method: {method}"
            ))),
        }
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
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const REVOKE: &str = "/v1/auth/token/revoke-self";
    const RENEW: &str = "/v1/auth/token/renew-self";
    const LOOKUP: &str = "/v1/auth/token/lookup-self";

    fn token_at(name: &str) -> PathBuf {
        let dir =
            PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/target/auth-tests")).join(name);
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
        let auth = VaultAuth::for_test(server.uri(), token_file.clone());

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
        let auth = VaultAuth::for_test(server.uri(), token_file.clone());

        let err = auth
            .logout()
            .await
            .expect_err("a refused revocation is reported")
            .to_string();
        assert!(err.contains("revocation failed"), "{err}");
        assert!(!token_file.exists(), "the token file must be gone anyway");
    }

    /// An unreachable Vault is the same case as a refusal: the operator asked
    /// for the credential to be gone from this machine.
    #[tokio::test]
    async fn an_unreachable_vault_still_removes_the_token() {
        let token_file = token_at("unreachable");
        fs::write(&token_file, "s.stored-token").expect("token");
        // A port nothing is listening on; the request fails to connect.
        let auth = VaultAuth::for_test("http://127.0.0.1:1".to_string(), token_file.clone());

        auth.logout()
            .await
            .expect_err("an unreachable server is reported");
        assert!(!token_file.exists(), "the token file must be gone anyway");
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
        let auth = VaultAuth::for_test(server.uri(), token_file);

        assert!(matches!(
            auth.logout().await.expect("logout"),
            LogoutOutcome::NoToken
        ));
    }
}
