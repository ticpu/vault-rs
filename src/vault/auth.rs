use crate::utils::errors::{Result, VaultCliError};
use crate::utils::paths::VaultCliPaths;
use reqwest::Client;
use serde_json::{json, Value};
use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;

pub struct VaultAuth {
    client: Client,
    vault_addr: String,
}

impl VaultAuth {
    pub fn new(vault_addr: String) -> Self {
        let client = super::create_http_client().expect("Failed to create HTTP client");

        Self { client, vault_addr }
    }

    /// Get Vault token from environment or stored token file
    pub async fn get_token(&self) -> Result<String> {
        // Check environment variable first
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
        let token_file = VaultCliPaths::vault_token()?;

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
        let token_file = VaultCliPaths::vault_token()?;

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
            if let Ok(renewed_token) = self.renew_token(&token).await {
                return Ok(renewed_token);
            }
            return Err(VaultCliError::Auth(
                "Stored token is invalid. Please login again.".to_string(),
            ));
        }

        Ok(token)
    }

    /// Clear stored token
    pub async fn logout(&self) -> Result<()> {
        let token_file = VaultCliPaths::vault_token()?;

        if token_file.exists() {
            fs::remove_file(&token_file)?;
            tracing::info!("Logged out - token removed");
        }

        Ok(())
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
