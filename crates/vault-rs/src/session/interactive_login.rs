//! A `Session` extension for the CLI's own prompting, kept out of the
//! published library along with every other `eprintln!`/`stdin` interaction.
//! Rust has no cross-crate inherent impls, so this is a trait.

use crate::utils::errors::{Result, VaultCliError};
use std::future::Future;
use std::io::{self, Write};
use vault_session::Session;

pub trait InteractiveLogin {
    /// Interactive login - prompts for username and password
    ///
    /// The prompts come after the method is dispatched on, not before: a method
    /// that authenticates through a browser has no username or password to ask
    /// for, and asking anyway collects a credential nothing then uses.
    fn interactive_login(
        &self,
        auth_method: Option<String>,
    ) -> impl Future<Output = Result<String>> + Send;
}

impl InteractiveLogin for Session {
    async fn interactive_login(&self, auth_method: Option<String>) -> Result<String> {
        let method = auth_method.unwrap_or_else(|| "ldap".to_string());

        if method == "oidc" {
            return Ok(self.login_oidc(&method, None).await?);
        }

        // Get username
        print!("Username: ");
        io::stdout().flush()?;

        let mut username = String::new();
        io::stdin().read_line(&mut username)?;
        let username = username.trim();

        // Get password securely
        let password = rpassword::prompt_password("Password: ")
            .map_err(|e| VaultCliError::Auth(format!("Failed to read password: {e}")))?;

        match method.as_str() {
            "ldap" => Ok(self.login_ldap(username, &password).await?),
            "userpass" => Ok(self.login_userpass(username, &password).await?),
            _ => Err(VaultCliError::Auth(format!(
                "Unsupported auth method: {method}"
            ))),
        }
    }
}
