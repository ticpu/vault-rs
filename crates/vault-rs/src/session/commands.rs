use crate::cli::args::{KeyCommands, SessionCommands};
use crate::session::InteractiveLogin;
use crate::utils::dns_discovery::get_vault_addr;
use crate::utils::errors::{Result, VaultCliError};
use crate::utils::output::OutputFormat;
use crate::vault::{
    auth::{LogoutOutcome, OidcLogin, TokenState, VaultAuth, OIDC_REDIRECT_PORT},
    client::VaultClient,
};

pub async fn handle_session_commands(
    command: SessionCommands,
    output: &OutputFormat,
) -> Result<()> {
    match command {
        SessionCommands::Login {
            method,
            username,
            role,
            port,
            no_browser,
        } => {
            login_command(LoginRequest {
                method,
                username,
                role,
                port,
                no_browser,
            })
            .await
        }
        SessionCommands::Logout => logout_command().await,
        SessionCommands::Status => status_command(output).await,
        SessionCommands::Key { command } => match command {
            KeyCommands::Status => crate::session::key::status(output).await,
            KeyCommands::History => crate::session::key::history(output).await,
            KeyCommands::Use { mount } => crate::session::key::use_mount(&mount).await,
            KeyCommands::Restore { version } => crate::session::key::restore(version).await,
        },
        SessionCommands::InitEncryption {
            mount,
            destroy_all_my_keys,
        } => init_encryption_command(mount.as_deref(), destroy_all_my_keys).await,
    }
}

pub struct LoginRequest {
    pub method: String,
    pub username: Option<String>,
    pub role: Option<String>,
    pub port: Option<u16>,
    pub no_browser: bool,
}

impl LoginRequest {
    /// An argument the chosen method cannot act on is refused rather than
    /// dropped: silently ignoring `--role` logs the operator in somewhere other
    /// than where they asked, and says nothing.
    fn refuse_inert_arguments(&self) -> Result<()> {
        let browser_flow = self.method == "oidc";
        let inert: Vec<&str> = [
            ("--username", self.username.is_some() && browser_flow),
            ("--role", self.role.is_some() && !browser_flow),
            ("--port", self.port.is_some() && !browser_flow),
            ("--no-browser", self.no_browser && !browser_flow),
        ]
        .into_iter()
        .filter(|(_, given)| *given)
        .map(|(name, _)| name)
        .collect();

        match inert.is_empty() {
            true => Ok(()),
            false => Err(VaultCliError::InvalidInput(format!(
                "`--method {}` does not use {}",
                self.method,
                inert.join(", ")
            ))),
        }
    }
}

async fn login_command(request: LoginRequest) -> Result<()> {
    let vault_addr = get_vault_addr().await?;
    let auth = VaultAuth::new(vault_addr);

    request.refuse_inert_arguments()?;

    // Dispatched before any prompt: a browser flow has no username or password
    // to ask for.
    let token = match (request.method.as_str(), request.username) {
        ("oidc", _) => {
            auth.login_oidc_with(OidcLogin {
                mount: &request.method,
                role: request.role.as_deref(),
                port: request.port.unwrap_or(OIDC_REDIRECT_PORT),
                open_browser: !request.no_browser,
            })
            .await?
        }
        (method, Some(user)) => login_with_credentials(&auth, method, &user).await?,
        (_, None) => auth.interactive_login(Some(request.method)).await?,
    };

    // Char boundaries, not bytes: a short or non-ASCII token panicked here.
    let prefix: String = token.chars().take(8).collect();
    eprintln!("Successfully logged in with token: {prefix}***");
    Ok(())
}

async fn login_with_credentials(auth: &VaultAuth, method: &str, username: &str) -> Result<String> {
    let password = rpassword::prompt_password("Password: ")
        .map_err(|e| VaultCliError::Auth(format!("Failed to read password: {e}")))?;

    match method {
        "ldap" => Ok(auth.login_ldap(username, &password).await?),
        "userpass" => Ok(auth.login_userpass(username, &password).await?),
        _ => Err(VaultCliError::Auth(format!(
            "Unsupported auth method: {method}"
        ))),
    }
}

async fn logout_command() -> Result<()> {
    let vault_addr = get_vault_addr().await?;
    let auth = VaultAuth::new(vault_addr);

    match auth.logout().await {
        Ok(LogoutOutcome::Revoked) => eprintln!("Logged out: token revoked and removed"),
        Ok(LogoutOutcome::NoToken) => eprintln!("No stored token to remove"),
        // The token is off this machine either way, so the failure is about the
        // server and not about whether logging out happened.
        Err(e) => {
            eprintln!("Stored token removed; revoking it on the server failed.");
            return Err(e.into());
        }
    }

    Ok(())
}

/// The token's state is what this command was asked for, so it goes to stdout
/// through `OutputFormat`. The reachability checklist below it is written for
/// a person and stays on stderr.
async fn status_command(output: &OutputFormat) -> Result<()> {
    let vault_addr = get_vault_addr().await?;
    let auth = VaultAuth::new(vault_addr);

    let token = match auth.token_state().await? {
        TokenState::Absent => return report_token(output, "absent", &serde_json::Value::Null),
        TokenState::Rejected => return report_token(output, "rejected", &serde_json::Value::Null),
        TokenState::Valid(token) => token,
    };

    let info = auth.get_token_info(&token).await?;
    report_token(output, "valid", &info)?;
    check_permissions().await;
    Ok(())
}

fn report_token(output: &OutputFormat, state: &str, info: &serde_json::Value) -> Result<()> {
    let mut rows = vec![("token".to_string(), state.to_string())];

    if let Some(data) = info.get("data") {
        for (label, key) in [
            ("user", "display_name"),
            ("policies", "policies"),
            ("ttl_seconds", "ttl"),
            ("entity_id", "entity_id"),
        ] {
            if let Some(value) = data.get(key) {
                // A string renders bare; anything else keeps its JSON shape
                // rather than being coerced into one it does not have.
                let rendered = match value.as_str() {
                    Some(s) => s.to_string(),
                    None => value.to_string(),
                };
                rows.push((label.to_string(), rendered));
            }
        }
    }

    output.print_key_value(&rows);
    Ok(())
}

async fn check_permissions() {
    eprintln!();
    eprintln!("Checking permissions:");
    let test_client = match VaultClient::new().await {
        Ok(client) => client,
        Err(e) => {
            eprintln!("✗ Cannot connect to Vault: {e}");
            return;
        }
    };

    match test_client.health().await {
        Ok(health) => {
            // A missing seal state used to render as "unsealed".
            let version = health
                .get("version")
                .and_then(|v| v.as_str())
                .unwrap_or("version not reported");
            let state = match health.get("sealed").and_then(|v| v.as_bool()) {
                Some(true) => "sealed",
                Some(false) => "unsealed",
                None => "seal state not reported",
            };
            eprintln!("✓ Vault reachable ({version}, {state})");
        }
        Err(e) => eprintln!("✗ Vault health check failed: {e}"),
    }

    match test_client.get("sys/mounts").await {
        Ok(_) => eprintln!("✓ Can list secret engines"),
        Err(e) => eprintln!("✗ Cannot list secret engines (sys/mounts): {e}"),
    }
}

async fn init_encryption_command(mount: Option<&str>, destroy_existing: bool) -> Result<()> {
    if let Some(mount) = mount {
        crate::session::key::choose_mount(mount)?;
    }

    let encryption_manager = crate::crypto::encryption::EncryptionManager::new().await?;
    encryption_manager
        .init_encryption_key(destroy_existing)
        .await?;
    eprintln!("Encryption key initialized in personal vault");
    Ok(())
}
