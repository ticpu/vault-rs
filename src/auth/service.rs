use crate::cli::args::AuthCommands;
use crate::utils::dns_discovery::get_vault_addr;
use crate::utils::errors::{Result, VaultCliError};
use crate::utils::output::OutputFormat;
use crate::vault::{
    auth::{TokenState, VaultAuth},
    client::VaultClient,
};

pub async fn handle_auth_commands(command: AuthCommands, output: &OutputFormat) -> Result<()> {
    match command {
        AuthCommands::Login { method, username } => login_command(method, username).await,
        AuthCommands::Logout => logout_command().await,
        AuthCommands::Status => status_command(output).await,
        AuthCommands::InitEncryption {
            destroy_all_my_keys,
        } => init_encryption_command(destroy_all_my_keys).await,
        AuthCommands::ListSecrets => list_secrets_command(output).await,
    }
}

async fn login_command(method: String, username: Option<String>) -> Result<()> {
    let vault_addr = get_vault_addr().await?;
    let auth = VaultAuth::new(vault_addr);

    let token = match username {
        Some(user) => login_with_credentials(&auth, &method, &user).await?,
        None => auth.interactive_login(Some(method)).await?,
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
        "ldap" => auth.login_ldap(username, &password).await,
        "userpass" => auth.login_userpass(username, &password).await,
        _ => Err(VaultCliError::Auth(format!(
            "Unsupported auth method: {method}"
        ))),
    }
}

async fn logout_command() -> Result<()> {
    let vault_addr = get_vault_addr().await?;
    let auth = VaultAuth::new(vault_addr);
    auth.logout().await?;
    eprintln!("Successfully logged out");
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

async fn init_encryption_command(destroy_existing: bool) -> Result<()> {
    let encryption_manager = crate::crypto::encryption::EncryptionManager::new().await?;
    encryption_manager
        .init_encryption_key(destroy_existing)
        .await?;
    eprintln!("Encryption key initialized in personal vault");
    Ok(())
}

async fn list_secrets_command(output: &OutputFormat) -> Result<()> {
    let client = VaultClient::new().await?;

    // Asserting a permission verdict for what may be a refused connection,
    // and exiting 1 where 1 means a match, not an error.
    let mounts = client.list_mounts().await?;

    output.print_table(&mounts.as_table_data());
    Ok(())
}
