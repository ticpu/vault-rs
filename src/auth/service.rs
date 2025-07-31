use crate::cli::args::AuthCommands;
use crate::utils::dns_discovery::get_vault_addr;
use crate::utils::errors::{Result, VaultCliError};
use crate::utils::output::OutputFormat;
use crate::vault::{auth::VaultAuth, client::VaultClient};

pub async fn handle_auth_commands(command: AuthCommands, output: &OutputFormat) -> Result<()> {
    match command {
        AuthCommands::Login { method, username } => login_command(method, username).await,
        AuthCommands::Logout => logout_command().await,
        AuthCommands::Status => status_command().await,
        AuthCommands::InitEncryption => init_encryption_command().await,
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

    println!("Successfully logged in with token: {}***", &token[..8]);
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
    println!("Successfully logged out");
    Ok(())
}

async fn status_command() -> Result<()> {
    let vault_addr = get_vault_addr().await?;
    let auth = VaultAuth::new(vault_addr);

    let token = match auth.get_token().await {
        Ok(token) => token,
        Err(_) => {
            println!("No active token found");
            return Ok(());
        }
    };

    let info = match auth.get_token_info(&token).await {
        Ok(info) => info,
        Err(_) => {
            println!("Token status: Invalid");
            return Ok(());
        }
    };

    print_token_status(&info);
    check_permissions().await;
    Ok(())
}

fn print_token_status(info: &serde_json::Value) {
    println!("Token status: Valid");

    let Some(data) = info.get("data") else { return };

    if let Some(display_name) = data.get("display_name") {
        println!("User: {display_name}");
    }
    if let Some(policies) = data.get("policies") {
        println!("Policies: {policies}");
    }
    if let Some(ttl) = data.get("ttl") {
        println!("TTL: {ttl} seconds");
    }
    if let Some(entity_id) = data.get("entity_id") {
        println!("Entity ID: {entity_id}");
    }
}

async fn check_permissions() {
    println!("\nChecking permissions:");
    let test_client = VaultClient::new().await;

    match test_client.get("sys/mounts").await {
        Ok(_) => println!("✓ Can list secret engines"),
        Err(_) => println!("✗ Cannot list secret engines (sys/mounts)"),
    }
}

async fn init_encryption_command() -> Result<()> {
    let encryption_manager = crate::crypto::encryption::EncryptionManager::new().await;
    encryption_manager.init_encryption_key().await?;
    println!("Encryption key initialized in personal vault");
    Ok(())
}

async fn list_secrets_command(output: &OutputFormat) -> Result<()> {
    let client = VaultClient::new().await;

    let mounts = match client.list_mounts().await {
        Ok(mounts) => mounts,
        Err(_) => {
            eprintln!("Cannot list secret engines - insufficient permissions");
            std::process::exit(1);
        }
    };

    output.print_table(&mounts.as_table_data());
    Ok(())
}
