use crate::utils::errors::{Result, VaultCliError};
use crate::vault::auth::VaultAuth;
use std::env;
use std::process::Command;

/// Execute the system vault command with preset VAULT_ADDR and VAULT_TOKEN
pub async fn exec_vault_command(
    vault_addr: String,
    subcommand: &str,
    args: &[String],
) -> Result<()> {
    // Get the token from VaultAuth
    let auth = VaultAuth::new(vault_addr.clone());
    let token = auth.get_token().await?;

    // Find the vault executable
    let vault_exe = which::which("vault").map_err(|_| {
        VaultCliError::Config(
            "vault command not found in PATH. Please install HashiCorp Vault CLI.".to_string(),
        )
    })?;

    // Build command arguments
    let mut command_args = vec![subcommand.to_string()];
    command_args.extend_from_slice(args);

    // Execute vault with environment variables set
    let mut cmd = Command::new(vault_exe);
    cmd.args(&command_args)
        .env("VAULT_ADDR", &vault_addr)
        .env("VAULT_TOKEN", token);

    // Inherit current environment but override VAULT_ADDR and VAULT_TOKEN
    for (key, value) in env::vars() {
        if key != "VAULT_ADDR" && key != "VAULT_TOKEN" {
            cmd.env(key, value);
        }
    }

    tracing::debug!(
        "Executing: vault {} with VAULT_ADDR={}",
        command_args.join(" "),
        vault_addr
    );

    // Execute the command and replace the current process
    let status = cmd
        .status()
        .map_err(|e| VaultCliError::Config(format!("Failed to execute vault command: {e}")))?;

    // Exit with the same code as the vault command
    if !status.success() {
        if let Some(code) = status.code() {
            std::process::exit(code);
        } else {
            std::process::exit(1);
        }
    }

    Ok(())
}
