//! A throwaway Vault to run this tool against by hand.
//!
//! `vault server -dev` writes its root token to `$HOME`, so started from a
//! shell it overwrites the operator's own — the credential for every other
//! Vault they use. The isolation is one environment variable, which is exactly
//! the kind of thing that gets left out at a terminal, so it lives here rather
//! than in an instruction to remember.

use crate::utils::errors::{Result, VaultCliError};
use crate::utils::PROGRAM_NAME;
use std::path::PathBuf;
use std::process::Command;

/// Fixed, because the server is thrown away and nothing else can reach it.
const ROOT_TOKEN: &str = "dev-server-root";

pub fn run(port: u16, at: Option<&str>) -> Result<()> {
    let vault = which::which("vault")
        .map_err(|e| VaultCliError::Config(format!("vault command not found in PATH ({e})")))?;

    let home = match at {
        Some(path) => PathBuf::from(path),
        None => std::env::current_dir()?.join("vault-dev"),
    };
    std::fs::create_dir_all(&home)?;
    let home = home.canonicalize()?;

    let addr = format!("http://127.0.0.1:{port}");
    eprintln!(
        "Starting a throwaway Vault. Everything it writes stays in {}.",
        home.display()
    );
    eprintln!("\nIn another shell:\n");
    eprintln!("  export VAULT_ADDR={addr}");
    eprintln!("  export VAULT_TOKEN={ROOT_TOKEN}");
    // The store and token this tool keeps are per-user paths too, so a live
    // test that does not move them writes into the real ones.
    eprintln!(
        "  export XDG_DATA_HOME={0}/data XDG_STATE_HOME={0}/state \\",
        home.display()
    );
    eprintln!(
        "         XDG_RUNTIME_DIR={0}/run XDG_CONFIG_HOME={0}/config",
        home.display()
    );
    eprintln!("\n  {PROGRAM_NAME} status\n");

    let status = Command::new(vault)
        .args([
            "server",
            "-dev",
            &format!("-dev-root-token-id={ROOT_TOKEN}"),
            &format!("-dev-listen-address=127.0.0.1:{port}"),
        ])
        // The whole point: its token file goes here, not in the operator's home.
        .env("HOME", &home)
        .status()
        .map_err(|e| VaultCliError::Config(format!("failed to start vault server -dev: {e}")))?;

    match status.success() {
        true => Ok(()),
        false => Err(VaultCliError::Config(format!(
            "vault server -dev exited with {status}"
        ))),
    }
}
