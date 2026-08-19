//! The operator's own session, which is the one thing in this tool that may
//! read the environment for it. A linking program names everything itself; a
//! command line is allowed to mean `VAULT_ADDR` and `VAULT_TOKEN`.

use crate::utils::errors::Result;
use crate::utils::PROGRAM_NAME;
use std::sync::OnceLock;
use vault_session::{Address, Session, SessionConfig, VaultClient};

/// The address named on the command line, outranking the environment for this
/// invocation. Following an artifact back to the cluster that sealed it should
/// not mean exporting a variable into the shell that produced the confusion.
///
/// A process has one command line, so this is one slot; a session a library
/// consumer opens carries its own address and never consults this.
static ADDRESS_OVERRIDE: OnceLock<String> = OnceLock::new();

/// Set once, before anything opens a session. A second call is the caller's
/// bug, not a race: nothing here is meant to change mid-run.
pub fn set_vault_addr_override(addr: String) {
    if ADDRESS_OVERRIDE.set(addr).is_err() {
        tracing::warn!("The Vault address was already fixed for this run; ignoring the second");
    }
}

/// How this tool finds its Vault and keeps its token.
pub fn operator_config() -> Result<SessionConfig> {
    let address = match ADDRESS_OVERRIDE.get() {
        Some(named) => Address::Explicit(named.clone()),
        None => Address::EnvThenSrv,
    };

    let config = SessionConfig::for_program(PROGRAM_NAME, address)?
        .token_env("VAULT_TOKEN")
        .srv_cache(vault_session::paths::runtime_dir(PROGRAM_NAME)?.join("dns_vault_addr.yaml"));

    // discard-ok: an unset namespace is the ordinary single-tenant case
    Ok(match std::env::var("VAULT_NAMESPACE") {
        Ok(namespace) if !namespace.is_empty() => config.namespace(namespace),
        _ => config,
    })
}

pub async fn operator_session() -> Result<Session> {
    Ok(Session::open(operator_config()?).await?)
}

pub async fn operator_client() -> Result<VaultClient> {
    Ok(VaultClient::for_session(&operator_session().await?).await?)
}
