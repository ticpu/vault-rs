//! Read a secret the way a linked program does, over the `client` feature
//! alone: the address comes from `VAULT_ADDR` or the SRV record, and the token
//! from a file this program named and nobody else writes — `VAULT_TOKEN` and
//! the session `vault-rs session login` keeps do not reach it, and a login is
//! only attempted when there is no usable token.
//!
//!     cargo run --no-default-features --features client,rustls-aws-lc-rs \
//!         --example read_secret -- kv fsa/prod

use std::path::PathBuf;
use vault_session::logical::kv;
use vault_session::utils::dns_discovery::get_vault_addr;
use vault_session::vault::auth::{TokenState, VaultAuth};
use vault_session::vault::client::VaultClient;

const PROGRAM: &str = "read_secret";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let (Some(mount), Some(path)) = (args.next(), args.next()) else {
        anyhow::bail!("usage: read_secret <mount> <path>");
    };

    let auth = VaultAuth::with_token_file(get_vault_addr().await?, token_file()?);
    if !matches!(auth.token_state().await?, TokenState::Valid(_)) {
        auth.login_oidc("oidc", None).await?;
    }

    // Built after the login, so it resolves the token that login stored.
    let client = VaultClient::for_auth(&auth).await?;
    let secret = kv::read_secret(&client, Some(&mount), &path, None).await?;

    println!("{secret}");
    Ok(())
}

/// This program's own token, beside the runtime files of whoever is running it.
fn token_file() -> anyhow::Result<PathBuf> {
    if let Some(runtime_dir) = std::env::var_os("XDG_RUNTIME_DIR") {
        return Ok(PathBuf::from(runtime_dir).join(PROGRAM).join("token"));
    }

    let state_dir = dirs::state_dir()
        .ok_or_else(|| anyhow::anyhow!("neither XDG_RUNTIME_DIR nor a state directory is set"))?;
    Ok(state_dir.join(PROGRAM).join("token"))
}
