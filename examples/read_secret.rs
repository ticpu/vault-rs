//! Read a secret the way a linked program does, over the `client` feature
//! alone: the address comes from `VAULT_ADDR` or the SRV record, the token from
//! the file `vault-rs session login` wrote, and a login is only attempted when
//! there is no usable token.
//!
//!     cargo run --no-default-features --features client,rustls-aws-lc-rs \
//!         --example read_secret -- kv fsa/prod

use vault_rs::logical::kv;
use vault_rs::utils::dns_discovery::get_vault_addr;
use vault_rs::vault::auth::{TokenState, VaultAuth};
use vault_rs::vault::client::VaultClient;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let (Some(mount), Some(path)) = (args.next(), args.next()) else {
        anyhow::bail!("usage: read_secret <mount> <path>");
    };

    let auth = VaultAuth::new(get_vault_addr().await?);
    if !matches!(auth.token_state().await?, TokenState::Valid(_)) {
        auth.login_oidc("oidc", None).await?;
    }

    // Built after the login, so it resolves the token that login stored.
    let client = VaultClient::new().await?;
    let secret = kv::read_secret(&client, Some(&mount), &path, None).await?;

    println!("{secret}");
    Ok(())
}
