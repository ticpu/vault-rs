//! Read a secret the way a linked program does: the address comes from
//! `VAULT_ADDR` or the SRV record, and the token from this program's own
//! runtime directory — `VAULT_TOKEN` and the session `vault-rs session login`
//! keeps do not reach it, and a login is only attempted when there is no
//! usable token.
//!
//!     cargo run --example read_secret -- kv fsa/prod

use vault_session::{kv, Session, SessionConfig, TokenState, VaultClient};

const PROGRAM: &str = "read_secret";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let (Some(mount), Some(path)) = (args.next(), args.next()) else {
        anyhow::bail!("usage: read_secret <mount> <path>");
    };

    let session = Session::open(SessionConfig::for_program(PROGRAM)?).await?;
    if !matches!(session.token_state().await?, TokenState::Valid(_)) {
        // The library has no console; where the URL goes is this program's
        // call, and so is whether a browser is launched at all.
        session
            .login_oidc("oidc", None, |url: &str| {
                eprintln!("Open this URL to authenticate:\n\n{url}\n");
                Ok(())
            })
            .await?;
    }

    // Built after the login, so it resolves the token that login stored.
    let client = VaultClient::for_session(&session).await?;
    let secret = kv::read_secret(&client, Some(&mount), &path, None).await?;

    println!("{secret}");
    Ok(())
}
