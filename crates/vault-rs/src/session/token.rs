//! The verbs that act on this machine's own token.
//!
//! Only the self surface is modelled. Looking up or revoking somebody else's
//! token by accessor or value is a different operation with a different blast
//! radius, and it forwards rather than being approximated here.

use crate::utils::dns_discovery::get_vault_addr;
use crate::utils::errors::Result;
use crate::utils::output::OutputFormat;
use crate::vault::auth::{LogoutOutcome, VaultAuth};
use serde_json::Value;

pub async fn lookup(output: &OutputFormat) -> Result<()> {
    let auth = VaultAuth::new(get_vault_addr().await?)?;
    let token = auth.get_token().await?;
    let info = auth.get_token_info(&token).await?;

    if output.json {
        return Ok(output.print_json(&info)?);
    }

    let Some(data) = info.get("data").and_then(|d| d.as_object()) else {
        return Ok(output.print_json(&info)?);
    };

    let mut rows: Vec<(String, String)> = data
        .iter()
        .map(|(key, value)| {
            let rendered = match value.as_str() {
                Some(text) => text.to_string(),
                None => value.to_string(),
            };
            (key.clone(), rendered)
        })
        .collect();
    rows.sort_by(|a, b| a.0.cmp(&b.0));

    output.print_key_value(&rows);
    Ok(())
}

/// Extend the current token. The renewed token is stored, which is why this
/// models only the self surface: renewing somebody else's would store theirs
/// as ours.
pub async fn renew() -> Result<()> {
    let auth = VaultAuth::new(get_vault_addr().await?)?;
    let token = auth.get_token().await?;
    auth.renew_token(&token).await?;

    let info = auth.get_token_info(&token).await?;
    let ttl = info
        .get("data")
        .and_then(|d| d.get("ttl"))
        .unwrap_or(&Value::Null);
    eprintln!("Renewed; {ttl} seconds remaining");
    Ok(())
}

/// Revoke the current token and drop it locally.
///
/// This is what logging out is, so it is the same call: revoking server-side
/// while leaving the file behind would make every later command fail against a
/// token the operator believes is fine — logout's own failure mode, inverted.
pub async fn revoke() -> Result<()> {
    let auth = VaultAuth::new(get_vault_addr().await?)?;

    match auth.logout().await {
        Ok(LogoutOutcome::Revoked) => eprintln!("Token revoked and removed"),
        Ok(LogoutOutcome::NoToken) => eprintln!("No stored token to revoke"),
        Err(e) => {
            eprintln!("Stored token removed; revoking it on the server failed.");
            return Err(e.into());
        }
    }

    Ok(())
}
