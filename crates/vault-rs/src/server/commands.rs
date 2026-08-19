//! What the Vault being addressed reports about itself.

use crate::utils::errors::Result;
use crate::utils::output::OutputFormat;
use crate::vault::client::VaultClient;
use serde_json::Value;

/// Whether a Vault answered, and in what state.
///
/// Sealed is a verdict about a reachable server, not a malfunction of this
/// command, so it takes the exit code this tool already uses for a verdict
/// rather than the one it uses for errors. That differs from the official
/// client, which reserves its error code for sealed — following it here would
/// give this tool two contradictory meanings for the same code.
pub struct ServerStatus {
    pub sealed: bool,
}

pub async fn status(output: &OutputFormat) -> Result<ServerStatus> {
    let session = crate::vault::operator_session().await?;
    let client = VaultClient::unauthenticated(&session);
    let seal = client.get("sys/seal-status").await?;

    if output.json {
        output.print_json(&seal)?;
        return Ok(ServerStatus {
            sealed: is_sealed(&seal),
        });
    }

    // Reported in the order an operator triages: can it serve at all, then
    // what it is, then where it sits.
    let mut rows = Vec::new();
    for (label, key) in [
        ("sealed", "sealed"),
        ("initialized", "initialized"),
        ("seal_type", "type"),
        ("version", "version"),
        ("storage_type", "storage_type"),
        ("cluster_name", "cluster_name"),
        ("cluster_id", "cluster_id"),
        ("ha_enabled", "ha_enabled"),
    ] {
        if let Some(value) = seal.get(key) {
            if !value.is_null() {
                rows.push((label.to_string(), render(value)));
            }
        }
    }

    // Only meaningful while sealed, and misleading otherwise: a threshold with
    // no progress against it reads as a target nobody is working towards.
    if is_sealed(&seal) {
        if let (Some(progress), Some(threshold)) = (seal.get("progress"), seal.get("t")) {
            rows.push((
                "unseal_progress".to_string(),
                format!("{}/{}", render(progress), render(threshold)),
            ));
        }
    }

    output.print_key_value(&rows);
    Ok(ServerStatus {
        sealed: is_sealed(&seal),
    })
}

/// A server that does not say is not assumed unsealed: the whole point of the
/// report is the one field, and guessing it defeats the command.
fn is_sealed(seal: &Value) -> bool {
    seal.get("sealed").and_then(|s| s.as_bool()).unwrap_or(true)
}

fn render(value: &Value) -> String {
    match value.as_str() {
        Some(text) => text.to_string(),
        None => value.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A server that did not report the one field the command exists to
    /// report is not assumed to be serving.
    #[test]
    fn an_unreported_seal_state_is_not_read_as_unsealed() {
        assert!(is_sealed(&json!({ "initialized": true })));
        assert!(is_sealed(&json!({ "sealed": null })));
        assert!(!is_sealed(&json!({ "sealed": false })));
        assert!(is_sealed(&json!({ "sealed": true })));
    }
}
