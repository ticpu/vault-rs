//! The generic path verbs, answered directly rather than forwarded.

use crate::crypto::keys::master_key_notice;
use crate::logical::data;
use crate::utils::errors::{Result, VaultCliError};
use crate::utils::output::OutputFormat;
use crate::utils::PROGRAM_NAME;
use crate::vault::client::VaultClient;
use serde_json::{Map, Value};

/// Read one path. Trailing `key=value` arguments become query parameters,
/// which is how a versioned read names its version and a counter query its
/// range; without them the path alone cannot ask those questions.
pub async fn read(
    client: &VaultClient,
    path: &str,
    args: &[String],
    field: Option<&str>,
    output: &OutputFormat,
) -> Result<()> {
    let query = data::parse(args, &mut std::io::stdin())?;
    let secret = client.get(&with_query(path, &query)).await?;

    report_secret(&secret, field, output)
}

pub async fn list(client: &VaultClient, path: &str, output: &OutputFormat) -> Result<()> {
    if output.json {
        return output.print_json(&client.list(path).await?);
    }

    output.print_list(&client.list_keys(path).await?);
    Ok(())
}

/// Write to one path.
///
/// No confirmation: rehearsing a write is the certificate authority's rule,
/// and the generic verb has to behave like the generic verb. What it owes is
/// notice, which `announce` gives before anything is sent.
pub async fn write(
    client: &VaultClient,
    path: &str,
    args: &[String],
    force: bool,
    field: Option<&str>,
    output: &OutputFormat,
) -> Result<()> {
    if args.is_empty() && !force {
        return Err(VaultCliError::InvalidInput(format!(
            "'{path}' was given no data. Pass key=value arguments, or --force to write nothing \
             to a path that expects none."
        )));
    }

    let body = data::parse(args, &mut std::io::stdin())?;
    announce(client, path).await;

    let written = client.post(path, Value::Object(body)).await?;
    if written.is_null() {
        eprintln!("Written to {path}");
        return Ok(());
    }

    report_secret(&written, field, output)
}

pub async fn delete(client: &VaultClient, path: &str) -> Result<()> {
    announce(client, path).await;

    client.delete(path).await?;
    eprintln!("Deleted {path}");
    Ok(())
}

/// Say what is about to be written over, where the target is a path some other
/// command guards. Best effort by construction: this is a warning attached to
/// an operation that proceeds either way, so a failure to produce it must not
/// become a failure to perform the write.
pub async fn announce(client: &VaultClient, path: &str) {
    if let Some(notice) = master_key_notice(client, path).await {
        eprintln!("{notice}\n");
    }
}

/// A read's query parameters, appended once rather than at each call site.
fn with_query(path: &str, query: &Map<String, Value>) -> String {
    if query.is_empty() {
        return path.to_string();
    }

    let pairs: Vec<String> = query
        .iter()
        .map(|(key, value)| {
            let rendered = match value.as_str() {
                Some(text) => text.to_string(),
                None => value.to_string(),
            };
            format!("{key}={rendered}")
        })
        .collect();

    format!("{path}?{}", pairs.join("&"))
}

/// What the caller asked for: one field bare, the whole envelope as JSON, or
/// the record as columns.
pub fn report_secret(secret: &Value, field: Option<&str>, output: &OutputFormat) -> Result<()> {
    let data = secret.get("data").unwrap_or(secret);

    if let Some(field) = field {
        let value = data.get(field).ok_or_else(|| {
            VaultCliError::InvalidInput(format!(
                "no field '{field}' in the response; {PROGRAM_NAME} --json shows what is there"
            ))
        })?;
        // A single bare value, with no formatting to strip back off.
        match value.as_str() {
            Some(text) => println!("{text}"),
            None => println!("{value}"),
        }
        return Ok(());
    }

    warn_about(secret);

    // The whole envelope, not just its data: leases and warnings are part of
    // what the server answered.
    if output.json {
        return output.print_json(secret);
    }

    let Some(fields) = data.as_object() else {
        println!("{data}");
        return Ok(());
    };

    // Sorted, because a map's order is not an answer and a diff of two reads
    // should show what changed rather than how they were serialized.
    let mut rows: Vec<(String, String)> = fields
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

fn warn_about(secret: &Value) {
    let Some(warnings) = secret.get("warnings").and_then(|w| w.as_array()) else {
        return;
    };

    for warning in warnings.iter().filter_map(|w| w.as_str()) {
        eprintln!("Warning: {warning}");
    }
}
