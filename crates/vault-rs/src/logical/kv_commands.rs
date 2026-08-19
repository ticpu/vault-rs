//! The KV engine's write and version verbs — CLI reporting and confirmation
//! over the library's `Target`, kept out of the published library along with
//! every other `eprintln!`.

use crate::crypto::keys::master_key_notice;
use crate::logical::data;
use crate::utils::errors::{Result, VaultCliError};
use crate::utils::output::OutputFormat;
use crate::vault::client::VaultClient;
use serde_json::{json, Value};
use vault_session::logical::kv::{read, Target};

pub async fn get(
    client: &VaultClient,
    target: &Target,
    version: Option<u64>,
    field: Option<&str>,
    output: &OutputFormat,
) -> Result<()> {
    let secret = read(client, target, version).await?;
    super::commands::report_secret(&secret, field, output)
}

pub async fn put(
    client: &VaultClient,
    target: &Target,
    args: &[String],
    cas: Option<u64>,
    output: &OutputFormat,
) -> Result<()> {
    let fields = data::parse(args, &mut std::io::stdin())?;
    let path = target.data();
    announce(client, &path).await;

    // The versioned layout wraps the value and takes options beside it; the
    // flat one stores what it was given.
    let body = match target.versioned() {
        false => Value::Object(fields),
        true => {
            let mut body = json!({ "data": Value::Object(fields) });
            if let Some(cas) = cas {
                body["options"] = json!({ "cas": cas });
            }
            body
        }
    };

    let written = client.post(&path, body).await?;
    match written.is_null() {
        true => eprintln!("Written to {path}"),
        false => super::commands::report_secret(&written, None, output)?,
    }
    Ok(())
}

pub async fn list(client: &VaultClient, target: &Target, output: &OutputFormat) -> Result<()> {
    let path = target.at("metadata");
    super::commands::list(client, &path, output).await
}

/// Withdraw the value, or the named versions of it. Without versions this is
/// the whole secret, which is why it reaches for the value's own prefix.
pub async fn delete(client: &VaultClient, target: &Target, versions: &[u64]) -> Result<()> {
    if versions.is_empty() {
        let path = target.data();
        announce(client, &path).await;
        client.delete(&path).await?;
        eprintln!("Deleted {path}");
        return Ok(());
    }

    target.require_versions("delete --version")?;
    act_on_versions(client, target, "delete", versions).await
}

pub async fn undelete(client: &VaultClient, target: &Target, versions: &[u64]) -> Result<()> {
    target.require_versions("undelete")?;
    act_on_versions(client, target, "undelete", versions).await
}

pub async fn destroy(client: &VaultClient, target: &Target, versions: &[u64]) -> Result<()> {
    target.require_versions("destroy")?;
    act_on_versions(client, target, "destroy", versions).await
}

async fn act_on_versions(
    client: &VaultClient,
    target: &Target,
    verb: &str,
    versions: &[u64],
) -> Result<()> {
    let path = target.at(verb);
    announce(client, &target.data()).await;

    client.post(&path, json!({ "versions": versions })).await?;
    eprintln!(
        "{verb} on {} version(s) of {}",
        versions.len(),
        target.data()
    );
    Ok(())
}

pub async fn metadata_get(
    client: &VaultClient,
    target: &Target,
    output: &OutputFormat,
) -> Result<()> {
    target.require_versions("metadata get")?;
    let secret = client.get(&target.at("metadata")).await?;
    super::commands::report_secret(&secret, None, output)
}

/// Remove the secret and every version of it. Worse than `delete`, since it
/// takes the history a rollback would have used.
pub async fn metadata_delete(client: &VaultClient, target: &Target) -> Result<()> {
    target.require_versions("metadata delete")?;
    let path = target.at("metadata");
    announce(client, &target.data()).await;

    client.delete(&path).await?;
    eprintln!("Deleted {path} and every version under it");
    Ok(())
}

/// Restore a prior version by writing it back as a new one.
///
/// Read twice on purpose: the current version supplies the check-and-set that
/// makes this fail rather than clobber a write that landed in between, and the
/// named version supplies the value. A version that was withdrawn or destroyed
/// is refused — its data is gone, and writing what came back would store an
/// empty value over a good one.
pub async fn rollback(client: &VaultClient, target: &Target, version: u64) -> Result<()> {
    target.require_versions("rollback")?;
    let path = target.data();

    let current = client.get_even_if_withdrawn(&path).await?;
    let cas = current["data"]["metadata"]["version"]
        .as_u64()
        .ok_or_else(|| {
            VaultCliError::InvalidInput(format!(
                "'{path}' reports no current version, so there is nothing to roll back from"
            ))
        })?;

    let wanted = client
        .get_even_if_withdrawn_at_version(&path, version)
        .await?;
    let metadata = &wanted["data"]["metadata"];

    if metadata["destroyed"].as_bool().unwrap_or(false) {
        return Err(VaultCliError::InvalidInput(format!(
            "version {version} of '{path}' was destroyed; its value is gone"
        )));
    }
    if !metadata["deletion_time"].as_str().unwrap_or("").is_empty() {
        return Err(VaultCliError::InvalidInput(format!(
            "version {version} of '{path}' is deleted; undelete it before rolling back to it"
        )));
    }

    let Some(value) = wanted["data"]["data"].as_object() else {
        return Err(VaultCliError::InvalidInput(format!(
            "version {version} of '{path}' holds no data to restore"
        )));
    };

    announce(client, &path).await;
    client
        .post(
            &path,
            json!({ "data": Value::Object(value.clone()), "options": { "cas": cas } }),
        )
        .await?;

    eprintln!("Restored version {version} of {path} as a new version");
    Ok(())
}

/// Say what is about to be written over, where the target is a path some other
/// command guards.
async fn announce(client: &VaultClient, path: &str) {
    if let Some(notice) = master_key_notice(client, path).await {
        eprintln!("{notice}\n");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn probe(server: &MockServer, at: &str, mount: &str, version: &str) {
        Mock::given(method("GET"))
            .and(path(format!("/v1/sys/internal/ui/mounts/{at}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": { "path": mount, "options": { "version": version } }
            })))
            .mount(server)
            .await;
    }

    fn client(server: &MockServer) -> VaultClient {
        VaultClient::with_token(server.uri(), "test-token".to_string()).expect("test client")
    }

    async fn versioned_secret(server: &MockServer, body: Value) {
        Mock::given(method("GET"))
            .and(path("/v1/secret/data/app/config"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(server)
            .await;
    }

    /// A verb the mount cannot serve is refused by name rather than sent to a
    /// path the engine does not have.
    #[tokio::test]
    async fn a_version_verb_on_a_flat_mount_is_refused() {
        let server = MockServer::start().await;
        probe(&server, "flat/app/config", "flat/", "1").await;
        let client = client(&server);
        let target = Target::resolve(&client, None, "flat/app/config")
            .await
            .expect("resolved");

        let err = rollback(&client, &target, 1)
            .await
            .expect_err("no history to roll back through")
            .to_string();
        assert!(err.contains("no version history"), "{err}");
    }

    /// Rolling back to a version whose value was destroyed would write an empty
    /// secret over a good one.
    #[tokio::test]
    async fn rolling_back_to_a_destroyed_version_is_refused() {
        let server = MockServer::start().await;
        probe(&server, "secret/app/config", "secret/", "2").await;
        versioned_secret(
            &server,
            json!({ "data": { "data": {}, "metadata": { "version": 3, "destroyed": true } } }),
        )
        .await;
        Mock::given(method("POST"))
            .and(path("/v1/secret/data/app/config"))
            .respond_with(ResponseTemplate::new(204))
            .expect(0)
            .mount(&server)
            .await;

        let client = client(&server);
        let target = Target::resolve(&client, None, "secret/app/config")
            .await
            .expect("resolved");
        let err = rollback(&client, &target, 1)
            .await
            .expect_err("destroyed")
            .to_string();
        assert!(err.contains("destroyed"), "{err}");
    }

    #[tokio::test]
    async fn rolling_back_to_a_deleted_version_is_refused() {
        let server = MockServer::start().await;
        probe(&server, "secret/app/config", "secret/", "2").await;
        versioned_secret(
            &server,
            json!({ "data": { "data": {}, "metadata": { "version": 3, "deletion_time": "2026-01-01T00:00:00Z" } } }),
        )
        .await;
        Mock::given(method("POST"))
            .and(path("/v1/secret/data/app/config"))
            .respond_with(ResponseTemplate::new(204))
            .expect(0)
            .mount(&server)
            .await;

        let client = client(&server);
        let target = Target::resolve(&client, None, "secret/app/config")
            .await
            .expect("resolved");
        let err = rollback(&client, &target, 1)
            .await
            .expect_err("deleted")
            .to_string();
        assert!(err.contains("undelete"), "{err}");
    }
}
