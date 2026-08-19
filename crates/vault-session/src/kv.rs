//! The KV engine's own verbs, on top of the generic path layer.
//!
//! The versioned layout addresses one secret through several prefixes — the
//! value, its metadata, and the operations that withdraw or restore a version.
//! Which prefix a verb needs is fixed; which layout the mount uses is not, and
//! is asked of the mount rather than read off the path's shape.

use crate::client::{MountVersion, VaultClient};
use crate::error::{Error, Result};
#[cfg(test)]
use serde_json::json;
use serde_json::Value;

/// A secret named either as `mount/path` or as `--mount mount path`, resolved
/// against the layout its mount reports.
#[derive(Debug)]
pub struct Target {
    mount: String,
    key: String,
    versioned: bool,
}

impl Target {
    /// A secret whose mount and layout the caller already established. The
    /// master key's mount is chosen by discovery rather than probed, so it
    /// arrives here already answered rather than being asked again.
    pub fn known(mount: &str, key: &str, versioned: bool) -> Self {
        Self {
            mount: mount.trim_matches('/').to_string(),
            key: key.trim_matches('/').to_string(),
            versioned,
        }
    }

    pub async fn resolve(client: &VaultClient, mount: Option<&str>, path: &str) -> Result<Self> {
        let path = path.trim_matches('/');

        // With an explicit mount the argument is the secret's own path, so the
        // probe has to be asked about the two joined.
        let probed = match mount {
            Some(mount) => format!("{}/{path}", mount.trim_matches('/')),
            None => path.to_string(),
        };
        let MountVersion {
            mount: reported,
            version,
        } = client.mount_version(&probed).await?;

        let reported = reported.trim_matches('/').to_string();
        let key = match mount {
            Some(_) => path.to_string(),
            // Without one the argument carried the mount, which comes back off.
            None => path
                .strip_prefix(reported.as_str())
                .unwrap_or(path)
                .trim_matches('/')
                .to_string(),
        };

        if key.is_empty() {
            return Err(Error::InvalidInput(format!(
                "'{path}' names a mount but no secret in it"
            )));
        }

        Ok(Self {
            mount: reported,
            key,
            versioned: version == 2,
        })
    }

    /// The path for one of the engine's prefixes. An unversioned mount has only
    /// the secret itself, so a verb needing any other prefix has nothing to
    /// address and must not invent one.
    pub fn at(&self, prefix: &str) -> String {
        match self.versioned {
            true => format!("{}/{prefix}/{}", self.mount, self.key),
            false => format!("{}/{}", self.mount, self.key),
        }
    }

    pub fn data(&self) -> String {
        self.at("data")
    }

    pub fn versioned(&self) -> bool {
        self.versioned
    }

    /// Refuse a verb that only the versioned layout has, naming the mount so
    /// the operator knows it is the mount and not the command.
    pub fn require_versions(&self, verb: &str) -> Result<()> {
        match self.versioned {
            true => Ok(()),
            false => Err(Error::InvalidInput(format!(
                "'{}' keeps no version history, so there is nothing for `kv {verb}` to act on",
                self.mount
            ))),
        }
    }
}

/// The server's answer with the mount's layout unwrapped, leases and warnings
/// still on it.
pub async fn read(client: &VaultClient, target: &Target, version: Option<u64>) -> Result<Value> {
    let path = target.data();
    let secret = match version {
        Some(version) => {
            target.require_versions("get -version")?;
            client
                .get_even_if_withdrawn_at_version(&path, version)
                .await?
        }
        None => client.get_even_if_withdrawn(&path).await?,
    };
    Ok(unwrap_data(&secret, target.versioned()))
}

/// The secret's own fields, for a caller that wants the value rather than a
/// rendering of it.
///
/// A version that was withdrawn or destroyed answers with no fields; that is
/// refused here rather than returned as an empty object, since a caller reading
/// a credential out of it would otherwise get one that is merely absent.
pub async fn read_secret(
    client: &VaultClient,
    mount: Option<&str>,
    path: &str,
    version: Option<u64>,
) -> Result<Value> {
    let target = Target::resolve(client, mount, path).await?;
    let envelope = read(client, &target, version).await?;

    match envelope.get("data") {
        Some(data) if data.is_object() => Ok(data.clone()),
        _ => Err(Error::InvalidInput(format!(
            "'{}' answered with no fields{}; a withdrawn or destroyed version reads this way",
            target.data(),
            match version {
                Some(version) => format!(" at version {version}"),
                None => String::new(),
            }
        ))),
    }
}

/// The versioned layout nests the value one level deeper than the flat one.
fn unwrap_data(secret: &Value, versioned: bool) -> Value {
    match versioned {
        false => secret.clone(),
        true => match secret.get("data") {
            Some(inner) => {
                let mut lifted = secret.clone();
                if let Some(object) = lifted.as_object_mut() {
                    object.insert("data".to_string(), inner["data"].clone());
                    if let Some(metadata) = inner.get("metadata") {
                        object.insert("metadata".to_string(), metadata.clone());
                    }
                }
                lifted
            }
            None => secret.clone(),
        },
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

    /// The two spellings name the same secret and have to resolve alike.
    #[tokio::test]
    async fn a_mount_flag_and_a_joined_path_resolve_the_same() {
        let server = MockServer::start().await;
        probe(&server, "secret/app/config", "secret/", "2").await;

        let client = client(&server);
        let joined = Target::resolve(&client, None, "secret/app/config")
            .await
            .expect("joined");
        let flagged = Target::resolve(&client, Some("secret"), "app/config")
            .await
            .expect("flagged");

        assert_eq!(joined.data(), "secret/data/app/config");
        assert_eq!(flagged.data(), joined.data());
    }

    /// A flat mount has one prefix and no others; the value is addressed
    /// directly rather than through the versioned layout's.
    #[tokio::test]
    async fn a_flat_mount_addresses_the_value_directly() {
        let server = MockServer::start().await;
        probe(&server, "flat/app/config", "flat/", "1").await;

        let target = Target::resolve(&client(&server), None, "flat/app/config")
            .await
            .expect("resolved");
        assert_eq!(target.data(), "flat/app/config");
        assert!(!target.versioned());
    }

    #[tokio::test]
    async fn a_mount_with_no_secret_named_is_refused() {
        let server = MockServer::start().await;
        probe(&server, "secret", "secret/", "2").await;

        let err = Target::resolve(&client(&server), None, "secret")
            .await
            .expect_err("a mount is not a secret")
            .to_string();
        assert!(err.contains("no secret"), "{err}");
    }

    async fn versioned_secret(server: &MockServer, body: Value) {
        Mock::given(method("GET"))
            .and(path("/v1/secret/data/app/config"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(server)
            .await;
    }

    /// The layouts nest the value at different depths, and a caller reading a
    /// credential gets the fields themselves either way.
    #[tokio::test]
    async fn read_secret_returns_the_fields_whichever_layout_the_mount_uses() {
        let server = MockServer::start().await;
        probe(&server, "secret/app/config", "secret/", "2").await;
        versioned_secret(
            &server,
            json!({ "data": { "data": { "password": "versioned" }, "metadata": { "version": 3 } } }),
        )
        .await;
        probe(&server, "flat/app/config", "flat/", "1").await;
        Mock::given(method("GET"))
            .and(path("/v1/flat/app/config"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({ "data": { "password": "flat" } })),
            )
            .mount(&server)
            .await;

        let client = client(&server);
        assert_eq!(
            read_secret(&client, None, "secret/app/config", None)
                .await
                .expect("versioned")["password"],
            json!("versioned")
        );
        assert_eq!(
            read_secret(&client, Some("flat"), "app/config", None)
                .await
                .expect("flat")["password"],
            json!("flat")
        );
    }

    /// A withdrawn version answers with metadata and no fields. Returning that
    /// as an empty object hands a caller reading a credential one that is
    /// merely absent.
    #[tokio::test]
    async fn read_secret_refuses_a_version_holding_no_fields() {
        let server = MockServer::start().await;
        probe(&server, "secret/app/config", "secret/", "2").await;
        versioned_secret(
            &server,
            json!({ "data": { "data": null, "metadata": { "version": 3, "destroyed": true } } }),
        )
        .await;

        let err = read_secret(&client(&server), None, "secret/app/config", None)
            .await
            .expect_err("no fields to return")
            .to_string();
        assert!(err.contains("no fields"), "{err}");
    }
}
