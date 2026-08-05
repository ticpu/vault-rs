use crate::utils::errors::{Result, VaultCliError};
use crate::utils::PROGRAM_NAME;
use crate::vault::client::VaultClient;
use aes_gcm::{Aes256Gcm, Key, KeyInit};
use rand::Rng;
use serde_json::json;
use sha2::{Digest, Sha256};

const DEFAULT_KV_MOUNT: &str = "secret";
const KV_PATH: &str = "vault-rs/encryption-key";

/// Where the master key lives: the mount discovered for it, and whether that
/// mount keeps versions. Carrying the layout with the location is what stops
/// every consumer reading it back out of the path's shape, which inverts a
/// consequence of the layout into evidence for it.
pub struct KeyLocation {
    pub mount: String,
    pub versioned: bool,
}

impl KeyLocation {
    /// The key's own path within its mount, which is fixed.
    pub fn key(&self) -> &'static str {
        KV_PATH
    }

    fn new(mount: &str, reported: Option<&str>) -> Self {
        Self {
            mount: mount.trim_end_matches('/').to_string(),
            versioned: reported == Some("2"),
        }
    }

    /// Where the value itself is addressed.
    pub fn data_path(&self) -> String {
        match self.versioned {
            true => format!("{}/data/{KV_PATH}", self.mount),
            false => format!("{}/{KV_PATH}", self.mount),
        }
    }
}

/// Whether the mount holding the master key would keep the version an
/// overwrite replaces. This decides whether losing the local store is a
/// rollback away or total, and the two must not read alike.
pub enum VersionRetention {
    Retained {
        current: u64,
        mount: String,
        key: String,
    },
    None {
        why: String,
        mount: String,
        key: String,
    },
}

impl VersionRetention {
    /// The same answer as `describe`, without the command to act on it: a
    /// status line reports the state, it does not instruct.
    pub fn summary(&self) -> String {
        match self {
            Self::Retained { current, .. } => {
                format!("yes, version {current} would remain")
            }
            Self::None { why, .. } => format!("no — {why}"),
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Self::Retained {
                current,
                mount,
                key,
            } => format!(
                "This mount retains prior versions, so version {current} would remain and could \
                 be restored with:\n  {PROGRAM_NAME} session key restore --version {current}\n  \
                 (mount {mount}, key {key})"
            ),
            Self::None { why, .. } => {
                format!("{why}, so this would be permanent: there is no recovery.")
            }
        }
    }
}

/// Whether replacing the value at `mount`/`key` leaves the current one
/// recoverable. Addressed by mount and key so a caller holding only a path can
/// ask it, and so nothing has to scan every mount to find out.
///
/// Unreadable metadata is not "probably fine": it is the case where the answer
/// is unknown, and callers refuse on it.
pub async fn retention_at(
    client: &VaultClient,
    mount: &str,
    versioned: bool,
    key: &str,
) -> Result<VersionRetention> {
    let mount = mount.trim_end_matches('/').to_string();
    let key = key.to_string();

    if !versioned {
        return Ok(VersionRetention::None {
            why: "this mount keeps no version history".to_string(),
            mount,
            key,
        });
    }

    let metadata_path = format!("{mount}/metadata/{key}");
    let metadata = client.get(&metadata_path).await.map_err(|e| {
        VaultCliError::Storage(format!(
            "Cannot read '{metadata_path}' ({e}), so cannot tell whether overwriting the key \
             there could be undone"
        ))
    })?;

    let max_versions = metadata["data"]["max_versions"].as_u64().ok_or_else(|| {
        VaultCliError::Storage(format!(
            "'{metadata_path}' does not report max_versions, so cannot tell whether overwriting \
             the key there could be undone"
        ))
    })?;

    // 0 means the mount default, which retains history; 1 means the write that
    // adds the new version drops the one it replaces.
    if max_versions == 1 {
        return Ok(VersionRetention::None {
            why: "max_versions is 1, so writing a new version drops the current one".to_string(),
            mount,
            key,
        });
    }

    let current = metadata["data"]["current_version"].as_u64().unwrap_or(0);
    Ok(VersionRetention::Retained {
        current,
        mount,
        key,
    })
}

/// Whether a path a generic verb was handed is where this tool keeps its master
/// key, and what the mount being written says about getting the current one
/// back.
///
/// `None` means checked and not that path — never "could not check". The tail
/// comparison costs nothing and gates the rest, so an ordinary write asks the
/// server nothing; only a match pays for the mount's answer. What holds the key
/// is never resolved here: that needs a listing of every mount, a permission the
/// write itself does not require.
pub async fn master_key_notice(client: &VaultClient, path: &str) -> Option<String> {
    if !path.trim_end_matches('/').ends_with(KV_PATH) {
        return None;
    }

    let guarded =
        format!("`{PROGRAM_NAME} session init-encryption` is the guarded way to replace it.");
    let lead = format!(
        "'{path}' matches where {PROGRAM_NAME} stores its master key. Replacing it \
                        makes every locally sealed artifact unreadable."
    );

    let recovery = match recoverability(client, path).await {
        Ok(retention) => retention.describe(),
        // Silence would be indistinguishable from a checked negative, so the
        // notice degrades and marks what it could not establish.
        Err(e) => format!(
            "Could not confirm whether this mount retains versions: {e}\n\
             If it does not, this is permanent."
        ),
    };

    Some(format!("{lead}\n{recovery}\n{guarded}"))
}

/// The retention answer for a path, asked entirely of the mount serving it.
async fn recoverability(client: &VaultClient, path: &str) -> Result<VersionRetention> {
    let mount_version = client.mount_version(path).await?;
    let mount = mount_version.mount.trim_end_matches('/');
    let versioned = mount_version.version == 2;

    // Everything after the mount, and after the versioned layout's own prefix.
    let key = path
        .trim_start_matches('/')
        .strip_prefix(mount)
        .unwrap_or(path)
        .trim_start_matches('/');
    let key = match versioned {
        true => key.strip_prefix("data/").unwrap_or(key),
        false => key,
    };

    retention_at(client, mount, versioned, key).await
}

pub struct KeyManager {
    client: VaultClient,
}

impl KeyManager {
    pub async fn new() -> Result<Self> {
        let client = VaultClient::new().await?;
        Ok(Self { client })
    }

    pub fn with_client(client: VaultClient) -> Self {
        Self { client }
    }

    /// Get or create the master encryption key from Vault.
    ///
    /// Minting happens only when the store genuinely holds no key. Treating a
    /// failed read as absence would overwrite the existing key, and every
    /// artifact in the local store is encrypted under it.
    pub async fn get_master_key(&self) -> Result<[u8; 32]> {
        if let Some(key) = self.retrieve_key_from_vault().await? {
            return Ok(key);
        }

        let new_key = self.generate_master_key();
        self.store_key_in_vault(&new_key).await?;

        Ok(new_key)
    }

    /// Initialize encryption key in personal vault. `destroy_existing`
    /// overwrites one that is already there.
    pub async fn init_encryption_key(&self, destroy_existing: bool) -> Result<()> {
        if self.retrieve_key_from_vault().await?.is_none() {
            let key = self.generate_master_key();
            self.store_key_in_vault(&key).await?;
            tracing::info!("Encryption key initialized in personal vault");
            return Ok(());
        }

        let location = self.key_location().await?;
        let kv_path = location.data_path();
        // Whether an overwrite can be undone is a property of the mount, not of
        // the flag: the same command is a rollback away from reversible on a
        // mount that retains versions and total on one that does not.
        let retention = self.version_retention(&location).await?;

        if !destroy_existing {
            return Err(VaultCliError::Storage(format!(
                "An encryption key already exists at '{kv_path}'.\n\n\
                 Overwriting it makes every certificate and private key in the local store \
                 undecryptable. {}\n\n\
                 If that is genuinely what you want: \
                 {PROGRAM_NAME} session init-encryption --destroy-all-my-keys",
                retention.describe()
            )));
        }

        // The flag consents to losing the local store. It cannot consent to a
        // loss that nothing can undo, because the operator was not told which
        // of the two they were agreeing to.
        if let VersionRetention::None { why, mount, key } = &retention {
            return Err(VaultCliError::Storage(format!(
                "Refusing to overwrite the key at '{kv_path}': {why}, so this would be permanent \
                 and total — every certificate and private key in the local store, including keys \
                 that exist nowhere else.\n\n\
                 --destroy-all-my-keys consents to losing the local store, not to losing it \
                 irreversibly.\n\n\
                 To go ahead anyway, remove the key yourself so the decision is explicit:\n  \
                 {PROGRAM_NAME} kv delete --mount {mount} {key}"
            )));
        }

        tracing::warn!("Overwriting the master key: {}", retention.describe());
        let key = self.generate_master_key();
        self.store_key_in_vault(&key).await?;
        tracing::info!("Encryption key initialized in personal vault");
        Ok(())
    }

    /// Whether writing a new key would leave the current one recoverable.
    ///
    /// Unreadable metadata is not "probably fine": it is the case where the
    /// answer is unknown, and the caller refuses on it.
    pub async fn version_retention(&self, location: &KeyLocation) -> Result<VersionRetention> {
        retention_at(&self.client, &location.mount, location.versioned, KV_PATH).await
    }

    /// Where the key lives, for messages that have to name a recovery command.
    /// Best effort: a failure here must not replace the error it was being
    /// attached to.
    async fn kv_location(&self) -> Option<KeyLocation> {
        // discard-ok: best effort for a message; the caller either falls back to
        // generic wording or turns None into its own error
        self.key_location().await.ok()
    }

    /// What an operator staring at an AEAD failure needs and does not have:
    /// the one likely cause, and the command that shows whether the previous
    /// key is still there.
    pub async fn recovery_hint(&self) -> String {
        let Some(location) = self.kv_location().await else {
            return "The master key in Vault may not be the one this artifact was sealed with; \
                    check that key's version history."
                .to_string();
        };
        let (mount, key) = (&location.mount, KV_PATH);

        format!(
            "The master key in Vault is probably not the one this artifact was sealed with.\n\
             Check whether the previous key is still there:\n  \
             {PROGRAM_NAME} session key history\n\
             If an earlier version holds it, restoring that version makes these artifacts \
             readable again without destroying the current one:\n  \
             {PROGRAM_NAME} session key restore --version N\n\
             (mount {mount}, key {key})"
        )
    }

    /// Generate a new 256-bit master key
    fn generate_master_key(&self) -> [u8; 32] {
        let mut key = [0u8; 32];
        rand::rng().fill_bytes(&mut key);
        key
    }

    /// Which mount holds the master key, and what that mount says about its own
    /// layout.
    ///
    /// The key's mount is chosen rather than given, so this is the one place
    /// that still reads the whole listing — a probe addressed at a path cannot
    /// answer which mount ought to hold it. The listing reports each mount's
    /// layout alongside, so the answer comes from the same request and travels
    /// with the location instead of being read back off a path later.
    pub async fn key_location(&self) -> Result<KeyLocation> {
        let mounts = self.client.list_mounts().await?;

        if let Some(preferred) = mounts.data.get(&format!("{DEFAULT_KV_MOUNT}/")) {
            if preferred.is_kv() {
                return Ok(KeyLocation::new(DEFAULT_KV_MOUNT, preferred.get_version()));
            }
        }

        // Lowest path wins, and the ordering is the point rather than the
        // choice: the mount listing is unordered, so picking whichever came
        // back first sends one run to a mount the next run does not look in,
        // where finding no key reads as an empty store and mints a second one.
        // Everything sealed under the first is then unreadable.
        let mut candidates: Vec<_> = mounts
            .data
            .iter()
            .filter(|(_, mount_info)| mount_info.is_kv())
            .collect();
        candidates.sort_by_key(|(a, _)| *a);

        if let Some((mount_path, mount_info)) = candidates.first() {
            let mount = mount_path.trim_end_matches('/');
            tracing::info!("Using KV mount '{mount}' for encryption key storage");
            return Ok(KeyLocation::new(mount, mount_info.get_version()));
        }

        Err(VaultCliError::Storage(
            format!("No KV mount found in Vault.\n\nTo enable encrypted local storage, create a KV mount:\n  {PROGRAM_NAME} secrets enable -path=secret kv-v2\n\nAlternatively, use --no-store with certificate creation to skip local storage.\nUse '{PROGRAM_NAME} secrets list' to see available secret engines.")
        ))
    }

    /// The stored key, or `Ok(None)` when the path genuinely holds nothing.
    ///
    /// Every other outcome is an error, including a payload that is present but
    /// malformed: the caller mints on `None`, so anything that cannot be read
    /// with certainty has to stop it rather than look like an empty store.
    async fn retrieve_key_from_vault(&self) -> Result<Option<[u8; 32]>> {
        let location = self.key_location().await?;
        let kv_path = location.data_path();

        let data = match self.client.get(&kv_path).await {
            Ok(data) => data,
            // Vault answers alike for a path never written and for a version
            // withdrawn; either way there is no key here.
            Err(e) if e.is_not_found() => return Ok(None),
            Err(e) => return Err(e),
        };

        // Handle both KV v1 and v2 response formats
        // The versioned layout nests the value one level deeper.
        let key_hex = match location.versioned {
            true => data["data"]["data"]["key"].as_str(),
            false => data["data"]["key"].as_str(),
        }
        .ok_or_else(|| {
            VaultCliError::Storage(format!(
                "'{kv_path}' exists but carries no 'key' field; refusing to read that as an absent key"
            ))
        })?;

        let key_bytes = hex::decode(key_hex).map_err(|e| {
            VaultCliError::Storage(format!(
                "'{kv_path}' holds a key that is not valid hex: {e}"
            ))
        })?;

        if key_bytes.len() != 32 {
            return Err(VaultCliError::Storage(format!(
                "'{kv_path}' holds a {}-byte key; 32 expected",
                key_bytes.len()
            )));
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&key_bytes);
        Ok(Some(key))
    }

    /// Store key in Vault KV store
    async fn store_key_in_vault(&self, key: &[u8; 32]) -> Result<()> {
        let location = self.key_location().await?;
        let kv_path = location.data_path();
        let key_hex = hex::encode(key);

        let key_data = json!({
            "key": key_hex,
            "created": chrono::Utc::now().to_rfc3339(),
            "description": "vault-rs master encryption key"
        });

        let payload = match location.versioned {
            true => json!({ "data": key_data }),
            false => key_data,
        };

        self.client.post(&kv_path, payload).await?;

        Ok(())
    }

    /// Derive a context-specific key from the master key
    pub fn derive_key(&self, master_key: &[u8; 32], context: &str) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(master_key);
        hasher.update(context.as_bytes());
        let result = hasher.finalize();

        let mut derived_key = [0u8; 32];
        derived_key.copy_from_slice(&result);
        derived_key
    }

    /// Create an AES-GCM cipher instance from a key
    pub fn create_cipher(&self, key: &[u8; 32]) -> Aes256Gcm {
        Aes256Gcm::new(&Key::<Aes256Gcm>::from(*key))
    }

    /// Generate a random nonce for AES-GCM
    pub fn generate_nonce(&self) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        rand::rng().fill_bytes(&mut nonce);
        nonce
    }
}

/// Every test here turns on one question: does this code path write to the key
/// path? A write over an existing key makes every artifact in the local store
/// permanently undecryptable, and no round-trip or return-value assertion can
/// see that happen — only counting the POST can. `expect(0)` is verified when
/// the `MockServer` drops.
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const V2_PATH: &str = "/v1/secret/data/vault-rs/encryption-key";
    const V1_PATH: &str = "/v1/secret/vault-rs/encryption-key";
    const V2_META: &str = "/v1/secret/metadata/vault-rs/encryption-key";

    fn manager(server: &MockServer) -> KeyManager {
        KeyManager::with_client(
            VaultClient::for_test(server.uri(), "test-token".to_string()).expect("test client"),
        )
    }

    /// `sys/mounts` shaped so the key resolves to the `secret` mount.
    async fn mount_kv(server: &MockServer, version: &str) {
        let body = json!({
            "data": { "secret/": { "type": "kv", "options": { "version": version } } }
        });
        Mock::given(method("GET"))
            .and(path("/v1/sys/mounts"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(server)
            .await;
    }

    async fn respond_to_read(server: &MockServer, at: &str, response: ResponseTemplate) {
        Mock::given(method("GET"))
            .and(path(at))
            .respond_with(response)
            .mount(server)
            .await;
    }

    /// Mounts a POST expectation at the key path. `writes` is the number of
    /// writes this test asserts must happen — usually zero.
    async fn expect_writes(server: &MockServer, at: &str, writes: u64) {
        Mock::given(method("POST"))
            .and(path(at))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "data": {} })))
            .expect(writes)
            .mount(server)
            .await;
    }

    /// The mount's version-retention answer. `max_versions` of 1 drops the
    /// version an overwrite replaces; 0 is the mount default, which keeps it.
    async fn mount_retention(server: &MockServer, max_versions: u64) {
        let body = json!({
            "data": { "max_versions": max_versions, "current_version": 7 }
        });
        Mock::given(method("GET"))
            .and(path(V2_META))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(server)
            .await;
    }

    fn stored_key(hex_key: &str, v2: bool) -> ResponseTemplate {
        let inner = json!({ "key": hex_key });
        let body: Value = if v2 {
            json!({ "data": { "data": inner } })
        } else {
            json!({ "data": inner })
        };
        ResponseTemplate::new(200).set_body_json(body)
    }

    #[tokio::test]
    async fn a_stored_key_is_read_from_kv_v2_and_nothing_is_written() {
        let server = MockServer::start().await;
        mount_kv(&server, "2").await;
        respond_to_read(&server, V2_PATH, stored_key(&"ab".repeat(32), true)).await;
        expect_writes(&server, V2_PATH, 0).await;

        let key = manager(&server).get_master_key().await.expect("read");
        assert_eq!(key, [0xab; 32]);
    }

    #[tokio::test]
    async fn a_stored_key_is_read_from_kv_v1_and_nothing_is_written() {
        let server = MockServer::start().await;
        mount_kv(&server, "1").await;
        respond_to_read(&server, V1_PATH, stored_key(&"cd".repeat(32), false)).await;
        expect_writes(&server, V1_PATH, 0).await;

        let key = manager(&server).get_master_key().await.expect("read");
        assert_eq!(key, [0xcd; 32]);
    }

    /// 404 is the one answer that means the store genuinely holds no key.
    #[tokio::test]
    async fn a_404_is_absence_and_mints_exactly_one_key() {
        let server = MockServer::start().await;
        mount_kv(&server, "2").await;
        respond_to_read(&server, V2_PATH, ResponseTemplate::new(404)).await;
        expect_writes(&server, V2_PATH, 1).await;

        manager(&server).get_master_key().await.expect("mint");
    }

    /// The defect this step exists to remove: a transient failure used to read
    /// as absence, mint a fresh key and overwrite the real one.
    #[tokio::test]
    async fn a_denied_read_never_writes() {
        let server = MockServer::start().await;
        mount_kv(&server, "2").await;
        respond_to_read(&server, V2_PATH, ResponseTemplate::new(403)).await;
        expect_writes(&server, V2_PATH, 0).await;

        manager(&server)
            .get_master_key()
            .await
            .expect_err("a denied read is not an absent key");
    }

    #[tokio::test]
    async fn a_server_error_never_writes() {
        let server = MockServer::start().await;
        mount_kv(&server, "2").await;
        respond_to_read(&server, V2_PATH, ResponseTemplate::new(500)).await;
        expect_writes(&server, V2_PATH, 0).await;

        manager(&server)
            .get_master_key()
            .await
            .expect_err("a server error is not an absent key");
    }

    /// A payload that is present but unreadable is not an empty store either.
    #[tokio::test]
    async fn a_malformed_stored_key_never_writes() {
        let server = MockServer::start().await;
        mount_kv(&server, "2").await;
        respond_to_read(&server, V2_PATH, stored_key("not-hex", true)).await;
        expect_writes(&server, V2_PATH, 0).await;

        let err = manager(&server)
            .get_master_key()
            .await
            .expect_err("malformed is not absent")
            .to_string();
        assert!(err.contains("not valid hex"), "{err}");
    }

    #[tokio::test]
    async fn init_refuses_when_a_key_already_exists() {
        let server = MockServer::start().await;
        mount_kv(&server, "2").await;
        respond_to_read(&server, V2_PATH, stored_key(&"ab".repeat(32), true)).await;
        mount_retention(&server, 0).await;
        expect_writes(&server, V2_PATH, 0).await;

        let err = manager(&server)
            .init_encryption_key(false)
            .await
            .expect_err("a second init must not overwrite")
            .to_string();
        assert!(err.contains("--destroy-all-my-keys"), "{err}");
    }

    /// Not knowing whether a key is there is not the same as knowing there is
    /// none, so `init` refuses on a failed read too.
    #[tokio::test]
    async fn init_refuses_when_the_existence_check_fails() {
        let server = MockServer::start().await;
        mount_kv(&server, "2").await;
        respond_to_read(&server, V2_PATH, ResponseTemplate::new(500)).await;
        expect_writes(&server, V2_PATH, 0).await;

        manager(&server)
            .init_encryption_key(false)
            .await
            .expect_err("an unread store is not an empty one");
    }

    /// The refusal has to say which situation the operator is in: the same
    /// flag is a rollback away from reversible here and total below.
    #[tokio::test]
    async fn the_refusal_names_the_rollback_when_history_is_kept() {
        let server = MockServer::start().await;
        mount_kv(&server, "2").await;
        respond_to_read(&server, V2_PATH, stored_key(&"ab".repeat(32), true)).await;
        mount_retention(&server, 0).await;
        expect_writes(&server, V2_PATH, 0).await;

        let err = manager(&server)
            .init_encryption_key(false)
            .await
            .expect_err("a key is present")
            .to_string();
        assert!(err.contains("session key restore"), "{err}");
        assert!(err.contains("--version 7"), "{err}");
        assert!(!err.contains("no recovery"), "{err}");
    }

    /// max_versions=1 drops the version being replaced, so the overwrite is
    /// total. The flag consents to losing the store, not to losing it with no
    /// way back, so it is refused outright.
    #[tokio::test]
    async fn an_unrecoverable_overwrite_is_refused_even_with_the_flag() {
        let server = MockServer::start().await;
        mount_kv(&server, "2").await;
        respond_to_read(&server, V2_PATH, stored_key(&"ab".repeat(32), true)).await;
        mount_retention(&server, 1).await;
        expect_writes(&server, V2_PATH, 0).await;

        let err = manager(&server)
            .init_encryption_key(true)
            .await
            .expect_err("no history means no consent")
            .to_string();
        assert!(err.contains("permanent"), "{err}");
        assert!(err.contains("kv delete"), "{err}");
    }

    /// KV v1 keeps no versions at all.
    #[tokio::test]
    async fn a_kv_v1_overwrite_is_refused_even_with_the_flag() {
        let server = MockServer::start().await;
        mount_kv(&server, "1").await;
        respond_to_read(&server, V1_PATH, stored_key(&"ab".repeat(32), false)).await;
        expect_writes(&server, V1_PATH, 0).await;

        let err = manager(&server)
            .init_encryption_key(true)
            .await
            .expect_err("KV v1 has no history")
            .to_string();
        assert!(err.contains("no version history"), "{err}");
    }

    /// Not knowing whether the overwrite could be undone is not the same as
    /// knowing it could.
    #[tokio::test]
    async fn unreadable_retention_metadata_refuses_the_overwrite() {
        let server = MockServer::start().await;
        mount_kv(&server, "2").await;
        respond_to_read(&server, V2_PATH, stored_key(&"ab".repeat(32), true)).await;
        Mock::given(method("GET"))
            .and(path(V2_META))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;
        expect_writes(&server, V2_PATH, 0).await;

        manager(&server)
            .init_encryption_key(true)
            .await
            .expect_err("an unknown answer is not a yes");
    }

    #[tokio::test]
    async fn init_overwrites_only_with_the_flag() {
        let server = MockServer::start().await;
        mount_kv(&server, "2").await;
        respond_to_read(&server, V2_PATH, stored_key(&"ab".repeat(32), true)).await;
        mount_retention(&server, 0).await;
        expect_writes(&server, V2_PATH, 1).await;

        manager(&server)
            .init_encryption_key(true)
            .await
            .expect("the flag permits the overwrite");
    }

    const PROBE_V2: &str = "/v1/sys/internal/ui/mounts/secret/data/vault-rs/encryption-key";

    async fn probe_says(server: &MockServer, at: &str, version: &str) {
        Mock::given(method("GET"))
            .and(path(at))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": { "path": "secret/", "options": { "version": version } }
            })))
            .mount(server)
            .await;
    }

    fn test_client(server: &MockServer) -> VaultClient {
        VaultClient::for_test(server.uri(), "test-token".to_string()).expect("test client")
    }

    /// Silence has to mean checked and not the path. An ordinary write must
    /// also ask the server nothing, or every write pays for the rare one.
    #[tokio::test]
    async fn an_ordinary_path_gets_no_notice_and_no_request() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;

        assert!(
            master_key_notice(&test_client(&server), "secret/data/app/config")
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn the_master_key_path_is_announced_with_the_route_back() {
        let server = MockServer::start().await;
        probe_says(&server, PROBE_V2, "2").await;
        mount_retention(&server, 0).await;

        let notice =
            master_key_notice(&test_client(&server), "secret/data/vault-rs/encryption-key")
                .await
                .expect("the master key path is announced");
        assert!(notice.contains("master key"), "{notice}");
        assert!(notice.contains("session init-encryption"), "{notice}");
        assert!(notice.contains("version 7"), "{notice}");
    }

    /// A mount keeping no history must not be offered a restore that cannot
    /// happen.
    #[tokio::test]
    async fn a_mount_without_history_is_told_the_loss_is_permanent() {
        let server = MockServer::start().await;
        probe_says(
            &server,
            "/v1/sys/internal/ui/mounts/secret/vault-rs/encryption-key",
            "1",
        )
        .await;

        let notice = master_key_notice(&test_client(&server), "secret/vault-rs/encryption-key")
            .await
            .expect("announced");
        assert!(notice.contains("no recovery"), "{notice}");
    }

    /// The confirmation reads paths the write does not, so a caller allowed to
    /// write may still be refused it. Falling silent there would make the
    /// absence of a warning a claim nothing established.
    #[tokio::test]
    async fn a_denied_confirmation_degrades_the_notice_rather_than_dropping_it() {
        let server = MockServer::start().await;
        probe_says(&server, PROBE_V2, "2").await;
        Mock::given(method("GET"))
            .and(path(V2_META))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;

        let notice =
            master_key_notice(&test_client(&server), "secret/data/vault-rs/encryption-key")
                .await
                .expect("a denied confirmation still warns");
        assert!(notice.contains("master key"), "{notice}");
        assert!(notice.contains("Could not confirm"), "{notice}");
        assert!(notice.contains("403"), "{notice}");
    }

    /// The listing is unordered, so a fallback that took whichever mount came
    /// back first would send one run to a mount the next run does not look in
    /// — minting a second key and stranding everything sealed under the first.
    #[tokio::test]
    async fn the_fallback_mount_is_the_same_one_every_time() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/sys/mounts"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": {
                    "zulu/": { "type": "kv", "options": { "version": "2" } },
                    "alpha/": { "type": "kv", "options": { "version": "2" } },
                    "mike/": { "type": "kv", "options": { "version": "2" } }
                }
            })))
            .mount(&server)
            .await;
        respond_to_read(
            &server,
            "/v1/alpha/data/vault-rs/encryption-key",
            stored_key(&"ab".repeat(32), true),
        )
        .await;
        expect_writes(&server, "/v1/alpha/data/vault-rs/encryption-key", 0).await;

        for _ in 0..8 {
            let key = manager(&server).get_master_key().await.expect("read");
            assert_eq!(key, [0xab; 32], "a different mount was chosen");
        }
    }
}
