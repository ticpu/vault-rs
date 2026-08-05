//! The master key's own commands.
//!
//! These exist because the alternative is a hint: an operator whose store will
//! not decrypt was being handed a KV incantation to compose by hand, at the one
//! moment they can least check they typed it right.

use crate::crypto::key_mount;
use crate::crypto::keys::{KeyLocation, KeyManager};
use crate::logical::kv::{self, Target};
use crate::storage::local::LocalStorage;
use crate::utils::errors::{Result, VaultCliError};
use crate::utils::output::OutputFormat;
use crate::utils::PROGRAM_NAME;
use crate::vault::client::VaultClient;

/// Where the key is, whether replacing it could be undone, and which cluster
/// answered.
///
/// The cluster is part of the report rather than context for it: a version
/// history read from the Vault in front of you is not the history of the
/// cluster that sealed an artifact, and the two look alike until they are
/// named.
pub async fn status(output: &OutputFormat) -> Result<()> {
    let client = VaultClient::new().await?;
    let manager = KeyManager::with_client(client.clone())?;
    let location = manager.key_location().await?;

    let mut rows = vec![
        ("mount".to_string(), location.mount.clone()),
        ("path".to_string(), location.data_path()),
        (
            "versioned".to_string(),
            match location.versioned {
                true => "yes".to_string(),
                false => "no".to_string(),
            },
        ),
        (
            "cluster_reached".to_string(),
            client
                .cluster_id()
                .await?
                .unwrap_or_else(|| "not reported".to_string()),
        ),
    ];

    match manager.version_retention(&location).await {
        Ok(retention) => rows.push(("recoverable".to_string(), retention.summary())),
        // Not knowing is its own answer, and a blank cell would read as "no".
        Err(e) => rows.push(("recoverable".to_string(), format!("unknown: {e}"))),
    }

    output.print_key_value(&rows);
    Ok(())
}

/// Every version the mount still holds, and what state each is in.
pub async fn history(output: &OutputFormat) -> Result<()> {
    let client = VaultClient::new().await?;
    let location = KeyManager::with_client(client.clone())?
        .key_location()
        .await?;
    let target = require_versions(&location, "history")?;

    kv::metadata_get(&client, &target, output).await
}

/// Write a prior version back as the current one, then say how much of the
/// local store that actually made readable.
///
/// The count is the answer, not a formality. A store can hold artifacts sealed
/// under different keys and by different clusters at once, so checking one
/// artifact reports whichever verdict that artifact happened to carry.
pub async fn restore(version: u64) -> Result<()> {
    let client = VaultClient::new().await?;
    let location = KeyManager::with_client(client.clone())?
        .key_location()
        .await?;
    let target = require_versions(&location, "restore")?;

    let before = readable_count().await?;
    kv::rollback(&client, &target, version).await?;
    let (readable, unreadable) = LocalStorage::new().await?.scan().await?.into_parts();

    let total = readable.len() + unreadable.len();
    if total == 0 {
        eprintln!(
            "Restored version {version}. Nothing in the local store to verify it against, so \
             whether it is the right key is untested here."
        );
        return Ok(());
    }

    if unreadable.is_empty() {
        eprintln!("Restored version {version}. All {total} artifacts decrypt.");
        return Ok(());
    }

    // A partial recovery is a success and has to read as one: taken for a
    // failure, the next move is to roll back further and burn the version that
    // was working.
    eprintln!(
        "Restored version {version}. {} of {total} artifacts decrypt, up from {before}.",
        readable.len()
    );
    if readable.len() == before {
        eprintln!(
            "That is no more than before, so version {version} is probably not the one these \
             were sealed with."
        );
    }
    eprintln!("\nStill unreadable:");
    for failure in &unreadable {
        eprintln!("  {}", failure.describe());
    }
    eprintln!(
        "\n`{PROGRAM_NAME} storage show <name>` gives the reason for each; an artifact sealed by \
         another cluster needs that cluster, not another version."
    );

    Ok(())
}

/// Say where a key about to be minted should go.
///
/// Only where the store has not already committed to a mount: re-pointing it
/// is what `key use` is for, and doing it here would mint a second key while
/// looking like initialisation.
pub fn choose_mount(mount: &str) -> Result<()> {
    let mount = mount.trim_end_matches('/');
    match key_mount::recorded()? {
        Some(recorded) if recorded.mount != mount => Err(VaultCliError::InvalidInput(format!(
            "this store's key is already recorded on '{}'. Initialising on '{mount}' would mint a \
             second key and leave everything already stored sealed under the first.\n\n\
             If the key really is on '{mount}' now:\n  {PROGRAM_NAME} session key use {mount}",
            recorded.mount
        ))),
        // Recording the same mount twice is what it already says.
        Some(_) => Ok(()),
        None => key_mount::record(mount),
    }
}

/// Adopt a mount as the one holding this store's key.
///
/// Deliberately does not move or mint anything: it records what the operator
/// asserts is already true. Whether a key is actually there is reported rather
/// than enforced — the mount may be about to receive one.
pub async fn use_mount(mount: &str) -> Result<()> {
    let mount = mount.trim_end_matches('/');
    let client = VaultClient::new().await?;

    let previous = key_mount::recorded()?;
    key_mount::record(mount)?;

    if let Some(previous) = previous {
        if previous.mount != mount {
            eprintln!(
                "This store's key was recorded on '{}' and is now recorded on '{mount}'. \
                 Artifacts sealed under the key on '{}' stay unreadable unless that same key is \
                 the one here.",
                previous.mount, previous.mount
            );
        }
    }

    // Reported, not enforced: an operator pointing at a mount before putting a
    // key on it is doing something reasonable, and being told is enough.
    let location = KeyManager::with_client(client.clone())?
        .key_location()
        .await?;
    match client.get(&location.data_path()).await {
        Ok(_) => eprintln!("A vault-rs key is on '{mount}'."),
        Err(e) if e.is_not_found() => eprintln!(
            "No vault-rs key is on '{mount}' yet. `{PROGRAM_NAME} session init-encryption` puts \
             one there; until then nothing in the local store can be read."
        ),
        Err(e) => eprintln!("Could not check whether a key is on '{mount}': {e}"),
    }

    Ok(())
}

/// How much of the store reads right now, for the comparison afterwards. A
/// store that cannot be walked at all is an error, not a count of zero.
async fn readable_count() -> Result<usize> {
    let (readable, _) = LocalStorage::new().await?.scan().await?.into_parts();
    Ok(readable.len())
}

/// The key's secret, refused where the mount has no versions to act on. That
/// mount is exactly where an operator most needs to be told, since it is the
/// one where replacing the key could not have been undone.
fn require_versions(location: &KeyLocation, verb: &str) -> Result<Target> {
    match location.versioned {
        true => Ok(Target::known(&location.mount, location.key(), true)),
        false => Err(VaultCliError::InvalidInput(format!(
            "'{}' keeps no version history, so there is nothing for `session key {verb}` to read. \
             A key replaced on this mount could not have been recovered.",
            location.mount
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flat() -> KeyLocation {
        KeyLocation {
            mount: "flat".to_string(),
            versioned: false,
        }
    }

    /// The mount with no history is the one where an operator most needs the
    /// truth, since it is the one where replacing the key could not have been
    /// undone. An empty version list would read as "none retained", which is
    /// the question being asked and the opposite of the answer.
    #[test]
    fn a_mount_without_history_is_refused_by_name() {
        for verb in ["history", "restore"] {
            let err = require_versions(&flat(), verb)
                .expect_err("no versions to act on")
                .to_string();
            assert!(err.contains("no version history"), "{err}");
            assert!(err.contains(verb), "{err}");
            assert!(err.contains("could not have been recovered"), "{err}");
        }
    }

    #[test]
    fn a_versioned_mount_addresses_the_key_in_it() {
        let location = KeyLocation {
            mount: "secret".to_string(),
            versioned: true,
        };
        let target = require_versions(&location, "restore").expect("versioned");
        assert_eq!(target.data(), "secret/data/vault-rs/encryption-key");
    }
}
