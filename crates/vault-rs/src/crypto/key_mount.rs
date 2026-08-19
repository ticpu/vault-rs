//! Which mount holds this store's master key, recorded beside the store.
//!
//! Discovery answers "which mount looks like the one" — a question whose
//! answer changes when somebody enables an unrelated engine. The store is
//! sealed under one key, so the mount is a property of the store and gets
//! written down once rather than re-derived per run: a re-derivation that came
//! out differently would find no key there, mint a second one, and leave every
//! artifact sealed under the first unreadable while reporting nothing.

use crate::utils::errors::{Result, VaultCliError};
use crate::utils::paths::VaultCliPaths;
use crate::utils::PROGRAM_NAME;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// What the store remembers about where its key lives.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecordedMount {
    pub mount: String,
}

/// Where the record lives for a store rooted at the default location. Tests
/// pass their own scratch root instead, so nothing here reaches a real store.
pub fn default_record_path() -> Result<PathBuf> {
    Ok(VaultCliPaths::data_dir()?.join("key-mount.yaml"))
}

pub fn recorded() -> Result<Option<RecordedMount>> {
    recorded_at(&default_record_path()?)
}

pub fn record(mount: &str) -> Result<()> {
    record_at(&default_record_path()?, mount)
}

/// The mount this store was sealed against, if it has one yet.
///
/// An unreadable record is an error rather than an absence: read as absent it
/// would send the caller to discovery, which is the path this record exists to
/// take away.
pub fn recorded_at(path: &std::path::Path) -> Result<Option<RecordedMount>> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(VaultCliError::Storage(format!(
                "cannot read '{}' ({e}), so which mount holds this store's key is unknown",
                path.display()
            )))
        }
    };

    serde_yaml_ng::from_str(&text).map(Some).map_err(|e| {
        VaultCliError::Storage(format!(
            "'{}' does not parse ({e}); it records which mount holds this store's key",
            path.display()
        ))
    })
}

/// Write the mount down. Called where the choice was made deliberately — by
/// naming it, or by there being only one.
pub fn record_at(path: &std::path::Path, mount: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let recorded = RecordedMount {
        mount: mount.trim_end_matches('/').to_string(),
    };
    fs::write(path, serde_yaml_ng::to_string(&recorded)?)?;
    crate::utils::set_secure_file_permissions(path)?;
    tracing::info!("This store's master key is on mount '{mount}'");
    Ok(())
}

/// A mount that could hold the key, and whether one is already there.
pub struct Candidate {
    pub mount: String,
    pub holds_a_key: bool,
}

/// Refuse to guess between mounts, naming what is there.
///
/// Which of several engines a store belongs to is not something to infer: the
/// wrong answer is not an error the operator sees, it is a second key and a
/// store that stops opening.
pub fn ambiguous(candidates: &[Candidate]) -> VaultCliError {
    let mut lines = vec![format!(
        "More than one KV mount could hold this store's master key, and picking one is not \
         something to guess at — the wrong choice mints a second key and leaves everything \
         already stored unreadable.\n\nCandidates:"
    )];

    for candidate in candidates {
        let note = match candidate.holds_a_key {
            true => "  <- already holds a vault-rs key",
            false => "",
        };
        lines.push(format!("  {}{note}", candidate.mount));
    }

    let existing: Vec<&str> = candidates
        .iter()
        .filter(|c| c.holds_a_key)
        .map(|c| c.mount.as_str())
        .collect();

    lines.push(String::new());
    match existing.as_slice() {
        // Adopting an existing key is the likely intent, and minting over it
        // would be the destructive one.
        [] => lines.push(format!(
            "None of them holds one yet. Choose where it goes:\n  \
             {PROGRAM_NAME} session init-encryption --mount <MOUNT>"
        )),
        mounts => lines.push(format!(
            "To use the key already on {}:\n  {PROGRAM_NAME} session key use {}",
            mounts.join(" or "),
            mounts[0]
        )),
    }

    VaultCliError::Storage(lines.join("\n"))
}

/// Refuse when the recorded mount is not there any more.
///
/// Named for what it is rather than reported as an absent key: the store is
/// still sealed under whatever is on that mount, so anything that treats this
/// as "no key yet" writes a new one and completes the loss.
pub fn recorded_mount_missing(recorded: &str, candidates: &[Candidate]) -> VaultCliError {
    let mut lines = vec![format!(
        "This store's master key was recorded on mount '{recorded}', which is not a KV mount on \
         the Vault being addressed.\n\n\
         Everything in the local store is sealed under the key that was there. Reaching a \
         different Vault, or that mount having been moved or removed, both look like this."
    )];

    let holders: Vec<&str> = candidates
        .iter()
        .filter(|c| c.holds_a_key)
        .map(|c| c.mount.as_str())
        .collect();

    if !holders.is_empty() {
        lines.push(format!(
            "\nA vault-rs key is on: {}\nIf the mount moved and that is the same key, adopt it \
             explicitly:\n  {PROGRAM_NAME} session key use {}",
            holders.join(", "),
            holders[0]
        ));
    } else {
        lines.push(format!(
            "\nNo mount here holds a vault-rs key. Point at the Vault that has it, or adopt a \
             different mount explicitly with `{PROGRAM_NAME} session key use <MOUNT>` — which \
             does not move the key, and leaves artifacts sealed under the old one unreadable."
        ));
    }

    VaultCliError::Storage(lines.join("\n"))
}
