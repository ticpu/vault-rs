use crate::storage::local::{EntryTarget, KeyMaterial, LocalStorage, StoredEntry};
use crate::utils::errors::{Result, VaultCliError};
use crate::utils::output::OutputFormat;
use crate::utils::PROGRAM_NAME;
use std::fmt::Write as _;

pub struct ShowRequest<'a> {
    pub cn: &'a str,
    pub pki_mount: Option<&'a str>,
    pub serial: Option<&'a str>,
    pub allow_partial: bool,
}

pub struct RemoveRequest<'a> {
    pub cn: &'a str,
    pub pki_mount: Option<&'a str>,
    pub serial: Option<&'a str>,
    pub destroy_my_private_key: bool,
    pub destroy_my_unreadable_artifact: bool,
}

/// Report one stored artifact.
///
/// An artifact that will not decrypt still reports: this is the first thing
/// run after a listing names one, so failing here fails on exactly the entry
/// the operator was sent to look at.
pub async fn show(
    storage: &LocalStorage,
    request: ShowRequest<'_>,
    output: &OutputFormat,
) -> Result<()> {
    let entry = storage
        .resolve_entry(&EntryTarget {
            cn: request.cn,
            pki_mount: request.pki_mount,
            serial: request.serial,
        })
        .await?;

    let why = match entry.record {
        Ok(ref record) => {
            return match output.json {
                true => output.print_json(record),
                false => {
                    output.print_key_value(&record_pairs(&entry, record));
                    Ok(())
                }
            }
        }
        Err(ref why) => why,
    };

    // Everything knowable without the key, which is all that is left.
    let pairs = unreadable_pairs(&entry)?;
    match output.json {
        true => output.print_json(
            &pairs
                .iter()
                .cloned()
                .collect::<std::collections::BTreeMap<String, String>>(),
        )?,
        false => output.print_key_value(&pairs),
    }

    eprintln!("\n{}", storage.diagnose_unreadable(&entry, why).await);

    match request.allow_partial {
        true => Ok(()),
        false => Err(VaultCliError::IncompleteRead(format!(
            "'{}' did not decrypt, so what is printed above is not the record. Pass \
             --allow-partial to accept it.",
            entry.cn
        ))),
    }
}

fn record_pairs(
    entry: &StoredEntry,
    record: &crate::storage::CertificateStorage,
) -> Vec<(String, String)> {
    let mut pairs = vec![
        ("pki_mount".to_string(), record.pki_mount.clone()),
        ("cn".to_string(), record.meta.cn.clone()),
        ("serial".to_string(), record.meta.serial.clone()),
        ("role".to_string(), record.meta.role.clone()),
        ("crypto".to_string(), record.meta.crypto.clone()),
        (
            "not_after".to_string(),
            record.meta.expires.format("%Y-%m-%d %H:%M:%S").to_string(),
        ),
        ("sans".to_string(), record.meta.sans.join(",")),
        ("stored".to_string(), record.created.to_rfc3339()),
        ("path".to_string(), record.storage_path.clone()),
    ];
    pairs.push((
        "private_key".to_string(),
        match entry.key_material() {
            Ok(KeyMaterial::Present) => "present".to_string(),
            Ok(KeyMaterial::None) => "none".to_string(),
            Ok(KeyMaterial::Malformed) => "malformed".to_string(),
            Err(e) => format!("unreadable: {e}"),
        },
    ));
    pairs.extend(sealed_by_pairs(entry));
    pairs
}

fn unreadable_pairs(entry: &StoredEntry) -> Result<Vec<(String, String)>> {
    let mut pairs = vec![
        ("pki_mount".to_string(), entry.pki_mount.clone()),
        ("cn".to_string(), entry.cn.clone()),
        ("serial".to_string(), entry.serial.clone()),
        ("readable".to_string(), "no".to_string()),
        ("path".to_string(), entry.path.to_string_lossy().to_string()),
    ];
    pairs.extend(sealed_by_pairs(entry));
    for (name, size) in entry.files()? {
        pairs.push((format!("file.{name}"), size.to_string()));
    }
    Ok(pairs)
}

fn sealed_by_pairs(entry: &StoredEntry) -> Vec<(String, String)> {
    match entry.sealed_by() {
        Some(sealed_by) => vec![
            ("sealed_by.cluster_id".to_string(), sealed_by.cluster_id),
            ("sealed_by.address".to_string(), sealed_by.address),
        ],
        None => vec![("sealed_by".to_string(), "unrecorded".to_string())],
    }
}

/// Delete one stored artifact.
///
/// Consent is graded to the loss: an option naming what is destroyed where
/// something unrecoverable goes, and where only the provenance the PKI never
/// recorded goes, a line saying so and no gate at all.
pub async fn remove(storage: &LocalStorage, request: RemoveRequest<'_>) -> Result<()> {
    let entry = storage
        .resolve_entry(&EntryTarget {
            cn: request.cn,
            pki_mount: request.pki_mount,
            serial: request.serial,
        })
        .await?;

    let key = entry.key_material()?;
    let unreadable = entry.record.is_err();
    let malformed = key == KeyMaterial::Malformed;

    let mut missing: Vec<&str> = Vec::new();
    if key == KeyMaterial::Present && !request.destroy_my_private_key {
        missing.push("--destroy-my-private-key");
    }
    if (unreadable || malformed) && !request.destroy_my_unreadable_artifact {
        missing.push("--destroy-my-unreadable-artifact");
    }

    if !missing.is_empty() {
        return Err(VaultCliError::InvalidInput(
            refusal(storage, &entry, &key, &missing).await,
        ));
    }

    // Nothing unrecoverable is at stake here, so nothing gated it. The store
    // is still the only place the issuing role was ever recorded — the PKI has
    // none — so it is named on the way out. Every other case reached this
    // point through an option that already named the loss.
    if let (KeyMaterial::None, Ok(record)) = (&key, &entry.record) {
        eprintln!(
            "Removing {}/{}/{}: the certificate stays in the PKI, but the issuing role ('{}'), \
             the time it was stored and its recorded status exist nowhere else.",
            entry.pki_mount, entry.cn, entry.serial, record.meta.role
        );
    }

    storage.remove_entry(&entry.path)?;
    eprintln!("Removed {}", entry.path.display());
    Ok(())
}

async fn refusal(
    storage: &LocalStorage,
    entry: &StoredEntry,
    key: &KeyMaterial,
    missing: &[&str],
) -> String {
    let mut report = format!(
        "Refusing to remove {}/{}/{} at {}.\n\n",
        entry.pki_mount,
        entry.cn,
        entry.serial,
        entry.path.display()
    );

    if *key == KeyMaterial::Present {
        report.push_str(
            "It holds a private key. Vault returned that key once and kept no copy, so removing \
             this artifact destroys it.\n\n",
        );
    }
    if let Err(ref why) = entry.record {
        // discard-ok: writing into a String is infallible
        let _ = write!(
            report,
            "It does not decrypt, so what it holds cannot be named and may still be \
             recoverable.\n\n{}\n\n",
            storage.diagnose_unreadable(entry, why).await
        );
    } else if *key == KeyMaterial::Malformed {
        report.push_str(
            "Its key file is shorter than a nonce and a tag, so it holds nothing that could \
             decrypt.\n\n",
        );
    }

    // discard-ok: writing into a String is infallible
    let _ = write!(
        report,
        "To go ahead, say what is being destroyed:\n  {PROGRAM_NAME} storage remove \
         --pki-mount {} --serial {} {} {}",
        entry.pki_mount,
        entry.serial,
        entry.cn,
        missing.join(" ")
    );
    report
}
