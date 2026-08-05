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
        (
            "role".to_string(),
            record.meta.role.clone().unwrap_or_default(),
        ),
        (
            "crypto".to_string(),
            record.meta.crypto.clone().unwrap_or_default(),
        ),
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
        // Named only when there is one: an artifact imported without a role
        // has none, and printing an empty name reads as a role called "".
        let role = match record.meta.role {
            Some(ref role) => format!("the issuing role ('{role}'), "),
            None => String::new(),
        };
        eprintln!(
            "Removing {}/{}/{}: the certificate stays in the PKI, but {role}the time it was \
             stored and its recorded status exist nowhere else.",
            entry.pki_mount, entry.cn, entry.serial
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::test_support::*;
    use std::fs;

    fn request<'a>(cn: &'a str, serial: &'a str) -> RemoveRequest<'a> {
        RemoveRequest {
            cn,
            pki_mount: None,
            serial: Some(serial),
            destroy_my_private_key: false,
            destroy_my_unreadable_artifact: false,
        }
    }

    /// Give the entry a key file long enough to read as key-bearing. Its
    /// contents do not matter: the grading is on ciphertext length.
    async fn give_it_a_key(storage: &LocalStorage, root: &std::path::Path, serial: &str) {
        let payload = storage
            .encrypt_for_test(b"a key", "cert-pki-leaf-client")
            .await;
        fs::write(
            root.join("pki")
                .join("leaf-client")
                .join(serial)
                .join("private_key.pem.enc"),
            payload,
        )
        .expect("writing a key file");
    }

    /// Nothing unrecoverable is at stake, so nothing gates it — the PKI still
    /// holds the certificate.
    #[tokio::test]
    async fn a_certificate_only_artifact_is_removed_without_an_option() {
        let root = scratch("remove-certonly");
        let server = stub_vault(CLUSTER, &"ab".repeat(32)).await;
        let storage = store(&server, &root);
        write_entry(&storage, "leaf-client", "aa01", "").await;

        remove(&storage, request("leaf-client", "aa01"))
            .await
            .expect("removing");
        assert!(!root.join("pki").join("leaf-client").join("aa01").exists());
        // The emptied CN and mount directories go with it, or the walk keeps
        // descending into shells.
        assert!(!root.join("pki").exists());
    }

    #[tokio::test]
    async fn a_key_bearing_artifact_needs_the_option_that_names_the_key() {
        let root = scratch("remove-keyed");
        let server = stub_vault(CLUSTER, &"ab".repeat(32)).await;
        let storage = store(&server, &root);
        write_entry(&storage, "leaf-client", "aa01", "").await;
        give_it_a_key(&storage, &root, "aa01").await;

        let refused = remove(&storage, request("leaf-client", "aa01"))
            .await
            .unwrap_err()
            .to_string();
        assert!(refused.contains("--destroy-my-private-key"), "{refused}");
        assert!(
            !refused.contains("--destroy-my-unreadable-artifact"),
            "a readable artifact must not demand the unreadable option: {refused}"
        );
        assert!(
            root.join("pki").join("leaf-client").join("aa01").exists(),
            "a refusal must destroy nothing"
        );

        remove(
            &storage,
            RemoveRequest {
                destroy_my_private_key: true,
                ..request("leaf-client", "aa01")
            },
        )
        .await
        .expect("removing with the option");
        assert!(!root.join("pki").join("leaf-client").join("aa01").exists());
    }

    /// Both hazards are real, so both options are required: gating this behind
    /// the unreadable one alone would destroy a private key without saying so.
    #[tokio::test]
    async fn an_unreadable_key_bearing_artifact_needs_both_options() {
        let root = scratch("remove-both");
        let sealing = stub_vault("sealing-cluster", &"ab".repeat(32)).await;
        let sealed = store(&sealing, &root);
        write_entry(&sealed, "leaf-client", "aa01", "").await;
        give_it_a_key(&sealed, &root, "aa01").await;

        // A different cluster with a different master key: intact, unreadable.
        let other = stub_vault("other-cluster", &"cd".repeat(32)).await;
        let storage = store(&other, &root);

        let refused = remove(&storage, request("leaf-client", "aa01"))
            .await
            .unwrap_err()
            .to_string();
        assert!(refused.contains("--destroy-my-private-key"), "{refused}");
        assert!(
            refused.contains("--destroy-my-unreadable-artifact"),
            "{refused}"
        );
        // The refusal has to carry the way back, not just the way to delete.
        assert!(refused.contains("sealing-cluster"), "{refused}");
        assert!(refused.contains("kv rollback"), "{refused}");

        // One option is not enough while two hazards apply.
        let still_refused = remove(
            &storage,
            RemoveRequest {
                destroy_my_unreadable_artifact: true,
                ..request("leaf-client", "aa01")
            },
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            still_refused.contains("--destroy-my-private-key"),
            "{still_refused}"
        );
        assert!(root.join("pki").join("leaf-client").join("aa01").exists());

        remove(
            &storage,
            RemoveRequest {
                destroy_my_private_key: true,
                destroy_my_unreadable_artifact: true,
                ..request("leaf-client", "aa01")
            },
        )
        .await
        .expect("removing with both options");
        assert!(!root.join("pki").join("leaf-client").join("aa01").exists());
    }

    /// `show` is the first thing run after a listing names an artifact, so it
    /// reports one that will not decrypt instead of failing on it.
    #[tokio::test]
    async fn show_reports_an_unreadable_artifact_rather_than_failing() {
        let root = scratch("show-unreadable");
        let sealing = stub_vault("sealing-cluster", &"ab".repeat(32)).await;
        write_entry(&store(&sealing, &root), "leaf-client", "aa01", "").await;

        let other = stub_vault("other-cluster", &"cd".repeat(32)).await;
        let storage = store(&other, &root);
        let request = |allow_partial| ShowRequest {
            cn: "leaf-client",
            pki_mount: None,
            serial: Some("aa01"),
            allow_partial,
        };
        let output = OutputFormat::new(true, false);

        let refused = show(&storage, request(false), &output)
            .await
            .unwrap_err()
            .to_string();
        assert!(refused.contains("--allow-partial"), "{refused}");

        show(&storage, request(true), &output)
            .await
            .expect("reporting what needs no key");
    }
}
