use crate::cert::CertificateParser;
use crate::storage::local::{CertificateData, EntryTarget, KeyMaterial, LocalStorage, StoredEntry};
use crate::storage::metadata::{normalize_serial, StoredIdentity, StoredMetadata};
use crate::storage::provenance::Provenance;
use crate::utils::errors::{Result, VaultCliError};
use crate::utils::output::OutputFormat;
use crate::utils::pem::{parse_certificate_chain, pem_blocks};
use crate::utils::PROGRAM_NAME;
use chrono::Utc;
use std::fmt::Write as _;
use std::fs;

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
                true => Ok(output.print_json(record)?),
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

    // Ungated: nothing unrecoverable is at stake. The issuing role is named on
    // the way out anyway, since the store is the only place it was recorded.
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

pub struct ImportRequest<'a> {
    pub file: &'a str,
    pub pki_mount: Option<&'a str>,
    pub role: Option<&'a str>,
}

/// Where a field of an imported record came from.
///
/// Reported rather than assumed: a field the invocation supplied and one the
/// artifact carried are different facts about the same record, and an
/// operator who believes the file set the role should find out here rather
/// than from a listing months later.
enum Source {
    Invocation,
    Artifact,
    Certificate,
    Unrecorded,
}

impl Source {
    fn describe(&self) -> &'static str {
        match self {
            Self::Invocation => "from the command line",
            Self::Artifact => "from the file's provenance",
            Self::Certificate => "read from the certificate",
            Self::Unrecorded => "not recorded",
        }
    }
}

/// File a PEM bundle into the local store.
///
/// The artifact is sealed by the cluster now being addressed, so `sealed-by`
/// describes this store and not wherever the file came from. Everything the
/// certificate answers is taken from the certificate; the provenance block
/// supplies only what it cannot, and never overrides it.
pub async fn import(storage: &LocalStorage, request: ImportRequest<'_>) -> Result<()> {
    let contents = fs::read_to_string(request.file)
        .map_err(|e| VaultCliError::Storage(format!("cannot read '{}': {e}", request.file)))?;
    let blocks = pem_blocks(&contents)?;
    let provenance = Provenance::from_pem_blocks(&blocks)?;

    let certificates = parse_certificate_chain(&contents)?;
    let (leaf, chain) = certificates.split_first().ok_or_else(|| {
        VaultCliError::InvalidInput(format!("'{}' holds no certificate", request.file))
    })?;

    let key = blocks
        .iter()
        .find(|b| b.label.ends_with("PRIVATE KEY"))
        .map(|b| b.text.clone())
        .unwrap_or_default();

    // The mount is a Vault path, not a property of what it issued, so nothing
    // in the file can stand in for it.
    let (pki_mount, mount_source) = match (request.pki_mount, provenance.as_ref()) {
        (Some(mount), _) => (mount.to_string(), Source::Invocation),
        (None, Some(p)) => (p.pki_mount.clone(), Source::Artifact),
        (None, None) => {
            return Err(VaultCliError::InvalidInput(format!(
                "'{}' carries no provenance, so the PKI mount has to be named with --pki-mount. \
                 No certificate records which mount issued it.",
                request.file
            )))
        }
    };

    let (role, role_source) = match (
        request.role,
        provenance.as_ref().and_then(|p| p.role.clone()),
    ) {
        (Some(role), _) => (Some(role.to_string()), Source::Invocation),
        (None, Some(role)) => (Some(role), Source::Artifact),
        (None, None) => (None, Source::Unrecorded),
    };

    let issued = CertificateParser::parse_pem(leaf.pem_data(), &pki_mount)?;
    let serial = normalize_serial(&issued.serial.as_colon_hex());

    let target = EntryTarget {
        cn: &issued.cn,
        pki_mount: Some(&pki_mount),
        serial: Some(&serial),
    };
    // Only "nothing matches" means the slot is free. A store that could not be
    // read is not an empty one, and treating it as empty writes over whatever
    // was unreadable.
    match storage.resolve_entry(&target).await {
        Ok(existing) => {
            return Err(VaultCliError::InvalidInput(format!(
                "{}/{}/{} is already stored at {}. Importing over it could destroy a private key \
                 that exists nowhere else, so removing it is its own decision:\n  \
                 {PROGRAM_NAME} storage show {} --serial {}\n  \
                 {PROGRAM_NAME} storage remove {} --serial {}",
                existing.pki_mount,
                existing.cn,
                existing.serial,
                existing.path.display(),
                existing.cn,
                existing.serial,
                existing.cn,
                existing.serial,
            )))
        }
        Err(VaultCliError::CertNotFound(_)) => {}
        Err(e) => return Err(e),
    }

    let chain_pem: String = chain.iter().map(|c| c.pem_data()).collect();
    let crypto = provenance.as_ref().and_then(|p| p.crypto.clone());
    let status = provenance
        .as_ref()
        .map(|p| p.status.clone())
        .unwrap_or_default();
    let created = provenance
        .as_ref()
        .map(|p| p.created)
        .unwrap_or_else(Utc::now);

    storage
        .store_certificate(CertificateData {
            pki_mount: &pki_mount,
            cn: &issued.cn,
            serial: &serial,
            certificate_pem: leaf.pem_data(),
            private_key_pem: &key,
            ca_chain_pem: &chain_pem,
            metadata: StoredMetadata {
                crypto: crypto.clone(),
                created,
                file_info: Default::default(),
                meta: StoredIdentity {
                    role: role.clone(),
                    status,
                },
            },
        })
        .await?;

    let crypto_source = match (provenance.as_ref().and_then(|p| p.crypto.as_ref()), &crypto) {
        (Some(_), _) => Source::Artifact,
        _ => Source::Unrecorded,
    };
    eprintln!(
        "Imported {pki_mount}/{}/{serial}\n  \
         mount     {pki_mount} ({})\n  \
         common name {} ({})\n  \
         role      {} ({})\n  \
         crypto    {} ({})\n  \
         key       {}",
        issued.cn,
        mount_source.describe(),
        issued.cn,
        Source::Certificate.describe(),
        role.as_deref().unwrap_or("-"),
        role_source.describe(),
        crypto.as_deref().unwrap_or("-"),
        crypto_source.describe(),
        match key.is_empty() {
            true => "none in the file",
            false => "stored",
        },
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::provenance::Provenance;
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
        assert!(refused.contains("session key restore"), "{refused}");

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

    /// A file with everything the store cannot re-derive, as `cert export
    /// --with-provenance` writes it.
    fn exported(root: &std::path::Path, name: &str, provenance: Option<Provenance>) -> String {
        let path = root.join(name);
        let mut contents = crate::storage::test_support::leaf_pem();
        if let Some(provenance) = provenance {
            contents.push_str(&provenance.to_pem_block().expect("encodes"));
        }
        fs::create_dir_all(root).expect("scratch");
        fs::write(&path, contents).expect("writing the export");
        path.to_string_lossy().to_string()
    }

    fn provenance() -> Provenance {
        Provenance::new(
            "pki".to_string(),
            Some("client".to_string()),
            Some("ec".to_string()),
            crate::storage::metadata::CertStatus::Active,
            "2020-01-02T03:04:05Z".parse().expect("timestamp"),
        )
    }

    /// The round trip the feature exists for: the role and mount survive,
    /// and so does the time the artifact was first stored.
    #[tokio::test]
    async fn provenance_restores_what_no_certificate_records() {
        let root = scratch("import-provenance");
        let server = stub_vault(CLUSTER, &"ab".repeat(32)).await;
        let storage = store(&server, &root.join("store"));
        let file = exported(&root, "exported.pem", Some(provenance()));

        import(
            &storage,
            ImportRequest {
                file: &file,
                pki_mount: None,
                role: None,
            },
        )
        .await
        .expect("importing");

        let stored = storage.scan().await.expect("scan").resolve(false).unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].pki_mount, "pki");
        assert_eq!(stored[0].meta.role.as_deref(), Some("client"));
        assert_eq!(stored[0].meta.crypto.as_deref(), Some("ec"));
        assert_eq!(stored[0].created, provenance().created);
        // Sealed by the cluster now being addressed, not by wherever the file
        // came from.
        assert_eq!(
            stored[0].sealed_by.as_ref().map(|s| s.cluster_id.as_str()),
            Some(CLUSTER)
        );
    }

    /// Nothing supplies the role, so nothing records one. The mount has to
    /// come from the invocation, since no certificate names one.
    #[tokio::test]
    async fn without_provenance_the_unknown_fields_are_absent() {
        let root = scratch("import-bare");
        let server = stub_vault(CLUSTER, &"ab".repeat(32)).await;
        let storage = store(&server, &root.join("store"));
        let file = exported(&root, "bare.pem", None);

        let refused = import(
            &storage,
            ImportRequest {
                file: &file,
                pki_mount: None,
                role: None,
            },
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(refused.contains("--pki-mount"), "{refused}");

        import(
            &storage,
            ImportRequest {
                file: &file,
                pki_mount: Some("pki"),
                role: None,
            },
        )
        .await
        .expect("importing with the mount named");

        let stored = storage.scan().await.expect("scan").resolve(false).unwrap();
        assert_eq!(stored[0].meta.role, None);
        assert_eq!(stored[0].meta.crypto, None);
    }

    /// The invocation is the more specific statement, and the operator hears
    /// which one won.
    #[tokio::test]
    async fn the_command_line_overrides_the_block() {
        let root = scratch("import-override");
        let server = stub_vault(CLUSTER, &"ab".repeat(32)).await;
        let storage = store(&server, &root.join("store"));
        let file = exported(&root, "exported.pem", Some(provenance()));

        import(
            &storage,
            ImportRequest {
                file: &file,
                pki_mount: Some("other-mount"),
                role: Some("server"),
            },
        )
        .await
        .expect("importing");

        let stored = storage.scan().await.expect("scan").resolve(false).unwrap();
        assert_eq!(stored[0].pki_mount, "other-mount");
        assert_eq!(stored[0].meta.role.as_deref(), Some("server"));
    }

    /// An overwrite could destroy a private key that exists nowhere else, and
    /// the option consenting to that lives on remove.
    #[tokio::test]
    async fn importing_over_an_existing_entry_is_refused() {
        let root = scratch("import-collision");
        let server = stub_vault(CLUSTER, &"ab".repeat(32)).await;
        let storage = store(&server, &root.join("store"));
        let file = exported(&root, "exported.pem", Some(provenance()));
        let request = || ImportRequest {
            file: &file,
            pki_mount: None,
            role: None,
        };

        import(&storage, request()).await.expect("first import");
        let refused = import(&storage, request()).await.unwrap_err().to_string();

        assert!(refused.contains("already stored"), "{refused}");
        assert!(refused.contains("storage remove"), "{refused}");
        assert_eq!(
            storage
                .scan()
                .await
                .expect("scan")
                .resolve(false)
                .unwrap()
                .len(),
            1,
            "the refusal leaves exactly what was there"
        );
    }

    /// A file with no certificate is not an artifact, whatever else it holds.
    #[tokio::test]
    async fn a_file_without_a_certificate_is_refused() {
        let root = scratch("import-empty");
        let server = stub_vault(CLUSTER, &"ab".repeat(32)).await;
        let storage = store(&server, &root.join("store"));
        fs::create_dir_all(&root).expect("scratch");
        let file = root.join("only-provenance.pem");
        fs::write(&file, provenance().to_pem_block().expect("encodes")).expect("writing");

        let refused = import(
            &storage,
            ImportRequest {
                file: &file.to_string_lossy(),
                pki_mount: None,
                role: None,
            },
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(refused.contains("no certificate"), "{refused}");
    }
}
