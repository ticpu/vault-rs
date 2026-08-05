use crate::crypto::encryption::{EncryptionManager, EMPTY_PAYLOAD_LEN};
use crate::storage::metadata::{
    normalize_serial, CertificateStorage, FileInfo, SealedBy, StorageCertificateMetadata,
    StoredMetadata,
};
use crate::utils::errors::{Result, VaultCliError};
use crate::utils::partial::{Incomplete, Partial};
use crate::utils::paths::VaultCliPaths;
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

/// Names the Vault that sealed the artifacts beside it, in the clear.
pub const SEALED_BY_FILE: &str = "sealed-by";

pub struct CertificateData<'a> {
    pub pki_mount: &'a str,
    pub cn: &'a str,
    /// Names the artifact's directory, so it is carried in its own right
    /// rather than read back out of the stored metadata.
    pub serial: &'a str,
    pub certificate_pem: &'a str,
    pub private_key_pem: &'a str,
    pub ca_chain_pem: &'a str,
    pub metadata: StoredMetadata,
}

pub struct LocalStorage {
    encryption_manager: EncryptionManager,
    client: crate::vault::client::VaultClient,
}

impl LocalStorage {
    pub async fn new() -> Result<Self> {
        let client = crate::vault::client::VaultClient::new().await?;
        Ok(Self::with_client(client))
    }

    pub fn with_client(client: crate::vault::client::VaultClient) -> Self {
        Self {
            encryption_manager: EncryptionManager::with_client(client.clone()),
            client,
        }
    }

    /// The key an artifact directory's files are encrypted under.
    fn context(pki_mount: &str, cn: &str) -> String {
        format!("cert-{pki_mount}-{cn}")
    }

    /// Store certificate data encrypted locally
    pub async fn store_certificate(&self, cert_data: CertificateData<'_>) -> Result<()> {
        let cert_dir =
            VaultCliPaths::cert_storage_dir(cert_data.pki_mount, cert_data.cn, cert_data.serial)?;
        VaultCliPaths::ensure_dir_exists(&cert_dir)?;

        let context = Self::context(cert_data.pki_mount, cert_data.cn);

        let cert_file = cert_dir.join("certificate.pem.enc");
        let key_file = cert_dir.join("private_key.pem.enc");
        let ca_file = cert_dir.join("ca_chain.pem.enc");
        let metadata_file = cert_dir.join("metadata.yaml.enc");

        self.encryption_manager
            .encrypt_to_file(cert_data.certificate_pem.as_bytes(), &context, &cert_file)
            .await?;

        self.encryption_manager
            .encrypt_to_file(cert_data.ca_chain_pem.as_bytes(), &context, &ca_file)
            .await?;

        // No key, no key file: CSR signing keeps the key with the requester.
        // Writing an empty one instead would make presence meaningless, and
        // `storage remove` grades its hazard on this file.
        let has_key = !cert_data.private_key_pem.is_empty();
        if has_key {
            self.encryption_manager
                .encrypt_to_file(cert_data.private_key_pem.as_bytes(), &context, &key_file)
                .await?;
        }

        let p12_data = self.create_p12_bundle(
            cert_data.certificate_pem,
            cert_data.private_key_pem,
            cert_data.ca_chain_pem,
        )?;
        let p12_file = cert_dir.join("p12.enc");
        if let Some(ref p12_data) = p12_data {
            self.encryption_manager
                .encrypt_to_file(p12_data, &context, &p12_file)
                .await?;
        }

        self.write_sealed_by(&cert_dir).await?;

        let mut file_info = std::collections::HashMap::new();
        for name in ["certificate.pem.enc", "ca_chain.pem.enc"]
            .into_iter()
            .chain(has_key.then_some("private_key.pem.enc"))
            .chain(p12_data.is_some().then_some("p12.enc"))
        {
            let path = cert_dir.join(name);
            file_info.insert(
                name.to_string(),
                FileInfo {
                    size: fs::metadata(&path)?.len(),
                    created: chrono::Utc::now(),
                    checksum: self.calculate_file_checksum(&path)?,
                },
            );
        }

        let stored = StoredMetadata {
            file_info,
            ..cert_data.metadata
        };

        self.encryption_manager
            .encrypt_yaml_to_file(&stored, &context, &metadata_file)
            .await?;

        tracing::info!(
            "Certificate stored encrypted locally: {}",
            cert_dir.display()
        );
        Ok(())
    }

    /// Record which cluster sealed this artifact. Unreadable cluster identity
    /// records no identity rather than a guessed one, and never fails the
    /// write: the artifact is what matters, the marker is a diagnostic.
    async fn write_sealed_by(&self, cert_dir: &Path) -> Result<()> {
        let Some(cluster_id) = self.cluster_id().await else {
            tracing::warn!(
                "Vault reported no cluster identity; storing without one. An artifact that later \
                 fails to decrypt cannot be told apart from one whose master key was replaced."
            );
            return Ok(());
        };

        let sealed_by = SealedBy {
            cluster_id,
            address: self.client.vault_addr().to_string(),
        };
        let path = cert_dir.join(SEALED_BY_FILE);
        fs::write(&path, serde_yaml_ng::to_string(&sealed_by)?)?;
        crate::utils::set_secure_file_permissions(&path)?;
        Ok(())
    }

    /// Read the sealing marker. Absent means unrecorded, which is not a
    /// mismatch; unparseable is worth a warning but not a failed read.
    fn read_sealed_by(cert_dir: &Path) -> Option<SealedBy> {
        let path = cert_dir.join(SEALED_BY_FILE);
        match fs::read_to_string(&path) {
            Ok(text) => match serde_yaml_ng::from_str(&text) {
                Ok(sealed_by) => Some(sealed_by),
                Err(e) => {
                    tracing::warn!("Ignoring unreadable {}: {e}", path.display());
                    None
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => {
                tracing::warn!("Ignoring unreadable {}: {e}", path.display());
                None
            }
        }
    }

    /// Read one artifact directory into a record.
    ///
    /// The certificate is the authority for everything it can yield, so a
    /// derivation corrected in this binary applies to artifacts already on
    /// disk; the stored metadata supplies only what it cannot.
    async fn load_entry(
        &self,
        cert_dir: &Path,
        pki_mount: &str,
        cn: &str,
    ) -> Result<CertificateStorage> {
        let context = Self::context(pki_mount, cn);
        let cert_file = cert_dir.join("certificate.pem.enc");
        let metadata_file = cert_dir.join("metadata.yaml.enc");

        for required in [&cert_file, &metadata_file] {
            if !required.exists() {
                return Err(VaultCliError::Storage(format!(
                    "incomplete artifact directory: {} is missing",
                    required.display()
                )));
            }
        }

        let stored: StoredMetadata = self
            .encryption_manager
            .decrypt_yaml_from_file(&context, &metadata_file)
            .await?;

        let certificate_pem = String::from_utf8(
            self.encryption_manager
                .decrypt_from_file(&context, &cert_file)
                .await?,
        )?;
        let issued = crate::cert::CertificateParser::parse_pem(&certificate_pem, pki_mount)?;

        Ok(CertificateStorage {
            pki_mount: pki_mount.to_string(),
            crypto: stored.crypto.clone(),
            created: stored.created,
            storage_path: cert_dir.to_string_lossy().to_string(),
            sealed_by: Self::read_sealed_by(cert_dir),
            file_info: stored.file_info,
            meta: StorageCertificateMetadata {
                serial: normalize_serial(&issued.serial.as_colon_hex()),
                cn: issued.cn,
                role: stored.meta.role,
                crypto: stored.crypto,
                created: stored.created,
                expires: issued.not_after,
                status: stored.meta.status,
                sans: issued.sans,
            },
        })
    }

    /// Every artifact on disk, with whatever could not be read named rather
    /// than dropped. Failing to read the tree at all propagates: an empty
    /// listing and an unreadable one are different answers.
    pub async fn scan(&self) -> Result<Partial<CertificateStorage>> {
        let mut result = Partial::new();
        let secrets_dir = VaultCliPaths::secrets_dir()?;
        if !secrets_dir.exists() {
            return Ok(result);
        }

        // Collected during the one walk rather than by a second pass: the
        // markers that matter belong to entries that did not load, so they
        // are not reachable through the records.
        let mut seals = Vec::new();

        for mount_entry in read_subdirs(&secrets_dir)? {
            let pki_mount = mount_entry.file_name().to_string_lossy().to_string();
            for cn_entry in read_subdirs(&mount_entry.path())? {
                let cn = cn_entry.file_name().to_string_lossy().to_string();
                for serial_entry in read_subdirs(&cn_entry.path())? {
                    let serial = serial_entry.file_name().to_string_lossy().to_string();
                    if let Some(sealed_by) = Self::read_sealed_by(&serial_entry.path()) {
                        seals.push(sealed_by);
                    }
                    match self.load_entry(&serial_entry.path(), &pki_mount, &cn).await {
                        Ok(record) => result.push(record),
                        Err(e) => {
                            result.fail(Incomplete::record(format!("{pki_mount}/{cn}/{serial}"), e))
                        }
                    }
                }
            }
        }

        // `read_dir` order is arbitrary and varies between filesystems and
        // runs, so the key is total: two artifacts sharing a notAfter still
        // come back in the same order every time.
        result.items_mut().sort_by(|a, b| {
            a.meta
                .expires
                .cmp(&b.meta.expires)
                .then_with(|| a.pki_mount.cmp(&b.pki_mount))
                .then_with(|| a.meta.cn.cmp(&b.meta.cn))
                .then_with(|| a.meta.serial.cmp(&b.meta.serial))
        });
        result.set_remedy(self.unreadable_remedy(&result, &seals).await);
        Ok(result)
    }

    /// What to do about entries that would not read. Only what applies: the
    /// key-history route is already attached to each decryption failure, and
    /// offering it for an artifact that decrypted and failed to parse sends
    /// the operator to a version history with nothing in it.
    async fn unreadable_remedy(
        &self,
        scanned: &Partial<CertificateStorage>,
        seals: &[SealedBy],
    ) -> Option<String> {
        if !scanned.has_failures() {
            return None;
        }

        let mut lines = Vec::new();
        if scanned.any_failure(|e| matches!(e, VaultCliError::Encryption(_))) {
            let reached = self.cluster_id().await;
            let foreign = reached
                .as_deref()
                .and_then(|r| seals.iter().find(|s| s.cluster_id != r));
            if let Some(foreign) = foreign {
                lines.push(Self::cluster_mismatch(foreign, reached.as_deref()));
            }
        }

        lines.push(format!(
            "An artifact that cannot be recovered is removed with `{} storage remove`, which \
             names the option required for what it holds.",
            crate::utils::PROGRAM_NAME
        ));
        Some(lines.join("\n\n"))
    }

    /// Why one artifact will not read, in the order the record can support it:
    /// the cluster comparison where there is one, then the key history.
    ///
    /// The comparison leads but never replaces — the identifier names the
    /// cluster, not the material at the key's path, and a performance
    /// secondary serves the replicated KV under its own id, so a mismatch that
    /// suppressed the key route would hide the one answer that worked.
    pub async fn diagnose_unreadable(&self, entry: &StoredEntry, why: &VaultCliError) -> String {
        if !matches!(why, VaultCliError::Encryption(_)) {
            return format!("{}/{}: {why}", entry.cn, entry.serial);
        }

        let reached = self.cluster_id().await;
        let mut lines = Vec::new();
        match entry.sealed_by() {
            Some(sealed_by)
                if reached
                    .as_deref()
                    .is_some_and(|r| r != sealed_by.cluster_id) =>
            {
                lines.push(Self::cluster_mismatch(&sealed_by, reached.as_deref()));
            }
            _ => {}
        }
        lines.push(self.encryption_manager.recovery_hint().await);
        lines.join("\n\n")
    }

    fn cluster_mismatch(sealed_by: &SealedBy, reached: Option<&str>) -> String {
        format!(
            "This artifact was sealed by a different Vault cluster ({}) than the one being \
             addressed ({}). Reach that cluster again and it reads:\n  VAULT_ADDR={}\n\
             That identifies the cluster, not the key itself, so if it is not the cause the key \
             history below still applies.",
            sealed_by.cluster_id,
            reached.unwrap_or("unknown"),
            sealed_by.address
        )
    }

    async fn cluster_id(&self) -> Option<String> {
        match self.client.health().await {
            Ok(health) => health
                .get("cluster_id")
                .and_then(|v| v.as_str())
                .map(str::to_string),
            Err(e) => {
                tracing::warn!("Could not read the cluster identity to compare it: {e}");
                None
            }
        }
    }

    /// The one artifact a command-line target names, resolved by path so an
    /// entry that will not decrypt is still reachable.
    ///
    /// `show` and `remove` share this: an operator inspects an entry and then
    /// removes it, so a `show` that picked a candidate where `remove` refuses
    /// would point at one artifact and delete another.
    pub async fn resolve_entry(&self, target: &EntryTarget<'_>) -> Result<StoredEntry> {
        let mut candidates = Vec::new();
        let secrets_dir = VaultCliPaths::secrets_dir()?;
        if secrets_dir.exists() {
            for mount_entry in read_subdirs(&secrets_dir)? {
                let pki_mount = mount_entry.file_name().to_string_lossy().to_string();
                if target.pki_mount.is_some_and(|m| m != pki_mount) {
                    continue;
                }
                for cn_entry in read_subdirs(&mount_entry.path())? {
                    let cn = cn_entry.file_name().to_string_lossy().to_string();
                    if cn != target.cn {
                        continue;
                    }
                    for serial_entry in read_subdirs(&cn_entry.path())? {
                        let serial = serial_entry.file_name().to_string_lossy().to_string();
                        if target.serial.is_some_and(|s| normalize_serial(s) != serial) {
                            continue;
                        }
                        candidates.push((
                            pki_mount.clone(),
                            cn.clone(),
                            serial,
                            serial_entry.path(),
                        ));
                    }
                }
            }
        }

        // Ambiguity is an error, never a choice: an unqualified name that
        // matched nothing must fail the same way, or a mistyped one silently
        // acts on a neighbour.
        match candidates.len() {
            0 => Err(VaultCliError::CertNotFound(format!(
                "no stored artifact matches {}",
                target.describe()
            ))),
            1 => {
                let (pki_mount, cn, serial, path) = candidates.remove(0);
                let record = self.load_entry(&path, &pki_mount, &cn).await;
                Ok(StoredEntry {
                    pki_mount,
                    cn,
                    serial,
                    path,
                    record,
                })
            }
            _ => {
                let mut report = format!(
                    "more than one entry matches {}; narrow it with --pki-mount or --serial:\n",
                    target.describe()
                );
                for (pki_mount, cn, serial, _) in &candidates {
                    // discard-ok: writing into a String is infallible
                    let _ = writeln!(
                        report,
                        "  --pki-mount {pki_mount} --serial {serial}  ({cn})"
                    );
                }
                Err(VaultCliError::InvalidInput(report))
            }
        }
    }

    /// Retrieve certificate data from local storage. Without a serial, the
    /// latest by expiry wins.
    pub async fn get_certificate(
        &self,
        pki_mount: &str,
        cn: &str,
        serial: Option<&str>,
    ) -> Result<(String, String, String, StorageCertificateMetadata)> {
        let cn_dir = VaultCliPaths::cert_cn_dir(pki_mount, cn)?;
        if !cn_dir.exists() {
            return Err(VaultCliError::CertNotFound(format!(
                "Certificate not found: {pki_mount}/{cn}"
            )));
        }

        let cert_dir = match serial {
            Some(serial) => VaultCliPaths::cert_storage_dir(pki_mount, cn, serial)?,
            None => self.latest_serial_dir(&cn_dir, pki_mount, cn).await?,
        };

        let record = self.load_entry(&cert_dir, pki_mount, cn).await?;
        let context = Self::context(pki_mount, cn);

        let certificate_pem = String::from_utf8(
            self.encryption_manager
                .decrypt_from_file(&context, &cert_dir.join("certificate.pem.enc"))
                .await?,
        )?;
        let ca_chain_pem = String::from_utf8(
            self.encryption_manager
                .decrypt_from_file(&context, &cert_dir.join("ca_chain.pem.enc"))
                .await?,
        )?;
        let key_file = cert_dir.join("private_key.pem.enc");
        let private_key_pem = match key_file.exists() {
            true => String::from_utf8(
                self.encryption_manager
                    .decrypt_from_file(&context, &key_file)
                    .await?,
            )?,
            false => String::new(),
        };

        Ok((certificate_pem, private_key_pem, ca_chain_pem, record.meta))
    }

    async fn latest_serial_dir(&self, cn_dir: &Path, pki_mount: &str, cn: &str) -> Result<PathBuf> {
        let mut latest: Option<(chrono::DateTime<chrono::Utc>, PathBuf)> = None;
        for entry in read_subdirs(cn_dir)? {
            match self.load_entry(&entry.path(), pki_mount, cn).await {
                Ok(record) => {
                    if latest
                        .as_ref()
                        .is_none_or(|(e, _)| record.meta.expires > *e)
                    {
                        latest = Some((record.meta.expires, entry.path()));
                    }
                }
                Err(e) => tracing::warn!(
                    "Skipping {} while looking for the latest certificate: {e}",
                    entry.path().display()
                ),
            }
        }

        latest.map(|(_, dir)| dir).ok_or_else(|| {
            VaultCliError::CertNotFound(format!(
                "No readable certificate found for: {pki_mount}/{cn}"
            ))
        })
    }

    /// List all locally stored certificates
    pub async fn list_certificates(&self) -> Result<Partial<CertificateStorage>> {
        self.scan().await
    }

    /// Remove one artifact directory, then whatever it leaves empty behind it.
    pub fn remove_entry(&self, cert_dir: &Path) -> Result<()> {
        fs::remove_dir_all(cert_dir)?;
        tracing::info!("Removed artifact directory: {}", cert_dir.display());

        // An empty CN or mount directory is a shell the walk would still
        // descend into and report nothing for.
        for parent in cert_dir.ancestors().skip(1).take(2) {
            match fs::read_dir(parent).map(|mut entries| entries.next().is_none()) {
                Ok(true) => {
                    if let Err(e) = fs::remove_dir(parent) {
                        tracing::warn!("Could not remove empty {}: {e}", parent.display());
                    }
                }
                Ok(false) => break,
                Err(e) => {
                    tracing::warn!("Could not inspect {}: {e}", parent.display());
                    break;
                }
            }
        }
        Ok(())
    }

    /// Build a real PKCS12 bundle via `utils::create_p12_file` (the same path
    /// `cert export --format p12` uses), or `None` when there's no private
    /// key to embed. `create_p12_file` writes to a final destination rather
    /// than returning bytes, so this runs it against a runtime-dir scratch
    /// file and reads the result back for encryption into `p12.enc`.
    fn create_p12_bundle(
        &self,
        cert_pem: &str,
        key_pem: &str,
        ca_pem: &str,
    ) -> Result<Option<Vec<u8>>> {
        if key_pem.is_empty() {
            return Ok(None);
        }

        let temp_dir = VaultCliPaths::runtime_dir()?;
        VaultCliPaths::ensure_dir_exists(&temp_dir)?;
        let temp_p12 = temp_dir.join(format!("store_{}.p12", std::process::id()));

        crate::utils::create_p12_file(&temp_p12, key_pem, cert_pem, ca_pem, true)?;

        let data = fs::read(&temp_p12)?;
        if let Err(e) = fs::remove_file(&temp_p12) {
            tracing::warn!(
                "Failed to remove temporary P12 file {}: {}",
                temp_p12.display(),
                e
            );
        }

        Ok(Some(data))
    }

    /// Calculate SHA256 checksum of a file
    fn calculate_file_checksum(&self, file_path: &Path) -> Result<String> {
        let data = fs::read(file_path)?;
        let mut hasher = Sha256::new();
        hasher.update(&data);
        Ok(hex::encode(hasher.finalize()))
    }

    /// Decrypt a file for debugging purposes
    pub async fn decrypt_file(&self, context: &str, file_path: &Path) -> Result<Vec<u8>> {
        self.encryption_manager
            .decrypt_from_file(context, file_path)
            .await
    }
}

/// What a command line named.
pub struct EntryTarget<'a> {
    pub cn: &'a str,
    pub pki_mount: Option<&'a str>,
    pub serial: Option<&'a str>,
}

impl EntryTarget<'_> {
    fn describe(&self) -> String {
        let mut described = format!("common name '{}'", self.cn);
        if let Some(mount) = self.pki_mount {
            described.push_str(&format!(" on mount '{mount}'"));
        }
        if let Some(serial) = self.serial {
            described.push_str(&format!(" with serial '{serial}'"));
        }
        described
    }
}

/// One resolved artifact directory, whether or not anything in it decrypts.
pub struct StoredEntry {
    pub pki_mount: String,
    pub cn: String,
    pub serial: String,
    pub path: PathBuf,
    /// The record, or why it would not load. Kept as a result rather than
    /// propagated so `show` can still report what needs no key and `remove`
    /// can still reach the artifact.
    pub record: std::result::Result<CertificateStorage, VaultCliError>,
}

/// What an artifact's key file holds, decided by ciphertext length so the
/// answer survives the artifact not decrypting.
#[derive(PartialEq, Eq)]
pub enum KeyMaterial {
    /// No key file, or one whose plaintext is empty — a CSR-signed artifact
    /// keeps its key with the requester.
    None,
    Present,
    /// Shorter than a nonce and a tag, so it holds nothing that could decrypt.
    Malformed,
}

impl StoredEntry {
    pub fn key_material(&self) -> Result<KeyMaterial> {
        let key_file = self.path.join("private_key.pem.enc");
        let len = match fs::metadata(&key_file) {
            Ok(metadata) => metadata.len(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(KeyMaterial::None),
            Err(e) => return Err(e.into()),
        };

        Ok(match len as usize {
            len if len == EMPTY_PAYLOAD_LEN => KeyMaterial::None,
            len if len > EMPTY_PAYLOAD_LEN => KeyMaterial::Present,
            _ => KeyMaterial::Malformed,
        })
    }

    /// Every artifact file with its size, for a report that cannot decrypt.
    pub fn files(&self) -> Result<Vec<(String, u64)>> {
        let mut files = Vec::new();
        for entry in fs::read_dir(&self.path)? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                files.push((
                    entry.file_name().to_string_lossy().to_string(),
                    entry.metadata()?.len(),
                ));
            }
        }
        files.sort();
        Ok(files)
    }

    pub fn sealed_by(&self) -> Option<SealedBy> {
        LocalStorage::read_sealed_by(&self.path)
    }
}

/// The subdirectories of `dir`, skipping files. A read failure propagates:
/// the walk cannot tell a directory it could not open from an empty one.
fn read_subdirs(dir: &Path) -> Result<Vec<fs::DirEntry>> {
    let mut dirs = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            dirs.push(entry);
        }
    }
    Ok(dirs)
}
