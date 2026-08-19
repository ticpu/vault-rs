use crate::utils::errors::{Result, VaultCliError};
use crate::vault::client::VaultClient;
use crate::vault::PkiClient;
use std::fs;
use std::path::Path;
use std::process::Command;

/// A path as a command-line argument. Paths are bytes on Unix, so a name that
/// is not UTF-8 is a legitimate path this cannot pass to openssl — report it
/// rather than panicking on the caller's filename.
fn path_arg(path: &Path) -> Result<&str> {
    path.to_str().ok_or_else(|| {
        VaultCliError::InvalidInput(format!("path is not valid UTF-8: {}", path.display()))
    })
}

pub fn create_p12_file(
    p12_path: &Path,
    private_key: &str,
    certificate: &str,
    ca_cert: &str,
    no_passphrase: bool,
) -> Result<()> {
    use std::fs;

    let temp_dir = vault_session::paths::runtime_dir(crate::utils::PROGRAM_NAME)?;
    vault_session::paths::ensure_owner_only_dir(&temp_dir)?;

    let key_file = temp_dir.join(format!("key_{}.pem", std::process::id()));
    let cert_file = temp_dir.join(format!("cert_{}.pem", std::process::id()));
    let ca_file = temp_dir.join(format!("ca_{}.pem", std::process::id()));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);

        fs::write(&key_file, private_key)?;
        fs::set_permissions(&key_file, perms.clone())?;

        fs::write(&cert_file, certificate)?;
        fs::set_permissions(&cert_file, perms.clone())?;

        if !ca_cert.is_empty() {
            fs::write(&ca_file, ca_cert)?;
            fs::set_permissions(&ca_file, perms)?;
        }
    }

    let mut args = vec![
        "pkcs12",
        "-export",
        "-out",
        path_arg(p12_path)?,
        "-inkey",
        path_arg(&key_file)?,
        "-in",
        path_arg(&cert_file)?,
    ];

    if !ca_cert.is_empty() {
        args.extend_from_slice(&["-certfile", path_arg(&ca_file)?]);
    }

    if no_passphrase {
        args.extend_from_slice(&["-passout", "pass:"]);
    }

    let output = Command::new("openssl")
        .args(&args)
        .output()
        .map_err(|e| VaultCliError::Storage(format!("Failed to run openssl: {e}")))?;

    // Best-effort cleanup: the P12 is already written, so a leftover file is
    // worth reporting but not worth failing over.
    for path in [&key_file, &cert_file, &ca_file] {
        if let Err(e) = fs::remove_file(path) {
            tracing::warn!("Failed to remove temporary file {}: {e}", path.display());
        }
    }

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(VaultCliError::Storage(format!(
            "OpenSSL PKCS12 export failed: {stderr}"
        )));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(p12_path)?.permissions();
        perms.set_mode(0o600); // Owner read/write only
        std::fs::set_permissions(p12_path, perms)?;
    }

    Ok(())
}

fn write_bytes_to_file(dir: &str, filename: &str, data: &[u8]) -> Result<()> {
    let path = Path::new(dir);
    fs::create_dir_all(path)?;

    let file_path = path.join(filename);
    fs::write(&file_path, data)?;

    eprintln!("Certificate exported to: {}", file_path.display());
    Ok(())
}

pub fn write_to_file(dir: &str, filename: &str, data: &str) -> Result<()> {
    write_bytes_to_file(dir, filename, data.as_bytes())
}

pub fn write_to_file_bytes(dir: &str, filename: &str, data: &[u8]) -> Result<()> {
    write_bytes_to_file(dir, filename, data)
}

pub async fn resolve_crypto_type(
    client: &VaultClient,
    pki_mount: &str,
    crypto_override: Option<&str>,
) -> Result<String> {
    if let Some(crypto_type) = crypto_override {
        Ok(crypto_type.to_string())
    } else {
        tracing::info!("Auto-detecting crypto type for PKI mount: {pki_mount}");
        let detected = client.detect_crypto_type(pki_mount).await?;
        tracing::info!("Detected crypto type: {detected}");
        Ok(detected)
    }
}

/// Validate that a role exists for the given PKI mount, failing before any
/// write. Revocation is the only undo for a bad issuance, so a bad --role
/// must not reach the CA as a write.
pub async fn validate_role_exists(client: &VaultClient, pki_mount: &str, role: &str) -> Result<()> {
    let available_roles = client.list_roles(pki_mount).await?;
    if available_roles.contains(&role.to_string()) {
        return Ok(());
    }
    Err(VaultCliError::InvalidInput(format!(
        "role '{role}' not found on mount '{pki_mount}'; available roles: [{}]",
        available_roles.join(", ")
    )))
}

pub fn parse_comma_separated(input: Option<&str>) -> Option<Vec<String>> {
    input.map(|names| {
        names
            .split(',')
            .map(|s| s.trim().to_string())
            .collect::<Vec<_>>()
    })
}

pub fn write_output_or_print(
    output_dir: Option<&str>,
    filename: &str,
    content: &str,
) -> Result<()> {
    if let Some(dir) = output_dir {
        write_to_file(dir, filename, content)?;
    } else {
        println!("{content}");
    }
    Ok(())
}

pub fn write_output_or_print_bytes(
    output_dir: Option<&str>,
    filename: &str,
    content: &[u8],
) -> Result<()> {
    if let Some(dir) = output_dir {
        write_to_file_bytes(dir, filename, content)?;
    } else {
        use std::io::Write;
        std::io::stdout().write_all(content)?;
    }
    Ok(())
}

pub struct CertificateStorageHelper {
    pub serial: String,
    pub cn: String,
    pub role: String,
    pub crypto: String,
    pub sans: Vec<String>,
    pub no_store: bool,
}

impl CertificateStorageHelper {
    pub async fn store_certificate(
        &self,
        pki_mount: &str,
        certificate_pem: &str,
        private_key_pem: Option<&str>,
        ca_chain_pem: &str,
    ) -> Result<()> {
        if self.no_store {
            return Ok(());
        }

        use crate::cert::CertificateParser;
        use crate::storage::metadata::{
            normalize_serial, CertStatus, StoredIdentity, StoredMetadata,
        };
        use crate::storage::{CertificateData, LocalStorage};
        use chrono::Utc;

        // Filed under the identity the CA actually issued, not the one that was
        // asked for: a role with use_csr_common_name leaves the CN argument
        // inert, and storing that name puts the certificate under a CN no
        // lookup will ever match.
        let issued = CertificateParser::parse_pem(certificate_pem, pki_mount)?;

        let storage = LocalStorage::new().await?;
        // Only what the certificate cannot yield; the rest is read back off it.
        let metadata = StoredMetadata {
            crypto: Some(self.crypto.clone()),
            created: Utc::now(),
            file_info: Default::default(),
            meta: StoredIdentity {
                role: Some(self.role.clone()),
                status: CertStatus::Active,
            },
        };

        let cert_data = CertificateData {
            pki_mount,
            cn: &issued.cn,
            serial: &normalize_serial(&self.serial),
            certificate_pem,
            private_key_pem: private_key_pem.unwrap_or(""),
            ca_chain_pem,
            metadata,
        };

        storage.store_certificate(cert_data).await?;
        Ok(())
    }
}
