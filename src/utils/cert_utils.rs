use crate::utils::errors::{Result, VaultCliError};
use crate::vault::client::VaultClient;
use std::fs;
use std::path::Path;
use std::process::Command;

/// Create a PKCS12 file using OpenSSL
pub fn create_p12_file(
    p12_path: &Path,
    private_key: &str,
    certificate: &str,
    ca_cert: &str,
    no_passphrase: bool,
) -> Result<()> {
    use std::fs;
    // Create temporary files for OpenSSL input in secure runtime directory
    use crate::utils::paths::VaultCliPaths;
    let temp_dir = VaultCliPaths::runtime_dir()?;
    VaultCliPaths::ensure_dir_exists(&temp_dir)?;

    let key_file = temp_dir.join(format!("key_{}.pem", std::process::id()));
    let cert_file = temp_dir.join(format!("cert_{}.pem", std::process::id()));
    let ca_file = temp_dir.join(format!("ca_{}.pem", std::process::id()));

    // Write files with secure permissions
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

    // Build OpenSSL command
    let mut args = vec![
        "pkcs12",
        "-export",
        "-out",
        p12_path.to_str().unwrap(),
        "-inkey",
        key_file.to_str().unwrap(),
        "-in",
        cert_file.to_str().unwrap(),
    ];

    if !ca_cert.is_empty() {
        args.extend_from_slice(&["-certfile", ca_file.to_str().unwrap()]);
    }

    if no_passphrase {
        args.extend_from_slice(&["-passout", "pass:"]);
    }

    let output = Command::new("openssl")
        .args(&args)
        .output()
        .map_err(|e| VaultCliError::Storage(format!("Failed to run openssl: {e}")))?;

    // Clean up temporary files
    let _ = fs::remove_file(&key_file);
    let _ = fs::remove_file(&cert_file);
    let _ = fs::remove_file(&ca_file);

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(VaultCliError::Storage(format!(
            "OpenSSL PKCS12 export failed: {stderr}"
        )));
    }

    // Set secure file permissions on output
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(p12_path)?.permissions();
        perms.set_mode(0o600); // Owner read/write only
        std::fs::set_permissions(p12_path, perms)?;
    }

    Ok(())
}

/// Write data to file, creating directories as needed
pub fn write_to_file(dir: &str, filename: &str, data: &str) -> Result<()> {
    let path = Path::new(dir);
    fs::create_dir_all(path)?;

    let file_path = path.join(filename);
    fs::write(&file_path, data)?;

    eprintln!("Certificate exported to: {}", file_path.display());
    Ok(())
}

/// Auto-detect crypto type for a PKI mount or use provided type
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

/// Validate that a role exists for the given PKI mount and show helpful warnings
pub async fn validate_role_exists(client: &VaultClient, pki_mount: &str, role: &str) -> Result<()> {
    if let Ok(available_roles) = client.list_roles(pki_mount).await {
        if !available_roles.is_empty() && !available_roles.contains(&role.to_string()) {
            eprintln!("Warning: Role '{role}' not found in available roles for PKI '{pki_mount}'");
            eprintln!("Available roles: {}", available_roles.join(", "));
            eprintln!("Continuing anyway - Vault will return an error if role is invalid.");
        }
    }
    Ok(())
}

/// Parse comma-separated strings into vectors, trimming whitespace
pub fn parse_comma_separated(input: Option<&str>) -> Option<Vec<String>> {
    input.map(|names| {
        names
            .split(',')
            .map(|s| s.trim().to_string())
            .collect::<Vec<_>>()
    })
}

/// Write content to file or stdout based on output directory
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

/// Helper for storing certificates to avoid code duplication
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

        use crate::storage::metadata::CertStatus;
        use crate::storage::{CertificateData, LocalStorage, StorageCertificateMetadata};
        use chrono::Utc;

        let storage = LocalStorage::new().await;
        let metadata = StorageCertificateMetadata {
            serial: self.serial.clone(),
            cn: self.cn.clone(),
            role: self.role.clone(),
            crypto: self.crypto.clone(),
            created: Utc::now(),
            expires: Utc::now() + chrono::Duration::days(365), // Will be updated with actual expiry
            status: CertStatus::Active,
            sans: self.sans.clone(),
        };

        let cert_data = CertificateData {
            pki_mount,
            cn: &self.cn,
            certificate_pem,
            private_key_pem: private_key_pem.unwrap_or(""),
            ca_chain_pem,
            metadata,
        };

        storage.store_certificate(cert_data).await?;
        Ok(())
    }
}
