use crate::utils::errors::{Result, VaultCliError};
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
    #[cfg(not(unix))]
    {
        fs::write(&key_file, private_key)?;
        fs::write(&cert_file, certificate)?;
        if !ca_cert.is_empty() {
            fs::write(&ca_file, ca_cert)?;
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
