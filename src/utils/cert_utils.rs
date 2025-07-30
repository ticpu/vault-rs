use crate::utils::errors::{Result, VaultCliError};
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

/// Create a PKCS12 file using OpenSSL with no password
pub fn create_p12_file(
    p12_path: &Path,
    private_key: &str,
    certificate: &str,
    ca_cert: &str,
) -> Result<()> {
    let mut cmd = Command::new("openssl")
        .args([
            "pkcs12",
            "-export",
            "-out",
            p12_path.to_str().unwrap(),
            "-passout",
            "pass:",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| VaultCliError::Storage(format!("Failed to run openssl: {e}")))?;

    if let Some(stdin) = cmd.stdin.as_mut() {
        let p12_content = format!("{private_key}{certificate}{ca_cert}");
        stdin.write_all(p12_content.as_bytes()).map_err(|e| {
            VaultCliError::Storage(format!("Failed to write to openssl stdin: {e}"))
        })?;
    }

    let output = cmd
        .wait()
        .map_err(|e| VaultCliError::Storage(format!("Failed to wait for openssl: {e}")))?;

    if !output.success() {
        return Err(VaultCliError::Storage(
            "OpenSSL PKCS12 export failed".to_string(),
        ));
    }

    Ok(())
}
