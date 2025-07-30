use crate::cli::args::ExportFormat;
use crate::utils::errors::{Result, VaultCliError};
use crate::vault::client::VaultClient;
use std::fs;
use std::path::Path;

/// Export certificate in various formats
pub async fn export_certificate(
    client: &VaultClient,
    token: &str,
    pem_data: &str,
    mount: &str,
    identifier: &str,
    format: &ExportFormat,
    output_dir: Option<&str>,
) -> Result<()> {
    // Normalize PEM data to ensure consistent formatting
    let normalized_pem = normalize_pem(pem_data);

    match format {
        ExportFormat::Pem => {
            // Default PEM format - output to stdout (pipe-friendly) or file
            if let Some(dir) = output_dir {
                write_to_file(
                    dir,
                    &format!("{}.pem", sanitize_filename(identifier)),
                    &normalized_pem,
                )?;
            } else {
                // Output to stdout for piping (normalized PEM already has newline)
                print!("{normalized_pem}");
            }
        }
        ExportFormat::Crt => {
            // Certificate only to .crt file
            let dir = output_dir.unwrap_or(".");
            write_to_file(
                dir,
                &format!("{}.crt", sanitize_filename(identifier)),
                &normalized_pem,
            )?;
        }
        ExportFormat::Chain => {
            // Get full certificate chain (already normalized)
            let ca_chain = get_ca_chain_safe(client, token, mount).await;
            let full_chain = format!("{normalized_pem}{ca_chain}");

            if let Some(dir) = output_dir {
                write_to_file(
                    dir,
                    &format!("{}_chain.pem", sanitize_filename(identifier)),
                    &full_chain,
                )?;
            } else {
                println!("{full_chain}");
            }
        }
        ExportFormat::Key => {
            // Key export requires local storage lookup
            use crate::storage::local::LocalStorage;
            let storage = LocalStorage::new(client.vault_addr().to_string());

            // First, try to find certificate metadata to get CN if identifier is serial
            match storage.list_certificates(token).await {
                Ok(certs) => {
                    // Find matching certificate by CN or serial
                    let matching_cert = certs
                        .iter()
                        .find(|cert| cert.meta.cn == identifier || cert.meta.serial == identifier);

                    if let Some(cert) = matching_cert {
                        // Get the certificate data with private key
                        match storage
                            .get_certificate(token, &cert.pki_mount, &cert.meta.cn)
                            .await
                        {
                            Ok((_, private_key, _, _)) => {
                                if let Some(dir) = output_dir {
                                    write_to_file(
                                        dir,
                                        &format!("{}.key", sanitize_filename(identifier)),
                                        &private_key,
                                    )?;
                                } else {
                                    println!("{private_key}");
                                }
                            }
                            Err(e) => {
                                return Err(VaultCliError::InvalidInput(format!(
                                    "Failed to retrieve private key: {e}"
                                )));
                            }
                        }
                    } else {
                        return Err(VaultCliError::InvalidInput(
                            format!("Private key for '{identifier}' not found in local storage. Keys are only available for certificates created with vault-rs.")
                        ));
                    }
                }
                Err(_) => {
                    return Err(VaultCliError::InvalidInput(
                        "Unable to access local storage for key export".to_string(),
                    ));
                }
            }
        }
        ExportFormat::P12 => {
            // P12 export requires both certificate and private key
            use crate::storage::local::LocalStorage;
            let storage = LocalStorage::new(client.vault_addr().to_string());

            // Get CA chain
            let ca_chain = get_ca_chain_safe(client, token, mount).await;

            // Try to get private key from local storage
            match storage.list_certificates(token).await {
                Ok(certs) => {
                    let matching_cert = certs
                        .iter()
                        .find(|cert| cert.meta.cn == identifier || cert.meta.serial == identifier);

                    if let Some(cert) = matching_cert {
                        match storage
                            .get_certificate(token, &cert.pki_mount, &cert.meta.cn)
                            .await
                        {
                            Ok((_, private_key, _, _)) => {
                                // Create P12 file using OpenSSL
                                let dir = output_dir.unwrap_or(".");
                                let p12_filename = format!("{}.p12", sanitize_filename(identifier));
                                let p12_path = Path::new(dir).join(&p12_filename);

                                fs::create_dir_all(dir)?;

                                let openssl_result = std::process::Command::new("openssl")
                                    .args([
                                        "pkcs12",
                                        "-export",
                                        "-out",
                                        p12_path.to_str().unwrap(),
                                        "-passout",
                                        "pass:",
                                    ])
                                    .stdin(std::process::Stdio::piped())
                                    .stdout(std::process::Stdio::null())
                                    .stderr(std::process::Stdio::piped())
                                    .spawn();

                                match openssl_result {
                                    Ok(mut child) => {
                                        if let Some(stdin) = child.stdin.as_mut() {
                                            use std::io::Write;
                                            let normalized_key = normalize_pem(&private_key);
                                            let combined = format!(
                                                "{normalized_key}{normalized_pem}{ca_chain}"
                                            );
                                            let _ = stdin.write_all(combined.as_bytes());
                                        }

                                        let output = child.wait_with_output()?;
                                        if output.status.success() {
                                            eprintln!(
                                                "P12 certificate exported to: {}",
                                                p12_path.display()
                                            );
                                        } else {
                                            let stderr = String::from_utf8_lossy(&output.stderr);
                                            return Err(VaultCliError::InvalidInput(format!(
                                                "OpenSSL failed to create P12: {stderr}"
                                            )));
                                        }
                                    }
                                    Err(e) => {
                                        return Err(VaultCliError::InvalidInput(format!(
                                            "Failed to run OpenSSL for P12 creation: {e}"
                                        )));
                                    }
                                }
                            }
                            Err(_) => {
                                return Err(VaultCliError::InvalidInput(
                                    format!("P12 export requires private key. Certificate '{identifier}' not found in local storage.")
                                ));
                            }
                        }
                    } else {
                        return Err(VaultCliError::InvalidInput(
                            format!("P12 export requires private key. Certificate '{identifier}' not found in local storage.")
                        ));
                    }
                }
                Err(_) => {
                    return Err(VaultCliError::InvalidInput(
                        "P12 export requires access to local storage".to_string(),
                    ));
                }
            }
        }
        ExportFormat::All => {
            // All format: private key + certificate + CA chain in PEM format
            use crate::storage::local::LocalStorage;
            let storage = LocalStorage::new(client.vault_addr().to_string());

            // Get CA chain
            let ca_chain = get_ca_chain_safe(client, token, mount).await;

            // Try to get private key from local storage
            let private_key = match storage.list_certificates(token).await {
                Ok(certs) => {
                    let matching_cert = certs
                        .iter()
                        .find(|cert| cert.meta.cn == identifier || cert.meta.serial == identifier);

                    if let Some(cert) = matching_cert {
                        match storage
                            .get_certificate(token, &cert.pki_mount, &cert.meta.cn)
                            .await
                        {
                            Ok((_, private_key, _, _)) => Some(private_key),
                            Err(_) => {
                                tracing::info!("Private key for '{}' not found in local storage, exporting certificate and chain only", identifier);
                                None
                            }
                        }
                    } else {
                        tracing::info!("Certificate '{}' not found in local storage, exporting certificate and chain only", identifier);
                        None
                    }
                }
                Err(_) => {
                    tracing::info!(
                        "Unable to access local storage, exporting certificate and chain only"
                    );
                    None
                }
            };

            // Combine in standard order: private key + certificate + CA chain
            let full_pem = match private_key {
                Some(key) => {
                    let normalized_key = normalize_pem(&key);
                    format!("{normalized_key}{normalized_pem}{ca_chain}")
                }
                None => format!("{normalized_pem}{ca_chain}"),
            };

            if let Some(dir) = output_dir {
                write_to_file(
                    dir,
                    &format!("{}.pem", sanitize_filename(identifier)),
                    &full_pem,
                )?;
            } else {
                println!("{full_pem}");
            }
        }
    }

    Ok(())
}

/// Write data to file, creating directories as needed
fn write_to_file(dir: &str, filename: &str, data: &str) -> Result<()> {
    let path = Path::new(dir);
    fs::create_dir_all(path)?;

    let file_path = path.join(filename);
    fs::write(&file_path, data)?;

    eprintln!("Certificate exported to: {}", file_path.display());
    Ok(())
}

/// Normalize PEM data to ensure consistent formatting
fn normalize_pem(pem_data: &str) -> String {
    let trimmed = pem_data.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    // Ensure PEM data ends with exactly one newline
    if trimmed.ends_with('\n') {
        trimmed.to_string()
    } else {
        format!("{trimmed}\n")
    }
}

/// Get CA chain with graceful error handling
async fn get_ca_chain_safe(client: &VaultClient, token: &str, mount: &str) -> String {
    match client.get_ca_chain(token, mount).await {
        Ok(chain) => normalize_pem(&chain),
        Err(e) => {
            tracing::warn!(
                "Failed to get CA chain for '{}': {}, continuing without CA chain",
                mount,
                e
            );
            String::new()
        }
    }
}

/// Sanitize filename by replacing problematic characters
fn sanitize_filename(name: &str) -> String {
    name.replace(['/', '\\', ':', '*', '?', '"', '<', '>', '|'], "_")
}
