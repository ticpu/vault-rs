use crate::cli::args::ExportFormat;
use crate::utils::errors::{Result, VaultCliError};
use crate::utils::{
    parse_certificate_chain, write_output_or_print, write_to_file, PemCertificate,
    PemCertificateBundle, PemCertificateChain, PemPrivateKey,
};
use crate::vault::client::VaultClient;
use std::fs;
use std::path::Path;

pub struct ExportCertificateRequest {
    pub pem_data: String,
    pub mount: String,
    pub identifier: String,
    pub format: ExportFormat,
    pub output_dir: Option<String>,
    pub no_passphrase: bool,
    pub text: bool,
}

/// Export certificate in various formats
pub async fn export_certificate(
    client: &VaultClient,
    request: ExportCertificateRequest,
) -> Result<()> {
    // Create PEM certificate from input data
    let certificate = PemCertificate::new(request.pem_data.clone());

    match request.format {
        ExportFormat::Pem => {
            // Default PEM format - output to stdout (pipe-friendly) or file
            let output_content = certificate.output(request.text);

            if let Some(ref dir) = request.output_dir {
                write_to_file(
                    dir,
                    &format!("{}.pem", sanitize_filename(&request.identifier)),
                    &output_content,
                )?;
            } else {
                // Output to stdout for piping (already has newline)
                print!("{output_content}");
            }
        }
        ExportFormat::Crt => {
            // Certificate only to .crt file
            let dir = request.output_dir.as_deref().unwrap_or(".");
            write_to_file(
                dir,
                &format!("{}.crt", sanitize_filename(&request.identifier)),
                certificate.pem_data(),
            )?;
        }
        ExportFormat::Chain => {
            // Get full certificate chain and create chain object
            let ca_chain_pem = get_ca_chain_safe(client, &request.mount).await;
            let mut chain = PemCertificateChain::new();
            chain.add_certificate(certificate);

            // Parse and add CA certificates to chain
            if !ca_chain_pem.is_empty() {
                let ca_certs = parse_certificate_chain(&ca_chain_pem);
                for ca_cert in ca_certs {
                    chain.add_certificate(ca_cert);
                }
            }

            let output_content = chain.output(request.text);

            if let Some(ref dir) = request.output_dir {
                write_to_file(
                    dir,
                    &format!("{}_chain.pem", sanitize_filename(&request.identifier)),
                    &output_content,
                )?;
            } else {
                println!("{output_content}");
            }
        }
        ExportFormat::Key => {
            // Key export requires local storage lookup
            use crate::storage::local::LocalStorage;
            let storage = LocalStorage::with_client(client.clone());

            // First, try to find certificate metadata to get CN if identifier is serial
            match storage.list_certificates().await {
                Ok(certs) => {
                    // Find matching certificate by CN or serial (storage has colons, user input doesn't)
                    let identifier_with_colons =
                        crate::cert::format_serial_with_colons(&request.identifier);

                    let matching_cert = certs.iter().find(|cert| {
                        cert.meta.cn == request.identifier
                            || cert.meta.serial == identifier_with_colons
                    });

                    if let Some(cert) = matching_cert {
                        // Get the certificate data with private key
                        match storage
                            .get_certificate(&cert.pki_mount, &cert.meta.cn)
                            .await
                        {
                            Ok((_, private_key, _, _)) => {
                                if let Some(ref dir) = request.output_dir {
                                    write_to_file(
                                        dir,
                                        &format!("{}.key", sanitize_filename(&request.identifier)),
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
                            format!("Private key for '{}' not found in local storage. Keys are only available for certificates created with vault-rs.", request.identifier)
                        ));
                    }
                }
                Err(e) => {
                    return Err(VaultCliError::InvalidInput(format!(
                        "Unable to access local storage for key export: {e}"
                    )));
                }
            }
        }
        ExportFormat::P12 => {
            // P12 export requires both certificate and private key
            use crate::storage::local::LocalStorage;
            let storage = LocalStorage::with_client(client.clone());

            // Try to get private key from local storage
            match storage.list_certificates().await {
                Ok(certs) => {
                    // Find matching certificate by CN or serial (storage has colons, user input doesn't)
                    let identifier_with_colons =
                        crate::cert::format_serial_with_colons(&request.identifier);

                    let matching_cert = certs.iter().find(|cert| {
                        cert.meta.cn == request.identifier
                            || cert.meta.serial == identifier_with_colons
                    });

                    if let Some(cert) = matching_cert {
                        match storage
                            .get_certificate(&cert.pki_mount, &cert.meta.cn)
                            .await
                        {
                            Ok((certificate_pem, private_key, ca_chain_pem, _)) => {
                                // Create P12 file using matching cert and key from local storage
                                let dir = request.output_dir.as_deref().unwrap_or(".");
                                let p12_filename =
                                    format!("{}.p12", sanitize_filename(&request.identifier));
                                let p12_path = Path::new(dir).join(&p12_filename);

                                fs::create_dir_all(dir)?;

                                // Create PEM bundle for cleaner handling
                                let pem_key = PemPrivateKey::new(private_key);
                                let pem_cert = PemCertificate::new(certificate_pem);
                                let mut ca_chain = PemCertificateChain::new();
                                if !ca_chain_pem.is_empty() {
                                    let ca_certs = parse_certificate_chain(&ca_chain_pem);
                                    for ca_cert in ca_certs {
                                        ca_chain.add_certificate(ca_cert);
                                    }
                                }

                                let bundle =
                                    PemCertificateBundle::new(Some(pem_key), pem_cert, ca_chain);

                                match crate::utils::create_p12_file(
                                    &p12_path,
                                    bundle.private_key().unwrap().pem_data(),
                                    bundle.certificate().pem_data(),
                                    &bundle.ca_chain().pem_data(),
                                    request.no_passphrase,
                                ) {
                                    Ok(()) => {
                                        eprintln!(
                                            "P12 certificate exported to: {}",
                                            p12_path.display()
                                        );
                                    }
                                    Err(e) => {
                                        return Err(VaultCliError::InvalidInput(format!(
                                            "Failed to create P12: {e}"
                                        )));
                                    }
                                }
                            }
                            Err(_) => {
                                return Err(VaultCliError::InvalidInput(
                                    format!("P12 export requires private key. Certificate '{}' not found in local storage.", request.identifier)
                                ));
                            }
                        }
                    } else {
                        return Err(VaultCliError::InvalidInput(
                            format!("P12 export requires private key. Certificate '{}' not found in local storage.", request.identifier)
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
            let storage = LocalStorage::with_client(client.clone());

            // Get CA chain
            let ca_chain_pem = get_ca_chain_safe(client, &request.mount).await;
            let mut ca_chain = PemCertificateChain::new();
            if !ca_chain_pem.is_empty() {
                let ca_certs = parse_certificate_chain(&ca_chain_pem);
                for ca_cert in ca_certs {
                    ca_chain.add_certificate(ca_cert);
                }
            }

            // Try to get private key from local storage
            if let Ok(certs) = storage.list_certificates().await {
                // Find matching certificate by CN or serial (storage has colons, user input doesn't)
                let identifier_with_colons =
                    crate::cert::format_serial_with_colons(&request.identifier);

                let matching_cert = certs.iter().find(|cert| {
                    cert.meta.cn == request.identifier || cert.meta.serial == identifier_with_colons
                });

                if let Some(cert) = matching_cert {
                    if let Ok((_certificate_pem, private_key, _ca_chain_pem, _)) = storage
                        .get_certificate(&cert.pki_mount, &cert.meta.cn)
                        .await
                    {
                        // Create bundle with private key
                        let pem_key = PemPrivateKey::new(private_key);
                        let bundle =
                            PemCertificateBundle::new(Some(pem_key), certificate, ca_chain);

                        let output_content = bundle.output(request.text);
                        write_output_or_print(
                            request.output_dir.as_deref(),
                            &format!("{}.pem", sanitize_filename(&request.identifier)),
                            &output_content,
                        )?;
                        return Ok(());
                    }
                }
            }

            // Fallback: export certificate and chain only (no private key)
            tracing::info!("Private key for '{}' not found in local storage, exporting certificate and chain only", request.identifier);
            let bundle = PemCertificateBundle::new(None, certificate, ca_chain);
            let output_content = bundle.output(request.text);

            write_output_or_print(
                request.output_dir.as_deref(),
                &format!("{}.pem", sanitize_filename(&request.identifier)),
                &output_content,
            )?;
        }
    }

    Ok(())
}

/// Get CA chain with graceful error handling
async fn get_ca_chain_safe(client: &VaultClient, mount: &str) -> String {
    match client.get_ca_chain(mount).await {
        Ok(chain) => chain,
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
