use crate::cert::format_serial_with_colons;
use crate::cli::args::ExportFormat;
use crate::storage::local::LocalStorage;
use crate::storage::CertificateStorage;
use crate::utils::errors::{Result, VaultCliError};
use crate::utils::pem::{PemCertificate, PemCertificateBundle, PemCertificateChain, PemPrivateKey};
use crate::utils::{parse_certificate_chain, write_output_or_print, write_to_file};
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

/// Find certificate in local storage by identifier (CN or serial)
async fn find_certificate_in_storage(
    storage: &LocalStorage,
    identifier: &str,
) -> Result<Option<CertificateStorage>> {
    let certs = storage.list_certificates().await?;
    let identifier_with_colons = format_serial_with_colons(identifier);

    let matching_cert = certs
        .iter()
        .find(|cert| cert.meta.cn == identifier || cert.meta.serial == identifier_with_colons)
        .cloned();

    Ok(matching_cert)
}

/// Get certificate data from local storage by certificate record
async fn get_certificate_data_from_storage(
    storage: &LocalStorage,
    cert_record: &CertificateStorage,
) -> Result<(String, String, String)> {
    let (certificate_pem, private_key, ca_chain_pem, _) = storage
        .get_certificate(&cert_record.pki_mount, &cert_record.meta.cn)
        .await?;
    Ok((certificate_pem, private_key, ca_chain_pem))
}

/// Build PEM certificate chain from CA chain PEM data
fn build_ca_chain(ca_chain_pem: &str) -> PemCertificateChain {
    let mut ca_chain = PemCertificateChain::new();
    if !ca_chain_pem.is_empty() {
        let ca_certs = parse_certificate_chain(ca_chain_pem);
        for ca_cert in ca_certs {
            ca_chain.add_certificate(ca_cert);
        }
    }
    ca_chain
}

/// Get certificate bundle from local storage
async fn get_certificate_bundle_from_storage(
    client: &VaultClient,
    identifier: &str,
) -> Result<(Option<PemPrivateKey>, PemCertificate, PemCertificateChain)> {
    let storage = LocalStorage::with_client(client.clone());

    let cert_record = find_certificate_in_storage(&storage, identifier)
        .await?
        .ok_or_else(|| {
            VaultCliError::InvalidInput(format!(
                "Certificate '{identifier}' not found in local storage"
            ))
        })?;

    let (certificate_pem, private_key, ca_chain_pem) =
        get_certificate_data_from_storage(&storage, &cert_record).await?;

    let pem_key = PemPrivateKey::new(private_key);
    let pem_cert = PemCertificate::new(certificate_pem);
    let ca_chain = build_ca_chain(&ca_chain_pem);

    Ok((Some(pem_key), pem_cert, ca_chain))
}

async fn export_p12(client: &VaultClient, request: &ExportCertificateRequest) -> Result<()> {
    // P12 export requires both certificate and private key from local storage
    let (private_key, certificate, ca_chain) =
        get_certificate_bundle_from_storage(client, &request.identifier)
            .await
            .map_err(|_| {
                VaultCliError::InvalidInput(format!(
                    "P12 export requires private key. Certificate '{}' not found in local storage.",
                    request.identifier
                ))
            })?;

    let dir = request.output_dir.as_deref().unwrap_or(".");
    let p12_filename = format!("{}.p12", sanitize_filename(&request.identifier));
    let p12_path = Path::new(dir).join(&p12_filename);

    fs::create_dir_all(dir)?;

    let bundle = PemCertificateBundle::new(private_key, certificate, ca_chain);

    match crate::utils::create_p12_file(
        &p12_path,
        bundle.private_key().unwrap().pem_data(),
        bundle.certificate().pem_data(),
        &bundle.ca_chain().pem_data(),
        request.no_passphrase,
    ) {
        Ok(()) => {
            eprintln!("P12 certificate exported to: {}", p12_path.display());
            Ok(())
        }
        Err(e) => Err(VaultCliError::InvalidInput(format!(
            "Failed to create P12: {e}"
        ))),
    }
}

/// All format: private key + certificate + CA chain in PEM format
async fn export_all(
    client: &VaultClient,
    request: &ExportCertificateRequest,
    certificate: PemCertificate,
) -> Result<()> {
    // Try to get complete bundle from local storage first
    match get_certificate_bundle_from_storage(client, &request.identifier).await {
        Ok((private_key, cert_from_storage, ca_chain_from_storage)) => {
            let bundle =
                PemCertificateBundle::new(private_key, cert_from_storage, ca_chain_from_storage);
            let output_content = bundle.output(request.text);
            write_output_or_print(
                request.output_dir.as_deref(),
                &format!("{}.pem", sanitize_filename(&request.identifier)),
                &output_content,
            )
        }
        Err(_) => {
            // Fallback: export certificate and chain only (no private key)
            tracing::info!("Private key for '{}' not found in local storage, exporting certificate and chain only", request.identifier);
            let ca_chain_pem = get_ca_chain_safe(client, &request.mount).await;
            let ca_chain = build_ca_chain(&ca_chain_pem);
            let bundle = PemCertificateBundle::new(None, certificate, ca_chain);
            let output_content = bundle.output(request.text);
            write_output_or_print(
                request.output_dir.as_deref(),
                &format!("{}.pem", sanitize_filename(&request.identifier)),
                &output_content,
            )
        }
    }
}

/// Default PEM format - output to stdout (pipe-friendly) or file
async fn export_pem_certificate(
    request: &ExportCertificateRequest,
    certificate: PemCertificate,
) -> Result<()> {
    let output_content = certificate.output(request.text);

    if let Some(ref dir) = request.output_dir {
        write_to_file(
            dir,
            &format!("{}.pem", sanitize_filename(&request.identifier)),
            &output_content,
        )
    } else {
        // Output to stdout for piping (already has newline)
        print!("{output_content}");
        Ok(())
    }
}

/// Certificate only to .crt file
async fn export_crt_certificate(
    request: &ExportCertificateRequest,
    certificate: PemCertificate,
) -> Result<()> {
    let dir = request.output_dir.as_deref().unwrap_or(".");
    write_to_file(
        dir,
        &format!("{}.crt", sanitize_filename(&request.identifier)),
        certificate.pem_data(),
    )
}

/// Get full certificate chain and create chain object
async fn export_certificate_chain(
    client: &VaultClient,
    request: &ExportCertificateRequest,
    certificate: PemCertificate,
) -> Result<()> {
    let ca_chain_pem = get_ca_chain_safe(client, &request.mount).await;
    let mut chain = PemCertificateChain::new();
    chain.add_certificate(certificate);

    // Add CA certificates using shared utility
    let ca_chain = build_ca_chain(&ca_chain_pem);
    for cert in ca_chain.certificates() {
        chain.add_certificate(cert.clone());
    }

    let output_content = chain.output(request.text);

    if let Some(ref dir) = request.output_dir {
        write_to_file(
            dir,
            &format!("{}_chain.pem", sanitize_filename(&request.identifier)),
            &output_content,
        )
    } else {
        println!("{output_content}");
        Ok(())
    }
}

/// Key export requires local storage lookup
async fn export_key(client: &VaultClient, request: &ExportCertificateRequest) -> Result<()> {
    let storage = LocalStorage::with_client(client.clone());

    let cert_record = find_certificate_in_storage(&storage, &request.identifier)
        .await?
        .ok_or_else(|| VaultCliError::InvalidInput(
            format!("Private key for '{}' not found in local storage. Keys are only available for certificates created with vault-rs.", request.identifier)
        ))?;

    let (_, private_key, _) = get_certificate_data_from_storage(&storage, &cert_record)
        .await
        .map_err(|e| VaultCliError::InvalidInput(format!("Failed to retrieve private key: {e}")))?;

    if let Some(ref dir) = request.output_dir {
        write_to_file(
            dir,
            &format!("{}.key", sanitize_filename(&request.identifier)),
            &private_key,
        )
    } else {
        println!("{private_key}");
        Ok(())
    }
}

/// Export certificate in various formats
pub async fn export_certificate(
    client: &VaultClient,
    request: ExportCertificateRequest,
) -> Result<()> {
    // Parse input PEM data to get the first certificate (leaf certificate)
    let parsed_certs = parse_certificate_chain(&request.pem_data);
    let certificate = if let Some(first_cert) = parsed_certs.first() {
        first_cert.clone()
    } else {
        return Err(VaultCliError::InvalidInput(
            "No valid certificate found in PEM data".to_string(),
        ));
    };

    match request.format {
        ExportFormat::Pem => export_pem_certificate(&request, certificate).await,
        ExportFormat::Crt => export_crt_certificate(&request, certificate).await,
        ExportFormat::Chain => export_certificate_chain(client, &request, certificate).await,
        ExportFormat::Key => export_key(client, &request).await,
        ExportFormat::P12 => export_p12(client, &request).await,
        ExportFormat::All => export_all(client, &request, certificate).await,
    }
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
