use crate::storage::local::{CertificateData, LocalStorage};
use crate::storage::metadata::{CertStatus, StorageCertificateMetadata};
use crate::utils::errors::{Result, VaultCliError};
use crate::vault::client::VaultClient;
use chrono::Utc;
use std::fs;
use std::path::Path;

pub struct CsrSignRequest {
    pub pki: String,
    pub cn: String,
    pub csr_file: String,
    pub role: String,
    pub crypto: Option<crate::cli::args::CryptoType>,
    pub alt_names: Option<String>,
    pub ip_sans: Option<String>,
    pub ttl: Option<String>,
    pub no_store: bool,
    pub export_plain: Option<String>,
}

pub async fn sign_certificate_from_csr(
    client: &VaultClient,
    token: &str,
    request: CsrSignRequest,
) -> Result<()> {
    // Use PKI mount directly - no system-specific suffixes
    let full_pki = request.pki.clone();

    // Auto-detect crypto type if not specified
    let detected_crypto = if let Some(crypto_type) = request.crypto {
        crypto_type.as_str().to_string()
    } else {
        tracing::info!("Auto-detecting crypto type for PKI mount: {full_pki}");
        let detected = client.detect_crypto_type(token, &full_pki).await?;
        tracing::info!("Detected crypto type: {detected}");
        detected
    };

    eprintln!("Signing certificate for CN: {}", request.cn);
    eprintln!("PKI: {full_pki} ({detected_crypto})");
    eprintln!("Role: {}", request.role);
    eprintln!("CSR file: {}", request.csr_file);

    if let Some(ref alt_names) = request.alt_names {
        eprintln!("Alt Names: {alt_names}");
    }
    if let Some(ref ip_sans) = request.ip_sans {
        eprintln!("IP SANs: {ip_sans}");
    }
    if let Some(ref ttl) = request.ttl {
        eprintln!("TTL: {ttl}");
    }

    // Read CSR from file
    let csr_content = fs::read_to_string(&request.csr_file).map_err(|e| {
        VaultCliError::Storage(format!(
            "Failed to read CSR file '{}': {e}",
            request.csr_file
        ))
    })?;

    // Validate CSR format (basic check)
    if !csr_content.contains("-----BEGIN CERTIFICATE REQUEST-----") {
        return Err(VaultCliError::Storage(format!(
            "Invalid CSR format in file '{}'. Expected PEM format.",
            request.csr_file
        )));
    }

    // Validate role exists (optional check with helpful error)
    if let Ok(available_roles) = client.list_roles(token, &full_pki).await {
        if !available_roles.is_empty() && !available_roles.contains(&request.role) {
            eprintln!(
                "Warning: Role '{}' not found in available roles for PKI '{full_pki}'",
                request.role
            );
            eprintln!("Available roles: {}", available_roles.join(", "));
            eprintln!("Continuing anyway - Vault will return an error if role is invalid.");
        }
    }

    // Parse alt_names and ip_sans
    let alt_names_vec = request.alt_names.as_ref().map(|names| {
        names
            .split(',')
            .map(|s| s.trim().to_string())
            .collect::<Vec<_>>()
    });

    let ip_sans_vec = request.ip_sans.as_ref().map(|ips| {
        ips.split(',')
            .map(|s| s.trim().to_string())
            .collect::<Vec<_>>()
    });

    // Sign certificate using CSR
    let sign_request = crate::vault::client::SignCertificateRequest {
        pki_mount: &full_pki,
        role: &request.role,
        common_name: &request.cn,
        csr_content: &csr_content,
        alt_names: alt_names_vec.clone(),
        ip_sans: ip_sans_vec,
        ttl: request.ttl.as_deref(),
    };

    let cert_data = client.sign_certificate(token, sign_request).await?;

    // Extract certificate components
    let certificate = cert_data["data"]["certificate"].as_str().ok_or_else(|| {
        VaultCliError::CertNotFound("Certificate data not found in response".to_string())
    })?;
    let issuing_ca = cert_data["data"]["issuing_ca"].as_str().ok_or_else(|| {
        VaultCliError::CertNotFound("Issuing CA not found in response".to_string())
    })?;
    let serial = cert_data["data"]["serial_number"].as_str().ok_or_else(|| {
        VaultCliError::CertNotFound("Serial number not found in response".to_string())
    })?;

    eprintln!("✓ Certificate signed with serial: {serial}");

    // Store locally unless --no-store
    if !request.no_store {
        let storage = LocalStorage::new(client.vault_addr().to_string());
        let metadata = StorageCertificateMetadata {
            serial: serial.to_string(),
            cn: request.cn.clone(),
            role: request.role.clone(),
            crypto: detected_crypto.clone(),
            created: Utc::now(),
            expires: Utc::now() + chrono::Duration::days(365), // Will be updated with actual expiry
            status: CertStatus::Active,
            sans: alt_names_vec.unwrap_or_default(),
        };

        // Get CA chain for storage
        let ca_chain = client.get_ca_chain(token, &full_pki).await?;

        // Note: For CSR signing, we don't have the private key, so we store empty string
        let cert_data = CertificateData {
            pki_mount: &full_pki,
            cn: &request.cn,
            certificate_pem: certificate,
            private_key_pem: "", // CSR signing doesn't provide private key
            ca_chain_pem: &ca_chain,
            metadata,
        };

        storage.store_certificate(token, cert_data).await?;

        eprintln!("✓ Certificate stored encrypted locally (without private key)");
    }

    // Export plain files if requested
    if let Some(export_dir) = request.export_plain {
        let export_path = Path::new(&export_dir);
        fs::create_dir_all(export_path)?;

        // Get CA chain for export
        let ca_chain = client.get_ca_chain(token, &full_pki).await?;

        // Write certificate files (no private key for CSR signing)
        fs::write(export_path.join(format!("{}.crt", request.cn)), certificate)?;
        fs::write(export_path.join(format!("{}.crt", request.pki)), issuing_ca)?;
        fs::write(
            export_path.join(format!("{}_chain.crt", request.pki)),
            &ca_chain,
        )?;

        eprintln!("✓ Certificate files exported to: {export_dir}");
        eprintln!("Note: Private key not exported (CSR signing - key remains with requester)");
    }

    Ok(())
}
