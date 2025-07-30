use crate::cli::args::CryptoType;
use crate::storage::local::{CertificateData, LocalStorage};
use crate::storage::metadata::{CertStatus, StorageCertificateMetadata};
use crate::utils::errors::{Result, VaultCliError};
use crate::vault::client::{IssueCertificateRequest, VaultClient};
use chrono::Utc;
use std::fs;
use std::path::Path;

pub struct CreateCertificateRequest {
    pub pki: String,
    pub cn: String,
    pub role: String,
    pub crypto: Option<CryptoType>,
    pub alt_names: Option<String>,
    pub ip_sans: Option<String>,
    pub ttl: Option<String>,
    pub no_store: bool,
    pub export_plain: Option<String>,
}

pub async fn create_certificate(
    client: &VaultClient,
    request: CreateCertificateRequest,
) -> Result<()> {
    // Use PKI mount directly - no system-specific suffixes
    let full_pki = request.pki.clone();

    // Auto-detect crypto type if not specified
    let detected_crypto = if let Some(crypto_type) = request.crypto {
        crypto_type.as_str().to_string()
    } else {
        tracing::info!("Auto-detecting crypto type for PKI mount: {full_pki}");
        let detected = client.detect_crypto_type(&full_pki).await?;
        tracing::info!("Detected crypto type: {detected}");
        detected
    };

    eprintln!("Creating certificate for CN: {}", request.cn);
    eprintln!("PKI: {full_pki} ({detected_crypto})");
    eprintln!("Role: {}", request.role);

    if let Some(ref alt_names) = request.alt_names {
        eprintln!("Alt Names: {alt_names}");
    }
    if let Some(ref ip_sans) = request.ip_sans {
        eprintln!("IP SANs: {ip_sans}");
    }
    if let Some(ref ttl) = request.ttl {
        eprintln!("TTL: {ttl}");
    }

    // Validate role exists (optional check with helpful error)
    if let Ok(available_roles) = client.list_roles(&full_pki).await {
        if !available_roles.is_empty() && !available_roles.contains(&request.role) {
            eprintln!(
                "Warning: Role '{}' not found in available roles for PKI '{full_pki}'",
                request.role
            );
            eprintln!("Available roles: {}", available_roles.join(", "));
            eprintln!("Continuing anyway - Vault will return an error if role is invalid.");
        }
    }

    // Issue certificate from Vault
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

    let issue_request = IssueCertificateRequest {
        pki_mount: &full_pki,
        role: &request.role,
        common_name: &request.cn,
        alt_names: alt_names_vec.clone(),
        ip_sans: ip_sans_vec,
        ttl: request.ttl.as_deref(),
    };

    let cert_data = client.issue_certificate(issue_request).await?;

    // Extract certificate components
    let certificate = cert_data["data"]["certificate"]
        .as_str()
        .ok_or_else(|| VaultCliError::CertNotFound("Certificate data not found".to_string()))?;
    let private_key = cert_data["data"]["private_key"]
        .as_str()
        .ok_or_else(|| VaultCliError::CertNotFound("Private key not found".to_string()))?;
    let issuing_ca = cert_data["data"]["issuing_ca"]
        .as_str()
        .ok_or_else(|| VaultCliError::CertNotFound("Issuing CA not found".to_string()))?;
    let serial = cert_data["data"]["serial_number"]
        .as_str()
        .ok_or_else(|| VaultCliError::CertNotFound("Serial number not found".to_string()))?;

    // Display serial without colons for consistency with lookup/export commands
    let display_serial = serial.replace(':', "");
    eprintln!("✓ Certificate issued with serial: {display_serial}");

    // Store locally unless --no-store
    if !request.no_store {
        let storage = LocalStorage::new().await;
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
        let ca_chain = client.get_ca_chain(&full_pki).await?;

        let cert_data = CertificateData {
            pki_mount: &full_pki,
            cn: &request.cn,
            certificate_pem: certificate,
            private_key_pem: private_key,
            ca_chain_pem: &ca_chain,
            metadata,
        };
        storage.store_certificate(cert_data).await?;
        eprintln!("✓ Certificate stored encrypted locally");
    }

    // Export plain files if requested
    if let Some(export_dir) = request.export_plain {
        let export_path = Path::new(&export_dir);
        fs::create_dir_all(export_path)?;

        // Get CA chain for export
        let ca_chain = client.get_ca_chain(&full_pki).await?;

        // Write certificate files
        fs::write(export_path.join(format!("{}.crt", request.cn)), certificate)?;
        fs::write(export_path.join(format!("{}.key", request.cn)), private_key)?;
        fs::write(
            export_path.join(format!("{}.pem", request.cn)),
            format!("{private_key}{certificate}"),
        )?;
        fs::write(export_path.join(format!("{}.crt", request.pki)), issuing_ca)?;
        fs::write(
            export_path.join(format!("{}_chain.crt", request.pki)),
            &ca_chain,
        )?;

        // Create P12 file using OpenSSL (like vlt.sh)
        let p12_file = export_path.join(format!("{}.p12", request.cn));
        let _ =
            crate::utils::create_p12_file(&p12_file, private_key, certificate, issuing_ca, true);

        eprintln!("✓ Plain files exported to: {export_dir}");
    }

    Ok(())
}
