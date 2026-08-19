use crate::cert::csr::parse_csr_pem;
use crate::cert::plan::{build_plan, PlanInput};
use crate::cert::report::{describe_certificate, print_identity_fields};
use crate::cert::{CertificateParser, SerialNumber};
use crate::utils::errors::{Result, VaultCliError};
use crate::utils::pem::{PemCertificate, PemCertificateChain};
use crate::utils::prompt::confirm;
use crate::utils::{parse_comma_separated, resolve_crypto_type, validate_role_exists};
use crate::vault::client::VaultClient;
use crate::vault::PkiClient;
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
    pub dry_run: bool,
    pub yes: bool,
}

pub async fn sign_certificate_from_csr(
    client: &VaultClient,
    request: CsrSignRequest,
) -> Result<()> {
    // Use PKI mount directly - no system-specific suffixes
    let full_pki = request.pki.clone();

    // Auto-detect crypto type if not specified
    let detected_crypto = resolve_crypto_type(
        client,
        &full_pki,
        request.crypto.as_ref().map(|c| c.as_str()),
    )
    .await?;

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

    validate_role_exists(client, &full_pki, &request.role).await?;

    // Parse alt_names and ip_sans
    let alt_names_vec = parse_comma_separated(request.alt_names.as_deref());
    let ip_sans_vec = parse_comma_separated(request.ip_sans.as_deref());

    // Everything needed to rehearse or confirm the issuance: the role that
    // governs the identity, the CSR's own claims, and the issuer's name.
    let role_config = client.read_role(&full_pki, &request.role).await?;
    let csr_info = parse_csr_pem(&csr_content)?;
    let issuer_pem = client.get_ca_certificate(&full_pki).await?;
    let issuer_cn = CertificateParser::parse_pem(&issuer_pem, &full_pki)?.cn;

    let plan_input = PlanInput {
        role: &role_config,
        cn_arg: Some(&request.cn),
        crypto_arg: request.crypto.as_ref().map(|c| c.as_str()),
        alt_names_arg: alt_names_vec.as_deref().unwrap_or(&[]),
        ip_sans_arg: ip_sans_vec.as_deref().unwrap_or(&[]),
        ttl_arg: request.ttl.as_deref(),
        csr: Some(&csr_info),
        issuer_cn: &issuer_cn,
    };

    if request.dry_run {
        print_identity_fields(&build_plan(&plan_input));
        return Ok(());
    }

    confirm(
        &format!(
            "Sign a certificate for CSR '{}' with role '{}' on {full_pki}?",
            request.csr_file, request.role
        ),
        request.yes,
    )?;

    let ca_chain = client.get_ca_chain(&full_pki).await?;

    // Sign certificate using CSR
    let sign_request = crate::vault::pki_client::SignCertificateRequest {
        pki_mount: &full_pki,
        role: &request.role,
        common_name: &request.cn,
        csr_content: &csr_content,
        alt_names: alt_names_vec.clone(),
        ip_sans: ip_sans_vec,
        ttl: request.ttl.as_deref(),
    };

    let cert_data = client.sign_certificate(sign_request).await?;

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

    eprintln!(
        "✓ Certificate signed with serial: {}",
        SerialNumber::new(serial).as_colon_hex()
    );
    print_identity_fields(&describe_certificate(certificate)?);

    // Store locally unless --no-store
    use crate::utils::cert_utils::CertificateStorageHelper;

    let storage_helper = CertificateStorageHelper {
        serial: serial.to_string(),
        cn: request.cn.clone(),
        role: request.role.clone(),
        crypto: detected_crypto.clone(),
        sans: alt_names_vec.clone().unwrap_or_default(),
        no_store: request.no_store,
    };

    // CSR signing doesn't provide private key
    storage_helper
        .store_certificate(&full_pki, certificate, None, &ca_chain)
        .await?;
    if !request.no_store {
        eprintln!("✓ Certificate stored encrypted locally (without private key)");
    }

    // Export plain files if requested
    if let Some(export_dir) = request.export_plain {
        let export_path = Path::new(&export_dir);
        fs::create_dir_all(export_path)?;

        // Write certificate files (no private key for CSR signing)
        let pem_cert = PemCertificate::new(certificate.to_string());
        let pem_issuing_ca = PemCertificate::new(issuing_ca.to_string());
        let ca_chain_with_root = PemCertificateChain::from_pem(&ca_chain)?;
        let ca_chain_no_root = ca_chain_with_root.without_root()?;
        fs::write(
            export_path.join(format!("{}.crt", request.cn)),
            pem_cert.pem_data(),
        )?;
        fs::write(
            export_path.join(format!("{}.crt", request.pki)),
            pem_issuing_ca.pem_data(),
        )?;
        fs::write(
            export_path.join(format!("{}_chain.crt", request.pki)),
            ca_chain_no_root.pem_data(),
        )?;
        fs::write(
            export_path.join(format!("{}_chain-with-root.crt", request.pki)),
            ca_chain_with_root.pem_data(),
        )?;

        eprintln!("✓ Certificate files exported to: {export_dir}");
        eprintln!("Note: Private key not exported (CSR signing - key remains with requester)");

        if ca_chain_no_root.certificates().len() < ca_chain_with_root.certificates().len() {
            crate::cert::report::print_handoff_note(
                &format!("{}.crt", request.cn),
                &format!("{}.crt", request.pki),
                &format!("{}_chain-with-root.crt", request.pki),
            );
        }
    }

    Ok(())
}
