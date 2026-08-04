//! `cert inspect-csr`: reads a CSR on its own terms first, then — only when a
//! mount and role are given — layers on the same role-vs-invocation
//! provenance `--dry-run` shows for `cert sign` (see
//! docs/design-rationale.md, "The issuing role, not the invocation, defines
//! the issued identity").

use crate::cert::csr::{parse_csr_pem, CsrInfo};
use crate::cert::parser::CertificateParser;
use crate::cert::plan::{build_plan, PlanInput};
use crate::cert::report::{print_identity_fields, IdentityField};
use crate::utils::errors::{Result, VaultCliError};
use crate::vault::client::VaultClient;
use std::fs;

pub struct InspectCsrRequest {
    pub csr_file: String,
    pub pki_mount: Option<String>,
    pub role: Option<String>,
}

pub async fn inspect_csr(client: Option<&VaultClient>, request: InspectCsrRequest) -> Result<()> {
    let csr_content = fs::read_to_string(&request.csr_file).map_err(|e| {
        VaultCliError::Storage(format!(
            "Failed to read CSR file '{}': {e}",
            request.csr_file
        ))
    })?;
    let csr_info = parse_csr_pem(&csr_content)?;

    print_identity_fields(&csr_fields(&csr_info));

    let (Some(mount), Some(role)) = (request.pki_mount.as_deref(), request.role.as_deref()) else {
        return Ok(());
    };
    let Some(client) = client else {
        return Err(VaultCliError::InvalidInput(
            "inspect-csr: pki_mount and role given but no Vault client available".to_string(),
        ));
    };

    let role_config = client.read_role(mount, role).await?;
    let issuer_pem = client.get_ca_certificate(mount).await?;
    let issuer_cn = CertificateParser::parse_pem(&issuer_pem, mount)?.cn;

    // No separate --cn: the CSR's own subject is the closest thing to "the
    // invocation" this command has, so it plays that role in the plan too.
    let plan_input = PlanInput {
        role: &role_config,
        cn_arg: csr_info.subject_cn.as_deref().unwrap_or(""),
        crypto_arg: None,
        alt_names_arg: &[],
        ip_sans_arg: &[],
        ttl_arg: None,
        csr: Some(&csr_info),
        issuer_cn: &issuer_cn,
    };

    eprintln!();
    eprintln!("role '{role}' on {mount} would issue:");
    print_identity_fields(&build_plan(&plan_input));

    Ok(())
}

fn csr_fields(csr: &CsrInfo) -> Vec<IdentityField> {
    vec![
        IdentityField::plain("subject", csr.subject.clone()),
        IdentityField::plain("key", csr.key_description.clone()),
        IdentityField::plain(
            "san",
            if csr.sans.is_empty() {
                "none".to_string()
            } else {
                csr.sans.join(", ")
            },
        ),
        IdentityField::plain(
            "extensions",
            if csr.requested_extensions.is_empty() {
                "none".to_string()
            } else {
                csr.requested_extensions.join(", ")
            },
        ),
    ]
}
