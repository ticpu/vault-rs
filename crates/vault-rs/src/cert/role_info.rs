//! What a PKI role will actually do to the next certificate it issues.
//!
//! `cert list-roles` gives names, and reading the role path gives forty fields
//! in no particular order. Neither says which of them decide the issued
//! identity, which is the question being asked.

use crate::cert::parser::CertificateParser;
use crate::cert::plan::{build_plan, PlanInput};
use crate::cert::report::identity_field_lines;
use crate::utils::errors::Result;
use crate::utils::output::OutputFormat;
use crate::vault::client::VaultClient;

/// Report the identity a role governs.
///
/// Rendered by the same builder `--dry-run` uses, with no CSR and no
/// invocation to attribute anything to. That is the point rather than reuse
/// for its own sake: the annotations say which fields come from the role and
/// which a request could still influence, and a second renderer would drift
/// from the rehearsal it is supposed to agree with.
pub async fn show_role_info(
    client: &VaultClient,
    pki_mount: &str,
    role: &str,
    output: &OutputFormat,
) -> Result<()> {
    // The whole record, not the parsed subset: the struct models what governs
    // an identity, and serializing it would drop every other field the role
    // carries without saying so.
    if output.json {
        let raw = client.get(&format!("{pki_mount}/roles/{role}")).await?;
        return Ok(output.print_json(&raw)?);
    }

    let role_config = client.read_role(pki_mount, role).await?;
    let issuer_pem = client.get_ca_certificate(pki_mount).await?;
    let issuer_cn = CertificateParser::parse_pem(&issuer_pem, pki_mount)?.cn;

    let fields = build_plan(&PlanInput {
        role: &role_config,
        cn_arg: None,
        crypto_arg: None,
        alt_names_arg: &[],
        ip_sans_arg: &[],
        ttl_arg: None,
        csr: None,
        issuer_cn: &issuer_cn,
    });

    // Stdout: this report is what the command was asked for, unlike the
    // rehearsal the same fields render for beside an issuance.
    output.print_list(&identity_field_lines(&fields));
    Ok(())
}
