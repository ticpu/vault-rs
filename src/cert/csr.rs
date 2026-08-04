//! What a CSR itself carries, read directly off the request rather than
//! trusted from the caller's arguments (see docs/design-rationale.md, "The
//! issuing role, not the invocation, defines the issued identity").

use crate::cert::parser::CertificateParser;
use crate::utils::errors::{Result, VaultCliError};
use x509_parser::prelude::*;

pub struct CsrInfo {
    pub subject_cn: Option<String>,
    pub sans: Vec<String>,
    pub key_description: String,
}

pub fn parse_csr_pem(pem_data: &str) -> Result<CsrInfo> {
    let (_, pem) = parse_x509_pem(pem_data.as_bytes())
        .map_err(|e| VaultCliError::CertParsing(format!("Failed to parse CSR PEM: {e}")))?;
    let (_, csr) = X509CertificationRequest::from_der(&pem.contents)
        .map_err(|e| VaultCliError::CertParsing(format!("Failed to parse CSR DER: {e}")))?;

    let info = &csr.certification_request_info;

    let subject_cn = info
        .subject
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(str::to_string);

    let sans = csr
        .requested_extensions()
        .into_iter()
        .flatten()
        .find_map(|ext| match ext {
            ParsedExtension::SubjectAlternativeName(san) => Some(
                san.general_names
                    .iter()
                    .filter_map(CertificateParser::format_general_name)
                    .collect(),
            ),
            _ => None,
        })
        .unwrap_or_default();

    let key_description = CertificateParser::describe_public_key(&info.subject_pki);

    Ok(CsrInfo {
        subject_cn,
        sans,
        key_description,
    })
}
