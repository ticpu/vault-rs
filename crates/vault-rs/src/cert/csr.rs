//! What a CSR itself carries, read directly off the request rather than
//! trusted from the caller's arguments (see docs/design-rationale.md, "The
//! issuing role, not the invocation, defines the issued identity").

use crate::cert::parser::CertificateParser;
use crate::utils::errors::{Result, VaultCliError};
use x509_parser::prelude::*;

pub struct CsrInfo {
    pub subject: String,
    pub subject_cn: Option<String>,
    pub sans: Vec<String>,
    pub key_description: String,
    /// Names of every extension the CSR asked for (via its extensionRequest
    /// attribute), independent of whether a role would honor any of them.
    pub requested_extensions: Vec<String>,
}

pub fn parse_csr_pem(pem_data: &str) -> Result<CsrInfo> {
    let (_, pem) = parse_x509_pem(pem_data.as_bytes())
        .map_err(|e| VaultCliError::CertParsing(format!("Failed to parse CSR PEM: {e}")))?;
    let (_, csr) = X509CertificationRequest::from_der(&pem.contents)
        .map_err(|e| VaultCliError::CertParsing(format!("Failed to parse CSR DER: {e}")))?;

    let info = &csr.certification_request_info;

    // Present-but-unreadable is not absent: reporting "CSR has no CN" for an
    // encoding this parser cannot decode sends the requester to fix the wrong
    // thing.
    let subject_cn = match info.subject.iter_common_name().next() {
        Some(attribute) => Some(attribute.as_str().map(str::to_string).map_err(|e| {
            VaultCliError::CertParsing(format!("CSR CN is present but not readable: {e}"))
        })?),
        None => None,
    };

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

    let requested_extensions = csr
        .requested_extensions()
        .into_iter()
        .flatten()
        .map(extension_name)
        .collect();

    let key_description = CertificateParser::describe_public_key(&info.subject_pki);

    Ok(CsrInfo {
        subject: info.subject.to_string(),
        subject_cn,
        sans,
        key_description,
        requested_extensions,
    })
}

/// A short name for a requested extension. Only the ones a signing decision
/// commonly turns on are spelled out; anything else falls back to its OID (for
/// `UnsupportedExtension`) or its variant name (everything x509-parser does
/// recognise but this tool has no opinion on).
fn extension_name(ext: &ParsedExtension) -> String {
    match ext {
        ParsedExtension::SubjectAlternativeName(_) => "subjectAltName".to_string(),
        ParsedExtension::KeyUsage(_) => "keyUsage".to_string(),
        ParsedExtension::ExtendedKeyUsage(_) => "extendedKeyUsage".to_string(),
        ParsedExtension::BasicConstraints(_) => "basicConstraints".to_string(),
        ParsedExtension::UnsupportedExtension { oid } => oid.to_string(),
        other => format!("{other:?}")
            .split(['(', ' '])
            .next()
            .unwrap_or("extension")
            .to_string(),
    }
}
