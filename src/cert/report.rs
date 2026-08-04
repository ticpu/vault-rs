//! Shared rendering for an issuance's identity: what `--dry-run` predicts and
//! what a completed sign/create actually produced use the same field shape,
//! so the two are directly comparable (see docs/design-rationale.md, "The
//! issuing role, not the invocation, defines the issued identity" and "The
//! issued identity is the report, not its serial").

use crate::cert::parser::CertificateParser;
use crate::utils::errors::{Result, VaultCliError};
use chrono::{DateTime, Utc};
use x509_parser::prelude::*;

const LABEL_WIDTH: usize = 10;
const VALUE_WIDTH: usize = 30;

/// One labeled fact about an issuance. `annotation` is a single inline note;
/// `details` breaks a field down by source when more than one applies (e.g. a
/// subject's CN and its OU/O/C come from different places).
pub struct IdentityField {
    pub label: &'static str,
    pub value: String,
    pub annotation: Option<String>,
    pub details: Vec<(String, String)>,
}

impl IdentityField {
    pub fn plain(label: &'static str, value: impl Into<String>) -> Self {
        Self {
            label,
            value: value.into(),
            annotation: None,
            details: Vec::new(),
        }
    }

    pub fn annotated(
        label: &'static str,
        value: impl Into<String>,
        annotation: impl Into<String>,
    ) -> Self {
        Self {
            label,
            value: value.into(),
            annotation: Some(annotation.into()),
            details: Vec::new(),
        }
    }

    /// Build a field from values that may come from more than one source: a
    /// single source becomes an inline annotation, several become a
    /// per-source breakdown so no source is misattributed to another.
    pub fn from_sourced_values(
        label: &'static str,
        entries: Vec<(String, String)>,
        empty_note: Option<&str>,
    ) -> Self {
        if entries.is_empty() {
            return Self {
                label,
                value: "none".to_string(),
                annotation: empty_note.map(str::to_string),
                details: Vec::new(),
            };
        }

        let mut sources = Vec::new();
        for (_, source) in &entries {
            if !sources.contains(source) {
                sources.push(source.clone());
            }
        }

        let value = entries
            .iter()
            .map(|(v, _)| v.as_str())
            .collect::<Vec<_>>()
            .join(", ");

        if let [only] = sources.as_slice() {
            return Self::annotated(label, value, only.clone());
        }

        let details = sources
            .into_iter()
            .map(|source| {
                let values = entries
                    .iter()
                    .filter(|(_, s)| *s == source)
                    .map(|(v, _)| v.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                (values, source)
            })
            .collect();

        Self {
            label,
            value,
            annotation: None,
            details,
        }
    }
}

/// Print the fields to stderr: a rehearsal or report is status for a person,
/// never data (see docs/design-rationale.md, "Austerity applies to the data
/// stream only").
pub fn print_identity_fields(fields: &[IdentityField]) {
    for field in fields {
        match &field.annotation {
            Some(note) => eprintln!(
                "{:<LABEL_WIDTH$}{:<VALUE_WIDTH$}({note})",
                field.label, field.value
            ),
            None => eprintln!("{:<LABEL_WIDTH$}{}", field.label, field.value),
        }

        if !field.details.is_empty() {
            let sub_width = field
                .details
                .iter()
                .map(|(sub, _)| sub.chars().count())
                .max()
                .unwrap_or(0)
                + 2;
            for (sub_label, text) in &field.details {
                eprintln!("{:LABEL_WIDTH$}{:<sub_width$}{text}", "", sub_label);
            }
        }
    }
}

/// Describe a just-issued leaf certificate with the same field shape as
/// `--dry-run`'s plan. Independent of `CertificateMetadata`: the cache-facing
/// struct only carries a CN, not the full subject DN or key description this
/// report needs.
pub fn describe_certificate(pem: &str) -> Result<Vec<IdentityField>> {
    let (_, pem_obj) = parse_x509_pem(pem.as_bytes())
        .map_err(|e| VaultCliError::CertParsing(format!("Failed to parse certificate PEM: {e}")))?;
    let (_, cert) = X509Certificate::from_der(&pem_obj.contents)
        .map_err(|e| VaultCliError::CertParsing(format!("Failed to parse certificate DER: {e}")))?;

    let eku = CertificateParser::extract_extended_key_usage(&cert)?;
    let sans = CertificateParser::extract_sans(&cert)?;
    let key = CertificateParser::describe_public_key(cert.public_key());

    let not_before = format_time(cert.validity().not_before.timestamp());
    let not_after = format_time(cert.validity().not_after.timestamp());

    Ok(vec![
        IdentityField::plain("subject", cert.subject().to_string()),
        IdentityField::plain(
            "eku",
            if eku.is_empty() {
                "none".to_string()
            } else {
                eku.join(", ")
            },
        ),
        IdentityField::plain(
            "san",
            if sans.is_empty() {
                "none".to_string()
            } else {
                sans.join(", ")
            },
        ),
        IdentityField::plain("validity", format!("{not_before} to {not_after}")),
        IdentityField::plain("key", key),
        IdentityField::plain("issuer", cert.issuer().to_string()),
    ])
}

/// After `--export-plain` writes a chain containing the internal root, name
/// which file is safe to hand a peer and which is not (see
/// docs/design-rationale.md, "Chain artifacts separate internal configuration
/// from external handoff").
pub fn print_handoff_note(
    leaf_filename: &str,
    issuer_filename: &str,
    chain_with_root_filename: &str,
) {
    eprintln!(
        "Send: {leaf_filename} (leaf). Add {issuer_filename} if the peer cannot find the issuer."
    );
    eprintln!("Do not send {chain_with_root_filename} externally - it contains the internal root.");
}

fn format_time(timestamp: i64) -> String {
    DateTime::<Utc>::from_timestamp(timestamp, 0)
        .map(|t| t.format("%Y-%m-%d %H:%M UTC").to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn testdata(name: &str) -> String {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/cert/testdata/");
        std::fs::read_to_string(format!("{path}{name}.pem"))
            .unwrap_or_else(|e| panic!("missing fixture {name}.pem: {e}"))
    }

    fn field<'a>(fields: &'a [IdentityField], label: &str) -> &'a IdentityField {
        fields
            .iter()
            .find(|f| f.label == label)
            .unwrap_or_else(|| panic!("no {label} field"))
    }

    #[test]
    fn describes_the_actual_leaf_not_just_its_serial() {
        let fields = describe_certificate(&testdata("eku-client")).unwrap();

        assert_eq!(
            field(&fields, "subject").value,
            "C=CA, O=Example Org, CN=eku-client"
        );
        assert_eq!(field(&fields, "eku").value, "ClientAuth");
        assert_eq!(field(&fields, "san").value, "eku-client.example.test");
        assert_eq!(field(&fields, "key").value, "EC prime256v1");
        assert_eq!(
            field(&fields, "issuer").value,
            "C=CA, O=Example Org, CN=eku-client"
        );
    }

    #[test]
    fn absent_eku_and_san_read_as_none_not_omitted() {
        let fields = describe_certificate(&testdata("eku-none")).unwrap();
        assert_eq!(field(&fields, "eku").value, "none");
    }
}
