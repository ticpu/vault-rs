use crate::cert::parser::CertificateParser;
use crate::utils::errors::{Result, VaultCliError};
use crate::utils::output::OutputFormat;
use crate::vault::client::VaultClient;
use crate::vault::PkiClient;
use chrono::{DateTime, Utc};
use x509_parser::der_parser::oid;
use x509_parser::prelude::*;

const SUBJECT_KEY_IDENTIFIER_OID: oid::Oid = oid!(2.5.29 .14);
const AUTHORITY_KEY_IDENTIFIER_OID: oid::Oid = oid!(2.5.29 .35);
const AUTHORITY_INFO_ACCESS_OID: oid::Oid = oid!(1.3.6 .1 .5 .5 .7 .1 .1);
const CRL_DISTRIBUTION_POINTS_OID: oid::Oid = oid!(2.5.29 .31);

/// The CA's identity, as needed to match it against a relying party's trust
/// anchor: SKI is what a peer's AKI must match.
pub struct CaCertInfo {
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub subject_key_identifier: Option<String>,
    pub authority_key_identifier: Option<String>,
    pub aia_urls: Vec<String>,
    pub crl_urls: Vec<String>,
}

/// Fetch and parse a PKI mount's CA certificate.
pub async fn show_ca_info(
    client: &VaultClient,
    pki_mount: &str,
    output: &OutputFormat,
) -> Result<()> {
    let pem = client.get_ca_certificate(pki_mount).await?;
    let info = parse_ca_info(&pem)?;

    let mut pairs: Vec<(String, String)> = vec![
        ("subject".to_string(), info.subject),
        ("issuer".to_string(), info.issuer),
        ("serial".to_string(), info.serial),
        (
            "not_before".to_string(),
            info.not_before.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        ),
        (
            "not_after".to_string(),
            info.not_after.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        ),
    ];

    if let Some(ski) = info.subject_key_identifier {
        pairs.push(("subject_key_identifier".to_string(), ski));
    }
    if let Some(aki) = info.authority_key_identifier {
        pairs.push(("authority_key_identifier".to_string(), aki));
    }
    if !info.aia_urls.is_empty() {
        pairs.push(("aia".to_string(), info.aia_urls.join(",")));
    }
    if !info.crl_urls.is_empty() {
        pairs.push((
            "crl_distribution_points".to_string(),
            info.crl_urls.join(","),
        ));
    }

    output.print_key_value(&pairs);
    Ok(())
}

/// Parse a CA certificate's identity out of its PEM data.
pub fn parse_ca_info(pem_data: &str) -> Result<CaCertInfo> {
    let (_, pem) = parse_x509_pem(pem_data.as_bytes())
        .map_err(|e| VaultCliError::CertParsing(format!("Failed to parse PEM certificate: {e}")))?;
    let (_, cert) = X509Certificate::from_der(&pem.contents)
        .map_err(|e| VaultCliError::CertParsing(format!("DER parsing error: {e}")))?;

    let not_before =
        crate::cert::parser::timestamp(cert.validity().not_before.timestamp(), "notBefore")?;
    let not_after =
        crate::cert::parser::timestamp(cert.validity().not_after.timestamp(), "notAfter")?;

    Ok(CaCertInfo {
        subject: cert.subject().to_string(),
        issuer: cert.issuer().to_string(),
        serial: crate::cert::SerialNumber::new(&hex::encode(cert.serial.to_bytes_be()))
            .as_colon_hex(),
        not_before,
        not_after,
        subject_key_identifier: extract_ski(&cert)?,
        authority_key_identifier: extract_aki(&cert)?,
        aia_urls: extract_aia_urls(&cert)?,
        crl_urls: extract_crl_urls(&cert)?,
    })
}

/// Colon-separated uppercase hex, the form `openssl x509` prints, so SKI/AKI
/// can be eyeballed against its output directly.
fn hex_colon_upper(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn extract_ski(cert: &X509Certificate) -> Result<Option<String>> {
    let Some(der) = CertificateParser::extension(cert, &SUBJECT_KEY_IDENTIFIER_OID) else {
        return Ok(None);
    };
    let ski: KeyIdentifier = CertificateParser::parse_extension(der, "subjectKeyIdentifier")?;
    Ok(Some(hex_colon_upper(ski.0)))
}

fn extract_aki(cert: &X509Certificate) -> Result<Option<String>> {
    let Some(der) = CertificateParser::extension(cert, &AUTHORITY_KEY_IDENTIFIER_OID) else {
        return Ok(None);
    };
    let aki: AuthorityKeyIdentifier =
        CertificateParser::parse_extension(der, "authorityKeyIdentifier")?;
    Ok(aki.key_identifier.map(|kid| hex_colon_upper(kid.0)))
}

fn extract_aia_urls(cert: &X509Certificate) -> Result<Vec<String>> {
    let Some(der) = CertificateParser::extension(cert, &AUTHORITY_INFO_ACCESS_OID) else {
        return Ok(Vec::new());
    };
    let aia: AuthorityInfoAccess = CertificateParser::parse_extension(der, "authorityInfoAccess")?;

    Ok(aia
        .accessdescs
        .iter()
        .filter_map(|desc| match &desc.access_location {
            GeneralName::URI(uri) => Some((*uri).to_string()),
            _ => None,
        })
        .collect())
}

fn extract_crl_urls(cert: &X509Certificate) -> Result<Vec<String>> {
    let Some(der) = CertificateParser::extension(cert, &CRL_DISTRIBUTION_POINTS_OID) else {
        return Ok(Vec::new());
    };
    let crl: CRLDistributionPoints =
        CertificateParser::parse_extension(der, "cRLDistributionPoints")?;

    Ok(crl
        .points
        .iter()
        .filter_map(|point| point.distribution_point.as_ref())
        .flat_map(|dp| match dp {
            DistributionPointName::FullName(names) => names.as_slice(),
            DistributionPointName::NameRelativeToCRLIssuer(_) => &[],
        })
        .filter_map(|name| match name {
            GeneralName::URI(uri) => Some((*uri).to_string()),
            _ => None,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn include_testdata(name: &str) -> String {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/cert/testdata/");
        std::fs::read_to_string(format!("{path}{name}.pem"))
            .unwrap_or_else(|e| panic!("missing fixture {name}.pem: {e}"))
    }

    fn fixture(name: &str) -> CaCertInfo {
        let pem = include_testdata(name);
        parse_ca_info(&pem).expect("fixture should parse")
    }

    #[test]
    fn root_ca_carries_a_self_referential_ski_and_aki() {
        let root = fixture("ca-root");
        let ski = root.subject_key_identifier.expect("root has an SKI");
        let aki = root.authority_key_identifier.expect("root has an AKI");
        // openssl generated the root's AKI from its own SKI: self-signed.
        assert_eq!(ski, aki);
        assert!(ski.contains(':'), "hex should be colon-separated: {ski}");
        assert_eq!(ski, ski.to_uppercase(), "hex should be uppercase: {ski}");
    }

    #[test]
    fn intermediate_aki_matches_root_ski() {
        let root = fixture("ca-root");
        let intermediate = fixture("ca-intermediate");
        assert_eq!(
            intermediate.authority_key_identifier,
            root.subject_key_identifier
        );
        assert_ne!(
            intermediate.subject_key_identifier,
            root.subject_key_identifier
        );
    }

    #[test]
    fn subject_and_issuer_come_from_the_certificate() {
        let intermediate = fixture("ca-intermediate");
        assert!(intermediate.subject.contains("Example Intermediate CA"));
        assert!(intermediate.issuer.contains("Example Root CA"));
    }

    #[test]
    fn fixtures_without_aia_or_crl_report_empty() {
        let root = fixture("ca-root");
        assert!(root.aia_urls.is_empty());
        assert!(root.crl_urls.is_empty());
    }
}
