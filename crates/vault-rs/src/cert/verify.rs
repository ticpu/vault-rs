//! Verifies a certificate against the trust anchor a relying party actually
//! loads, rather than against the issuer's own hierarchy (see
//! docs/design-rationale.md, "Verification takes the peer's anchor, not the
//! issuer's own chain").

use crate::cert::ca_info::parse_ca_info;
use crate::utils::errors::{Result, VaultCliError};
use crate::utils::output::OutputFormat;
use crate::utils::pem::PemCertificateChain;
use crate::vault::client::VaultClient;
use chrono::Utc;
use rustls_pki_types::{CertificateDer, UnixTime};
use std::time::{Duration, SystemTime};
use webpki::{
    anchor_from_trusted_cert, EndEntityCert, Error as WebpkiError, ExtendedKeyUsageValidator,
    KeyPurposeIdIter, KeyUsage, ALL_VERIFICATION_ALGS,
};
use x509_parser::prelude::*;

pub struct VerifyRequest {
    pub certificate_file: String,
    pub against_ca: Option<String>,
    pub pki_mount: Option<String>,
    pub purpose: Option<Purpose>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    ClientAuth,
    ServerAuth,
}

impl Purpose {
    /// `required_if_present`, not `required`: a certificate carrying no
    /// extended key usage is unconstrained under RFC 5280, so demanding the OID
    /// outright would reject one that every relying party would accept. Vault
    /// intermediates typically carry no EKU either, and the validator checks
    /// them too.
    fn key_usage(self) -> KeyUsage {
        match self {
            Self::ClientAuth => KeyUsage::client_auth(),
            Self::ServerAuth => KeyUsage::server_auth(),
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::ClientAuth => "clientAuth",
            Self::ServerAuth => "serverAuth",
        }
    }
}

/// What the chain check demands of the leaf's extended key usage.
enum EkuPolicy {
    /// No `--purpose` given: the chain question is whether the anchor signs
    /// this certificate, not what it may be used for. An empty OID list is not
    /// the way to say that — `required_if_present` would then demand an OID no
    /// certificate carries and reject every leaf that declares any usage.
    Any,
    Named(KeyUsage),
}

impl ExtendedKeyUsageValidator for EkuPolicy {
    fn validate(&self, iter: KeyPurposeIdIter<'_, '_>) -> std::result::Result<(), WebpkiError> {
        match self {
            Self::Any => Ok(()),
            Self::Named(usage) => usage.validate(iter),
        }
    }
}

/// One reported check. `ok` drives the exit code; the detail explains it.
struct Check {
    name: &'static str,
    ok: bool,
    detail: String,
}

impl Check {
    fn new(name: &'static str, ok: bool, detail: impl Into<String>) -> Self {
        Self {
            name,
            ok,
            detail: detail.into(),
        }
    }
}

/// Returns whether every check passed; the caller maps that to an exit code.
pub async fn verify_certificate(
    client: Option<&VaultClient>,
    request: VerifyRequest,
    output: &OutputFormat,
) -> Result<bool> {
    let leaf_pem = std::fs::read_to_string(&request.certificate_file).map_err(|e| {
        VaultCliError::Storage(format!(
            "Failed to read certificate '{}': {e}",
            request.certificate_file
        ))
    })?;

    let anchor_pem = load_anchor(client, &request).await?;
    let bundle = PemCertificateChain::from_pem(&leaf_pem)?;
    let (leaf_pem_text, intermediate_pems) = split_leaf(&bundle, &request.certificate_file)?;

    let leaf_der = to_der(&leaf_pem_text, "certificate")?;
    let anchor_der = to_der(&anchor_pem, "trust anchor")?;
    let intermediate_ders = intermediate_pems
        .iter()
        .map(|pem| to_der(pem, "intermediate"))
        .collect::<Result<Vec<_>>>()?;

    let mut checks = vec![
        check_chain(&leaf_der, &anchor_der, &intermediate_ders, request.purpose)?,
        check_anchor(&leaf_pem_text, &anchor_pem, &intermediate_pems)?,
        check_expiry(&leaf_pem_text)?,
    ];
    if let Some(purpose) = request.purpose {
        checks.push(check_purpose(&leaf_pem_text, purpose)?);
    }

    let all_ok = checks.iter().all(|c| c.ok);
    let rows: Vec<Vec<String>> = checks
        .iter()
        .map(|c| {
            vec![
                c.name.to_string(),
                if c.ok { "OK" } else { "FAIL" }.to_string(),
                c.detail.clone(),
            ]
        })
        .collect();
    output.print_table(&rows);

    Ok(all_ok)
}

/// The anchor is whatever the relying party loads. A mount is the same choice
/// made in advance, so it is offered, but never as a silent default: without
/// either the command has nothing to verify against.
async fn load_anchor(client: Option<&VaultClient>, request: &VerifyRequest) -> Result<String> {
    match (&request.against_ca, &request.pki_mount) {
        (Some(path), _) => std::fs::read_to_string(path)
            .map_err(|e| VaultCliError::Storage(format!("Failed to read CA '{path}': {e}"))),
        (None, Some(mount)) => match client {
            Some(client) => Ok(client.get_ca_certificate(mount).await?),
            None => Err(VaultCliError::Config(
                "a mount was given but no Vault client was built".to_string(),
            )),
        },
        (None, None) => Err(VaultCliError::InvalidInput(
            "one of --against-ca or --pki-mount is required: verification needs an anchor"
                .to_string(),
        )),
    }
}

/// Splits a bundle into the leaf and any intermediates shipped alongside it,
/// which is how a fullchain file arrives.
fn split_leaf(bundle: &PemCertificateChain, path: &str) -> Result<(String, Vec<String>)> {
    let certificates = bundle.certificates();
    let Some((leaf, rest)) = certificates.split_first() else {
        return Err(VaultCliError::CertParsing(format!(
            "no certificate found in '{path}'"
        )));
    };

    Ok((
        leaf.pem_data().to_string(),
        rest.iter()
            .map(|cert| cert.pem_data().to_string())
            .collect(),
    ))
}

fn to_der(pem: &str, what: &str) -> Result<Vec<u8>> {
    let (_, parsed) = parse_x509_pem(pem.as_bytes())
        .map_err(|e| VaultCliError::CertParsing(format!("Failed to parse {what} PEM: {e}")))?;
    Ok(parsed.contents)
}

fn check_chain(
    leaf_der: &[u8],
    anchor_der: &[u8],
    intermediate_ders: &[Vec<u8>],
    purpose: Option<Purpose>,
) -> Result<Check> {
    let leaf = CertificateDer::from(leaf_der);
    let anchor_cert = CertificateDer::from(anchor_der);
    let intermediates: Vec<CertificateDer> = intermediate_ders
        .iter()
        .map(|der| CertificateDer::from(der.as_slice()))
        .collect();

    let anchor = anchor_from_trusted_cert(&anchor_cert)
        .map_err(|e| VaultCliError::CertParsing(format!("trust anchor is unusable: {e}")))?;
    let end_entity = EndEntityCert::try_from(&leaf)
        .map_err(|e| VaultCliError::CertParsing(format!("certificate is unusable: {e}")))?;

    let now = UnixTime::since_unix_epoch(Duration::from_secs(
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|e| VaultCliError::Config(format!("system clock is before the epoch: {e}")))?
            .as_secs(),
    ));

    let usage = purpose.map_or(EkuPolicy::Any, |purpose| {
        EkuPolicy::Named(purpose.key_usage())
    });

    match end_entity.verify_for_usage(
        ALL_VERIFICATION_ALGS,
        &[anchor],
        &intermediates,
        now,
        usage,
        None,
        None,
    ) {
        Ok(_) => Ok(Check::new(
            "chain",
            true,
            format!("{} intermediate(s) to the anchor", intermediates.len()),
        )),
        // This variant's Display dumps the OID lists as a debug struct; the
        // purpose check states the same thing in a line a person can read.
        Err(WebpkiError::RequiredEkuNotFoundContext(_)) => Ok(Check::new(
            "chain",
            false,
            "extended key usage does not permit the requested purpose",
        )),
        Err(e) => Ok(Check::new("chain", false, e.to_string())),
    }
}

/// Names the certificate that actually issued the leaf, which is what explains
/// a chain failure: a certificate can verify perfectly against its own
/// hierarchy and still be issued from a CA the relying party never loaded.
///
/// The leaf's authority key identifier matches its *immediate* issuer, so it
/// equals the anchor's subject key identifier only where the anchor issued the
/// leaf directly. Under an intermediate it matches that instead, which is not a
/// failure — comparing it against the anchor alone would report every
/// three-level hierarchy as broken.
fn check_anchor(leaf_pem: &str, anchor_pem: &str, intermediate_pems: &[String]) -> Result<Check> {
    let leaf = parse_ca_info(leaf_pem)?;
    let anchor = parse_ca_info(anchor_pem)?;

    // Not a failure: RFC 5280 does not require an authority key identifier, and
    // one given as issuer-and-serial carries no key id to compare. The chain
    // check verifies signatures either way, so treating absence as a failure
    // would reject certificates every relying party accepts.
    let Some(aki) = leaf.authority_key_identifier else {
        return Ok(Check::new(
            "anchor",
            true,
            "no authority key identifier to match; chain check governs",
        ));
    };

    if anchor.subject_key_identifier.as_deref() == Some(aki.as_str()) {
        return Ok(Check::new(
            "anchor",
            true,
            format!("AKI {aki} matches CA SKI"),
        ));
    }

    for pem in intermediate_pems {
        let intermediate = parse_ca_info(pem)?;
        if intermediate.subject_key_identifier.as_deref() == Some(aki.as_str()) {
            return Ok(Check::new(
                "anchor",
                true,
                format!(
                    "issued by {}, not the anchor directly",
                    intermediate.subject
                ),
            ));
        }
    }

    Ok(Check::new(
        "anchor",
        false,
        format!("AKI {aki} matches neither the CA nor any supplied intermediate"),
    ))
}

fn check_expiry(leaf_pem: &str) -> Result<Check> {
    let info = parse_ca_info(leaf_pem)?;
    let now = Utc::now();
    let day = info.not_after.format("%Y-%m-%d");

    Ok(if now > info.not_after {
        Check::new("expiry", false, format!("expired {day}"))
    } else if now < info.not_before {
        Check::new(
            "expiry",
            false,
            format!("not valid until {}", info.not_before.format("%Y-%m-%d")),
        )
    } else {
        let days = (info.not_after - now).num_days();
        Check::new("expiry", true, format!("{day} ({days}d)"))
    })
}

fn check_purpose(leaf_pem: &str, purpose: Purpose) -> Result<Check> {
    let metadata = crate::cert::CertificateParser::parse_pem(leaf_pem, "")?;
    let wanted = match purpose {
        Purpose::ClientAuth => "ClientAuth",
        Purpose::ServerAuth => "ServerAuth",
    };

    Ok(if metadata.extended_key_usage.is_empty() {
        // Unconstrained under RFC 5280, so this is a pass, but say why rather
        // than printing the same OK a declared usage would produce.
        Check::new(
            "purpose",
            true,
            format!("{} (no EKU: unconstrained)", purpose.label()),
        )
    } else if metadata.extended_key_usage.iter().any(|u| u == wanted) {
        Check::new("purpose", true, purpose.label())
    } else {
        Check::new(
            "purpose",
            false,
            format!(
                "{} not among {}",
                purpose.label(),
                metadata.extended_key_usage.join(", ")
            ),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn testdata(name: &str) -> String {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/cert/testdata/");
        std::fs::read_to_string(format!("{path}{name}.pem"))
            .unwrap_or_else(|e| panic!("missing fixture {name}.pem: {e}"))
    }

    fn der(name: &str) -> Vec<u8> {
        to_der(&testdata(name), "fixture").unwrap()
    }

    fn chain_check(leaf: &str, anchor: &str, purpose: Option<Purpose>) -> Check {
        check_chain(&der(leaf), &der(anchor), &[der("ca-intermediate")], purpose).unwrap()
    }

    #[test]
    fn a_leaf_verifies_against_its_own_root() {
        assert!(chain_check("leaf-client", "ca-root", None).ok);
    }

    #[test]
    fn a_leaf_fails_against_an_unrelated_root() {
        let check = chain_check("leaf-client", "ca-other-root", None);
        assert!(!check.ok, "{}", check.detail);
    }

    /// Guards the required vs required_if_present distinction: demanding the
    /// OID outright would reject a certificate RFC 5280 leaves unconstrained.
    #[test]
    fn an_eku_less_leaf_verifies_for_a_named_purpose() {
        let check = chain_check("leaf-noeku", "ca-root", Some(Purpose::ClientAuth));
        assert!(check.ok, "{}", check.detail);
    }

    #[test]
    fn a_server_leaf_fails_a_client_purpose() {
        let check = chain_check("leaf-server", "ca-root", Some(Purpose::ClientAuth));
        assert!(!check.ok, "{}", check.detail);
    }

    #[test]
    fn the_anchor_check_matches_aki_against_ski() {
        let direct =
            check_anchor(&testdata("leaf-client"), &testdata("ca-intermediate"), &[]).unwrap();
        assert!(direct.ok, "{}", direct.detail);

        let unrelated =
            check_anchor(&testdata("leaf-client"), &testdata("ca-other-root"), &[]).unwrap();
        assert!(!unrelated.ok);
    }

    /// Under an intermediate the leaf's AKI names that intermediate, not the
    /// root; comparing it against the anchor alone reported this as broken.
    #[test]
    fn an_intermediate_issuer_is_named_not_called_a_mismatch() {
        let check = check_anchor(
            &testdata("leaf-client"),
            &testdata("ca-root"),
            &[testdata("ca-intermediate")],
        )
        .unwrap();

        assert!(check.ok, "{}", check.detail);
        assert!(check.detail.contains("Intermediate"), "{}", check.detail);
    }

    #[test]
    fn purpose_reports_an_absent_eku_as_unconstrained() {
        let check = check_purpose(&testdata("leaf-noeku"), Purpose::ClientAuth).unwrap();
        assert!(check.ok);
        assert!(check.detail.contains("unconstrained"), "{}", check.detail);
    }

    #[test]
    fn fixtures_are_not_expired() {
        assert!(check_expiry(&testdata("leaf-client")).unwrap().ok);
    }

    #[test]
    fn a_fullchain_file_splits_into_leaf_and_intermediates() {
        let bundle = PemCertificateChain::from_pem(&testdata("chain-with-root")).unwrap();
        let (leaf, rest) = split_leaf(&bundle, "chain-with-root.pem").unwrap();
        assert!(leaf.contains("BEGIN CERTIFICATE"));
        assert_eq!(rest.len(), 2);
    }
}
