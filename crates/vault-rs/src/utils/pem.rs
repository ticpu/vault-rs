use crate::utils::errors::{Result, VaultCliError};
use std::io::Write;
use std::process::{Command, Stdio};
use x509_parser::pem::parse_x509_pem;
use x509_parser::prelude::*;

#[derive(Debug, Clone)]
pub struct PemCertificate {
    pem_data: String,
}

/// Represents a PEM-encoded private key (never generates text output for security)
#[derive(Debug, Clone)]
pub struct PemPrivateKey {
    pem_data: String,
}

#[derive(Debug, Clone)]
pub struct PemCertificateChain {
    certificates: Vec<PemCertificate>,
}

impl PemCertificate {
    pub fn new(pem_data: String) -> Self {
        Self {
            pem_data: normalize_pem(&pem_data),
        }
    }

    pub fn pem_data(&self) -> &str {
        &self.pem_data
    }

    pub fn generate_text(&self) -> Result<String> {
        let line_8 = 483;
        let line_length = 64;

        if self.pem_data.len() >= line_8 + line_length {
            tracing::debug!(
                "Invoking openssl for PEM {}",
                self.pem_data[line_8..line_8 + line_length].to_string()
            );
        } else {
            tracing::debug!("PEM data is too short");
        }

        let mut child = Command::new("openssl")
            .args(["x509", "-text"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|e| {
                VaultCliError::InvalidInput(format!("Failed to execute openssl command: {e}"))
            })?;

        if let Some(stdin) = child.stdin.as_mut() {
            stdin.write_all(self.pem_data.as_bytes()).map_err(|e| {
                VaultCliError::InvalidInput(format!("Failed to write to openssl stdin: {e}"))
            })?;
        }

        let output = child.wait_with_output().map_err(|e| {
            VaultCliError::InvalidInput(format!("Failed to read openssl output: {e}"))
        })?;

        if !output.status.success() {
            let error_msg = String::from_utf8_lossy(&output.stderr);
            return Err(VaultCliError::InvalidInput(format!(
                "OpenSSL command failed: {error_msg}"
            )));
        }

        let text_output = String::from_utf8_lossy(&output.stdout);
        Ok(text_output.to_string())
    }

    pub fn output(&self, include_text: bool) -> String {
        if include_text {
            match self.generate_text() {
                Ok(text) => text,
                Err(e) => {
                    tracing::warn!("Failed to generate OpenSSL text output: {e}, using PEM only");
                    self.pem_data.clone()
                }
            }
        } else {
            self.pem_data.clone()
        }
    }
}

impl PemPrivateKey {
    pub fn new(pem_data: String) -> Self {
        Self {
            pem_data: normalize_pem(&pem_data),
        }
    }

    pub fn pem_data(&self) -> &str {
        &self.pem_data
    }

    /// Output private key (never includes text for security reasons)
    pub fn output(&self, _include_text: bool) -> String {
        self.pem_data.clone()
    }
}

impl PemCertificateChain {
    pub fn new() -> Self {
        Self {
            certificates: Vec::new(),
        }
    }

    /// Create a chain from one blob holding several concatenated certificates,
    /// which is how Vault returns `ca_chain`.
    pub fn from_pem(pem_data: &str) -> Result<Self> {
        Ok(Self {
            certificates: parse_certificate_chain(pem_data)?,
        })
    }

    pub fn add_certificate(&mut self, cert: PemCertificate) {
        self.certificates.push(cert);
    }

    pub fn certificates(&self) -> &[PemCertificate] {
        &self.certificates
    }

    /// Output the entire chain with optional text for the first certificate only
    pub fn output(&self, include_text: bool) -> String {
        let mut result = String::new();

        for (i, cert) in self.certificates.iter().enumerate() {
            let cert_text = include_text && i == 0;
            result.push_str(&cert.output(cert_text));
        }

        result
    }

    pub fn pem_data(&self) -> String {
        self.certificates
            .iter()
            .map(|cert| cert.pem_data())
            .collect::<Vec<_>>()
            .join("")
    }

    /// This chain with self-signed roots dropped, for handoff outside this trust
    /// boundary (see docs/design-rationale.md, "Chain artifacts separate internal
    /// configuration from external handoff"). Scans every certificate; Vault's
    /// `ca_chain` ordering is not guaranteed and the root may be absent entirely.
    pub fn without_root(&self) -> Result<Self> {
        let mut result = Self::new();
        for cert in &self.certificates {
            if !is_self_signed(cert)? {
                result.add_certificate(cert.clone());
            }
        }
        Ok(result)
    }
}

/// True if a certificate's subject equals its issuer, i.e. a self-signed root.
/// Compares the full raw DN, not `CertificateMetadata`'s CN-reduced subject/issuer,
/// which misclassifies an intermediate sharing a CN with its root.
pub fn is_self_signed(cert: &PemCertificate) -> Result<bool> {
    let (_, pem) = parse_x509_pem(cert.pem_data().as_bytes())
        .map_err(|e| VaultCliError::CertParsing(format!("Failed to parse PEM: {e}")))?;
    let (_, x509) = X509Certificate::from_der(&pem.contents)
        .map_err(|e| VaultCliError::CertParsing(format!("Failed to parse DER: {e}")))?;

    Ok(x509.subject().as_raw() == x509.issuer().as_raw())
}

impl Default for PemCertificateChain {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct PemCertificateBundle {
    private_key: Option<PemPrivateKey>,
    certificate: PemCertificate,
    ca_chain: PemCertificateChain,
}

impl PemCertificateBundle {
    pub fn new(
        private_key: Option<PemPrivateKey>,
        certificate: PemCertificate,
        ca_chain: PemCertificateChain,
    ) -> Self {
        Self {
            private_key,
            certificate,
            ca_chain,
        }
    }

    pub fn output(&self, include_text: bool) -> String {
        let mut result = String::new();

        if let Some(key) = &self.private_key {
            result.push_str(&key.output(false)); // Never include text for private keys
        }

        result.push_str(&self.certificate.output(include_text));

        result.push_str(&self.ca_chain.output(false));

        result
    }

    pub fn certificate(&self) -> &PemCertificate {
        &self.certificate
    }

    pub fn private_key(&self) -> Option<&PemPrivateKey> {
        self.private_key.as_ref()
    }

    pub fn ca_chain(&self) -> &PemCertificateChain {
        &self.ca_chain
    }
}

fn normalize_pem(pem_data: &str) -> String {
    let trimmed = pem_data.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    if trimmed.ends_with('\n') {
        trimmed.to_string()
    } else {
        format!("{trimmed}\n")
    }
}

/// Parse multiple certificates from a PEM string.
///
/// A block that does not end, or does not parse, is an error rather than a
/// shorter chain, which a caller cannot tell from a chain of that length.
pub fn parse_certificate_chain(pem_data: &str) -> Result<Vec<PemCertificate>> {
    let mut certificates = Vec::new();

    for block in pem_blocks(pem_data)? {
        if block.label != CERTIFICATE_LABEL {
            continue;
        }

        parse_x509_pem(block.text.as_bytes()).map_err(|e| {
            VaultCliError::CertParsing(format!(
                "PEM block {} does not parse: {e}",
                certificates.len() + 1
            ))
        })?;
        certificates.push(PemCertificate::new(block.text));
    }

    Ok(certificates)
}

pub const CERTIFICATE_LABEL: &str = "CERTIFICATE";

/// One `-----BEGIN <label>-----` … `-----END <label>-----` block.
#[derive(Debug, Clone)]
pub struct PemBlock {
    pub label: String,
    /// The block itself, markers included, newline-terminated.
    pub text: String,
}

/// Every labelled block in a PEM file, in the order they appear.
///
/// One scanner, because a second one written beside it for a different label
/// would silently disagree with this one about the same file. Blocks whose
/// label the caller does not want are its business to skip: a file may
/// legitimately hold a key, a chain and provenance together.
pub fn pem_blocks(pem_data: &str) -> Result<Vec<PemBlock>> {
    let mut blocks: Vec<PemBlock> = Vec::new();
    let mut open: Option<(String, String)> = None;

    for line in pem_data.lines() {
        let trimmed = line.trim();

        if let Some(label) = trimmed
            .strip_prefix("-----BEGIN ")
            .and_then(|rest| rest.strip_suffix("-----"))
        {
            if let Some((open_label, _)) = open {
                return Err(VaultCliError::CertParsing(format!(
                    "PEM block {} begins before the {open_label} block ends",
                    blocks.len() + 1
                )));
            }
            open = Some((label.to_string(), format!("{trimmed}\n")));
            continue;
        }

        if let Some(label) = trimmed
            .strip_prefix("-----END ")
            .and_then(|rest| rest.strip_suffix("-----"))
        {
            // A stray END with nothing open is a malformed file, not a block:
            // read as one it reaches the certificate parser as a single line
            // and comes back as unparseable base64, naming the wrong problem.
            let Some((open_label, mut text)) = open.take() else {
                return Err(VaultCliError::CertParsing(format!(
                    "PEM block {} ends with no matching BEGIN {label}",
                    blocks.len() + 1
                )));
            };
            if open_label != label {
                return Err(VaultCliError::CertParsing(format!(
                    "PEM block {} opens as {open_label} and closes as {label}",
                    blocks.len() + 1
                )));
            }
            text.push_str(trimmed);
            text.push('\n');
            blocks.push(PemBlock {
                label: open_label,
                text,
            });
            continue;
        }

        // Anything outside a block is explanatory text, which the format
        // permits and every reader here already skips.
        if let Some((_, ref mut text)) = open {
            text.push_str(line);
            text.push('\n');
        }
    }

    match open {
        Some((label, _)) => Err(VaultCliError::CertParsing(format!(
            "PEM block {} has no END {label} line",
            blocks.len() + 1
        ))),
        None => Ok(blocks),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn testdata(name: &str) -> String {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/cert/testdata/");
        std::fs::read_to_string(format!("{path}{name}.pem"))
            .unwrap_or_else(|e| panic!("missing fixture {name}.pem: {e}"))
    }

    /// Vault's JSON `certificate`/`issuing_ca` fields carry no trailing newline;
    /// callers must go through PemCertificate/PemPrivateKey to get exactly one.
    fn without_trailing_newline(name: &str) -> String {
        testdata(name).trim_end().to_string()
    }

    #[test]
    fn pem_certificate_ends_with_exactly_one_newline() {
        let cert = PemCertificate::new(without_trailing_newline("leaf-client"));
        assert!(cert.pem_data().ends_with("-----END CERTIFICATE-----\n"));
        assert!(!cert.pem_data().ends_with("-----\n\n"));
    }

    #[test]
    fn pem_private_key_ends_with_exactly_one_newline() {
        // No private-key fixture on disk; reuse a certificate body, only the
        // newline behavior of PemPrivateKey::new is under test here.
        let key = PemPrivateKey::new(without_trailing_newline("leaf-client"));
        assert!(key.pem_data().ends_with("-----END CERTIFICATE-----\n"));
        assert!(!key.pem_data().ends_with("-----\n\n"));
    }

    #[test]
    fn concatenated_leaf_and_ca_reparse() {
        let leaf = PemCertificate::new(without_trailing_newline("leaf-client"));
        let ca = PemCertificate::new(without_trailing_newline("ca-intermediate"));

        let combined = format!("{}{}", leaf.pem_data(), ca.pem_data());

        // Guard against the historical defect: concatenated PEMs without a
        // separating newline glue END/BEGIN markers onto one line.
        assert!(!combined.contains("----------"));

        let parsed = parse_certificate_chain(&combined).expect("fixtures parse");
        assert_eq!(parsed.len(), 2);
    }

    /// A caller cannot tell a truncated chain from a chain of that length.
    #[test]
    fn a_truncated_block_is_an_error_not_a_shorter_chain() {
        let mut truncated = testdata("chain-no-root");
        truncated.truncate(truncated.len() - 40);

        let err = parse_certificate_chain(&truncated)
            .expect_err("a block with no END line is not a chain")
            .to_string();
        assert!(err.contains("END CERTIFICATE"), "{err}");
    }

    #[test]
    fn a_block_that_does_not_parse_is_an_error() {
        let corrupt = "-----BEGIN CERTIFICATE-----\nnot base64 at all\n-----END CERTIFICATE-----\n";
        assert!(parse_certificate_chain(corrupt).is_err());
    }

    #[test]
    fn self_signed_detects_root_only() {
        assert!(is_self_signed(&PemCertificate::new(testdata("ca-root"))).unwrap());
        assert!(!is_self_signed(&PemCertificate::new(testdata("ca-intermediate"))).unwrap());
        assert!(!is_self_signed(&PemCertificate::new(testdata("leaf-client"))).unwrap());
    }

    fn chain_from_fixture(name: &str) -> PemCertificateChain {
        let mut chain = PemCertificateChain::new();
        for cert in parse_certificate_chain(&testdata(name)).expect("fixture parses") {
            chain.add_certificate(cert);
        }
        chain
    }

    #[test]
    fn without_root_drops_only_the_self_signed_certificate() {
        let with_root = chain_from_fixture("chain-with-root");
        assert_eq!(with_root.certificates().len(), 3);

        let no_root = with_root.without_root().unwrap();
        assert_eq!(no_root.certificates().len(), 2);
        for cert in no_root.certificates() {
            assert!(!is_self_signed(cert).unwrap());
        }
    }

    #[test]
    fn without_root_is_a_noop_when_root_is_absent() {
        let no_root_chain = chain_from_fixture("chain-no-root");
        assert_eq!(no_root_chain.certificates().len(), 2);

        let filtered = no_root_chain.without_root().unwrap();
        assert_eq!(filtered.certificates().len(), 2);
    }
}

#[cfg(test)]
mod block_tests {
    use super::*;

    #[test]
    fn blocks_keep_their_labels_and_order() {
        let file = "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n\
                    -----BEGIN VAULT-RS PROVENANCE-----\nBB==\n-----END VAULT-RS PROVENANCE-----\n";
        let blocks = pem_blocks(file).expect("scans");

        let labels: Vec<_> = blocks.iter().map(|b| b.label.as_str()).collect();
        assert_eq!(labels, ["CERTIFICATE", "VAULT-RS PROVENANCE"]);
        assert!(blocks[0].text.ends_with("-----END CERTIFICATE-----\n"));
    }

    /// Explanatory text before a block is permitted by the format, and every
    /// reader here already skips it — including `--text` output, which puts an
    /// openssl dump exactly there.
    #[test]
    fn text_outside_a_block_is_ignored() {
        let file = "Certificate:\n    Data:\n-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n";
        let blocks = pem_blocks(file).expect("scans");
        assert_eq!(blocks.len(), 1);
        assert!(blocks[0].text.starts_with("-----BEGIN"));
    }

    /// A stray END is malformed input, and has to say so — read as a one-line
    /// block it reports unparseable base64, naming neither problem nor file.
    #[test]
    fn an_end_with_no_begin_names_the_real_problem() {
        let err = pem_blocks("-----END CERTIFICATE-----\n")
            .expect_err("a stray END is malformed")
            .to_string();
        assert!(err.contains("no matching BEGIN"), "{err}");
    }

    #[test]
    fn a_block_closing_under_another_label_is_an_error() {
        let err = pem_blocks("-----BEGIN CERTIFICATE-----\nAA==\n-----END PRIVATE KEY-----\n")
            .expect_err("labels must match")
            .to_string();
        assert!(err.contains("closes as"), "{err}");
    }
}
