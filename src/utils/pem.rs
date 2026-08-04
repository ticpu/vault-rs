use crate::utils::errors::{Result, VaultCliError};
use std::io::Write;
use std::process::{Command, Stdio};
use x509_parser::pem::parse_x509_pem;
use x509_parser::prelude::*;

/// Represents a PEM-encoded certificate that can generate OpenSSL text output
#[derive(Debug, Clone)]
pub struct PemCertificate {
    pem_data: String,
}

/// Represents a PEM-encoded private key (never generates text output for security)
#[derive(Debug, Clone)]
pub struct PemPrivateKey {
    pem_data: String,
}

/// Represents a chain of PEM certificates
#[derive(Debug, Clone)]
pub struct PemCertificateChain {
    certificates: Vec<PemCertificate>,
}

impl PemCertificate {
    /// Create a new PEM certificate from PEM data
    pub fn new(pem_data: String) -> Self {
        Self {
            pem_data: normalize_pem(&pem_data),
        }
    }

    /// Get the raw PEM data
    pub fn pem_data(&self) -> &str {
        &self.pem_data
    }

    /// Generate OpenSSL text output for this certificate
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

        // Write PEM data to stdin
        if let Some(stdin) = child.stdin.as_mut() {
            stdin.write_all(self.pem_data.as_bytes()).map_err(|e| {
                VaultCliError::InvalidInput(format!("Failed to write to openssl stdin: {e}"))
            })?;
        }

        // Get output
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

    /// Output certificate with optional text
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
    /// Create a new PEM private key from PEM data
    pub fn new(pem_data: String) -> Self {
        Self {
            pem_data: normalize_pem(&pem_data),
        }
    }

    /// Get the raw PEM data
    pub fn pem_data(&self) -> &str {
        &self.pem_data
    }

    /// Output private key (never includes text for security reasons)
    pub fn output(&self, _include_text: bool) -> String {
        self.pem_data.clone()
    }
}

impl PemCertificateChain {
    /// Create a new certificate chain
    pub fn new() -> Self {
        Self {
            certificates: Vec::new(),
        }
    }

    /// Create a chain from multiple PEM certificate strings
    pub fn from_pem_strings(pem_strings: Vec<String>) -> Self {
        let certificates = pem_strings.into_iter().map(PemCertificate::new).collect();

        Self { certificates }
    }

    /// Create a chain from one blob holding several concatenated certificates,
    /// which is how Vault returns `ca_chain`.
    pub fn from_pem(pem_data: &str) -> Self {
        Self {
            certificates: parse_certificate_chain(pem_data),
        }
    }

    /// Add a certificate to the chain
    pub fn add_certificate(&mut self, cert: PemCertificate) {
        self.certificates.push(cert);
    }

    /// Get all certificates in the chain
    pub fn certificates(&self) -> &[PemCertificate] {
        &self.certificates
    }

    /// Output the entire chain with optional text for the first certificate only
    pub fn output(&self, include_text: bool) -> String {
        let mut result = String::new();

        for cert in self.certificates.iter() {
            // Only include text for the first certificate (the leaf certificate)
            let cert_text = include_text;
            result.push_str(&cert.output(cert_text));
        }

        result
    }

    /// Get raw PEM data for all certificates concatenated
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

/// Represents a complete certificate bundle (private key + certificate + chain)
#[derive(Debug, Clone)]
pub struct PemCertificateBundle {
    private_key: Option<PemPrivateKey>,
    certificate: PemCertificate,
    ca_chain: PemCertificateChain,
}

impl PemCertificateBundle {
    /// Create a new certificate bundle
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

    /// Output the complete bundle with optional text for the certificate
    pub fn output(&self, include_text: bool) -> String {
        let mut result = String::new();

        // Add private key first if present
        if let Some(key) = &self.private_key {
            result.push_str(&key.output(false)); // Never include text for private keys
        }

        // Add certificate with optional text
        result.push_str(&self.certificate.output(include_text));

        // Add CA chain without text
        result.push_str(&self.ca_chain.output(false));

        result
    }

    /// Get the certificate
    pub fn certificate(&self) -> &PemCertificate {
        &self.certificate
    }

    /// Get the private key if present
    pub fn private_key(&self) -> Option<&PemPrivateKey> {
        self.private_key.as_ref()
    }

    /// Get the CA chain
    pub fn ca_chain(&self) -> &PemCertificateChain {
        &self.ca_chain
    }
}

/// Normalize PEM data to ensure consistent formatting
fn normalize_pem(pem_data: &str) -> String {
    let trimmed = pem_data.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    // Ensure PEM data ends with exactly one newline
    if trimmed.ends_with('\n') {
        trimmed.to_string()
    } else {
        format!("{trimmed}\n")
    }
}

/// Parse multiple certificates from a PEM string
pub fn parse_certificate_chain(pem_data: &str) -> Vec<PemCertificate> {
    let mut certificates = Vec::new();
    let mut current_cert = String::new();
    let mut in_cert = false;

    for line in pem_data.lines() {
        if line.starts_with("-----BEGIN CERTIFICATE-----") {
            in_cert = true;
            current_cert.clear();
            current_cert.push_str(line);
            current_cert.push('\n');
        } else if line.starts_with("-----END CERTIFICATE-----") {
            current_cert.push_str(line);
            current_cert.push('\n');
            certificates.push(PemCertificate::new(current_cert.clone()));
            current_cert.clear();
            in_cert = false;
        } else if in_cert {
            current_cert.push_str(line);
            current_cert.push('\n');
        }
    }

    certificates
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

        let parsed = parse_certificate_chain(&combined);
        assert_eq!(parsed.len(), 2);
    }

    #[test]
    fn self_signed_detects_root_only() {
        assert!(is_self_signed(&PemCertificate::new(testdata("ca-root"))).unwrap());
        assert!(!is_self_signed(&PemCertificate::new(testdata("ca-intermediate"))).unwrap());
        assert!(!is_self_signed(&PemCertificate::new(testdata("leaf-client"))).unwrap());
    }

    fn chain_from_fixture(name: &str) -> PemCertificateChain {
        let mut chain = PemCertificateChain::new();
        for cert in parse_certificate_chain(&testdata(name)) {
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
