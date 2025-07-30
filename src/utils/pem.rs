use crate::utils::errors::{Result, VaultCliError};
use std::io::Write;
use std::process::{Command, Stdio};

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
        let mut child = Command::new("openssl")
            .args(["x509", "-text", "-noout"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
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
                Ok(text) => format!("{text}{}", self.pem_data),
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

        for (index, cert) in self.certificates.iter().enumerate() {
            // Only include text for the first certificate (the leaf certificate)
            let cert_text = include_text && index == 0;
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
