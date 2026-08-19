use crate::cert::metadata::CertificateMetadata;
use crate::cert::SerialNumber;
use crate::utils::errors::{Result, VaultCliError};
use base64::{engine::general_purpose, Engine as _};
use chrono::{DateTime, Utc};
use x509_parser::der_parser::oid;
use x509_parser::prelude::*;

// X.509 Extension OIDs
const SUBJECT_ALT_NAME_OID: oid::Oid = oid!(2.5.29 .17);
const KEY_USAGE_OID: oid::Oid = oid!(2.5.29 .15);
const EXTENDED_KEY_USAGE_OID: oid::Oid = oid!(2.5.29 .37);
const BASIC_CONSTRAINTS_OID: oid::Oid = oid!(2.5.29 .19);

/// A UNIX timestamp as a date, or an error naming the field — never today's
/// date substituted, which is indistinguishable from a certificate that really
/// does expire now.
pub(crate) fn timestamp(seconds: i64, field: &str) -> Result<DateTime<Utc>> {
    DateTime::from_timestamp(seconds, 0).ok_or_else(|| {
        VaultCliError::CertParsing(format!("{field} is not a representable date: {seconds}"))
    })
}

/// A distinguished name's common name, absent or unreadable reported as such —
/// not folded into one placeholder, which a CN literally saying that would then
/// print identically to.
fn common_name(name: &x509_parser::x509::X509Name, which: &str) -> Result<String> {
    let Some(attribute) = name.iter_common_name().next() else {
        return Ok(format!("(no {which} CN)"));
    };

    attribute.as_str().map(str::to_string).map_err(|e| {
        VaultCliError::CertParsing(format!("{which} CN is present but not readable: {e}"))
    })
}

pub struct CertificateParser;

impl CertificateParser {
    /// Parse certificate PEM data into metadata
    pub fn parse_pem(pem_data: &str, pki_mount: &str) -> Result<CertificateMetadata> {
        // Extract the base64 content from PEM
        let cert_data = Self::extract_cert_from_pem(pem_data)?;

        // Decode base64
        let der_bytes = general_purpose::STANDARD
            .decode(&cert_data)
            .map_err(|e| VaultCliError::CertParsing(format!("Base64 decode error: {e}")))?;

        // Parse DER certificate
        let (_, cert) = X509Certificate::from_der(&der_bytes)
            .map_err(|e| VaultCliError::CertParsing(format!("DER parsing error: {e}")))?;

        Self::extract_metadata(&cert, pki_mount)
    }

    /// Extract certificate data from PEM format
    fn extract_cert_from_pem(pem_data: &str) -> Result<String> {
        let mut in_cert = false;
        let mut cert_lines = Vec::new();

        for line in pem_data.lines() {
            let line = line.trim();
            if line == "-----BEGIN CERTIFICATE-----" {
                in_cert = true;
                continue;
            } else if line == "-----END CERTIFICATE-----" {
                break;
            } else if in_cert {
                cert_lines.push(line);
            }
        }

        if cert_lines.is_empty() {
            return Err(VaultCliError::CertParsing(
                "No certificate data found in PEM".to_string(),
            ));
        }

        Ok(cert_lines.join(""))
    }

    /// Extract metadata from X509 certificate
    fn extract_metadata(cert: &X509Certificate, pki_mount: &str) -> Result<CertificateMetadata> {
        // Extract serial number - normalize to continuous hex format
        let serial = SerialNumber::new(&hex::encode(cert.serial.to_bytes_be()));

        let cn = common_name(cert.subject(), "subject")?;
        let issuer = common_name(cert.issuer(), "issuer")?;

        // An unrepresentable validity aborts rather than falling back to now:
        // --expiring-within would report that as a match, and the cache would
        // then serve the conclusion from disk.
        let not_before = timestamp(cert.validity().not_before.timestamp(), "notBefore")?;
        let not_after = timestamp(cert.validity().not_after.timestamp(), "notAfter")?;

        Ok(CertificateMetadata {
            serial,
            cn,
            not_before,
            not_after,
            sans: Self::extract_sans(cert)?,
            key_usage: Self::extract_key_usage(cert)?,
            extended_key_usage: Self::extract_extended_key_usage(cert)?,
            is_ca: Self::extract_is_ca(cert)?,
            issuer,
            pki_mount: pki_mount.to_string(),
            cached_at: Utc::now(),
            revocation_time: None, // Will be set by the service from Vault API response
        })
    }

    /// Raw DER of the first extension with this OID, or None if the certificate
    /// does not carry it. `pub(crate)` so ca_info can look up SKI/AKI/AIA/CRL
    /// without a parallel extension-lookup helper.
    pub(crate) fn extension<'a>(cert: &'a X509Certificate, oid: &oid::Oid) -> Option<&'a [u8]> {
        cert.extensions()
            .iter()
            .find(|ext| &ext.oid == oid)
            .map(|ext| ext.value)
    }

    /// A present-but-unparseable extension aborts rather than reading as absent:
    /// the two are indistinguishable downstream, and empty reads as "not set".
    pub(crate) fn parse_extension<'a, T: FromDer<'a, X509Error>>(
        der: &'a [u8],
        name: &str,
    ) -> Result<T> {
        T::from_der(der)
            .map(|(_rem, parsed)| parsed)
            .map_err(|e| VaultCliError::CertParsing(format!("malformed {name} extension: {e}")))
    }

    pub(crate) fn extract_sans(cert: &X509Certificate) -> Result<Vec<String>> {
        let Some(der) = Self::extension(cert, &SUBJECT_ALT_NAME_OID) else {
            return Ok(Vec::new());
        };
        let san: SubjectAlternativeName = Self::parse_extension(der, "subjectAltName")?;

        Ok(san
            .general_names
            .iter()
            .filter_map(Self::format_general_name)
            .collect())
    }

    pub(crate) fn format_general_name(name: &GeneralName) -> Option<String> {
        match name {
            GeneralName::DNSName(dns) => Some(dns.to_string()),
            GeneralName::IPAddress(ip) => match <[u8; 4]>::try_from(*ip) {
                Ok(v4) => Some(std::net::Ipv4Addr::from(v4).to_string()),
                // discard-ok: not 4 bytes, so try 16; neither is not an address
                Err(_) => <[u8; 16]>::try_from(*ip)
                    .ok()
                    .map(|v6| std::net::Ipv6Addr::from(v6).to_string()),
            },
            _ => None,
        }
    }

    fn extract_key_usage(cert: &X509Certificate) -> Result<Vec<String>> {
        let Some(der) = Self::extension(cert, &KEY_USAGE_OID) else {
            return Ok(Vec::new());
        };
        let ku: KeyUsage = Self::parse_extension(der, "keyUsage")?;

        let flags = [
            (ku.digital_signature(), "DigitalSignature"),
            (ku.non_repudiation(), "NonRepudiation"),
            (ku.key_encipherment(), "KeyEncipherment"),
            (ku.data_encipherment(), "DataEncipherment"),
            (ku.key_agreement(), "KeyAgreement"),
            (ku.key_cert_sign(), "KeyCertSign"),
            (ku.crl_sign(), "CRLSign"),
            (ku.encipher_only(), "EncipherOnly"),
            (ku.decipher_only(), "DecipherOnly"),
        ];

        Ok(Self::set_flags(&flags))
    }

    /// x509-parser exposes the well-known usages as typed booleans and leaves
    /// `other` for OIDs it did not recognise, so reading `other` alone yields
    /// nothing for any certificate using standard EKUs.
    pub(crate) fn extract_extended_key_usage(cert: &X509Certificate) -> Result<Vec<String>> {
        let Some(der) = Self::extension(cert, &EXTENDED_KEY_USAGE_OID) else {
            return Ok(Vec::new());
        };
        let eku: ExtendedKeyUsage = Self::parse_extension(der, "extendedKeyUsage")?;

        let flags = [
            (eku.any, "Any"),
            (eku.server_auth, "ServerAuth"),
            (eku.client_auth, "ClientAuth"),
            (eku.code_signing, "CodeSigning"),
            (eku.email_protection, "EmailProtection"),
            (eku.time_stamping, "TimeStamping"),
            (eku.ocsp_signing, "OCSPSigning"),
        ];

        let mut usages = Self::set_flags(&flags);
        usages.extend(eku.other.iter().map(|oid| oid.to_string()));

        Ok(usages)
    }

    fn set_flags(flags: &[(bool, &str)]) -> Vec<String> {
        flags
            .iter()
            .filter(|(set, _)| *set)
            .map(|(_, name)| (*name).to_string())
            .collect()
    }

    /// A short, human-legible key description ("EC prime256v1", "RSA 2048"),
    /// shared between a CSR's key and an issued certificate's key so
    /// `--dry-run` and the post-issuance report describe it identically.
    pub(crate) fn describe_public_key(spki: &SubjectPublicKeyInfo) -> String {
        use x509_parser::public_key::PublicKey;

        match spki.parsed() {
            Ok(PublicKey::RSA(rsa)) => format!("RSA {}", rsa.key_size()),
            Ok(PublicKey::EC(_)) => {
                let curve = spki
                    .algorithm
                    .parameters
                    .as_ref()
                    // discard-ok: an absent or unregistered curve OID reports as
                    // plain "EC" below rather than naming a curve nobody read
                    .and_then(|p| p.as_oid().ok())
                    .and_then(|oid| oid2sn(&oid, oid_registry()).ok().map(str::to_string));
                match curve {
                    Some(name) => format!("EC {name}"),
                    None => "EC".to_string(),
                }
            }
            Ok(_) => "unrecognised key type".to_string(),
            // discard-ok: the value reports the failure rather than hiding it
            Err(_) => "unparseable key".to_string(),
        }
    }

    fn extract_is_ca(cert: &X509Certificate) -> Result<bool> {
        let Some(der) = Self::extension(cert, &BASIC_CONSTRAINTS_OID) else {
            return Ok(false);
        };
        let bc: BasicConstraints = Self::parse_extension(der, "basicConstraints")?;

        Ok(bc.ca)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> CertificateMetadata {
        let pem = include_testdata(name);
        CertificateParser::parse_pem(&pem, "test-mount").expect("fixture should parse")
    }

    fn include_testdata(name: &str) -> String {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/cert/testdata/");
        std::fs::read_to_string(format!("{path}{name}.pem"))
            .unwrap_or_else(|e| panic!("missing fixture {name}.pem: {e}"))
    }

    #[test]
    fn client_auth_eku_is_read() {
        assert_eq!(fixture("eku-client").extended_key_usage, ["ClientAuth"]);
    }

    #[test]
    fn server_auth_eku_is_read() {
        assert_eq!(fixture("eku-server").extended_key_usage, ["ServerAuth"]);
    }

    #[test]
    fn multiple_ekus_are_read() {
        assert_eq!(
            fixture("eku-client-server").extended_key_usage,
            ["ServerAuth", "ClientAuth"]
        );
    }

    /// digitalSignature + keyEncipherment + a SAN must not read as an implied
    /// server usage: an EKU is what the certificate states, or nothing.
    #[test]
    fn absent_eku_stays_empty() {
        let cert = fixture("eku-none");
        assert!(cert.extended_key_usage.is_empty());
        assert_eq!(cert.key_usage, ["DigitalSignature", "KeyEncipherment"]);
        assert!(!cert.sans.is_empty());
    }

    #[test]
    fn unrecognised_eku_keeps_its_oid() {
        assert_eq!(
            fixture("eku-unknown").extended_key_usage,
            ["1.3.6.1.4.1.99999.1"]
        );
    }

    #[test]
    fn ca_certificate_is_flagged() {
        assert!(fixture("ca-root").is_ca);
        assert!(!fixture("leaf-client").is_ca);
    }

    #[test]
    fn subject_and_issuer_come_from_the_certificate() {
        let leaf = fixture("leaf-client");
        assert_eq!(leaf.cn, "leaf-client");
        assert_eq!(leaf.issuer, "Example Intermediate CA");
    }

    #[test]
    fn sans_are_extracted() {
        assert_eq!(fixture("eku-client").sans, ["eku-client.example.test"]);
    }

    #[test]
    fn non_certificate_input_is_rejected() {
        assert!(CertificateParser::parse_pem("not a certificate", "m").is_err());
    }
}
