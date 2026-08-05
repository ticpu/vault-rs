//! What an exported artifact can carry that its certificate cannot.
//!
//! See `docs/design-rationale.md`, "An exported artifact may carry the
//! provenance the certificate cannot".

use crate::storage::metadata::CertStatus;
use crate::utils::errors::{Result, VaultCliError};
use crate::utils::pem::PemBlock;
use base64::{engine::general_purpose, Engine as _};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// The PEM label this rides under. A label the format does not define, so no
/// reader looking for certificates or keys will claim it.
pub const PROVENANCE_LABEL: &str = "VAULT-RS PROVENANCE";

/// Bumped when this shape changes. An unfamiliar version is refused rather
/// than read as though it were this one: the fields it names exist nowhere
/// else, so guessing at them writes a wrong answer into the only copy.
const PROVENANCE_VERSION: u32 = 1;

/// Only what no certificate answers. Everything else about a stored artifact
/// is re-read from the certificate itself on every listing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Provenance {
    pub version: u32,
    /// Not derivable from a certificate: the mount is a Vault path, not a
    /// property of what it issued.
    pub pki_mount: String,
    pub role: Option<String>,
    pub crypto: Option<String>,
    pub status: CertStatus,
    /// When the artifact was first stored, carried across so a re-import does
    /// not present itself as newly issued.
    pub created: DateTime<Utc>,
}

impl Provenance {
    pub fn new(
        pki_mount: String,
        role: Option<String>,
        crypto: Option<String>,
        status: CertStatus,
        created: DateTime<Utc>,
    ) -> Self {
        Self {
            version: PROVENANCE_VERSION,
            pki_mount,
            role,
            crypto,
            status,
            created,
        }
    }

    /// The PEM block to append after the certificates.
    pub fn to_pem_block(&self) -> Result<String> {
        let yaml = serde_yaml_ng::to_string(self)?;
        let encoded = general_purpose::STANDARD.encode(yaml.as_bytes());

        let mut block = format!("-----BEGIN {PROVENANCE_LABEL}-----\n");
        for line in encoded.as_bytes().chunks(64) {
            block.push_str(&String::from_utf8_lossy(line));
            block.push('\n');
        }
        block.push_str(&format!("-----END {PROVENANCE_LABEL}-----\n"));
        Ok(block)
    }

    /// The provenance in a parsed PEM file, if it carries one.
    ///
    /// A block that is present but will not read is an error rather than an
    /// absence: absent means the exporter never wrote one, and reporting a
    /// damaged block as "no provenance" would quietly drop the fields it was
    /// written to preserve.
    pub fn from_pem_blocks(blocks: &[PemBlock]) -> Result<Option<Self>> {
        let Some(block) = blocks.iter().find(|b| b.label == PROVENANCE_LABEL) else {
            return Ok(None);
        };

        let body: String = block
            .text
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        let decoded = general_purpose::STANDARD.decode(body.trim()).map_err(|e| {
            VaultCliError::CertParsing(format!("the {PROVENANCE_LABEL} block is not base64: {e}"))
        })?;
        let provenance: Self = serde_yaml_ng::from_slice(&decoded).map_err(|e| {
            VaultCliError::CertParsing(format!("the {PROVENANCE_LABEL} block does not parse: {e}"))
        })?;

        if provenance.version != PROVENANCE_VERSION {
            return Err(VaultCliError::CertParsing(format!(
                "the {PROVENANCE_LABEL} block is version {}, and this build reads version \
                 {PROVENANCE_VERSION}. Import it with a build that knows that version, or drop \
                 the block and supply --pki-mount and --role yourself.",
                provenance.version
            )));
        }

        Ok(Some(provenance))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::pem::pem_blocks;

    fn sample() -> Provenance {
        Provenance::new(
            "pki".to_string(),
            Some("client".to_string()),
            Some("ec".to_string()),
            CertStatus::Active,
            "2026-08-04T14:04:33Z".parse().expect("timestamp"),
        )
    }

    #[test]
    fn a_block_round_trips_through_the_pem_scanner() {
        let file = format!(
            "{}{}",
            "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n",
            sample().to_pem_block().unwrap()
        );
        let blocks = pem_blocks(&file).expect("scans");

        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].label, "CERTIFICATE");
        assert_eq!(blocks[1].label, PROVENANCE_LABEL);
        assert_eq!(
            Provenance::from_pem_blocks(&blocks).expect("reads"),
            Some(sample())
        );
    }

    /// The exporter may not have written one, and that is not a failure.
    #[test]
    fn a_file_without_a_block_reports_no_provenance() {
        let blocks = pem_blocks("-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n")
            .expect("scans");
        assert_eq!(Provenance::from_pem_blocks(&blocks).expect("reads"), None);
    }

    /// Reading a version this build does not know would write a guess into
    /// the only copy of fields nothing else holds.
    #[test]
    fn an_unknown_version_is_refused_rather_than_read() {
        let mut ahead = sample();
        ahead.version = PROVENANCE_VERSION + 1;
        let blocks = pem_blocks(&ahead.to_pem_block().unwrap()).expect("scans");

        let err = Provenance::from_pem_blocks(&blocks)
            .expect_err("an unfamiliar version is not readable")
            .to_string();
        assert!(err.contains(&(PROVENANCE_VERSION + 1).to_string()), "{err}");
    }

    /// A damaged block is not the same as no block: reporting it as absent
    /// would silently drop the fields it exists to carry.
    #[test]
    fn a_damaged_block_is_an_error_not_an_absence() {
        let blocks = pem_blocks(&format!(
            "-----BEGIN {PROVENANCE_LABEL}-----\nnot base64 at all\n-----END {PROVENANCE_LABEL}-----\n"
        ))
        .expect("scans");
        assert!(Provenance::from_pem_blocks(&blocks).is_err());
    }
}
