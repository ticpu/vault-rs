use crate::cert::{CertificateColumn, CertificateMetadata, CertificateService};
use crate::storage::{local::LocalStorage, metadata::CertificateStorage};
use crate::utils::errors::Result;
use std::str::FromStr;

/// Unified certificate listing service that handles both CertCommands::List and StorageCommands::List
pub struct CertificateListingService;

impl CertificateListingService {
    /// List certificates from Vault with column formatting
    pub async fn list_vault_certificates(
        cert_service: &CertificateService,
        pki_mount: Option<&str>,
        columns: Option<String>,
    ) -> Result<()> {
        let certificates = cert_service
            .list_certificates_with_metadata(pki_mount)
            .await?;

        if certificates.is_empty() {
            return Ok(());
        }

        let parsed_columns = Self::parse_columns(columns, pki_mount.is_some())?;

        // UNIX-friendly output: one line per certificate with specified columns
        for cert in certificates {
            let values: Vec<String> = parsed_columns
                .iter()
                .map(|col| cert.get_column_value(col))
                .collect();
            println!("{}", values.join("\t"));
        }
        Ok(())
    }

    /// List certificates from local storage with column formatting
    pub async fn list_storage_certificates(
        storage: &LocalStorage,
        pki: Option<String>,
        expired: bool,
        expires_soon: Option<String>,
        columns: Option<String>,
    ) -> Result<()> {
        let certificates = storage.list_certificates().await?;

        let filtered_certs: Vec<_> = certificates
            .into_iter()
            .filter(|cert| {
                // Filter by PKI mount if specified
                if let Some(ref pki_filter) = pki {
                    if cert.pki_mount != *pki_filter {
                        return false;
                    }
                }
                // Filter by expiration status
                if expired && !cert.meta.is_expired() {
                    return false;
                }
                // Filter by expires soon
                if let Some(days) = &expires_soon {
                    let days_u32 = days.parse::<u32>().unwrap_or(30);
                    if !cert.meta.expires_soon(days_u32) {
                        return false;
                    }
                }
                true
            })
            .collect();

        if filtered_certs.is_empty() {
            return Ok(());
        }

        let parsed_columns = Self::parse_columns(columns, pki.is_some())?;

        // UNIX-friendly output: one line per certificate with specified columns
        for cert in filtered_certs {
            let values: Vec<String> = parsed_columns
                .iter()
                .map(|col| cert.get_column_value(col))
                .collect();
            println!("{}", values.join("\t"));
        }
        Ok(())
    }

    /// Parse columns parameter with default logic
    fn parse_columns(
        columns: Option<String>,
        single_mount: bool,
    ) -> Result<Vec<CertificateColumn>> {
        // Set default columns based on whether listing all mounts or specific mount
        let default_columns = if single_mount {
            vec!["cn", "not_after", "extended_key_usage", "sans"]
        } else {
            vec!["pki_mount", "cn", "not_after", "extended_key_usage", "sans"]
        };

        // Parse columns with support for + prefix (append to defaults)
        let columns = if let Some(columns_str) = columns {
            if let Some(stripped) = columns_str.strip_prefix('+') {
                // Append mode: start with defaults and add specified columns
                let mut result_columns = default_columns;
                let additional_cols: Vec<&str> = stripped
                    .split(',')
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty())
                    .collect();
                result_columns.extend(additional_cols);
                result_columns
            } else {
                // Override mode: use only specified columns
                columns_str
                    .split(',')
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty())
                    .collect()
            }
        } else {
            default_columns
        };

        // Parse column enums
        let parsed_columns: std::result::Result<Vec<CertificateColumn>, _> = columns
            .into_iter()
            .map(|col| CertificateColumn::from_str(col))
            .collect();

        match parsed_columns {
            Ok(cols) => Ok(cols),
            Err(e) => {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
    }
}
