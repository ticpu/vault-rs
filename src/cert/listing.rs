use crate::cert::{CertificateColumn, CertificateService};
use crate::storage::local::LocalStorage;
use crate::utils::build_table_data_with_headers;
use crate::utils::errors::Result;
use crate::utils::output::OutputFormat;
use std::str::FromStr;

/// Unified certificate listing service that handles both CertCommands::List and StorageCommands::List
pub struct CertificateListingService;

impl CertificateListingService {
    /// List certificates from Vault with column formatting
    pub async fn list_vault_certificates(
        cert_service: &CertificateService,
        pki_mount: Option<&str>,
        columns: Option<String>,
        output: &OutputFormat,
    ) -> Result<()> {
        let certificates = cert_service
            .list_certificates_with_metadata(pki_mount)
            .await?;

        if certificates.is_empty() {
            return Ok(());
        }

        let parsed_columns = Self::parse_columns(columns, pki_mount.is_some())?;
        let (headers, table_data) = build_table_data_with_headers(&certificates, &parsed_columns);

        output.print_table_with_headers(&headers, &table_data);
        Ok(())
    }

    /// List certificates from local storage with column formatting
    pub async fn list_storage_certificates(
        storage: &LocalStorage,
        pki: Option<String>,
        expired: bool,
        expires_soon: Option<String>,
        columns: Option<String>,
        output: &OutputFormat,
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
        let (headers, table_data) = build_table_data_with_headers(&filtered_certs, &parsed_columns);

        output.print_table_with_headers(&headers, &table_data);
        Ok(())
    }

    /// Parse columns parameter with default logic
    fn parse_columns(
        columns: Option<String>,
        single_mount: bool,
    ) -> Result<Vec<CertificateColumn>> {
        // Set default columns based on whether listing all mounts or specific mount
        let default_columns = if single_mount {
            vec!["cn", "not_after", "revoked", "expired", "extended_key_usage"]
        } else {
            vec![
                "pki_mount",
                "cn",
                "not_after",
                "revoked",
                "expired",
                "extended_key_usage",
            ]
        };

        // Parse columns with support for + prefix (append to defaults)
        let column_names: Vec<String> = if let Some(columns_str) = columns {
            if let Some(stripped) = columns_str.strip_prefix('+') {
                // Append mode: start with defaults and add specified columns
                let mut result_columns: Vec<String> =
                    default_columns.into_iter().map(|s| s.to_string()).collect();
                let additional_cols: Vec<String> = stripped
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                result_columns.extend(additional_cols);
                result_columns
            } else {
                // Override mode: use only specified columns
                columns_str
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            }
        } else {
            default_columns.into_iter().map(|s| s.to_string()).collect()
        };

        // Parse column enums
        let parsed_columns: std::result::Result<Vec<CertificateColumn>, _> = column_names
            .into_iter()
            .map(|col| CertificateColumn::from_str(&col))
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
