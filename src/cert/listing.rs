use crate::cert::metadata::COLUMN_NAMES;
use crate::cert::{CertificateColumn, CertificateService};
use crate::storage::local::LocalStorage;
use crate::utils::build_table_data_with_headers;
use crate::utils::errors::{Result, VaultCliError};
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

        let expires_soon_days = expires_soon
            .map(|days| {
                days.parse::<u32>().map_err(|e| {
                    VaultCliError::InvalidInput(format!("--expires-soon '{days}': {e}"))
                })
            })
            .transpose()?;

        let filtered_certs: Vec<_> = certificates
            .into_iter()
            .filter(|cert| {
                if let Some(ref pki_filter) = pki {
                    if cert.pki_mount != *pki_filter {
                        return false;
                    }
                }
                if expired && !cert.meta.is_expired() {
                    return false;
                }
                if let Some(days) = expires_soon_days {
                    if !cert.meta.expires_soon(days) {
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

    /// Parse the `--columns` value. A `+` on any entry means "add to the
    /// defaults" rather than replace them, and is accepted anywhere in the
    /// list; the result is deduplicated so appending a column that is already
    /// a default does not print it twice.
    fn parse_columns(
        columns: Option<String>,
        single_mount: bool,
    ) -> Result<Vec<CertificateColumn>> {
        let mut defaults = vec![
            "cn",
            "not_after",
            "revoked",
            "expired",
            "extended_key_usage",
        ];
        if !single_mount {
            defaults.insert(0, "pki_mount");
        }

        let Some(spec) = columns else {
            return Self::resolve(&defaults);
        };

        let requested: Vec<&str> = spec
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();

        let mut names = match requested.iter().any(|s| s.starts_with('+')) {
            true => defaults,
            false => Vec::new(),
        };
        names.extend(requested.iter().map(|s| s.trim_start_matches('+')));

        Self::resolve(&names)
    }

    fn resolve(names: &[&str]) -> Result<Vec<CertificateColumn>> {
        let mut columns = Vec::new();
        for name in names {
            let column = CertificateColumn::from_str(name).map_err(|e| {
                VaultCliError::InvalidInput(format!("{e}. Known columns: {COLUMN_NAMES}"))
            })?;
            if !columns.contains(&column) {
                columns.push(column);
            }
        }

        Ok(columns)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use CertificateColumn as C;

    fn parse(spec: &str) -> Result<Vec<CertificateColumn>> {
        CertificateListingService::parse_columns(Some(spec.to_string()), true)
    }

    #[test]
    fn defaults_apply_when_unspecified() {
        let columns = CertificateListingService::parse_columns(None, true).unwrap();
        assert_eq!(
            columns,
            [
                C::Cn,
                C::NotAfter,
                C::Revoked,
                C::Expired,
                C::ExtendedKeyUsage
            ]
        );
        assert_eq!(
            CertificateListingService::parse_columns(None, false).unwrap()[0],
            C::PkiMount
        );
    }

    #[test]
    fn without_plus_the_list_replaces_the_defaults() {
        assert_eq!(parse("cn,serial").unwrap(), [C::Cn, C::Serial]);
    }

    /// `+` used to be recognised only as a prefix on the whole string, so this
    /// reported `Invalid column: +issuer`.
    #[test]
    fn plus_is_accepted_anywhere_in_the_list() {
        let columns = parse("cn,+issuer").unwrap();
        assert!(columns.contains(&C::Issuer));
        assert!(columns.contains(&C::NotAfter), "defaults kept");
    }

    /// Appending a column already in the defaults printed it twice.
    #[test]
    fn appending_a_default_does_not_duplicate_it() {
        let columns = parse("+extended_key_usage").unwrap();
        let count = columns
            .iter()
            .filter(|c| **c == C::ExtendedKeyUsage)
            .count();
        assert_eq!(count, 1);
    }

    /// Previously this called process::exit, so it could not be tested at all.
    #[test]
    fn an_unknown_column_is_an_error_not_an_exit() {
        let err = parse("cn,nope").unwrap_err().to_string();
        assert!(err.contains("nope"), "{err}");
        assert!(err.contains("Known columns"), "{err}");
    }
}
