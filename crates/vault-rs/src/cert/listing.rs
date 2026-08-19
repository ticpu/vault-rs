use crate::cert::metadata::COLUMN_NAMES;
use crate::cert::{CertificateColumn, CertificateMetadata, CertificateService};
use crate::storage::local::LocalStorage;
use crate::utils::build_table_data_with_headers;
use crate::utils::errors::{Result, VaultCliError};
use crate::utils::output::OutputFormat;
use chrono::{DateTime, Utc};
use std::str::FromStr;
use std::time::Duration;

/// Filters for `cert list`. Vault's certificate store (and the cache built on
/// top of it) records no issuing role, so unlike `storage list` there is no
/// `--role` filter here: offering one would silently return nothing instead
/// of failing, which is worse than not offering it.
pub struct CertListFilter {
    expiring_before: Option<DateTime<Utc>>,
    only_expired: bool,
    exclude_expired: bool,
    only_revoked: bool,
    exclude_revoked: bool,
    eku: Option<String>,
}

impl CertListFilter {
    pub fn new(
        expiring_within: Option<Duration>,
        only_expired: bool,
        exclude_expired: bool,
        only_revoked: bool,
        exclude_revoked: bool,
        eku: Option<String>,
    ) -> Result<Self> {
        let expiring_before = expiring_within
            .map(|duration| {
                chrono::Duration::from_std(duration)
                    .map(|delta| Utc::now() + delta)
                    .map_err(|e| {
                        VaultCliError::InvalidInput(format!(
                            "--expiring-within duration out of range: {e}"
                        ))
                    })
            })
            .transpose()?;

        Ok(Self {
            expiring_before,
            only_expired,
            exclude_expired,
            only_revoked,
            exclude_revoked,
            eku,
        })
    }

    /// Whether `--expiring-within` was given. Drives the exit-code contract:
    /// only this flag turns "at least one match" into a distinct exit code
    /// (for cron/Checkmk), other filters do not.
    pub fn is_expiring_within_active(&self) -> bool {
        self.expiring_before.is_some()
    }

    pub fn matches(&self, cert: &CertificateMetadata) -> bool {
        if self.only_expired && !cert.is_expired() {
            return false;
        }
        if self.exclude_expired && cert.is_expired() {
            return false;
        }
        if self.only_revoked && !cert.is_revoked() {
            return false;
        }
        if self.exclude_revoked && cert.is_revoked() {
            return false;
        }
        if let Some(threshold) = self.expiring_before {
            if cert.not_after > threshold {
                return false;
            }
        }
        if let Some(ref eku) = self.eku {
            if !eku_matches(&cert.extended_key_usage, eku) {
                return false;
            }
        }
        true
    }
}

/// Matches extended key usage entries against a filter value. `client` and
/// `server` are friendly aliases for the strings the parser produces
/// (`ClientAuth`, `ServerAuth`); anything else, including raw OIDs, is
/// compared case-insensitively as-is.
fn eku_matches(cert_ekus: &[String], filter: &str) -> bool {
    let filter_lower = filter.to_lowercase();
    let target = match filter_lower.as_str() {
        "client" => "clientauth",
        "server" => "serverauth",
        other => other,
    };
    cert_ekus.iter().any(|usage| usage.to_lowercase() == target)
}

/// What `storage list` was asked for.
pub struct StorageListRequest {
    pub pki: Option<String>,
    pub expired: bool,
    pub expires_soon: Option<String>,
    pub role: Option<String>,
    pub columns: Option<String>,
    pub allow_partial: bool,
}

/// Which command is asking for columns. `Role` is only ever populated by
/// local storage (see `CertListFilter`'s doc comment), so `cert list` must
/// reject it rather than silently print a blank column.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ListingCommand {
    CertList,
    StorageList,
}

/// Unified certificate listing service that handles both CertCommands::List and StorageCommands::List
pub struct CertificateListingService;

impl CertificateListingService {
    /// Runs `cert list` end to end, including standing up the `CertificateService`.
    /// Keeping every fallible step inside one `Result` lets the caller map any
    /// failure to a single exit code without a `?` escaping its local handling.
    pub async fn run_cert_list(
        pki_mount: Option<&str>,
        columns: Option<String>,
        filter: &CertListFilter,
        allow_partial: bool,
        output: &OutputFormat,
    ) -> Result<bool> {
        let cert_service = CertificateService::new().await?;
        Self::list_vault_certificates(
            &cert_service,
            pki_mount,
            columns,
            filter,
            allow_partial,
            output,
        )
        .await
    }

    /// List certificates from Vault with column formatting. Returns whether at
    /// least one certificate matched `filter`.
    pub async fn list_vault_certificates(
        cert_service: &CertificateService,
        pki_mount: Option<&str>,
        columns: Option<String>,
        filter: &CertListFilter,
        allow_partial: bool,
        output: &OutputFormat,
    ) -> Result<bool> {
        if output.json && columns.is_some() {
            return Err(VaultCliError::InvalidInput(
                "--columns has no effect with --json".to_string(),
            ));
        }

        let certificates = cert_service
            .list_certificates_with_metadata(pki_mount)
            .await?
            .resolve(allow_partial)?;

        // Already sorted ascending by not_after (soonest expiry first) by
        // the service layer; filtering with retain-style semantics preserves it.
        let filtered: Vec<_> = certificates
            .into_iter()
            .filter(|c| filter.matches(c))
            .collect();
        let matched = !filtered.is_empty();

        if output.json {
            // The full record, not the display-truncated table cells: see
            // OutputFormat::print_json.
            output.print_json(&filtered)?;
            return Ok(matched);
        }

        if !matched {
            return Ok(false);
        }

        let parsed_columns =
            Self::parse_columns(columns, pki_mount.is_some(), ListingCommand::CertList)?;
        let (headers, table_data) = build_table_data_with_headers(&filtered, &parsed_columns);

        output.print_table_with_headers(&headers, &table_data);
        Ok(true)
    }

    /// List certificates from local storage with column formatting
    pub async fn list_storage_certificates(
        storage: &LocalStorage,
        request: StorageListRequest,
        output: &OutputFormat,
    ) -> Result<()> {
        let StorageListRequest {
            pki,
            expired,
            expires_soon,
            role,
            columns,
            allow_partial,
        } = request;

        if output.json && columns.is_some() {
            return Err(VaultCliError::InvalidInput(
                "--columns has no effect with --json".to_string(),
            ));
        }

        let certificates = storage.list_certificates().await?.resolve(allow_partial)?;

        let expires_soon_days = expires_soon
            .map(|days| {
                days.parse::<u32>().map_err(|e| {
                    VaultCliError::InvalidInput(format!("--expires-soon '{days}': {e}"))
                })
            })
            .transpose()?;

        // Already ordered by the walk on a total key; filtering preserves it.
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
                if let Some(ref role_filter) = role {
                    // An artifact with no recorded role matches no role
                    // filter; it is not a wildcard.
                    if cert.meta.role.as_deref() != Some(role_filter.as_str()) {
                        return false;
                    }
                }
                true
            })
            .collect();

        if output.json {
            return output.print_json(&filtered_certs);
        }

        if filtered_certs.is_empty() {
            return Ok(());
        }

        let parsed_columns =
            Self::parse_columns(columns, pki.is_some(), ListingCommand::StorageList)?;
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
        command: ListingCommand,
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
            return Self::resolve(&defaults, command);
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

        Self::resolve(&names, command)
    }

    fn resolve(names: &[&str], command: ListingCommand) -> Result<Vec<CertificateColumn>> {
        let mut columns = Vec::new();
        for name in names {
            let column = CertificateColumn::from_str(name).map_err(|e| {
                VaultCliError::InvalidInput(format!("{e}. Known columns: {COLUMN_NAMES}"))
            })?;
            if column == CertificateColumn::Role && command == ListingCommand::CertList {
                return Err(VaultCliError::InvalidInput(
                    "column 'role' is not available for cert list: Vault's certificate store \
                     records no issuing role, it is only recorded for certificates this tool \
                     stored locally (storage list --columns role has it)"
                        .to_string(),
                ));
            }
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
    use crate::cert::SerialNumber;
    use CertificateColumn as C;

    fn parse(spec: &str) -> Result<Vec<CertificateColumn>> {
        CertificateListingService::parse_columns(
            Some(spec.to_string()),
            true,
            ListingCommand::CertList,
        )
    }

    #[test]
    fn defaults_apply_when_unspecified() {
        let columns =
            CertificateListingService::parse_columns(None, true, ListingCommand::CertList).unwrap();
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
            CertificateListingService::parse_columns(None, false, ListingCommand::CertList)
                .unwrap()[0],
            C::PkiMount
        );
    }

    /// `cert list` reads straight from Vault's certificate store, which has
    /// no role field: accepting the column would silently print blanks.
    #[test]
    fn cert_list_rejects_role_column() {
        let err = parse("cn,role").unwrap_err().to_string();
        assert!(err.contains("role"), "{err}");
        assert!(err.contains("cert list"), "{err}");
    }

    /// `storage list` records the issuing role locally, so it may request it.
    #[test]
    fn storage_list_accepts_role_column() {
        let columns = CertificateListingService::parse_columns(
            Some("cn,role".to_string()),
            true,
            ListingCommand::StorageList,
        )
        .unwrap();
        assert!(columns.contains(&C::Role));
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

    fn cert(not_after: DateTime<Utc>, extended_key_usage: &[&str]) -> CertificateMetadata {
        CertificateMetadata {
            serial: SerialNumber::new("00"),
            cn: "test".to_string(),
            not_before: Utc::now(),
            not_after,
            sans: vec!["test.example.test".to_string()],
            key_usage: vec![],
            extended_key_usage: extended_key_usage.iter().map(|s| s.to_string()).collect(),
            is_ca: false,
            issuer: "issuer".to_string(),
            pki_mount: "mount".to_string(),
            cached_at: Utc::now(),
            revocation_time: None,
        }
    }

    fn no_filter() -> CertListFilter {
        CertListFilter::new(None, false, false, false, false, None).unwrap()
    }

    #[test]
    fn expiring_before_excludes_certs_past_the_threshold() {
        let filter = CertListFilter {
            expiring_before: Some(Utc::now() + chrono::Duration::days(30)),
            ..no_filter()
        };
        let soon = cert(Utc::now() + chrono::Duration::days(10), &[]);
        let later = cert(Utc::now() + chrono::Duration::days(100), &[]);
        assert!(filter.matches(&soon));
        assert!(!filter.matches(&later));
    }

    #[test]
    fn only_expired_keeps_only_expired_certs() {
        let filter = CertListFilter {
            only_expired: true,
            ..no_filter()
        };
        let expired = cert(Utc::now() - chrono::Duration::days(1), &[]);
        let valid = cert(Utc::now() + chrono::Duration::days(1), &[]);
        assert!(filter.matches(&expired));
        assert!(!filter.matches(&valid));
    }

    #[test]
    fn exclude_expired_drops_expired_certs() {
        let filter = CertListFilter {
            exclude_expired: true,
            ..no_filter()
        };
        let expired = cert(Utc::now() - chrono::Duration::days(1), &[]);
        let valid = cert(Utc::now() + chrono::Duration::days(1), &[]);
        assert!(!filter.matches(&expired));
        assert!(filter.matches(&valid));
    }

    #[test]
    fn only_revoked_and_exclude_revoked_are_opposite_filters() {
        let mut revoked = cert(Utc::now() + chrono::Duration::days(1), &[]);
        revoked.revocation_time = Some(Utc::now());
        let active = cert(Utc::now() + chrono::Duration::days(1), &[]);

        let only_revoked = CertListFilter {
            only_revoked: true,
            ..no_filter()
        };
        assert!(only_revoked.matches(&revoked));
        assert!(!only_revoked.matches(&active));

        let exclude_revoked = CertListFilter {
            exclude_revoked: true,
            ..no_filter()
        };
        assert!(!exclude_revoked.matches(&revoked));
        assert!(exclude_revoked.matches(&active));
    }

    #[test]
    fn eku_filter_accepts_client_server_aliases_case_insensitively() {
        let now = Utc::now();
        let client_cert = cert(now, &["ClientAuth"]);
        let server_cert = cert(now, &["ServerAuth"]);

        let want_client = CertListFilter {
            eku: Some("CLIENT".to_string()),
            ..no_filter()
        };
        assert!(want_client.matches(&client_cert));
        assert!(!want_client.matches(&server_cert));

        let want_server = CertListFilter {
            eku: Some("server".to_string()),
            ..no_filter()
        };
        assert!(want_server.matches(&server_cert));
        assert!(!want_server.matches(&client_cert));
    }

    #[test]
    fn eku_filter_matches_raw_names_and_oids() {
        let now = Utc::now();
        let code_signing = cert(now, &["CodeSigning"]);
        let oid_cert = cert(now, &["1.2.3.4"]);

        let filter = CertListFilter {
            eku: Some("codesigning".to_string()),
            ..no_filter()
        };
        assert!(filter.matches(&code_signing));

        let oid_filter = CertListFilter {
            eku: Some("1.2.3.4".to_string()),
            ..no_filter()
        };
        assert!(oid_filter.matches(&oid_cert));
    }

    #[test]
    fn expiring_within_flag_reflects_construction() {
        let inactive = CertListFilter::new(None, false, false, false, false, None).unwrap();
        assert!(!inactive.is_expiring_within_active());

        let active = CertListFilter::new(
            Some(Duration::from_secs(3600)),
            false,
            false,
            false,
            false,
            None,
        )
        .unwrap();
        assert!(active.is_expiring_within_active());
    }

    /// `cert list --json` must serialize the record, not the display string
    /// `ExtendedKeyUsage` renders to (e.g. "CA:Client"): a nested field must
    /// stay a JSON array for consumers to parse.
    #[test]
    fn json_serialization_keeps_extended_key_usage_as_an_array() {
        let certs = vec![cert(Utc::now(), &["ClientAuth", "CodeSigning"])];

        let json = serde_json::to_value(&certs).unwrap();
        let eku = &json[0]["extended_key_usage"];
        assert!(eku.is_array(), "expected array, got {eku}");
        assert_eq!(eku[0], "ClientAuth");
        assert_eq!(eku[1], "CodeSigning");

        let round_tripped: Vec<CertificateMetadata> = serde_json::from_value(json).unwrap();
        assert_eq!(
            round_tripped[0].extended_key_usage,
            certs[0].extended_key_usage
        );
    }
}
