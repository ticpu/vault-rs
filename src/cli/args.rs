use clap::{Parser, Subcommand, ValueEnum};
use clap_complete::Shell;
use std::time::Duration;

fn parse_expiring_within(s: &str) -> Result<Duration, String> {
    humantime::parse_duration(s).map_err(|e| e.to_string())
}

#[derive(Parser)]
#[command(name = "vault-rs")]
#[command(version)]
#[command(about = "A secure Vault PKI management tool for sysadmins")]
#[command(long_about = None)]
pub struct Cli {
    /// Vault server URL
    #[arg(long, env = "VAULT_ADDR")]
    pub vault_addr: Option<String>,

    /// Config file path
    #[arg(long, default_value = "~/.config/vault-rs/config.toml")]
    pub config: String,

    /// Enable verbose logging (repeat for more verbosity: -v INFO, -vv DEBUG, -vvv TRACE)
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Suppress non-error output
    #[arg(short, long)]
    pub quiet: bool,

    /// Output raw tab-separated values (no formatting)
    #[arg(short, long, conflicts_with = "json")]
    pub raw: bool,

    /// Output JSON instead of formatted or raw tables (list/show commands only)
    #[arg(long, conflicts_with = "raw")]
    pub json: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// This machine's Vault session: login, token state, encryption key
    Session {
        #[command(subcommand)]
        command: SessionCommands,
    },
    /// Certificate operations
    Cert {
        #[command(subcommand)]
        command: CertCommands,
    },
    /// Local storage management
    Storage {
        #[command(subcommand)]
        command: StorageCommands,
    },
    /// Cache management
    Cache {
        #[command(subcommand)]
        command: CacheCommands,
    },
    /// Generate shell completion scripts
    Completion {
        #[command(subcommand)]
        command: CompletionCommands,
    },
    /// Internal completion helpers (hidden)
    #[command(hide = true)]
    CompletionHelper {
        #[command(subcommand)]
        command: CompletionHelperCommands,
    },
    /// Read data from a path
    Read {
        /// Path to read
        path: String,
        /// Query parameters as key=value; @file and - read from a file or stdin
        args: Vec<String>,
        /// Print only this field's value, bare
        #[arg(long)]
        field: Option<String>,
    },
    /// Write data to a path
    Write {
        /// Path to write
        path: String,
        /// Data as key=value; @file and - read from a file or stdin, and an
        /// argument with no = supplies the whole body as JSON
        args: Vec<String>,
        /// Write with no data, for paths that expect none
        #[arg(long, short)]
        force: bool,
        /// Print only this field's value from the response, bare
        #[arg(long)]
        field: Option<String>,
    },
    /// Delete data at a path
    Delete {
        /// Path to delete
        path: String,
    },
    /// List keys under a path
    List {
        /// Path to list
        path: String,
    },
    /// Patch data, configuration, and secrets (passthrough to vault)
    Patch {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Unwrap a wrapped secret (passthrough to vault)
    Unwrap {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Print seal and HA status (passthrough to vault)
    Status {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Retrieve API help for paths (passthrough to vault)
    PathHelp {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Print runtime configurations (passthrough to vault)
    Print {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Print the version history of the target Vault server (passthrough to vault)
    VersionHistory {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Interact with audit devices (passthrough to vault)
    Audit {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Run the debug command (passthrough to vault)
    Debug {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Interact with events (passthrough to vault)
    Events {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Interact with Vault's Key-Value storage; unmodelled subcommands forward
    Kv {
        #[command(subcommand)]
        command: KvCommands,
    },
    /// Interact with leases (passthrough to vault)
    Lease {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Stream log messages from a Vault server (passthrough to vault)
    Monitor {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Interact with namespaces (passthrough to vault)
    Namespace {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Perform operator-specific tasks (passthrough to vault)
    Operator {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Interact with Vault's PKI Secrets Engine (passthrough to vault)
    Pki {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Interact with Vault plugins and catalog (passthrough to vault)
    Plugin {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Interact with policies (passthrough to vault)
    Policy {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Interact with secrets engines; `list` is native, the rest is forwarded
    Secrets {
        #[command(subcommand)]
        command: SecretsCommands,
    },
    /// Run the official vault binary with this session's address and token
    Vault {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Interact with auth methods (passthrough to vault)
    Auth {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Initiate an SSH session (passthrough to vault)
    Ssh {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Interact with tokens (passthrough to vault)
    Token {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Interact with Vault's Transform Secrets Engine (passthrough to vault)
    Transform {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Interact with Vault's Transit Secrets Engine (passthrough to vault)
    Transit {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
}

/// Vault's own secrets-engine verbs. Only the listing is modelled; everything
/// else reaches the same engine through the forwarding command, which is what
/// keeps `secrets enable` working without this enum growing a variant per verb.
#[derive(Subcommand)]
pub enum SecretsCommands {
    /// List enabled secret engines
    List,
    #[command(external_subcommand)]
    Forwarded(Vec<String>),
}

/// `--mount` deliberately has no short form. Vault spells it `-mount=secret`,
/// and clap reads a single dash as a short flag, so `-m ount=secret` would be a
/// silently wrong mount where an error is wanted.
#[derive(Subcommand)]
pub enum KvCommands {
    /// Read a secret
    Get {
        /// Secret path, as mount/path unless --mount names the mount
        path: String,
        /// Mount holding the secret
        #[arg(long)]
        mount: Option<String>,
        /// Read this version instead of the current one
        #[arg(long)]
        version: Option<u64>,
        /// Print only this field's value, bare
        #[arg(long)]
        field: Option<String>,
    },
    /// Write a secret
    Put {
        /// Secret path, as mount/path unless --mount names the mount
        path: String,
        /// Data as key=value; @file and - read from a file or stdin
        args: Vec<String>,
        /// Mount holding the secret
        #[arg(long)]
        mount: Option<String>,
        /// Write only if the current version matches
        #[arg(long)]
        cas: Option<u64>,
    },
    /// List keys under a path
    List {
        /// Path to list, as mount/path unless --mount names the mount
        path: String,
        /// Mount holding the secrets
        #[arg(long)]
        mount: Option<String>,
    },
    /// Delete a secret, or the named versions of it
    Delete {
        /// Secret path, as mount/path unless --mount names the mount
        path: String,
        /// Mount holding the secret
        #[arg(long)]
        mount: Option<String>,
        /// Versions to delete; without any, the secret itself
        #[arg(long)]
        version: Vec<u64>,
    },
    /// Restore versions a delete withdrew
    Undelete {
        /// Secret path, as mount/path unless --mount names the mount
        path: String,
        /// Mount holding the secret
        #[arg(long)]
        mount: Option<String>,
        /// Versions to restore
        #[arg(long, required = true)]
        version: Vec<u64>,
    },
    /// Destroy versions permanently
    Destroy {
        /// Secret path, as mount/path unless --mount names the mount
        path: String,
        /// Mount holding the secret
        #[arg(long)]
        mount: Option<String>,
        /// Versions to destroy
        #[arg(long, required = true)]
        version: Vec<u64>,
    },
    /// Restore a prior version by writing it back as a new one
    Rollback {
        /// Secret path, as mount/path unless --mount names the mount
        path: String,
        /// Mount holding the secret
        #[arg(long)]
        mount: Option<String>,
        /// Version to restore
        #[arg(long)]
        version: u64,
    },
    /// Secret metadata and version history
    Metadata {
        #[command(subcommand)]
        command: KvMetadataCommands,
    },
    #[command(external_subcommand)]
    Forwarded(Vec<String>),
}

#[derive(Subcommand)]
pub enum KvMetadataCommands {
    /// Show a secret's version history
    Get {
        /// Secret path, as mount/path unless --mount names the mount
        path: String,
        /// Mount holding the secret
        #[arg(long)]
        mount: Option<String>,
    },
    /// Delete a secret and every version of it
    Delete {
        /// Secret path, as mount/path unless --mount names the mount
        path: String,
        /// Mount holding the secret
        #[arg(long)]
        mount: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum KeyCommands {
    /// Where the master key is, and whether replacing it could be undone
    Status,
    /// Every version of the master key the mount still holds
    History,
    /// Write a prior version back, and report how much of the store it recovers
    Restore {
        /// Version to restore
        #[arg(long)]
        version: u64,
    },
}

#[derive(Subcommand)]
pub enum SessionCommands {
    /// Login to Vault
    Login {
        /// Authentication method
        #[arg(long, default_value = "ldap")]
        method: String,

        /// Username
        #[arg(long)]
        username: Option<String>,
    },
    /// Logout from Vault
    Logout,
    /// Show authentication status
    Status,
    /// The master key this machine's local store is sealed with
    Key {
        #[command(subcommand)]
        command: KeyCommands,
    },
    /// Initialize encryption key in personal vault
    InitEncryption {
        /// Overwrite an existing key. Every certificate and private key already
        /// in the local store becomes permanently undecryptable.
        #[arg(long)]
        destroy_all_my_keys: bool,
    },
}

#[derive(Subcommand)]
pub enum CertCommands {
    /// List certificates in PKI mount (or all mounts if not specified)
    List {
        /// PKI mount path (lists all mounts if not provided)
        #[arg(long, short = 'm', value_hint = clap::ValueHint::Other)]
        pki_mount: Option<String>,
        /// Columns to display (comma-separated): cn, serial, not_before, not_after, sans, key_usage, extended_key_usage, issuer, pki_mount, revoked, expired. Prefix any with + to add it to the defaults instead of replacing them.
        #[arg(long)]
        columns: Option<String>,
        /// Only certificates expiring within this duration (e.g. 90d, 6M, 1y). Matching at least one certificate exits 1, for cron/monitoring use.
        #[arg(long, value_parser = parse_expiring_within)]
        expiring_within: Option<Duration>,
        /// Only expired certificates
        #[arg(long, conflicts_with = "exclude_expired")]
        only_expired: bool,
        /// Exclude expired certificates
        #[arg(long, conflicts_with = "only_expired")]
        exclude_expired: bool,
        /// Only revoked certificates
        #[arg(long, conflicts_with = "exclude_revoked")]
        only_revoked: bool,
        /// Exclude revoked certificates
        #[arg(long, conflicts_with = "only_revoked")]
        exclude_revoked: bool,
        /// Filter by extended key usage: client, server, or a raw usage name/OID (case-insensitive)
        #[arg(long)]
        eku: Option<String>,
        /// List what could be read instead of failing when a record cannot be. Skipped records are named on stderr. Combined with --expiring-within the exit status is not authoritative: a partial read can exit 0 while blind to certificates it never read.
        #[arg(long)]
        allow_partial: bool,
    },
    /// List all PKI mounts
    ListMounts {
        /// List mounts whose crypto type could not be detected, with that cell left empty, instead of failing. Skipped mounts are named on stderr.
        #[arg(long)]
        allow_partial: bool,
    },
    /// List available roles in PKI mount
    ListRoles {
        /// PKI mount path
        #[arg(value_hint = clap::ValueHint::Other)]
        pki_mount: String,
    },
    /// Show CA certificate info for a PKI mount: subject, issuer, serial,
    /// validity, Subject/Authority Key Identifier, AIA and CRL URLs
    CaInfo {
        /// PKI mount path
        #[arg(value_name = "PKI_MOUNT", value_hint = clap::ValueHint::Other)]
        pki_mount_pos: Option<String>,
        /// PKI mount path
        #[arg(long = "pki-mount", short = 'm', value_hint = clap::ValueHint::Other)]
        pki_mount: Option<String>,
    },
    /// Verify a certificate against the CA a relying party actually loads:
    /// chain, anchor match, purpose and expiry. Non-zero exit if any check fails
    Verify {
        /// Certificate file to verify (a leaf, or a bundle whose first entry is the leaf)
        #[arg(value_name = "FILE", value_hint = clap::ValueHint::FilePath)]
        certificate_file: String,
        /// CA the relying party loads. The anchor that decides acceptance
        #[arg(long, value_name = "FILE", value_hint = clap::ValueHint::FilePath)]
        against_ca: Option<String>,
        /// Verify against this mount's CA instead of a file
        #[arg(long = "pki-mount", short = 'm', conflicts_with = "against_ca", value_hint = clap::ValueHint::Other)]
        pki_mount: Option<String>,
        /// Require the certificate be usable for this purpose
        #[arg(long, value_enum)]
        purpose: Option<VerifyPurpose>,
    },
    /// Create new certificate
    Create {
        /// PKI mount
        #[arg(long, short = 'm', value_hint = clap::ValueHint::Other)]
        pki_mount: String,
        /// Common name
        cn: String,
        /// Certificate role (use 'vault-rs cert list-roles <pki>' to see available roles)
        #[arg(long)]
        role: String,
        /// Cryptographic algorithm (auto-detected from PKI mount if not specified)
        #[arg(long)]
        crypto: Option<CryptoType>,
        /// Alternative names (comma-separated)
        #[arg(long)]
        alt_names: Option<String>,
        /// IP SANs (comma-separated)
        #[arg(long)]
        ip_sans: Option<String>,
        /// Certificate TTL
        #[arg(long)]
        ttl: Option<String>,
        /// Don't store encrypted locally
        #[arg(long)]
        no_store: bool,
        /// Also export unencrypted to directory
        #[arg(long)]
        export_plain: Option<String>,
        /// Show what would be issued, with provenance, and exit without writing
        #[arg(long)]
        dry_run: bool,
        /// Skip the confirmation prompt
        #[arg(long)]
        yes: bool,
    },
    /// Sign certificate from CSR
    Sign {
        /// PKI mount
        #[arg(long, short = 'm', value_hint = clap::ValueHint::Other)]
        pki_mount: String,
        /// Common name
        cn: String,
        /// CSR file path
        csr_file: String,
        /// Certificate role (use 'vault-rs cert list-roles <pki>' to see available roles)
        #[arg(long)]
        role: String,
        /// Cryptographic algorithm (auto-detected from PKI mount if not specified)
        #[arg(long)]
        crypto: Option<CryptoType>,
        /// Alternative names (comma-separated)
        #[arg(long)]
        alt_names: Option<String>,
        /// IP SANs (comma-separated)
        #[arg(long)]
        ip_sans: Option<String>,
        /// Certificate TTL
        #[arg(long)]
        ttl: Option<String>,
        /// Don't store encrypted locally
        #[arg(long)]
        no_store: bool,
        /// Also export unencrypted to directory
        #[arg(long)]
        export_plain: Option<String>,
        /// Show what would be issued, with provenance, and exit without writing
        #[arg(long)]
        dry_run: bool,
        /// Skip the confirmation prompt
        #[arg(long)]
        yes: bool,
    },
    /// Inspect a CSR: subject, key type, SANs and requested extensions. With
    /// -m/--pki-mount and --role, also show what the role would keep,
    /// override or drop when signing it
    InspectCsr {
        /// CSR file path
        #[arg(value_name = "FILE", value_hint = clap::ValueHint::FilePath)]
        file: String,
        /// PKI mount to check the role against (requires --role)
        #[arg(long = "pki-mount", short = 'm', requires = "role", value_hint = clap::ValueHint::Other)]
        pki_mount: Option<String>,
        /// Role to check the CSR against (requires -m/--pki-mount)
        #[arg(long, requires = "pki_mount")]
        role: Option<String>,
    },
    /// Export certificate by CN or serial
    Export {
        /// Certificate identifier (Common Name or serial number)
        identifier: String,
        /// PKI mount (for CN lookups, optional)
        #[arg(long, short = 'm')]
        pki_mount: Option<String>,
        /// Export format: pem, der, key, p12, chain, chain-with-root, or bundle
        #[arg(long, default_value = "pem")]
        format: ExportFormat,
        /// Output directory (default: stdout for PEM format)
        #[arg(long)]
        output: Option<String>,
        /// Skip passphrase prompt for P12 export (creates unprotected P12)
        #[arg(long)]
        no_passphrase: bool,
        /// Include OpenSSL-style text output before PEM data
        #[arg(long)]
        text: bool,
        /// Append the mount and issuing role, which no certificate records, so storage import can restore them
        #[arg(long)]
        with_provenance: bool,
    },
    /// Show certificate details by CN or serial
    Show {
        /// Certificate identifier (Common Name or serial number)
        identifier: String,
        /// PKI mount (for CN lookups, optional)
        #[arg(long, short = 'm')]
        pki_mount: Option<String>,
    },
    /// Export certificate by serial number
    ExportBySerial {
        /// Certificate serial number
        serial: String,
        /// PKI mount to scope the search (optional)
        #[arg(long, short = 'm')]
        pki_mount: Option<String>,
        /// Export format: pem, der, key, p12, chain, chain-with-root, or bundle
        #[arg(long, default_value = "pem")]
        format: ExportFormat,
        /// Output directory
        #[arg(long, default_value = ".")]
        output: String,
        /// Include OpenSSL-style text output before PEM data
        #[arg(long)]
        text: bool,
    },
    /// Revoke certificate in Vault
    Revoke {
        /// Certificate identifier (Common Name or serial number)
        identifier: String,
        /// PKI mount (for CN lookups, optional)
        #[arg(long, short = 'm')]
        pki_mount: Option<String>,
        /// Skip the confirmation prompt
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
pub enum StorageCommands {
    /// List locally stored certificates
    List {
        /// Filter by PKI mount
        #[arg(long)]
        pki: Option<String>,
        /// Show only expired certificates
        #[arg(long)]
        expired: bool,
        /// Show certificates expiring soon
        #[arg(long)]
        expires_soon: Option<String>,
        /// Filter by issuing role. Only local storage records the role; cert list cannot offer this filter.
        #[arg(long)]
        role: Option<String>,
        /// Columns to display (comma-separated): cn, serial, not_before, not_after, sans, key_usage, extended_key_usage, issuer, pki_mount, revoked, expired, role. Prefix any with + to add it to the defaults instead of replacing them.
        #[arg(long)]
        columns: Option<String>,
        /// List what could be read, treating unreadable artifacts as a warning. The result is not authoritative for that run.
        #[arg(long)]
        allow_partial: bool,
    },
    /// Show detailed info for stored certificate
    Show {
        /// Common name
        cn: String,
        /// PKI mount, when the same common name is held under more than one
        #[arg(long)]
        pki_mount: Option<String>,
        /// Serial, when the same common name is held more than once
        #[arg(long)]
        serial: Option<String>,
        /// Report an artifact that will not decrypt instead of failing on it
        #[arg(long)]
        allow_partial: bool,
    },
    /// Remove one stored artifact. Destroying anything unrecoverable requires the option that names it.
    Remove {
        /// Common name
        cn: String,
        /// PKI mount, when the same common name is held under more than one
        #[arg(long)]
        pki_mount: Option<String>,
        /// Serial, when the same common name is held more than once
        #[arg(long)]
        serial: Option<String>,
        /// Consent to destroying a private key that exists nowhere else
        #[arg(long)]
        destroy_my_private_key: bool,
        /// Consent to destroying an artifact nothing can currently read, whose contents cannot be named
        #[arg(long)]
        destroy_my_unreadable_artifact: bool,
    },
    /// File a PEM bundle into the local store, sealed by the Vault now being addressed
    Import {
        /// PEM file holding a certificate, optionally a key, a chain and a provenance block
        file: String,
        /// PKI mount. Required unless the file carries provenance; no certificate names one
        #[arg(long)]
        pki_mount: Option<String>,
        /// Issuing role. Recorded as absent when neither this nor the file supplies it
        #[arg(long)]
        role: Option<String>,
    },
    /// Decrypt storage file for debugging
    Decrypt {
        /// Path to encrypted file
        file_path: String,
    },
}

#[derive(Subcommand)]
pub enum CacheCommands {
    /// Show cache statistics
    Status {
        /// Report mounts whose cache file will not load, with the count left empty, instead of failing. Skipped mounts are named on stderr.
        #[arg(long)]
        allow_partial: bool,
    },
    /// Clear certificate cache (lazy caching will refetch as needed)
    Clear {
        /// Specific PKI mount to clear
        #[arg(long)]
        pki: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum CompletionCommands {
    /// Generate bash completion script
    Bash,
    /// Generate zsh completion script
    Zsh,
    /// Generate fish completion script
    Fish,
    /// Generate PowerShell completion script
    PowerShell,
}

impl CompletionCommands {
    pub fn shell(&self) -> Shell {
        match self {
            CompletionCommands::Bash => Shell::Bash,
            CompletionCommands::Zsh => Shell::Zsh,
            CompletionCommands::Fish => Shell::Fish,
            CompletionCommands::PowerShell => Shell::PowerShell,
        }
    }
}

#[derive(Subcommand)]
pub enum CompletionHelperCommands {
    /// List PKI mounts for completion
    PkiMounts,
    /// List roles for a PKI mount for completion
    Roles {
        /// PKI mount path
        pki_mount: String,
    },
    /// List available columns for completion
    Columns,
}

#[derive(ValueEnum, Clone, Debug)]
pub enum CryptoType {
    Rsa,
    Ec,
}

#[derive(ValueEnum, Clone, Debug)]
pub enum VerifyPurpose {
    ClientAuth,
    ServerAuth,
}

impl CryptoType {
    pub fn as_str(&self) -> &'static str {
        match self {
            CryptoType::Rsa => "rsa",
            CryptoType::Ec => "ec",
        }
    }
}

#[derive(ValueEnum, Clone, Debug)]
pub enum ExportFormat {
    Pem,
    Der,
    Key,
    P12,
    /// Leaf + intermediates, self-signed root dropped (safe for external handoff)
    Chain,
    /// Leaf + intermediates + root, for internal trust configuration
    ChainWithRoot,
    /// Private key + leaf + intermediates, self-signed root dropped; requires a stored key
    Bundle,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expiring_within_accepts_humantime_durations() {
        assert_eq!(
            parse_expiring_within("90d").unwrap(),
            Duration::from_secs(90 * 24 * 3600)
        );
        assert_eq!(
            parse_expiring_within("1y").unwrap(),
            Duration::from_secs(365 * 24 * 3600 + 6 * 3600) // humantime's year includes leap-day fraction
        );
        assert_eq!(
            parse_expiring_within("6M").unwrap(),
            Duration::from_secs(6 * 2630016) // humantime's month is 30.44 days
        );
    }

    #[test]
    fn expiring_within_rejects_garbage() {
        assert!(parse_expiring_within("not-a-duration").is_err());
    }
}
