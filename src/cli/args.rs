use clap::{Parser, Subcommand, ValueEnum};
use clap_complete::Shell;

#[derive(Parser)]
#[command(name = "vault-rs")]
#[command(version = "1.0.0")]
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
    #[arg(short, long)]
    pub raw: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Authentication management
    Auth {
        #[command(subcommand)]
        command: AuthCommands,
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
    /// Vault read operations (wrapper for vault secrets with preset VAULT_ADDR/VAULT_TOKEN)
    /// Pass-through arguments to vault.
    Read {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Vault read operations (wrapper for vault secrets with preset VAULT_ADDR/VAULT_TOKEN)
    /// Pass-through arguments to vault.
    Write {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Vault secrets engine operations (wrapper for vault secrets with preset VAULT_ADDR/VAULT_TOKEN)
    /// Pass-through arguments to vault.
    Secrets {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Vault operator operations (wrapper for vault operator with preset VAULT_ADDR/VAULT_TOKEN)
    /// Pass-through arguments to vault.
    Operator {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
}

#[derive(Subcommand)]
pub enum AuthCommands {
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
    /// Initialize encryption key in personal vault
    InitEncryption,
    /// List available secret engines
    ListSecrets,
}

#[derive(Subcommand)]
pub enum CertCommands {
    /// List certificates in PKI mount (or all mounts if not specified)
    List {
        /// PKI mount path (lists all mounts if not provided)
        #[arg(long, short = 'm', value_hint = clap::ValueHint::Other)]
        pki_mount: Option<String>,
        /// Columns to display (comma-separated): cn,serial,not_before,not_after,sans,key_usage,extended_key_usage,issuer,pki_mount. Use +column to append to defaults.
        #[arg(long)]
        columns: Option<String>,
    },
    /// List all PKI mounts
    ListMounts,
    /// List available roles in PKI mount
    ListRoles {
        /// PKI mount path
        #[arg(value_hint = clap::ValueHint::Other)]
        pki_mount: String,
    },
    /// Create new certificate
    Create {
        /// PKI mount
        #[arg(value_hint = clap::ValueHint::Other)]
        pki: String,
        /// Common name
        cn: String,
        /// Certificate role (use 'vault-rs cert list-roles <pki>' to see available roles)
        #[arg(long, default_value = "default")]
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
    },
    /// Sign certificate from CSR
    Sign {
        /// PKI mount
        #[arg(value_hint = clap::ValueHint::Other)]
        pki: String,
        /// Common name
        cn: String,
        /// CSR file path
        csr_file: String,
        /// Certificate role (use 'vault-rs cert list-roles <pki>' to see available roles)
        #[arg(long, default_value = "default")]
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
    },
    /// Export certificate by CN or serial
    Export {
        /// Certificate identifier (Common Name or serial number)
        identifier: String,
        /// PKI mount (for CN lookups, optional)
        #[arg(long)]
        pki_mount: Option<String>,
        /// Export formats
        #[arg(long, default_value = "pem")]
        format: ExportFormat,
        /// Output directory (default: stdout for PEM format)
        #[arg(long)]
        output: Option<String>,
        /// Export decrypted files
        #[arg(long)]
        decrypt: bool,
        /// Skip passphrase prompt for P12 export (creates unprotected P12)
        #[arg(long)]
        no_passphrase: bool,
        /// Include OpenSSL-style text output before PEM data
        #[arg(long)]
        text: bool,
    },
    /// Extract and store from Vault JSON response
    Extract {
        /// JSON file path
        json_file: String,
        /// Override common name for storage
        #[arg(long)]
        cn: Option<String>,
        /// Specify PKI mount for organization
        #[arg(long)]
        pki_mount: Option<String>,
    },
    /// Show certificate details by CN or serial
    Show {
        /// Certificate identifier (Common Name or serial number)
        identifier: String,
        /// PKI mount (for CN lookups, optional)
        #[arg(long)]
        pki_mount: Option<String>,
    },
    /// Export certificate by serial number
    ExportBySerial {
        /// Certificate serial number
        serial: String,
        /// Export formats
        #[arg(long, default_value = "all")]
        format: ExportFormat,
        /// Output directory
        #[arg(long, default_value = ".")]
        output: String,
    },
    /// Find certificate by serial number
    FindSerial {
        /// Certificate serial number
        serial: String,
    },
    /// Revoke certificate in Vault
    Revoke {
        /// Certificate identifier (Common Name or serial number)
        identifier: String,
        /// PKI mount (for CN lookups, optional)
        #[arg(long)]
        pki_mount: Option<String>,
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
        /// Columns to display (comma-separated): cn,serial,not_before,not_after,sans,key_usage,extended_key_usage,issuer,pki_mount. Use +column to append to defaults.
        #[arg(long)]
        columns: Option<String>,
    },
    /// Show detailed info for stored certificate
    Show {
        /// Common name
        cn: String,
        /// PKI mount
        #[arg(long)]
        pki_mount: Option<String>,
    },
    /// Remove stored certificate
    Remove {
        /// Common name
        cn: String,
        /// PKI mount
        #[arg(long)]
        pki_mount: Option<String>,
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
    Status,
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
}

#[derive(ValueEnum, Clone, Debug)]
pub enum CryptoType {
    Rsa,
    Ec,
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
    Crt,
    Key,
    P12,
    Chain,
    All,
}
