# Vault-RS Development Guidelines

## Output Format Requirements

**UNIX-friendly output only** - All output should be machine-readable and pipeline-friendly:

- One item per line, no prefixes
- Clean data that can be piped to other commands
- No decorative headers like "PKI Mounts:"
- No leading spaces or formatting fluff
- No pretty-printing or human-friendly labels
- No decorative output that breaks `grep`, `awk`, etc.
- **All logs, warnings, and errors must go to stderr, never stdout**
- Stdout is reserved for data output only

### Output Handling Guidelines (src/utils/output.rs)

**MANDATORY: Use OutputFormat methods for ALL structured data:**
- `output.print_table()` - Multi-column tabular data with --raw support
- `output.print_list()` - Single-column lists, one item per line  
- `output.print_key_value()` - Key-value pairs (2-column data)

**NEVER use direct println!() for structured data** - Always use OutputFormat methods.

**Direct output only for these specific cases:**
- `println!()` - Single values only when OutputFormat isn't available
- `eprintln!()` - User-facing status messages and errors to stderr
- `tracing::info!()` - Debug/internal logging (controlled by -v flags)

**Critical:** OutputFormat automatically handles --raw vs formatted modes. Using direct println!() breaks UNIX pipeline compatibility and user formatting preferences.

## Certificate Management Features

### Crypto Type Auto-Detection (src/vault/client.rs)

- PKI mounts can auto-detect crypto type (RSA/EC) from issuer certificates
- Use `client.detect_crypto_type(token, pki_mount)` to get crypto type
- **Never default to RSA** - fail fast if detection fails to prevent wrong cert types
- Auto-detection queries `/pki/config/issuers` and parses certificate OIDs
- Falls back to explicit `--crypto` parameter when auto-detection unavailable

## Security Principles

- Always use proper TLS certificate validation
- Never disable security checks by default
- Use system certificate stores (rustls-tls-native-roots)
- Store tokens securely in `XDG_RUNTIME_DIR` with mode 600
- **Never create certificates with wrong crypto type** - fail fast instead
- **NEVER use /tmp for temporary files** - always use `VaultCliPaths::runtime_dir()` for volatile storage
- Temporary files must have secure permissions (0o600) and be cleaned up immediately after use

## Rust Coding Guidelines

- **Use direct variable interpolation in format macros**:
  - Good: `format!("{variable}")`, `println!("{value}")`, `eprintln!("Error: {error}")`
  - Bad: `format!("{}", variable)`, `println!("{}", value)`, `eprintln!("Error: {}", error)`
  - This prevents clippy warnings and is more readable
  - Only use positional arguments (`{}`) when you need complex formatting or multiple uses of the same variable

- **Keep commands.rs lightweight** - NEVER add complex logic to commands.rs. It should only:
  - Parse command arguments
  - Call functions from other modules
  - Handle basic error responses
  - All business logic must be in separate modules (cert/, vault/, storage/, etc.)

- If a function call takes more than ~7 arguments, use a data structure

## Implementation Guidelines

- When possible, use `PROGRAM_NAME` instead of `"vault-rs"` (import `crate::utils::PROGRAM_NAME` first)
