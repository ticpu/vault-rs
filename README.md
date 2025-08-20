# vault-rs

A secure, UNIX-friendly PKI management tool for HashiCorp Vault with advanced certificate lifecycle management.

## Why vault-rs?

While the official `vault` CLI is comprehensive for general Vault operations, `vault-rs` is purpose-built for PKI certificate management with several key enhancements:

### 🔒 **Encrypted Local Storage**
- **Local certificate caching**: All certificates and private keys are stored encrypted locally using AES-GCM
- **Master key management**: Uses personal Vault storage (`kv-v2/users/<username>/vault-rs`) for master key encryption
- **Secure permissions**: Runtime files stored in `XDG_RUNTIME_DIR` with mode 600
- **NEVER uses /tmp**: All temporary operations use secure runtime directories

### 📊 **Enhanced Certificate Listing** 
```bash
# vault-rs provides rich, machine-readable certificate data
vault-rs cert list --columns cn,not_after,revoked,extended_key_usage
vault-rs cert list --pki-mount internal --columns +sans,+key_usage  # append to defaults
vault-rs storage list --expired                                     # show only expired certs
vault-rs storage list --expires-soon 30                            # expiring in 30 days
```

**vs. official vault:**
```bash
vault list pki/certs/  # only shows serial numbers, no metadata
```

### 🌐 **Automatic DNS Discovery**
- **SRV record support**: Discovers Vault servers via `_vault._tcp.<domain>` SRV records
- **DNS TTL caching**: Respects DNS TTL for intelligent cache expiration
- **Search domain parsing**: Automatically parses `/etc/resolv.conf` for domain search

### 🛡️ **Smart Certificate Management**
- **Crypto type auto-detection**: Automatically detects RSA vs EC from PKI mount issuers
- **Fail-fast validation**: Never creates certificates with wrong crypto type
- **Certificate revocation tracking**: Shows revocation status in listings
- **Expiration monitoring**: Built-in expiration tracking and alerts

### 📤 **Advanced Export Capabilities**
```bash
# Multiple export formats with intelligent fallbacks
vault-rs cert export example.com --format pem     # PEM to stdout (pipe-friendly)  
vault-rs cert export example.com --format p12     # PKCS#12 with passphrase
vault-rs cert export example.com --format all     # All formats to directory
vault-rs cert export example.com --format chain   # Full certificate chain
```

### 🔧 **UNIX Philosophy Compliance**
- **Machine-readable output**: All output designed for shell scripting and automation
- **Pipeline-friendly**: Clean stdout data, errors/logs to stderr only
- **Tab completion**: Comprehensive bash/zsh/fish completion for all commands
- **Raw mode**: `--raw` flag for tab-separated values without formatting

### ⚡ **Performance Optimizations**
- **Lazy certificate caching**: Certificates cached on first access, refreshed as needed
- **Bulk operations**: Efficient batch processing for multiple certificates
- **Intelligent refresh**: Only fetches certificates when cache is stale

### 🔄 **Vault Integration**
- **Command passthrough**: `vault-rs read/write/secrets/operator` commands pass through to official vault with preset auth
- **Token management**: Secure token storage and automatic refresh
- **Mount discovery**: Automatic PKI mount detection and validation

## Installation

```bash
# Build from source
git clone https://github.com/your-org/vault-rs
cd vault-rs
cargo build --release
sudo cp target/release/vault-rs /usr/local/bin/
```

## Quick Start

```bash
# Login and initialize encryption
vault-rs auth login --method ldap --username yourname
vault-rs auth init-encryption

# Create a certificate  
vault-rs cert create internal example.com --alt-names "*.example.com,api.example.com"

# List certificates with detailed info
vault-rs cert list --columns cn,not_after,revoked,extended_key_usage

# Export for use
vault-rs cert export example.com --format p12 --output ./certs/
```

## Key Differences from Official Vault CLI

| Feature | Official `vault` | `vault-rs` |
|---------|------------------|------------|
| Certificate listing | Serial numbers only | Rich metadata with filtering |
| Local storage | None | Encrypted local cache |
| Output format | Human-readable | UNIX-friendly, machine-readable |
| DNS discovery | Manual VAULT_ADDR | Automatic SRV record discovery |
| Export formats | Limited | PEM, CRT, P12, chain, key, all |
| Certificate tracking | None | Expiration monitoring, revocation status |
| Crypto validation | Basic | Auto-detection, fail-fast validation |
| Caching | None | Intelligent lazy loading |

## Configuration

```bash
# Set via environment
export VAULT_ADDR="https://vault.company.com:8200"

# Or let vault-rs discover via DNS
# (requires _vault._tcp.company.com SRV record)
unset VAULT_ADDR

# Enable verbose logging
vault-rs -vv cert list
```

## Architecture

- **Local Storage**: `~/.local/share/vault-rs/` - Encrypted certificate storage
- **Runtime**: `$XDG_RUNTIME_DIR/vault-rs/` - Tokens, cache, temp files  
- **Config**: `~/.config/vault-rs/` - User configuration
- **Cache**: Certificate metadata cached per PKI mount with TTL

## Security Model

1. **Master key** stored in personal Vault KV store (`kv-v2/users/<username>/vault-rs`)
2. **All certificates** encrypted locally with AES-GCM using derived keys
3. **Secure file permissions** (600) on all sensitive files
4. **No plaintext storage** of certificates or private keys
5. **TLS verification** always enabled, uses system certificate store

## Contributing

vault-rs follows strict security and UNIX philosophy principles:
- All output must be machine-readable  
- Errors/logs go to stderr, data to stdout
- Fail fast on security violations
- Never store secrets in plaintext

See [CLAUDE.md](CLAUDE.md) for detailed development guidelines.