# vault-rs

A secure, UNIX-friendly PKI management tool for HashiCorp Vault with advanced certificate lifecycle management.

## Why vault-rs?

While the official `vault` CLI is comprehensive for general Vault operations, `vault-rs` is purpose-built for PKI certificate management with several key enhancements:

### Encrypted Local Storage

- **Local certificate caching**: All certificates and private keys are stored encrypted locally using AES-GCM
- **Master key management**: Master key stored at a fixed `vault-rs/encryption-key` path in an auto-discovered KV mount (the `secret` mount if present, otherwise the first KV mount found)
- **Secure permissions**: Runtime files stored in `$XDG_RUNTIME_DIR/vault-rs/` (falling back to `~/.local/state/vault-rs/` when unset) with mode 600
- **NEVER uses /tmp**: All temporary operations use secure runtime directories

### Enhanced Certificate Listing 
```bash
# vault-rs provides rich, machine-readable certificate data
vault-rs cert list --columns cn,not_after,revoked,extended_key_usage
vault-rs cert list --pki-mount internal --columns +sans,+key_usage  # append to defaults
vault-rs storage list --expired                                     # show only expired certs
vault-rs storage list --expires-soon 30                            # expiring in 30 days

# Renewal monitoring: exits 1 when anything matches, so cron needs no output parsing
vault-rs cert list --expiring-within 90d
vault-rs cert list --expiring-within 1y --columns cn,not_after,pki_mount

# Filter by usage or state
vault-rs cert list --pki-mount internal --eku client
vault-rs cert list --exclude-expired --exclude-revoked

# JSON for anything nested (--json is global, before the subcommand)
vault-rs --json cert list --pki-mount internal
```

**vs. official vault:**
```bash
vault list pki/certs/  # only shows serial numbers, no metadata
```

`--allow-partial` on `cert list`, `cert list-mounts` and `cache status` lists what it could read
instead of failing on a record it can't; skipped records are named on stderr. Combined with
`--expiring-within`, a partial read can still exit 0 while blind to certificates it never read —
the exit code is not authoritative in that case.

### Automatic DNS Discovery

- **SRV record support**: Discovers Vault servers via `_vault._tcp.<domain>` SRV records
- **DNS TTL caching**: Respects DNS TTL for intelligent cache expiration
- **Search domain parsing**: Automatically parses `/etc/resolv.conf` for domain search

### Smart Certificate Management

- **Crypto type auto-detection**: Automatically detects RSA vs EC from PKI mount issuers
- **Fail-fast validation**: Never creates certificates with wrong crypto type
- **Certificate revocation tracking**: Shows revocation status in listings
- **Expiration monitoring**: Built-in expiration tracking and alerts

### Export Formats

```bash
# With no --output, every format goes to stdout except p12, which needs a directory
vault-rs cert export example.com --format pem     # PEM to stdout (pipe-friendly)
vault-rs cert export example.com --format p12     # PKCS#12 with passphrase
vault-rs cert export example.com --format der     # DER, binary
vault-rs cert export example.com --format chain   # leaf + intermediates, root excluded, no key needed
vault-rs cert export example.com --format chain-with-root  # for internal trust config
vault-rs cert export example.com --format bundle  # key + leaf + chain; errors without a locally stored key
```

`chain` excludes the self-signed root deliberately: it is the artifact a peer needs and the one
safe to send outside. `chain-with-root` is for configuring your own trust stores — handing a root
to an external party invites them to trust the whole hierarchy system-wide. `bundle` requires the
private key to be held in local storage; use `chain` for a keyless artifact.

### Rehearse Before Issuing, Verify After

Issuance is durable and its only undo is a revocation that has to reach every relying party, so the
write path is rehearsable:

```bash
# What would actually be issued, and where each field comes from
vault-rs cert sign -m internal --role client example.com request.csr --dry-run

# Inspect a CSR on its own, or projected through a role
vault-rs cert inspect-csr request.csr
vault-rs cert inspect-csr request.csr -m internal --role client
```

The provenance matters more than the result: with `use_csr_common_name=true` the subject comes from
the CSR and the CN argument is inert, so `--dry-run` reports the argument as unused rather than
letting you believe the command line decided it. A wrong CN in a CSR cannot be corrected at signing
time — it needs a new request from whoever holds the key.

`sign`, `create` and `revoke` confirm before writing; `--yes` skips the prompt for scripts.

### Verify Against the Anchor That Decides Acceptance

```bash
# The CA the relying party actually loads — not the chain the issuer would assemble
vault-rs cert verify leaf.pem --against-ca ca.crt --purpose client-auth
vault-rs cert verify leaf.pem -m internal --purpose server-auth

# What a mount's CA is, for matching against a deployed trust anchor
vault-rs cert ca-info internal
```

```
chain    OK  0 intermediate(s) to the anchor
anchor   OK  AKI D5:F2:…:99:5D matches CA SKI
expiry   OK  2031-08-03 (1824d)
purpose  OK  clientAuth
```

The anchor line is reported separately from path validation because it is the check that predicts
acceptance. A certificate can validate perfectly against its own hierarchy and still be refused by
a peer that was never given that hierarchy. Non-zero exit if any check fails, so this works as a
monitoring probe.

### UNIX Philosophy Compliance

- **Machine-readable output**: All output designed for shell scripting and automation
- **Pipeline-friendly**: Clean stdout data, errors/logs to stderr only
- **Tab completion**: Comprehensive bash/zsh/fish completion for all commands
- **Raw mode**: `--raw` flag for tab-separated values without formatting

### Performance Optimizations

- **Lazy certificate caching**: certificates are immutable, so each is fetched from Vault once and read from the local cache afterward — only serials missing from the cache are ever fetched
- **Bulk operations**: Efficient batch processing for multiple certificates

### Vault Integration

- **Command passthrough**: every Vault verb this tool does not wrap itself is forwarded to the official `vault` binary with the address and token already resolved. Reasoning about an issuance means reading role and issuer configuration no curated command anticipates, and the passthrough keeps that in one tool and one login instead of two. `vault-rs --help` lists what is currently forwarded
- **Token management**: Secure token storage and automatic refresh
- **Mount discovery**: Automatic PKI mount detection and validation

## Installation

```bash
# Build from source
git clone https://github.com/ticpu/vault-rs
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
vault-rs cert create -m internal --role server example.com --alt-names "*.example.com,api.example.com"

# Sign someone else's CSR — rehearse first, then issue
vault-rs cert sign -m internal --role client example.com request.csr --dry-run
vault-rs cert sign -m internal --role client example.com request.csr --export-plain .

# List certificates with detailed info
vault-rs cert list --columns cn,not_after,revoked,extended_key_usage

# Confirm it will be accepted by the party receiving it
vault-rs cert verify example.com.pem --against-ca their-trusted-ca.crt --purpose client-auth

# Export for use
vault-rs cert export example.com --format p12 --output ./certs/
```

The mount is `-m/--pki-mount` on every `cert` subcommand, and `--role` has no default — an unknown
or omitted role errors before anything reaches the CA.

## Key Differences from Official Vault CLI

| Feature | Official `vault` | `vault-rs` |
|---------|------------------|------------|
| Certificate listing | Serial numbers only | Rich metadata with filtering |
| Local storage | None | Encrypted local cache |
| Output format | Human-readable | UNIX-friendly, machine-readable |
| DNS discovery | Manual VAULT_ADDR | Automatic SRV record discovery |
| Export formats | Limited | Text and binary encodings, plus chain variants for handoff vs internal trust |
| Certificate tracking | None | Expiration monitoring, revocation status |
| Pre-issuance preview | None | `--dry-run` with per-field provenance |
| Chain verification | None | Against the anchor the relying party loads |
| Crypto validation | Basic | Auto-detection, fail-fast validation |
| Caching | None | Lazy loading; fetches only what is missing from the cache |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Ran successfully |
| 1 | `--expiring-within` matched a certificate, or `cert verify` failed a check |
| 2 | Error |

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
- **Runtime**: `$XDG_RUNTIME_DIR/vault-rs/` (falling back to `~/.local/state/vault-rs/` when unset) - Tokens, cache, temp files
- **Config**: `~/.config/vault-rs/` - User configuration
- **Cache**: Certificate metadata cached per PKI mount; certificates are immutable, so once fetched an entry is never re-fetched

## Security Model

1. **Master key** stored at a fixed `vault-rs/encryption-key` path in an auto-discovered KV mount; `auth init-encryption` refuses to overwrite an existing key unless `--destroy-all-my-keys` is passed, which makes every locally stored artifact permanently undecryptable
2. **All certificates** encrypted locally with AES-GCM using derived keys
3. **Secure file permissions** (600) on all sensitive files
4. **No plaintext storage** of certificates or private keys
5. **TLS verification** always enabled, uses system certificate store