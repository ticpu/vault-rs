# vault-rs

A secure, UNIX-friendly PKI management tool for HashiCorp Vault with advanced certificate lifecycle management.

## Why vault-rs?

While the official `vault` CLI is comprehensive for general Vault operations, `vault-rs` is purpose-built for PKI certificate management with several key enhancements:

### Encrypted Local Storage

- **Local certificate caching**: All certificates and private keys are stored encrypted locally using AES-GCM
- **Master key management**: Master key stored at a fixed `vault-rs/encryption-key` path in an auto-discovered KV mount (the `secret` mount if present, otherwise the first KV mount found)
- **Secure permissions**: Runtime files stored in `$XDG_RUNTIME_DIR/vault-rs/` (falling back to `~/.local/state/vault-rs/` when unset) with mode 600
- **NEVER uses /tmp**: All temporary operations use secure runtime directories
- **The directory is the store**: every read walks `~/.local/share/vault-rs/secrets/{mount}/{cn}/{serial}/` and takes each record from that artifact's own files. There is no index to rebuild, so a store copied or restored by hand lists as-is.
- **Sealed per cluster**: the master key comes from whichever Vault `VAULT_ADDR` resolved to when the artifact was written, and each artifact records that cluster beside it. Point the tool at a second server, issue something, and point it back: that artifact is readable only from the cluster that sealed it, and `storage list` says so instead of blaming the key.

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

`cert list --json` and `storage list --json` emit different schemas, because they are different
records: one is what the PKI holds, the other is what is on this disk. Neither carries a
`vault_status` — nothing checked it.

### The Local Store

```bash
vault-rs storage list                          # refuses if anything is unreadable, and says why
vault-rs storage list --allow-partial          # list what could be read; the rest named on stderr
vault-rs storage show example.com              # one artifact, including files and sealing cluster
vault-rs storage show example.com --serial 3a1f…   # when one name is held more than once
vault-rs storage import ./example.com.pem      # file an exported bundle back in
```

An artifact that will not decrypt is a corruption signal, not a row: `storage list` names it on
stderr and exits non-zero, and `--allow-partial` is the explicit escape hatch. `storage show` still
reports such an artifact — the path, which cluster sealed it, and each file's size — because it is
the first thing you run after a listing points at one.

Removal names what it destroys instead of taking a general-purpose `--yes`:

```bash
vault-rs storage remove example.com                                  # deleted if only a certificate
vault-rs storage remove example.com --destroy-my-private-key         # key exists nowhere else
vault-rs storage remove example.com --destroy-my-unreadable-artifact # nothing can read it today
```

Removing a certificate-only artifact needs no option — the PKI still holds the certificate — but it
does drop the issuing role, which the PKI never recorded. An ambiguous name is refused with the
candidates listed, never resolved to the first match.

### Moving Entries Between Machines or Clusters

An artifact is encrypted under a key derived from the master key of the Vault cluster that sealed
it, so copying `secrets/` to a host pointed at a different cluster produces a directory nothing can
read. Export it and import it instead:

```bash
# On the source host, pointed at the cluster that sealed it
vault-rs cert export example.com --format bundle --with-provenance --output ./   # key + leaf + chain
vault-rs cert export example.com --format chain --with-provenance --output ./    # keyless artifact

# On the target host, pointed at wherever it should live now
vault-rs storage import ./example.com.pem
```

`--with-provenance` appends a `VAULT-RS PROVENANCE` block after the certificates, holding the two
things no certificate records: the **mount** and the **issuing role**. Without it the file still
imports, but you must name the mount yourself and the role is recorded as absent — the PKI never
held it, so nothing can recover it later. openssl and anything else reading the file ignore the
block; it is refused on `der`, `p12` and `key`, which have nowhere to put it, rather than silently
dropped.

Import takes everything else off the certificate itself, seals the artifact with the cluster you are
now addressing, and reports where each field came from. It refuses onto an entry that already
exists — overwriting could destroy a private key that exists nowhere else, so `storage remove` is a
separate, explicitly named step.

To read an old artifact again rather than move it, point back at the cluster that sealed it; the
address is recorded next to the artifact and `storage show` prints it.

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
- **Partly-modelled verbs split by subcommand**: `vault-rs secrets list` is answered directly; `vault-rs secrets enable` and every other subcommand is forwarded. `vault-rs --help secrets` says which
- **`vault-rs vault <args…>`**: runs the official binary verbatim with this session's address and token. The token lives in `$XDG_RUNTIME_DIR/vault-rs/` and is never exported, so this is how you reach anything vault-rs does not model — invoking `vault` yourself would not be authenticated
- **`--vault-addr` applies to one invocation**, outranking `VAULT_ADDR`. Useful for reaching the cluster that sealed an artifact (`vault-rs storage show` names it) without exporting anything into the shell you are in
- **`VAULT_NAMESPACE` is sent on every request**, not only on forwarded ones
- **`session` is this machine, everything else is the server**: `vault-rs session login/logout/status` and `session init-encryption` act on the local token and encryption key. `vault-rs auth …` and `vault-rs secrets …` reach Vault's own auth methods and engines
- **Logging out revokes**: `vault-rs session logout` revokes the token server-side and removes it locally. The local token goes even when revocation fails — an expired token or an unreachable server should not leave the credential on disk — and the command exits non-zero so a script can tell
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
vault-rs session login --method ldap --username yourname
vault-rs session init-encryption

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
| Local storage | None | Encrypted per-artifact directory, listed by walking it |
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

A command that could not read every record it was asked about is an error, not a partial success:
there is no exit code meaning "answered, partially", because a caller who did not ask for one would
find a code it has never seen. `--allow-partial` (on `cert list`, `storage list`, `storage show`)
takes the answer anyway and prints what was missing on stderr — having been told it is not
authoritative for that run.

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

1. **Master key** stored at a fixed `vault-rs/encryption-key` path in an auto-discovered KV mount; `session init-encryption` refuses to overwrite an existing key unless `--destroy-all-my-keys` is passed, which makes every locally stored artifact permanently undecryptable
2. **All certificates** encrypted locally with AES-GCM using derived keys
3. **Secure file permissions** (600) on all sensitive files
4. **No plaintext storage** of certificates or private keys
5. **TLS verification** always enabled, uses system certificate store