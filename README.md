# vault-rs

A secure, UNIX-friendly Vault CLI for sysadmins: PKI certificate lifecycle management, KV,
policies, and an encrypted local store for the certificates it issues.

## Why vault-rs?

While the official `vault` CLI is comprehensive for general Vault operations, `vault-rs` is purpose-built for PKI certificate management with several key enhancements. It speaks the API itself for the verbs used daily — `read`, `write`, `list`, `delete`, `kv`, `policy`, `secrets`, `status`, `token` — and forwards the rest to the `vault` binary, which is therefore optional rather than required.

### Encrypted Local Storage

- **Local certificate caching**: All certificates and private keys are stored encrypted locally using AES-GCM
- **Master key management**: Master key stored at a fixed `vault-rs/encryption-key` path in a KV mount the store records once and then keeps using. With one KV mount that choice is made for you; with several it is refused rather than guessed, because guessing wrong mints a second key and leaves everything already stored unreadable:

```bash
vault-rs session init-encryption --mount secret   # put a new key here
vault-rs session key use secret                   # adopt a key already there
vault-rs session key status                       # which mount, and whether replacing it could be undone
```

  If the recorded mount later stops being there, that is reported as itself rather than as an empty store — the artifacts are still sealed under whatever was on it, so adopting a different one is an explicit step.
- **Recovery is a command, not a hint**: `session key history` lists the versions the mount still holds, and `session key restore --version N` writes one back and reports how much of the store that made readable — `4 of 7 artifacts decrypt, up from 0`. A partial recovery is a success: the remaining artifacts are named, and one sealed by another cluster needs that cluster rather than another version
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

`--allow-partial` — on `cert list`, `cert list-mounts`, `cache status`, `storage list` and
`storage show` — lists what it could read instead of failing on a record it can't; skipped records
are named on stderr. Combined with
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

# What the role decides, before there is a request at all
vault-rs cert role-info internal client

# Inspect a CSR on its own, or projected through a role
vault-rs cert inspect-csr request.csr
vault-rs cert inspect-csr request.csr -m internal --role client
```

`cert list-roles` gives names and reading the role path gives forty fields in no order; neither
says which of them govern the identity. `role-info` renders through the same builder `--dry-run`
uses, so the two cannot disagree about what the role fixes and what a request could still
influence:

```
subject  O=Example Org, CN=(supplied at issuance)
         CN  from the argument given to cert create
         O   from role
eku      ClientAuth                 (role client_flag)
validity 72h                        (role max_ttl; role sets no explicit default)
issuer   Example Issuing CA
```

`--json` emits the whole role record instead, since the parsed view models what governs an
identity and would drop the rest without saying so.

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
- **Tab completion**: bash, zsh, fish and PowerShell, for all commands
- **Raw mode**: `--raw` flag for tab-separated values without formatting

### Performance Optimizations

- **Lazy certificate caching**: certificates are immutable, so each is fetched from Vault once and read from the local cache afterward — only serials missing from the cache are ever fetched
- **Bulk operations**: Efficient batch processing for multiple certificates

### Vault Integration

The verbs an operator reaches for daily are answered over the API. The `vault` binary is optional,
and needed only for what this tool does not model.

```bash
vault-rs read secret/data/app                  # --field on read, write and kv get
vault-rs write pki/roles/web ttl=72h allow_any_name=true
vault-rs kv get --mount secret app
vault-rs kv put --mount secret app user=alice  # --cas for compare-and-set
vault-rs policy list                           # policy read/write/delete too
vault-rs secrets list
vault-rs status                                # no token needed
vault-rs vault operator raft list-peers        # anything not modelled, with the session's token
```

`--json` and `--raw` are global and go before the subcommand.

- **Data keeps vault's own spelling**, because an operator pasting a documented invocation is
  pasting its data arguments: `key=value`, `key=@file`, `key=-` for stdin, a bare `@file` or `-`
  for a whole JSON body, and a repeated key for a list
- **Partly-modelled verbs split by subcommand, visibly.** `kv get` is answered here and `kv patch`
  forwards; `secrets list` is answered here and `secrets enable` forwards. `vault-rs kv --help`
  says which. A modelled subcommand handed something it does not understand fails and names the
  forwarding command rather than quietly re-dispatching
- **`vault-rs vault <args…>` runs the official binary verbatim** with this session's address and
  token. The token lives in `$XDG_RUNTIME_DIR/vault-rs/` and is never exported, so this — not
  invoking `vault` yourself — is how you reach what is not modelled and stay authenticated
- **`session` is this machine.** `session login/logout/status/verify`, `session init-encryption`
  and `session key …` act on the local token and encryption key. `token lookup/renew/revoke` act on
  this session's token and everything naming another token forwards. `policy` and `secrets list`
  are answered here over the API; `auth` forwards
- **Logging out revokes.** `session logout` revokes server-side and removes the local token — and
  removes it even when revocation fails, since an expired token or an unreachable server should
  not leave the credential on disk. It exits non-zero so a script can tell. `token revoke` is the
  same call
- **`status` needs no token**, because a sealed Vault can neither mint nor validate one. **Its
  exit code differs from `vault status`**: sealed is 1 here and 2 there, since 2 already means
  "error" for every other vault-rs command and one tool cannot carry both meanings
- **`--mount` has no `-m` short on the `kv` commands.** Vault spells it `-mount=secret`, which
  clap would read as a mount named `ount=secret` — a silently wrong write where an error is wanted
- **`--vault-addr` applies to one invocation**, outranking `VAULT_ADDR`: useful for reaching the
  cluster that sealed an artifact (`storage show` names it) without exporting it into the shell
  that produced the confusion. **`VAULT_NAMESPACE` is sent on every request**, not only forwarded
  ones
- **A write to a guarded path says so first.** The generic write verbs and every `kv` verb that
  writes or withdraws — `put`, `delete`, `undelete`, `destroy`, `rollback` — announce a target that
  some other command owns — the master key's path — naming that command and whether the mount can give
  the key back, then proceed. The generic verb stays generic; if the check itself is refused the
  notice says that rather than falling silent, so no warning means checked, never could-not-check

## Installation

```bash
cargo install vault-rs
```

For a process that installs its own rustls `CryptoProvider`:

```bash
cargo install vault-rs --no-default-features --features rustls-ring
```

Or from source:

```bash
git clone https://github.com/ticpu/vault-rs
cd vault-rs
cargo build --release
sudo cp target/release/vault-rs /usr/local/bin/
```

Rust 1.88 or later. Unix only.

## Quick Start

```bash
# Login and initialize encryption
vault-rs session login --method ldap --username yourname
vault-rs session login --method oidc --role engineer   # or a browser flow
vault-rs session init-encryption

# Check the Vault is set up the way you need, with the token that will use it
vault-rs session verify --read secret/data/app --kv-mount secret:2 --policy app-read

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
| Role configuration | Forty fields in no order | `cert role-info` marks the ones that decide the issued identity |
| `read`/`write`/`kv` output | `-format=json` or a table | Honours the global `--json`, `--raw` and `--field` |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Ran successfully |
| 1 | A verdict: `--expiring-within` matched, `cert verify` failed a check, `session verify` found something wrong, or `status` found the server sealed |
| 2 | Error |

A command that could not read every record it was asked about is an error, not a partial success:
there is no exit code meaning "answered, partially", because a caller who did not ask for one would
find a code it has never seen. `--allow-partial` takes the answer anyway and prints what was missing on stderr — having been told it is not
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

### The config file

Defaults for the flags you would otherwise retype, read from
`~/.config/vault-rs/config.yaml` — or from a path given to `--config`, which then has to exist.
Every setting is optional and a file that sets nothing changes nothing.

```yaml
pki_mount: pki-int

login:
  method: oidc
  oidc_mount: oidc
  oidc_role: engineer
  oidc_port: 8250

output: formatted   # formatted | raw | json

columns:
  cert_list: cn,serial,not_after,revoked
  storage_list: cn,serial,not_after,role
```

A flag beats a `VAULT_RS_`-prefixed variable (`VAULT_RS_PKI_MOUNT`, `VAULT_RS_OUTPUT`,
`VAULT_RS_COLUMNS_CERT_LIST`, …), which beats the file, which beats the built-in.

`pki_mount` only narrows: unset still means every mount your token can see. It does not reach
`storage remove`, where a default that picks between two artifacts would turn a refusal into a
deletion, and it reaches `cert verify` only when no `--against-ca` anchor was named. Commands
taking the mount as a required positional (`cert create`, `cert sign`, `cert list-roles`) keep
requiring it.

A configured column list replaces the built-in defaults, so a `+` entry on `--columns` adds to
the configured one. A key the file has no field for is an error, not a setting that silently does
nothing.

## Architecture

- **Local Storage**: `~/.local/share/vault-rs/` - Encrypted certificate storage
- **Runtime**: `$XDG_RUNTIME_DIR/vault-rs/` (falling back to `~/.local/state/vault-rs/` when unset) - Tokens, cache, temp files
- **Config**: `~/.config/vault-rs/config.yaml` - Defaults for the flags above
- **Cache**: Certificate metadata cached per PKI mount; certificates are immutable, so once fetched an entry is never re-fetched

## Security Model

1. **Master key** stored at a fixed `vault-rs/encryption-key` path in the KV mount this store recorded; `session init-encryption` refuses to overwrite an existing key unless `--destroy-all-my-keys` is passed, and refuses even then on a mount keeping no version history, where the loss could not be undone
2. **All certificates** encrypted locally with AES-GCM using derived keys
3. **Secure file permissions** (600) on all sensitive files
4. **No plaintext storage** of certificates or private keys
5. **TLS verification** always enabled, uses system certificate store

## Tests

`cargo test --release` runs both suites. The unit tests stub Vault over HTTP; the integration tests drive the
built binary against a throwaway `vault server -dev`, covering what a stub cannot — exit codes,
which stream a line went to, and whether a path this code builds is one Vault actually accepts.
They need the official `vault` binary and fail without it rather than skipping, since a suite that
quietly does not run reads like one that passed. `VAULT_RS_NO_INTEGRATION=1` opts out knowingly.

Both suites confine themselves with **Landlock** before doing anything: readable everywhere,
writable only under `target/`. Pointing every path at a scratch directory is a promise the tests
make to themselves, and one forgotten environment variable breaks it — a dev server writes its root
token to `$HOME`, so an unconfined run overwrites the operator's own. This makes it the kernel's
refusal instead. A kernel without Landlock warns and continues; the tests are correct about their
paths either way, and what is lost is the backstop. Each suite has a test that writes just outside
the boundary and expects to be refused, so a confinement that stopped working is caught by the
harmless probe rather than by a real one.

## License

This repository is a Cargo workspace of two published crates, each under its own license.
`crates/vault-session` — address discovery, OIDC login, token-file lifecycle, KV reads — is
**LGPL-2.1-or-later** (`crates/vault-session/COPYING.LESSER`), so a program that does not share its
license may still link it. `crates/vault-rs`, the binary, is **GPL-3.0-only**
(`crates/vault-rs/COPYING`). See each crate's own `README.md` for what it covers.
