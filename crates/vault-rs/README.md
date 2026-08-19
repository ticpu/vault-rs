# vault-rs

A UNIX-friendly Vault CLI for sysadmins: PKI certificate management, KV, policies, and a local
store for the certificates it issues. Built on
[`vault-session`](https://crates.io/crates/vault-session) for address discovery, login and token
handling.

Stdout carries data only — one record per line, no headers or alignment fluff — so `grep`, `awk`
and `cut` work on it. Everything addressed to a person goes to stderr.

## Install

```sh
cargo install vault-rs
```

For a process that installs its own rustls `CryptoProvider`:

```sh
cargo install vault-rs --no-default-features --features rustls-ring
```

Rust 1.88 or later. Unix only.

## What it does

- **Certificates.** Issue, sign a CSR, inspect, verify against a mount's CA or a local anchor,
  export as PEM/PKCS12/chain, revoke. Crypto type is detected from the mount's issuers, never
  guessed.
- **A local store.** Certificates it issues are kept encrypted under a master key in your own
  Vault, so the private key exists somewhere you control rather than only in a shell history.
- **Vault verbs.** `read`, `write`, `list`, `delete`, `kv`, `policy`, `secrets`, `token`, `status`
  natively; anything not modelled forwards to the `vault` binary.
- **Your session.** `session login` (ldap, userpass, oidc), `session status`, and `session verify`
  to check a Vault is set up the way a program needs.

`vault-rs <command> --help` documents each. The
[repository README](https://github.com/ticpu/vault-rs) has the full reference, the config file and
the exit-code table.

## Exit codes

`0` success, `1` a verdict (nothing matched, a check failed, a Vault is sealed), `2` an error.

## License

GPL-3.0-only (`COPYING`).
