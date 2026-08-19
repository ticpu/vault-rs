# vault-session

Address discovery, login, token handling and KV reads against HashiCorp Vault, for a program that
links this crate rather than shelling out to `vault`.

This is **not** a general Vault API client — for that, use [`vaultrs`](https://crates.io/crates/vaultrs).
`vault-session` covers the part a program has to solve before it can call one:

- **Where Vault is.** `VAULT_ADDR`, or the `_vault._tcp` SRV record for the resolver's search
  domains.
- **Getting a token.** A complete OIDC login — authorization URL, loopback callback listener, token
  exchange — plus LDAP and userpass.
- **Keeping it.** A token file the caller names, mode 0600, checked for validity before use, renewed
  when it can be, unlinked on logout. A linking program's session is its own: it does not share the
  slot with whatever `vault-rs` or `vault` keeps for the operator.
- **Reading a secret.** KV reads that ask the mount which storage layout it uses rather than making
  the caller pick a v1 or v2 API.

## TLS backend

Pick one:

- `rustls-aws-lc-rs` (default) — this crate's TLS comes with its own `CryptoProvider`.
- `rustls-ring` — for a process that installs its own provider; this crate installs none.

## License

LGPL-2.1-or-later (`COPYING.LESSER`), so a program under another licence may link it.
