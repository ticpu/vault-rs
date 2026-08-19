# vault-session

Address discovery, login, token handling and KV reads against HashiCorp Vault, for a program that
links this crate rather than shelling out to `vault`.

This is **not** a general Vault API client — for that, use [`vaultrs`](https://crates.io/crates/vaultrs).
`vault-session` covers the part a program has to solve before it can call one:

- **Where Vault is.** `VAULT_ADDR`, or the `_vault._tcp` SRV record for the resolver's search
  domains — whichever the caller asks for, by passing an `Address`.
- **Getting a token.** A complete OIDC login — authorization URL, loopback callback listener, token
  exchange — plus LDAP and userpass. A token from any other method is seated with `store_token`.
- **Keeping it.** A token file the caller names, mode 0600, checked for validity before use, renewed
  when it can be, unlinked on logout.
- **Reading a secret.** KV reads that ask the mount which storage layout it uses rather than making
  the caller pick a v1 or v2 API.
- **Checking the setup.** `verify` reports what a token cannot do against what a program needs,
  using only reads a narrow token already has.

## The session is the caller's

Nothing here reads an environment variable, a file or a directory the caller did not name, so a
linking program never inherits the operator's own Vault session by accident. Nothing here prints,
prompts, opens a browser or exits: an OIDC login hands its authorization URL to a `LoginPresenter`
the caller supplies, and every failure is a returned `Error` carrying its source.

```rust
use vault_session::{kv, Address, Session, SessionConfig, VaultClient};

let config = SessionConfig::for_program("my-program", Address::EnvThenSrv)?;
let session = Session::open(config).await?;

let client = VaultClient::for_session(&session).await?;
let secret = kv::read_secret(&client, Some("secret"), "app/config", None).await?;
```

`examples/read_secret.rs` is the same thing with an OIDC login in front of it.

## TLS backend

`rustls-aws-lc-rs` is the default, and brings its own `CryptoProvider`.

For a process that installs its own provider, turn the default off. Cargo features are additive, so
selecting `rustls-ring` without `default-features = false` compiles both backends in:

```toml
vault-session = { version = "0.4", default-features = false, features = ["rustls-ring"] }
```

Under `rustls-ring` this crate installs no provider; building a client before the process installs
one returns `Error::NoTlsProvider` rather than panicking.

## Requirements

Rust 1.88 or later. Unix only — the token file is created with an explicit mode.

## License

MIT OR Apache-2.0, at your option.
