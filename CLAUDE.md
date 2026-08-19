# Vault-RS Development Guidelines

## Output

Stdout carries data only; every log, warning, prompt and status line goes to stderr. Records are
one item per line with no prefixes, headers, labels, leading spaces or alignment fluff that would
break `grep`/`awk`/`cut`.

### OutputFormat (crates/vault-rs/src/utils/output.rs)

**Use `OutputFormat` for all structured data** — `print_table` / `print_table_with_headers` for
columns, `print_list` for single-column, `print_key_value` for pairs, `print_json` for records. It
owns the three output modes (formatted, `--raw`, `--json`); a direct `println!` bypasses whichever
one the caller asked for.

`println!` is for a single bare value with no `OutputFormat` in scope, `eprintln!` for anything
addressed to a person, `tracing::*` for debug detail behind `-v`.

**`--json` must branch before `build_table_data`.** Table cells are display strings, already
summarized and truncated — extended key usage renders as `CA:Client`, timestamps lose their
seconds. Serializing a built table emits those strings instead of the data; serialize the records
themselves. `cert list --json` and `storage list --json` therefore emit different schemas, because
they are different records.

## Certificates

**Crypto type is detected, never defaulted.** `client.detect_crypto_type(mount)` reads the OIDs in
the mount's issuer certificates; on failure it errors and tells the caller to pass `--crypto`. A
certificate minted with the wrong key type has to be revoked, so guessing costs more than failing.

The same rule runs through the parser: an attribute is read off the artifact or reported absent,
and a present-but-unparseable extension aborts rather than reading as empty. Where a value is
predicted rather than read — `--dry-run` cannot know what Vault will do — the annotation says so.

`docs/design-rationale.md` records why these commands are shaped the way they are. Read it before
changing issuance, verification or export behaviour.

## Security

- System trust store via reqwest, which pulls in `rustls-platform-verifier` under either backend
  feature. There is no separate native-roots feature to enable.
- The tool's own token is in `XDG_RUNTIME_DIR`, mode 0600; a linking program names its own path,
  which gets the same mode and a directory this tool creates but does not re-mode.
- Temporary files go under `paths::runtime_dir(PROGRAM_NAME)`, mode 0600, removed after use.

## Rust

- Two published crates: `crates/vault-session` is the library another program links, and
  `crates/vault-rs` is the binary. `crates/test-confine` is the test-only helper and never ships.
- **Keep `crates/vault-rs/src/cli/commands.rs` thin.** It parses arguments, calls a module, and maps
  errors to exit codes. Business logic lives in `cert/`, `vault/`, `storage/`.
- Past ~7 arguments, take a struct.
- Prefer `crate::utils::PROGRAM_NAME` over a literal `"vault-rs"`.
- Inside the binary, `cert -> cli -> crypto -> storage -> utils` is a real dependency cycle, caused
  by `utils/cert_utils.rs` holding certificate logic. Do not deepen it: certificate logic belongs in
  `cert/`, Vault API types in `vault/`, and only generic I/O in `utils/`.
- **Every change has to build under `cargo check -p vault-session --no-default-features --features
  rustls-ring`.** That is the shape the external consumer compiles, the one `--all-targets` cannot
  reach, and the pre-commit hook runs it. A dependency added to the library reaches every consumer,
  so it belongs in the binary unless the library genuinely needs it.
- Nothing in the library may print, exit the process, prompt, or read an environment variable the
  caller did not name — see `docs/design-rationale.md`. The binary owns the console.
- No `vaultrs` type appears in the library's public API. It is the transport, it is pre-1.0, and
  keeping it internal means their next breaking release is not ours.

## Tests and hooks

`.git/hooks/pre-commit` runs fmt, clippy `-D warnings`, `cargo test --release` and
`gitleaks git --staged`. It is the verification — do not re-run those separately. `--no-verify` is
for a `test:` commit that deliberately lands a failing test. `.git/hooks/pre-push` refuses a branch
whose tip tracks `Cargo.lock`, which a rebase or an amend can carry there after the commit-time
check has passed; tags are exempt, since the release tag is where the lock belongs.

`.gitleaks.local.toml` extends the committed config with private patterns and is never committed
itself.

`crates/vault-rs/tests/against_a_real_vault.rs` drives the built binary against a throwaway
`vault server -dev`,
covering what a stub cannot: exit codes, which stream a line went to, and whether a path this code
builds is one Vault accepts. It needs the official `vault` binary and fails without it rather than
skipping — a suite that quietly does not run reads like one that passed. `VAULT_RS_NO_INTEGRATION=1`
opts out knowingly. Every server and store is scratch under `target/integration/`, including the
server's own `HOME`: a dev server writes its root token there, and left pointing at the real one it
overwrites yours.

Landlock makes that boundary the kernel's rather than the harness's, applied per test thread since
it covers the calling thread and its children and not siblings, and in the unit binary from a
constructor because the write that motivated it came from code with no test helper in front of it.
A kernel without it warns and continues — the tests are correct about their paths regardless, and
what is lost is the backstop. Each binary probes just outside the boundary
(`the_unit_tests_cannot_write_outside_the_build_directory`,
`these_tests_cannot_write_outside_their_scratch_directory`) so a confinement that stopped working
is caught by the harmless probe rather than a real write.

**Testing by hand goes through `cargo run --features dev-server -- dev-server`, never a bare
`vault server -dev`.** That server writes its root token to `$HOME`, so started from a shell it
destroys the operator's token for every other Vault they use — this has happened twice, both times
while checking something unrelated. The command keeps that and the XDG paths in a scratch
directory and prints the exports to paste; the local store and token this tool keeps are per-user
too, so a live test that moves only `VAULT_ADDR` still writes into the real ones. The feature is
off by default because a released binary has no business carrying it.

Never point a live check at a Vault whose KV holds a master key sealing artifacts anyone needs:
`session init-encryption`, `kv destroy` and `key restore` are in that battery, and on a mount with
no version history the overwrite cannot be undone.

Fixtures live in `crates/vault-rs/src/cert/testdata/`, regenerated by `generate.sh` (certificates
only; it deletes the keys it makes). `.gitignore` excludes `*.pem` repo-wide and negates that
directory — a negation containing a slash is anchored to the repo root, so a new fixture extension,
or a move, needs the path spelled in full or it will silently not be committed.

Scratch and confinement roots come from `test_confine::target_dir()`, which reads the running
executable. `CARGO_MANIFEST_DIR` is a crate directory now and `target/` is not under it.
