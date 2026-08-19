Perform a release of vault-rs.

Optional override: $ARGUMENTS (format: vX.Y.Z). If provided, use that version.

## Version determination

1. Find the last release tag (`git tag --sort=-v:refname | head -1`).
2. Examine commits since that tag to classify the release type:
   - **Patch**: only bug fixes, dependency bumps, build changes, docs.
   - **Minor**: new features (`feat:`), new commands or flags.
   - **Major**: breaking changes (`feat!:`, `fix!:`) — removed or renamed flags,
     changed exit codes, changed artifact contents.
3. Bump accordingly. While on 0.x a breaking change bumps the minor. If the
   bump is **major**, stop and confirm before proceeding.

## Pre-release checks

Run in sequence — stop and report on any failure:

```sh
cargo clippy --fix --allow-dirty --message-format=short && cargo fmt --all
cargo test --release
./scripts/check-error-discards.sh
make deb
```

`make deb` is part of the checks: a broken Containerfile or control file only
shows up there, and the release workflow builds the same way.

Then rehearse the publish, while everything is still reversible:

```sh
cargo publish --dry-run -p landlock-test-confine
cargo publish --dry-run -p vault-session
cargo publish --dry-run -p vault-rs
```

A downstream dry-run stops at `no matching package named <dep> found` until the
crate below it is on the index at the new version. That one message is the
ordering showing through and is expected; anything else — a missing field, a
file that should not ship, a verification build that does not compile — is a
real failure and has to be fixed before the tag exists.

Each crate's dev-dependency on `landlock-test-confine` carries a version as well
as a path. A version bump that leaves that requirement behind resolves locally
against the path and fails at publish, so bump it with the workspace.

## The CI gate

**A green local run does not mean CI is green, and the tag is what publishes.**
After pushing master and before tagging, wait for CI on the exact commit being
released and refuse to tag unless it succeeded:

```sh
sha=$(git rev-parse HEAD)
gh run list --commit "$sha" --workflow CI --limit 1
gh run watch "$(gh run list --commit "$sha" --workflow CI --limit 1 --json databaseId --jq '.[0].databaseId')" --exit-status
```

`--exit-status` makes a failed run a non-zero exit, so the release stops there.
If no run exists for the commit yet, wait for one rather than reading the
previous commit's result.

The machine cutting the release is not the machine CI runs on, and a test can
pass here for a reason that does not hold there — a directory this machine
happens to have, a binary on this `PATH`, a kernel feature this kernel offers.
The local checks catch what they can early; CI is the one that decides.

## Steps

1. Bump `version` in `Cargo.toml`. It is the only copy — `--version` reads it
   through clap, so nothing else needs editing.

2. Run the pre-release checks above.

3. Draft a changelog from `git log --oneline <last-tag>..HEAD`.

   **Rules:**
   - Group under: `New features:`, `Bug fixes:`, `Build:`, `Refactoring:` — omit empty sections.
   - Describe user-visible behavior, not implementation details.
   - Merge related commits for the same feature into one bullet.
   - Call out anything that changes an exit code, a flag name or an artifact's
     contents — those break scripts silently.
   - No git hashes, no raw commit subjects, no co-author lines.

4. Commit the bump on master and push it:

```sh
git add Cargo.toml
git commit -m "release: vX.Y.Z"
git push
```

5. **Wait for CI on the pushed commit and stop if it failed** — see "The CI
   gate" above. Nothing below this point is reversible: the tag is immutable and
   a published crate version can never be replaced.

6. Tag a detached child commit that pins `Cargo.lock`. The tag is the only ref
   that reaches it, so the lock never lands on master while the released
   binaries still build from an exact dependency set:

```sh
git checkout --detach
git add -f Cargo.lock
git commit -m "build: pin Cargo.lock for vX.Y.Z"
git tag -as vX.Y.Z -m "$(cat <<'EOF'
vX.Y.Z

<changelog>
EOF
)"
git push origin vX.Y.Z
git switch master
```

   `git switch master` leaves the working-tree `Cargo.lock` untracked; the next
   cargo command regenerates it. Force-adding it on a master commit instead
   would not be a one-off: the file stays tracked afterwards, and every later
   development commit carries its churn.

7. Publish to crates.io, in dependency order. Each waits for the one before it
   to reach the index, which `cargo publish` polls for on its own:

```sh
cargo publish -p landlock-test-confine
cargo publish -p vault-session
cargo publish -p vault-rs
```

   Publishing a crate name for the first time needs a token scoped to allow it;
   an update-only token gets `403 Forbidden` at the upload step, after packaging
   has already reported success. Never put a token in a prompt, a file or a
   command that is kept: `cargo login`, or `CARGO_REGISTRY_TOKEN` in the
   environment for the one command.

8. Report the tag, the changelog and the published versions.

   Pushing the tag triggers `.github/workflows/release.yml`, which builds the
   amd64/arm64 `.deb`s and bare binaries, attaches a source tarball and
   `SHA256SUMS`, and creates the GitHub release using the tag annotation as its
   body — so the changelog above is what the release page shows.

## Important

- **`Cargo.lock` never reaches master** — it is gitignored there and exists only
  on the tag's own commit, so a release build is reproducible and development
  commits carry no lockfile churn.
- The tag is IMMUTABLE once pushed — never retag. Wrong? Make a new patch release.
- A published crate version is immutable too, and the name is taken forever. A
  bad one is yanked, never replaced; the fix is the next version.
- Three crates publish: `landlock-test-confine`, `vault-session`, then
  `vault-rs`. The `.deb` and the GitHub release remain the distribution for
  operators — crates.io is for whoever links the library or runs `cargo install`.
- Never cut a release without being asked for one explicitly.
