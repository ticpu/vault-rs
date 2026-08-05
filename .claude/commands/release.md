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

5. Tag a detached child commit that pins `Cargo.lock`. The tag is the only ref
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

6. Report the tag and changelog.

   Pushing the tag triggers `.github/workflows/release.yml`, which builds the
   amd64/arm64 `.deb`s and bare binaries, attaches a source tarball and
   `SHA256SUMS`, and creates the GitHub release using the tag annotation as its
   body — so the changelog above is what the release page shows.

## Important

- **`Cargo.lock` never reaches master** — it is gitignored there and exists only
  on the tag's own commit, so a release build is reproducible and development
  commits carry no lockfile churn.
- The tag is IMMUTABLE once pushed — never retag. Wrong? Make a new patch release.
- Not published to crates.io. It is a binary; the `.deb` and the GitHub release
  are the distribution. Do not run `cargo publish`.
- Never cut a release without being asked for one explicitly.
