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

4. Commit the bump and the lock together, then tag it:

```sh
git add Cargo.toml
git add -f Cargo.lock
git commit -m "release: vX.Y.Z"
git tag -as vX.Y.Z -m "$(cat <<'EOF'
vX.Y.Z

<changelog>
EOF
)"
```

   `Cargo.lock` is gitignored during development and force-added only on a
   release commit: this is a binary, so a released build has to be reproducible
   from an exact dependency set.

5. Push, and report the tag and changelog:

```sh
git push
git push origin vX.Y.Z
```

   Pushing the tag triggers `.github/workflows/release.yml`, which builds the
   amd64/arm64 `.deb`s and bare binaries, attaches a source tarball and
   `SHA256SUMS`, and creates the GitHub release using the tag annotation as its
   body — so the changelog above is what the release page shows.

## Important

- The tag is IMMUTABLE once pushed — never retag. Wrong? Make a new patch release.
- Not published to crates.io. It is a binary; the `.deb` and the GitHub release
  are the distribution. Do not run `cargo publish`.
- Never cut a release without being asked for one explicitly.
