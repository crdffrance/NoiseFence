# Version and publish NoiseFence

`Cargo.toml` is the source of truth for the product version. The frontend, `Cargo.lock`, the fuzz lockfile and `web/package-lock.json` carry the same version for NoiseFence. The model has its own version: a training run is not a new version of the software.

The repository uses `main`, descriptive commits and annotated tags `vMAJOR.MINOR.PATCH`. Unsuffixed tags are the final releases; `-dev.N` and `-rc.N` are prereleases. The project remains in 0.x. An incompatible change requires a minor version as long as the project remains in 0.x; a compatible correction requires a patch version. The changelog specifies migrations and limits.

```sh
python3 scripts/version.py --set 0.18.0
# Update the corresponding section of CHANGELOG.md.
python3 scripts/version.py --check
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
```

Also check the console as indicated in CONTRIBUTING.md. Commit changes and wait for CI to pass, then create and push the corresponding annotated tag. The `scripts/version.py --check --tag v0.18.0` command refuses a different tag from the manifest version.

The `release.yml` workflow compiles into a Rust Bookworm image identified by its digest, on x86-64 and ARM64. It assembles binary, static frontend, licenses, examples, and documentation, then prepares a GitHub Release with the SHA-256 checksums. The workflow also calls the complete `check.yml` suite on the same tag; failure prohibits publication. Tests use `cargo test --release`, with the same profile as the distributed binary. This profile also avoids [gemm-f16's debug ARM64 compilation issue](https://github.com/sarah-quinones/gemm/issues/31). The main CI also checks the multilingual engine on an ARM64 runner. The exact sources are accessible from the release tag. Reports, trained models, keys and server-specific configurations remain outside Git, with the exception of explicitly versioned aggregated research reports.

The notes are extracted from the only section of the changelog corresponding to the tag by `scripts/release_notes.py`. An absent, empty or duplicated section blocks the release. Prereleases are published with the GitHub indicator "Pre-release"; the final versions are prepared in draft to check the two archives before publication. Control the SHA-256 checksums, `build.json` (version, commit and architecture), licenses and the absence of private data. Then publish the draft:

```sh
gh release edit v0.18.0 --repo crdffrance/NoiseFence --draft=false --prerelease=false --latest
```

Never move a published tag or replace its archives with a different build. A correction requires a new version. Before the first opening of the repository, also check branches, tags and objects of history to avoid publishing deleted secrets from the only current tree.

A release does not change the server configuration, MX, or filtering mode. Proton deployment and validation remain separate steps. Keep the previous version and its configuration directory to support a compatible rollback.

Current archives declare `storage_schema: 5` in `build.json`. This is the maximum supported schema; paired replication activates schema 5. Earlier cluster versions introduced schema 3. Automatic rollback to an archive with insufficient schema support is refused. Never lower `user_version`, erase `ha_required` or restore a stale database over accepted mail. See [HA recovery](high-availability.md).
