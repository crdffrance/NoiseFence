# Version and publish NoiseFence

`Cargo.toml` is the source of truth for the product version. The frontend, `Cargo.lock`, the fuzz lockfile and `web/package-lock.json` carry the same version for NoiseFence. The model has its own version: a training run is not a new version of the software.

The repository uses `master`, descriptive commits and annotated tags `vMAJOR.MINOR.PATCH`. Unsuffixed tags are the final releases; `-dev.N` and `-rc.N` are prereleases. The project remains in 0.x. An incompatible change requires a minor version as long as the project remains in 0.x; a compatible correction requires a patch version. The changelog specifies migrations and limits.

```sh
python3 scripts/version.py --set 0.29.1
# Update the corresponding section of CHANGELOG.md.
python3 scripts/version.py --check
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
```

Also check the console as indicated in CONTRIBUTING.md. Commit changes and wait for CI to pass, then create and push the corresponding annotated tag. The `scripts/version.py --check --tag v0.29.1` command refuses a different tag from the manifest version.

The `release.yml` workflow compiles into a Rust Bookworm image identified by its digest, on x86-64 and ARM64. It assembles binary, static frontend, licenses, examples, and documentation, then prepares a GitHub Release with the SHA-256 checksums. The workflow also calls the complete `check.yml` suite on the same tag; failure prohibits publication. Tests use `cargo test --release`, with the same profile as the distributed binary. This profile also avoids [gemm-f16's debug ARM64 compilation issue](https://github.com/sarah-quinones/gemm/issues/31). The main CI also checks the multilingual engine on an ARM64 runner. The exact sources are accessible from the release tag. Reports, trained models, keys and server-specific configurations remain outside Git, with the exception of explicitly versioned aggregated research reports.

The notes are extracted from the single matching changelog section by
`scripts/release_notes.py`; missing, empty or duplicate sections block publication.
The publish job verifies both architectures, each outer SHA-256, every internal
`SHA256SUMS` entry, and `build.json` version/platform/commit against the tag checkout.
It uploads to a draft, downloads and compares the uploaded bytes, then publishes.
Unsuffixed versions become stable releases; suffixed versions remain prereleases.

Release publication is triggered by a pushed tag, not by an ordinary commit to
`master`. A successful branch build alone does not create a release. For example:

```sh
git tag -a v0.29.1 -m "NoiseFence v0.29.1"
git push origin v0.29.1
```

For a transient infrastructure failure, re-run the failed jobs in Actions, or run
`gh workflow run release.yml --repo crdffrance/NoiseFence --ref v0.29.1`.
Manual dispatch requires a tag matching the manifests. Drafts can be resumed;
if a release is already public, a retry verifies identical assets and leaves it
unchanged. Differing public assets fail rather than being replaced. Code fixes
require a new version and tag, not a rerun of an old tag. Publication runs are
serialized per tag and are never cancelled by a later request for the same tag.

StepSecurity Harden-Runner monitors dependency-heavy build jobs in audit mode.
The publish job blocks connections outside its GitHub/artifact allowlist. Review
network findings in each Actions job summary; see [build security](../SECURITY.md).
Third-party Actions are pinned by full commit SHA and updated through Dependabot.

Never move a published tag or replace its archives with a different build. A correction requires a new version. Before the first opening of the repository, also check branches, tags and objects of history to avoid publishing deleted secrets from the only current tree.

The native packager requires a clean, committed source checkout so that the
commit recorded in `build.json` identifies the packaged code and documentation.
Keep the source inventory and binary checksum from the successful build; do not
package an older cached binary after a failed compilation.

A release does not change the server configuration, MX, or filtering mode. Proton deployment and validation remain separate steps. Keep the previous version and its configuration directory to support a compatible rollback.

Current archives declare `storage_schema: 7` in `build.json`, the maximum supported local format. Paired replication uses format 5, management transport uses format 6, and selecting a PostgreSQL authority activates format 7. A format number alone does not establish management-database compatibility: the simple deployment helper refuses selected or transport-enabled installations, and automatic rollback remains disabled for them. Use the [coordinated migration procedure](../deploy/postgresql/MIGRATION-SUPERVISOR.md) and its recovery path. Never lower `user_version`, erase `ha_required` or restore a stale database over accepted mail. See [HA recovery](high-availability.md).
