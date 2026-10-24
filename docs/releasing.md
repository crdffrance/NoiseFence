# Version and publish NoiseFence

`Cargo.toml` is the source of truth for the product version. The frontend, `Cargo.lock`, the fuzz lockfile and `web/package-lock.json` carry the same version for NoiseFence. The model has its own version: a training run is not a new version of the software.

The repository uses `master`, descriptive commits and annotated tags `vMAJOR.MINOR.PATCH`. Unsuffixed tags are the final releases; `-dev.N` and `-rc.N` are prereleases. The project remains in 0.x. An incompatible change requires a minor version as long as the project remains in 0.x; a compatible correction requires a patch version. The changelog specifies migrations and limits.

```sh
python3 scripts/version.py --set 0.29.4
# Update the corresponding section of CHANGELOG.md.
python3 scripts/version.py --check
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
```

Also check the console as indicated in CONTRIBUTING.md. Merge changes into the protected default branch after CI passes, then create and push the corresponding annotated tag from that merged commit. The `scripts/version.py --check --tag v0.29.4` command refuses a different tag from the manifest version.

The `release.yml` workflow compiles into a Rust Bookworm image identified by its digest, on x86-64 and ARM64. It assembles binary, static frontend, licenses, examples, and documentation, then prepares a GitHub Release with the SHA-256 checksums. The workflow also calls the complete `check.yml` suite on the same tag; failure prohibits publication. Tests use `cargo test --release`, with the same profile as the distributed binary. This profile also avoids [gemm-f16's debug ARM64 compilation issue](https://github.com/sarah-quinones/gemm/issues/31). The main CI also checks the multilingual engine on an ARM64 runner. The exact sources are accessible from the release tag. Reports, trained models, keys and server-specific configurations remain outside Git, with the exception of explicitly versioned aggregated research reports.

The notes are extracted from the single matching changelog section by
`scripts/release_notes.py`; missing, empty or duplicate sections block publication.
The publish job verifies both architectures, each outer SHA-256, every internal
`SHA256SUMS` entry, and `build.json` version/platform/commit against the tag checkout.
The publish job then creates signed build-provenance attestations for the validated
archives and verifies their exact workflow/tag/source identity before upload.
It uploads to a draft, downloads and compares the uploaded bytes, then publishes.
See [authenticated release staging](release-staging.md) for the trust policy,
historical-release behavior and native preparation procedure. The first release
using this workflow must qualify the complete attestation path.
Unsuffixed versions become stable releases; suffixed versions remain prereleases.

Release publication is triggered by a pushed tag, not by an ordinary commit to
`master`. A successful branch build alone does not create a release. For example:

```sh
git tag -a v0.29.4 -m "NoiseFence v0.29.4"
git push origin v0.29.4
```

For a transient infrastructure failure, re-run the failed jobs in Actions, or run
`gh workflow run release.yml --repo crdffrance/NoiseFence --ref v0.29.4`.
Manual dispatch must run on the version tag itself. Running it on a branch is
refused before checkout. There is no alternate source-tag input: the workflow,
validation, build and publication all use the immutable event commit. Preflight
requires complete Git history and proves that the tag and checkout match that
commit and that it belongs to the protected default branch. These checks apply
to tags containing this workflow. Older tags retain their historical workflow;
inspect it before rerunning an old release.

A build-infrastructure change requires a new reviewed commit and version tag.
Do not run a newer workflow on an older source tag to work around this boundary.

Bookworm test containers explicitly map `localhost.` to
loopback so the rooted-MX regression test never depends on external DNS. Rust
CI runs test cases serially to keep independent timing-sensitive network fixtures
from competing for runner resources; concurrency within each fixture is retained. Drafts can be resumed;
if a release is already public, a retry verifies identical assets and leaves it
unchanged. Differing public assets fail rather than being replaced. Review the explicit compatibility windows in `src/cluster/protocol.rs`,
`artifacts.rs` and `worker.rs` when changing the version; a shared SemVer prefix
is not a compatibility guarantee. Run the cluster and retained-policy regression
tests before tagging. The failed v0.29.1 and v0.29.2 tags are retained for traceability and have
no published releases. Code fixes
require a new version and tag, not a rerun of an old tag. Publication runs are
serialized per tag and are never cancelled by a later request for the same tag.

StepSecurity Harden-Runner monitors dependency-heavy build jobs in audit mode.
The publish job blocks connections outside its GitHub/artifact allowlist. Review
network findings in each Actions job summary; see [build security](../SECURITY.md).
Third-party Actions are pinned by full commit SHA and updated through Dependabot.
Release artifact builds do not restore or save a shared Actions dependency cache.
The reusable validation suite can use caches for tests; its outputs are not
packaged as release artifacts. The repository protects version tags from updates
and deletion, and newly published releases are immutable. Upload and verify all
assets while a release is still a draft; publish only after verification.

Never move a published tag or replace its archives with a different build. A correction requires a new version. Before the first opening of the repository, also check branches, tags and objects of history to avoid publishing deleted secrets from the only current tree.

The native packager requires a clean, committed source checkout so that the
commit recorded in `build.json` identifies the packaged code and documentation.
Keep the source inventory and binary checksum from the successful build; do not
package an older cached binary after a failed compilation. Public tar members use
root ownership, traversable directories, executable programs and readable data
files, independent of the builder's umask; private source directories keep their
original permissions. Special files and links are refused by the packager.

A release does not change the server configuration, MX, or filtering mode. Proton deployment and validation remain separate steps. Keep the previous version and its configuration directory to support a compatible rollback.

Current archives declare `storage_schema: 7` in `build.json`, the maximum supported local format. Paired replication uses format 5, management transport uses format 6, and selecting a PostgreSQL authority activates format 7. A format number alone does not establish management-database compatibility: the native installer and restricted deployment helper refuse configured, selected or partially selected management installations, and automatic rollback remains disabled for them. Use the [coordinated migration procedure](../deploy/postgresql/MIGRATION-SUPERVISOR.md) and its recovery path. Never lower `user_version`, erase `ha_required` or restore a stale database over accepted mail. See [HA recovery](high-availability.md) and [paired upgrade preparation and rehearsal](paired-upgrades.md).

For paired installations, follow the [selected-management archive rehearsal](paired-upgrades.md#run-the-disposable-archive-pair-fixture). Qualify each architecture and exact candidate; a cached healthy process or the legacy policy compatibility window does not prove a mixed-build PostgreSQL deployment works.

The [native maintenance reservation](maintenance-reservations.md) is a stopped-host
primitive. Its tests do not authorize a candidate upgrade or rollback; retain the
exact paired archive and selected-authority lifecycle gates.


## Mandatory native lifecycle gates

Both semantic CI jobs (amd64 and arm64) exercise installation and paired recovery
before they can pass. These host-built fixtures are marked `rehearsal_only` and
make no Bookworm/glibc compatibility claim. The publisher rejects them. The
release build independently repeats the same checks against each **exact Bookworm
archive** before uploading it for attestation and publication. A passing branch
rehearsal does not qualify future release bytes.

The baseline version, source commit and both published archive hashes are pinned
in `tests/fixtures/release-baseline.json`. Review changes to this file explicitly;
never silently replace the baseline with whatever release is latest. The initial
0.31.9 baseline predates attestations. Its reviewed checksum is a test dependency,
not a replacement for the new release's required provenance verification.

A separate positive retained-release gate pins the immutable rc.1 archives in
`tests/fixtures/retained-release-baseline.json`. It must complete a forward
upgrade, explicit retained activation with current data, recovery after discarded
start/completion replies, new mail acceptance and a new forward operation. A
missing maintenance command, skipped probe or failed rollback fails this gate.
Both branch checks and release builds run it on each architecture; it supplements
the historical baseline's safe-refusal coverage.

`scripts/check_release_lifecycle.sh` downloads and verifies that baseline, builds
unique temporary systemd fixture images, then runs the standalone installation
and `--archive-candidate` pair scenarios on the matching architecture. It uses
fresh synthetic accounts and mail, selected PostgreSQL management, bounded
candidate validation, two-copy acceptance, peer loss, failed startup, forward
recovery and interrupted SSH completion. The standalone fixture also uses a bounded
64 MiB tmpfs to provoke real kernel ENOSPC before MAIL and after DATA begins. It
requires temporary SMTP failures, unchanged accepted bodies and queue state, and
recovery after space is released. This checks storage-error handling, not power-loss
persistence or full-disk recovery on a production filesystem. Test containers have no external route;
run this only on a disposable test host, never a production MX. Release builds
reuse dependencies only inside their own job, including offline fixture generation;
no shared Actions dependency cache is restored or saved for official artifacts.

For a manual rehearsal from a clean committed checkout, after compiling the
native binary and console and assembling the candidate archive:

```sh
platform=linux-arm64 # linux-amd64 on x86-64
version=$(python3 scripts/version.py)
baseline=$(python3 scripts/release_rehearsal.py baseline-version)
NOISEFENCE_REHEARSAL_OUTPUT="$PWD/var/native-rehearsal/fixture" \
NOISEFENCE_REHEARSAL_BASE_BUILD="$baseline" \
NOISEFENCE_REHEARSAL_SHARED_LOOPBACK=1 \
  cargo test --release --locked --features semantic --test management_rehearsal_fixture -- --ignored
sh scripts/check_release_lifecycle.sh "$platform" \
  "release/noisefence-$version-$platform.tar.gz" \
  var/native-rehearsal/fixture var/native-rehearsal/results
```

Repeat the commands with fresh `fixture-retained` and `results-retained`
directories for the second gate. Obtain its baseline with
`baseline-version --baseline-kind retained`, then pass `retained` as the fifth
argument to `check_release_lifecycle.sh`. This selects the separate pinned
baseline and requires `--require-retained-activation`; do not reuse the historical
fixture or change its recorded baseline build. See the
[retained activation procedure](maintenance-rollback.md) for the tested protocol.

Python 3.11+, Docker, GitHub CLI download access, Rust and a fresh fixture/output
directory are required. Container builds and the pinned public download need
network access; the running mail fixtures do not. `qualification.json` is produced
only after both reports pass and their archive, installed helper and running
binary identities match. Each fixture must also confirm removal of its disposable
container and anonymous volumes. Failed or incomplete cleanup cannot produce a
successful qualification report. GitHub retains **only this anonymous summary**. Keep raw
fixture logs, messages, addresses, test credentials and journals private; do not
upload the result directory. A failure records its phase in the job log and stops
publication. The publish job downloads only the `linux-*` archive artifacts, not
these test reports.

These gates do not qualify detection accuracy, external delivery, production
security profiles, full-disk disaster recovery or rollback between other archive
pairs. Positive retained activation applies only to the exact pair and fixture
conditions recorded by the retained gate. The summary explicitly leaves
provenance unverified: attestation and authenticated
staging remain separate gates. See the [paired fixture contract](paired-upgrades.md#run-the-disposable-archive-pair-fixture).

## Release candidate identities

Artifact versions use the core and optional prerelease form of
[Semantic Versioning](https://semver.org/), limited to 64 ASCII characters. Examples
are `0.32.0-rc.1`, `0.32.0-rc.2` and `0.32.0`. Numeric components cannot contain
leading zeroes; empty components and build metadata (`+...`) are not supported in
NoiseFence artifact identities. The exact source commit remains in `build.json`
and the provenance attestation.

Manifest validation, bounded archive inspection, native validation descriptors
and lifecycle fixtures share `deploy/postgresql/release_version.py`. Both native
nodes must still name the same exact version and source commit. A prerelease and
its stable successor are distinct candidates, not interchangeable identities.

The lifecycle runners use semantic precedence, so `rc.2` precedes `rc.11`, and a
stable version follows prereleases of the same core. This orders the rehearsal;
it does not authorize an upgrade or prove rollback/storage compatibility. Keep
all archive, authority, policy, replica, source and qualification checks. A public
tag or released asset must never be moved or replaced to turn an RC into a final
release. Publish a separately reviewed version instead.

## 0.32.0-rc.1 qualification boundary

This candidate adds the console and maintenance work described in the
[changelog](../CHANGELOG.md#0320-rc1--consistent-decisions-reviewed-administration-and-paired-maintenance).
It does not establish the filter's capture or false-positive targets. Keep the
[human-label and independent-evaluation procedure](filter-qualification.md) as a
separate gate; source changes create a distinct detector cohort unless verified
equivalence proves otherwise.

The audited policy shape can retain an unchanged, digest-verified 0.31.9 journal.
This does not authorize a new old-build activation, an unknown future release,
or mixed-build selected PostgreSQL synchronization. The two nodes must run the
same application build for new policy exchange. Use coordinated maintenance,
not a rolling upgrade. Post-start downgrade compatibility remains unqualified.

Before calling the RC installation qualified, record successful validation of
both exact Linux archives, their SHA-256 manifests, `build.json`, provenance and
native staging. Run the standalone and selected-authority pair rehearsals on
both architectures, using `--archive-candidate` for the paired runner to exercise
the exact archive's native activation and recovery paths. Earlier locally built ARM64 results are supporting evidence, not substitutes
for those archives. Keep the first positive attestation round trip explicit.

The Web release checker follows public stable releases and identifies an installed
RC as a development version. It never treats the RC as its future stable release
or installs it automatically. Publishing the RC does not change server policies,
models, provider consent or MX routing.
