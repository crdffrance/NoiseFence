# Authenticate and stage a release

A checksum detects a change to an archive. It does not establish who produced it.
The release workflow now signs the validated archives with GitHub artifact
attestations, after both architecture builds and the full validation workflow
succeed. The action is pinned to a full commit. Only the publish job receives OIDC
and attestation permissions; build jobs remain read-only. StepSecurity retains its
publish-job network allowlist, with the required Sigstore endpoints.

Before publishing, the release script verifies each archive against the exact
repository, release workflow certificate identity, tag, source commit and signer
commit, and rejects attestations from self-hosted runners. It uses
[GitHub CLI attestation verification](https://cli.github.com/manual/gh_attestation_verify);
it does not implement its own signature verifier. The current implementation was
tested with GitHub CLI 2.102.0. Install a trusted CLI supporting all the documented
flags before using the staging helper.

Attestation is a provenance claim made by the reviewed workflow. It is not a
guarantee that dependencies are harmless, that an archive works on your machines,
or that its spam-detection quality has been qualified. Preserve the independent
release, lifecycle and model-quality gates.

## Historical releases and forks

Archives published before this workflow do not acquire build attestations
retroactively. The strict staging path refuses missing or invalid provenance,
including an otherwise valid checksum. Keep existing installations and historical
qualification evidence; publish a new reviewed version to obtain a new attested
archive. Never replace public assets or move a tag.

The trust policy explicitly names `crdffrance/NoiseFence` and
`.github/workflows/release.yml`. A maintained fork must review and change its
trust policy together with its publication workflow. Merely changing a download
URL or the `GH_REPO` environment variable does not change trusted signing identity.

## Verify before a first installation

With a trusted GitHub CLI, set `ARCHIVE`, `VERSION` and
`APPROVED_COMMIT` from the reviewed release and verify before extracting
or executing any packaged helper:

```sh
gh attestation verify "$ARCHIVE" \
  --repo crdffrance/NoiseFence --hostname github.com \
  --source-ref "refs/tags/v$VERSION" \
  --source-digest "$APPROVED_COMMIT" --signer-digest "$APPROVED_COMMIT" \
  --cert-identity "https://github.com/crdffrance/NoiseFence/.github/workflows/release.yml@refs/tags/v$VERSION" \
  --cert-oidc-issuer https://token.actions.githubusercontent.com \
  --deny-self-hosted-runners --digest-alg sha256 \
  --predicate-type https://slsa.dev/provenance/v1
```

The exact certificate identity already binds the workflow and tag. Do not add
`--signer-workflow`: GitHub CLI treats it as mutually exclusive with
`--cert-identity`. Successful verification establishes the expected origin;
the [installation procedure](installation.md#linux-release-installation) and
configuration checks still apply.

## Prepare an installed native MX

Use the reviewed management helpers already installed on the host. Do not execute
an installer or helper extracted from an unverified archive to verify itself.
Staging requires Linux, root, Python 3.11+, a trusted GitHub CLI at `/usr/bin/gh`,
the native `/opt/noisefence/releases` layout, and protected root-owned input paths.
Obtain the archive, expected SHA-256, version and approved source commit through
your authenticated release-review process.

If the GitHub CLI needs authentication, supply an approved read-access token
through `GH_TOKEN`. The helper uses an empty private CLI configuration, disables
interactive prompts and pins the GitHub hostname. It does not reuse proxy or
custom trust-root environment variables. Never put credentials in a release,
receipt, shell argument or repository.

In a root shell with `umask 077`, set these values from the reviewed release:

```sh
python3 /usr/local/libexec/noisefence-management/upgrade_stage.py \
  --archive /root/incoming/noisefence-release.tar.gz \
  --version "$VERSION" \
  --commit "$APPROVED_COMMIT" \
  --sha256 "$ARCHIVE_SHA256"
```

The helper performs these steps under the shared native operation lock:

1. Refuse an active upgrade reservation or insufficient disk headroom.
2. Copy the bounded input into a private snapshot and check its expected SHA-256.
3. Verify that snapshot's provenance with GitHub, using exact certificate and
   commit bindings. An unavailable provider or failed verification stops staging.
4. Inspect and extract the archive into a new private directory. Limit compressed
   input to 512 MiB, regular-file content to 2 GiB, members to 30,000, and metadata
   to bounded records. Reject noncanonical paths, links, devices, sparse files,
   unsupported TAR extensions, duplicates, conflicting file/directory names,
   unexpected trailing data and incomplete checksum manifests.
5. Check the metadata and little-endian 64-bit ELF architecture for this host.
   Require the binary, console and manifest; never run an archive member.
6. Synchronize files/directories, then rename the complete tree into
   `/opt/noisefence/releases/<version>`. A different or incomplete existing tree
   is refused. A matching tree is verified and retained.
7. Persist a root-owned staging receipt under
   `/var/lib/noisefence-upgrade/release-<archive-sha256>.json`.

Staging does not modify `current`, configuration, models, policy, databases,
queues or systemd services. It does not change the filtering mode.

## Recovery and subsequent activation

A failure before the rename removes the temporary tree during normal exception
cleanup. A process or machine crash can leave a private
`.noisefence-staging-*` directory; it is not a usable release and is never silently
adopted. Inspect such leftovers before explicit cleanup. Retry with the same
archive and approved identities. If the rename succeeded but receipt persistence
failed, the retry verifies the existing complete release and synchronizes its
parent before recording success. It never replaces a conflicting version.

The local receipt records verification time, archive/content hashes and a hash of
the verifier result. It is an operational record, not an independently signed
authorization. A receipt does not establish upgrade or rollback compatibility.

After both architecture-specific archives have been authenticated and their exact
old/new combination rehearsed, follow the [paired maintenance procedure](paired-upgrades.md)
and the [activation protocol](maintenance-activation.md). Preparation, a durable
pair decision and fresh runtime checks remain mandatory. Remote report exchange,
first-release end-to-end attestation qualification, production security profiles
and compatible recovery after ordinary runtime writes remain separate gates.
