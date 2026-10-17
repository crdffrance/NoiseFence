# Security policy

Security fixes target the latest stable release, listed on the [GitHub Releases page](https://github.com/crdffrance/NoiseFence/releases/latest). Earlier series and development prereleases do not receive separate maintenance. NoiseFence remains in 0.x; incompatible changes include migration instructions.

Report vulnerabilities through [GitHub private vulnerability reporting](https://github.com/crdffrance/NoiseFence/security/advisories/new). Include affected versions and a minimal reproduction using synthetic messages. Relevant issues include open relay, cross-user access, accepted-message loss and SMTP ambiguity. Do not publish private mail, keys or session tokens.

If private reporting is unavailable, open an issue requesting a private contact channel without exploit details or sensitive data. No contractual response time is promised.

Read the [security boundaries](docs/security.md), [validation limits](docs/validation-results.md) and [Linux hardening guide](deploy/hardening/README.md). TOTP only protects accounts whose owners have enrolled it. Paired message durability does not replace independent backups, verified fencing or recovery drills.

## Build security

GitHub Actions uses commit-pinned third-party actions and StepSecurity Harden-Runner
as the first step of each job. Build jobs audit outbound connections; the publication
job restricts egress to the GitHub and artifact endpoints it needs. Network observations
are sent to StepSecurity and linked from the job summary. This is build telemetry from
public source and synthetic tests, not production mail. Audit mode is not a network
allowlist. Review its findings before enforcing an allowlist on dependency-heavy jobs.
Docker and sudo remain available to jobs that exercise systemd, OCR and containers.
Service containers are provisioned before steps run, so their initial image pull is not
covered by the first hardening step. Do not run this workflow with private mail or
production credentials.

Only the publish job has repository-content write permission. Checkout does not persist
credentials. Weekly Dependabot proposals keep pinned action commits reviewable.
See [release verification](docs/releasing.md) for artifact integrity and retry behavior.

## Repository controls

The hosted repository requires a pull request, up-to-date CI results and CodeQL
results for changes to the default branch. CodeQL blocks new high/critical
security findings and error-level findings. Secret-scanning push protection,
Dependabot security alerts and private vulnerability reporting are enabled.
There are no ruleset bypass actors. Version tags cannot be moved or deleted;
newly published releases are immutable. These are GitHub settings, not settings
that are automatically inherited by a fork.

Actions default to read-only repository access and cannot approve pull requests.
External contributors need approval before their fork workflows run. Remote
Actions must use a full commit SHA; the allowed third-party actions are
StepSecurity Harden-Runner and dtolnay/rust-toolchain, alongside GitHub-owned
actions. Dependency review checks newly introduced high/critical vulnerabilities
in runtime, development and unknown scopes on pull requests, without posting
comments or receiving a write token. It depends on GitHub's dependency graph and
advisory coverage; it is not a guarantee that a package is safe.

Release workflows run only on their own version-tag commit, which must already
belong to the default branch. Artifact builds do not reuse shared Actions caches.
See [the release procedure](docs/releasing.md) for retries and source verification.

CODEOWNERS routes sensitive changes to the maintainer. It does not create an
independent review: while there is only one maintainer, the ruleset does not
require a second person's approval. Add that requirement when another trusted
maintainer is available. Maintainers should protect their GitHub accounts with
a passkey or hardware security key and retain offline recovery codes. Repository
settings cannot enforce account-wide 2FA on a personal repository.

Review CodeQL findings individually, including test-only credentials and mock DOM
helpers. Do not disable a security query or exclude all tests to clear a dashboard.
Record the reason and affected revision when dismissing a proven false positive;
keep uncertain findings open for investigation.
