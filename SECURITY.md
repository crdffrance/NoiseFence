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
