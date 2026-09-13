# Security policy

Security fixes target the latest stable release, currently **0.18.x**. Earlier series and development prereleases do not receive separate maintenance. NoiseFence remains in 0.x; incompatible changes include migration instructions.

Report vulnerabilities through [GitHub private vulnerability reporting](https://github.com/crdffrance/NoiseFence/security/advisories/new). Include affected versions and a minimal reproduction using synthetic messages. Relevant issues include open relay, cross-user access, accepted-message loss and SMTP ambiguity. Do not publish private mail, keys or session tokens.

If private reporting is unavailable, open an issue requesting a private contact channel without exploit details or sensitive data. No contractual response time is promised.

Read the [security boundaries](docs/security.md), [validation limits](docs/validation-results.md) and [Linux hardening guide](deploy/hardening/README.md). TOTP only protects accounts whose owners have enrolled it. Paired message durability does not replace independent backups, verified fencing or recovery drills.
