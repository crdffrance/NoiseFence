# NoiseFence documentation

## Install and operate

- [Installation: Docker and Linux](installation.md)
- [Operations and routing](operations.md)
- [Paired upgrades and recovery boundaries](paired-upgrades.md)
- [Production readiness, health monitoring and incident recovery](production-readiness.md)
- [Web configuration](web-configuration.md)
- [Console and access control](console.md)
- [Multiple MX servers](multi-mx.md)
- [Two-copy durability and console recovery](high-availability.md)
- [Independent monitoring and backup handoff](external-resilience.md)
- [Independent SMTP/TLS/HTTPS probe](../deploy/external-monitor/README.md)
- [Linux hardening and backups](../deploy/hardening/README.md)
- [Security boundaries](security.md)

## Understand filtering

- [Score, classification, coverage and actions](filter-policy.md)
- [Filter qualification procedure](filter-qualification.md)
- [Private offline decision replay](decision-replay.md)
- [Message diagnostic headers](message-headers.md)
- [Remote SMTP and filter diagnostics](smtp-diagnostics.md)
- [Custom rules, profiles and onboarding](custom-filtering.md)
- [Delivery actions and quarantine](actions.md)
- [Marketing and newsletters](mailing.md)
- [Corroboration policy](confirmation.md)
- [Recorded detector evidence](decision-evidence.md)
- [Advanced message search](message-search.md)

## Configure checks

- [Early IP reputation / RBL](early-rbl.md)
- [SMTP admission, greylisting and rate limits](smtp-admission.md)
- [Destination recipient verification and optional fallback](recipient-fallback.md)
- [SMTP/DNS consistency](smtp-policy.md)
- [Protection and reputation providers](protection.md)
- [Automatic correspondent memory: learning, privacy and limits](contact-learning.md)
- [Private memory key: installation, matching MXs and exact-key recovery](contact-memory-key.md)
- [Identity protection: manual directories, protected names and integration status](identity-protection.md)
- [Entra candidate collection, permissions and failure boundaries](identity-entra.md)
- [Okta collection, org scope and review](identity-okta.md)
- [Google Workspace collection, customer scope and exclusions](identity-google.md)
- [AWS Identity Store collection, temporary access and review](identity-aws.md)
- [Active Directory internal collection, signed imports and key enrollment](identity-active-directory.md)
- [SCIM development profile and remaining integration requirements](identity-scim.md)
- [Encrypted directory access: Web setup, rotation, revocation and backups](directory-credential-storage.md)
- [URL redirect resolution](url-resolution.md)
- [OCR and QR codes](vision.md)
- [Antivirus and complementary signatures](antivirus.md)
- [LLM analysis](scaleway.md)
- [Native Rust filtering](native-filtering.md)
- [Rules inspired by Rspamd](rspamd-rules.md)
- [Adaptive statistical models](adaptive-filtering.md)

## Evaluate and contribute

- [Proton compatibility](proton-validation.md)
- [Quality sampling and labels](quality.md)
- [Reliability audit](reliability.md)
- [Coverage and contextual signals](capture-coverage.md)
- [Feedback training](feedback-training.md)
- [Performance measurement](performance.md)
- [Validation status and reproducible checks](validation-results.md)
- [Research protocols](../research/README.md)
- [Contributing](../CONTRIBUTING.md)

- [Automatic classification](automatic-classification.md): explicit score-threshold policy and immutable history.
- [Final release qualification](final-release-plan.md): evidence, calibration, coherence and release gates.

- [Unified receipt decisions](unified-decisions.md): canonical records, policy variants and remaining qualification work.

- [Model identity and provenance](model-provenance.md)
