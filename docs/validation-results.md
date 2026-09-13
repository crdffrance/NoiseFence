<a id="résultats-locaux--6-septembre-2026"></a>
# Local results — 6 September 2026

## Code and protocols

The release 0.10 has 28 automated Rust tests: SMTP and PIPELING, alias and refusal of the open relay, DATA interrupted, disk pressure, CRLF ambiguities, recovery, multiple recipients, failed notifications, cancelled transaction, actual TLS and unreliable certificate, rights per user and BCC, sessions and CSRF, preservation, falsification of results, encoded objects and limits of signatures.

The cryptographic test uses a public test key and a local DNS cache: DKIM valid on the original and the observed version; DKIM invalid after modifying the object; ARC valid on the modified version; ARC invalid after altering the body. It verifies the cryptography, not the confidence given to the seal by Proton.

The tests go to macOS ARM64 and Linux. The Linux build uses the official image Rust 1.98 Bookworm, imprint `sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922`. The IC reproduces formatting, Clippy, tests and compilation. The binary must be used on the corresponding architecture with glibc 2.36 or later.

The console passes TypeScript and the lint. Static export is compiled, served by Axum with HTTP 200 response; the sessionless API returns 401. The npm audit indicates zero known vulnerability on that date. No automated visual validation or WebMCP compliance is claimed.

<a id="connecteurs-de-la-version-de-développement"></a>
## Development version connectors

The development branch `0.2.0-dev.1` adds 10 Rust tests, i.e. 38 automatic tests out of real ClamAV tests: INSTREAM exchanges bounded, scanner failure, persistent verdicts, separation of consultative signatures, Bayes calculation, competing and persistent LLM budget, exclusion of recipient fields and attachments, and valid or hostile HTTPS/JSON responses. Six Python Linux tests cover certificates and download of pind sources.

The real ClamAV test, ignored by default in `cargo test`, was executed separately in a Linux ARM64 container: ClamAV 1.4.3, daily 28115, hand 63 and bytecode 339. The healthy message passes; EICAR is detected in a base-encoded MIME attachment64. This checks the transport and decoding, not the detection rate of recent threats. FreshClam recommends 1.4.6: check packages maintained before deployment.

The same harness executed clamav-unofficial-sigs 8.0.0 as a user `clamav`. He separately checked GPG signatures and installed copy of the `sanesecurity.ftm`, `sigwhitelist.ign2`, `phish.ndb` and `junk.ndb` bases with the pin key, then loaded the additional scanner and scanned a healthy file. The official and complementary sockets were distinct. These tests do not measure the recall or false positives of the signatures on the real traffic.

The development console passes lint, TypeScript and static export. Scaleway exchanges are simulated by a local HTTPS server; no real cloud call, IAM right or delivability effect is validated by these tests.

<a id="modèle-candidat--objectifs-non-atteints"></a>
## Candidate model: objectives not achieved

Source: public corpus Apache SpamHistoric Assassin. 5,874 examples after import and standardized deduplication, of which 4,659 for training, 609 for validation, 606 for testing. Remote variants of a campaign can escape consolidation. This result is exploratory on old data, without guarantee of temporal independence.

| Measurement on the test | Result |
|---|---:|
| Spams detected | 117 / 192 |
| Recall | 60.94 % |
| 95% CI of recall | 53.89–67.56 % |
| Legitimate messages marked | 0 / 414 |
| False positives observed | 0 % |
| 95% CI of false positives | 0–0,919 % |
| Accuracy observed | 100 % |
| Activation of the candidate | Denied |

The machine-readable ratio is [model-bootstrap.report.json](model-bootstrap.report.json). The small number does not show ≤ 0.1% false positives. The recall remains under 95%. The activation control therefore refuses this candidate. This measure concerns the local classifier; the rules, authentication and reputation of the complete pipeline must be evaluated separately on a recent and representative corpus. No candidate model is activated in the delivered configuration.

Candidate Bernoulli Bayes of the development branch uses exactly the same separation. He detects 1 spam out of 192 (recall 0.52%, IC 95% 0.092–2.891 %), with 0 false positive on 414 legitimate messages. The conservative threshold is calibrated only on validation. It is refused and does not replace logistics. His [full report](model-bayes.report.json) makes this comparison reproducible.

<a id="rapidité-et-robustesse"></a>
## Rapidity and robustness

Local extraction on a synthetic message of 1,048,521 bytes, 1,000 repeats on the development Mac: p50 3,954 ms, p95 7,491 ms. This test excludes DNS, classification with loaded model, TLS and persistence. This is not a measure of the full incremental cost on the reference machine 4 vCPU / 8GB.

The reception limits four competing analyses. Network checks of a message are limited to five seconds and an incomplete analysis keeps the object unfixed.

The libfuzzer SMTP/MIME targets were compiled and executed on 10,000 inputs each, as well as 5,000 deterministic mutations in the tests. These first stable executions did not have cover instrumentation/sanitizer: they constitute a control of the harness operation, not a guided fuzzing campaign. Long-run instruments and real full disk/crash hardware tests remain to be performed.

## Pending Proton validation

A first transport test was performed from the Linux server to a controlled Proton box: a direct message, a message via the NoiseFence file, and a message via the already prefixed and international file with object. Direct sending received `250` under TLS 1.3; both relays were accepted by Proton, marked delivered, and then their bodies were deleted from the spool. The user confirmed the three messages in the spam folder. The correct display of international characters has not yet been confirmed.

These synthetic messages did not have a DKIM signature and the sender domain FPS did not allow the server IP. As the direct cookie also arrives in spam, the trial does not allow to assign this ranking to the prefix. The server reputation and authentication must be isolated in the next trials. The third message had an already prefixed object: it was not a real modification trial followed by a published ARC seal. The deployment-specific proofs and test addresses remain outside the public repository.

No MX has been modified. The switch remains suspended. The eight full cases of the [proton-validation.md](proton-validation.md) protocol remain to be executed. The observation mode remains the starting configuration and the marking requires a recent report provided with proof of delivery. The server details and the actual addresses belong to the local configuration of each deployment.
