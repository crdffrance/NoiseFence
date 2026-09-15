# Context, coverage and calibration

NoiseFence 0.20.3 uses decision policy `decision-policy-3` and LLM prompt `noisefence-classify-4`. The prompt fingerprint and recorded policy distinguish new observations from earlier results.

## Readable content survives independent failures

LLM selection uses the stored local extraction status rather than the final completeness of every detector. A DNS, semantic or optional scanner failure no longer prevents analysing readable text. The original incomplete status remains: a successful LLM response does not repair a failed check. Configured selection intervals, the per-request text cap, concurrency and the budget still apply. Historical records without extraction status retain conservative behavior.

Encrypted PGP/MIME and opaque S/MIME bodies are explicitly recorded as limited content coverage. NoiseFence cannot inspect their plaintext and does not ask the LLM to invent a content verdict. Readable signed MIME is not classified as encrypted. Raw scores remain available as partial diagnostic indices, not calibrated probabilities.

## Contextual false-positive safeguard

The content parser recognizes bounded security-report and shipment-receipt contexts without a vendor allowlist. A high **legacy** score for one of these contexts requires review when aligned authentication was actually observed by the gateway and independent corroboration is absent. For example, a feed containing defanged threat indicators is not necessarily an attack; a receipt mentioning an automatic payment is not necessarily financial coercion.

This safeguard can only move an unwanted decision to **undetermined**. It never declares a message legitimate, reduces the numeric score, supplies missing authentication, or overrides the main antivirus or a separately validated fusion decision. Message-provided Authentication-Results headers cannot satisfy it. A malicious sender copying reporting language does not receive an allowlist bypass. Review remains necessary, and primary malware findings retain priority.

The LLM receives lexical domain relationships derived from URLs already present in its bounded text payload. A host under the sender's registrable domain is distinguished from a lookalike under another domain. These facts do not establish ownership, authentication or legitimacy. No link is opened by this analysis.

Mailing categorization also separates planned service maintenance from commercial newsletters. List and unsubscribe headers combined with an offer can establish newsletter purpose even without the word “newsletter”. This purpose classification adds no spam weight and cannot override a security decision.

## Semantic deadline

An administrator can edit **Filters → Engine parameters → Semantic analysis → Maximum time (ms)**. The allowed range is 50–5,000 ms. Model paths and CPU concurrency remain installed host settings. The deadline includes waiting for a slot and inference; a timed-out task retains its slot until its CPU work actually finishes. Deadline edits reuse the loaded weights and existing limiter.

Choose a deadline based on measurements on the slowest MX. Identical software does not imply identical execution speed on different CPU allocations. A longer bounded deadline addresses unavailable inference, not a miscalibrated model. Recorded semantic failures distinguish capacity, deadline, inference and worker errors; older rows may lack this detail.

## Validate before enforcing

Do not lower a threshold just to clear a review queue or treat comparator agreement as a reference label. High raw scores on confirmed legitimate traffic call for calibration on recent labelled examples. Keep security reports, transactional notices, wanted newsletters, phishing and spam represented; deduplicate campaigns and reserve an independent evaluation set. Corrections used to develop a safeguard are development examples, not an unbiased test set.

Rspamd remains an independent observation. New prompts need evaluation on fresh results; replaying an old LLM verdict does not validate a new prompt. Historical messages and their headers are not silently rescored. User corrections do not create retrospective changes in Proton.
