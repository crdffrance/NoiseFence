<a id="règles-locales-inspirées-de-rspamd"></a>
# Local rules inspired by Rspamd

NoiseFence 0.9.0 transposes into Rust twelve structured controls and two composites. They complement the existing pattern bank and authentication controls, reputation, deceptive links, Bayes and similarity already present.

The native module remains in **observation.** The new rules do not change the decision score, SMTP actions, or LLM selection. A symbol indicates one feature to be examined: it does not alone prove that a message is spam. The following weights are initial values to be measured on recent human annotations, not Rspamd scores or calibrated probabilities.

<a id="banque-et-portée"></a>
## Rule catalog and scope

| Symbole | Monitoring | Poids initial |
|---|---|---:|
| `NF_HTML_PASSWORD_FORM` | Password type field associated with a form | 0.3 |
| `NF_HTML_REMOTE_PASSWORD_FORM` | This same form sends to a different domain than that of From | 0.9 |
| `NF_HTML_INSECURE_PASSWORD_FORM` | This same form sends by HTTP | 0.5 |
| `NF_HTML_HIDDEN_TEXT` | At least 200 significant masked characters, more than visible characters | 0.15 |
| `NF_HTML_LINK_SCHEME` | HTTPS anchor text with an HTTP destination | 0.3 |
| `NF_HTML_DATA_LINK` | Anchoring to HTML/XHTML/SVG data URL | 0.4 |
| `NF_HTML_META_REFRESH` | Meta refresh tag to an absolute HTTP(S) URL | 0.3 |
| `NF_MIME_EXECUTABLE_EXTENSION` | Extension of executable program, script or shortcut | 0.2 |
| `NF_MIME_DOUBLE_EXTENSION` | Document or image extension followed by executable extension | 0.8 |
| `NF_MIME_EXECUTABLE_DISGUISED` | PE/ELF header in an attachment named or declared document/media | 1.0 |
| `NF_MIME_FILENAME_BIDI` | Unicode control d-override LTR/RTL in the attachment name | 0.3 |
| `NF_HEADER_DISPLAY_DOMAIN` | Name From a full address of another domain | 0.4 |

`NF_REMOTE_LOGIN_FORM` replaces the contributions of the password field and its external form with 1.2 points. `NF_DISGUISED_ATTACHMENT` replaces the contributions of the disguised binary and its dual extension with 1.5 points. The absorbed symbols remain visible. Repeating a form or attachment does not multiply a symbol. The family ceiling contained remains 1.5 points by default in the native comparative calculation.

External forms may be legitimate, especially with a separate identity provider. The comparison uses IDNA and the Public Suffix List's registrable domains, including its private suffixes. A subdomain of the same registered domain is accepted; two separate sites under `github.io` remain separate. A From or a name displayed is never treated as an authenticated identity. A simple difference in person name does not trigger control.

Short previews of newsletters, invisible filling spaces and script/style/template content do not count as a suspicious volume of hidden text. Only `hidden` attributes and some explicit built-in styles are interpreted; no remote CSS sheet, complete cascade, JavaScript or network request is executed. Escaped HTML examples and comments are not forms. `form=id` association must designate a single form; different forms are not combined to make a suspicious destination.

Forms and redirect URLs must be absolute in HTTP(S). Relative paths, base attributes, JavaScript actions, `formaction` buttons and remote pages are not solved by these rules. The existing reputation and redirect engine remains independent. Data links are observed without decoding their payload; embedded PNG images do not trigger this control.

The attachment names are decoded by the MIME parser (RFC 2231/2047). `rapport.2026.pdf` is not a double executable extension; the `%2e` literals in a name are not arbitrarily transformed. A properly declared JavaScript source file or executable can be legitimate. PE/ELF controls only check bounded headers, without disassembly or execution. They do not replace the antivirus. Archive, HTML attachments and Office macros are not explored by this bank.

## Configuration and inspection

The bank is active with `[native_filter]`, with the limits of the module and without new dependency. To disable a rule or change a weight:

```toml
[native_filter]
mode = "observe"

[native_filter.content_rules]
enabled = true
disabled = ["NF_HTML_HIDDEN_TEXT"]

[native_filter.content_rules.weights]
NF_MIME_DOUBLE_EXTENSION = 0.8
```

Allowable weights are finished and range from 0 to 2. A zero weight retains the symbol for observation and composites; `disabled` removes its emission. Composites can be customized separately as described in [the native engine guide](native-filtering.md). Unknown identifiers and collisions with custom patterns are refused. New symbols are not allowed in a negative condition `none`: a disabled rule or incomplete control does not become proof of absence of risk.

```sh
noisefence --config /etc/noisefence/config.toml native-rules
noisefence --config /etc/noisefence/config.toml native-rules example.eml
```

These commands show the original identifiers, labels, weights and references. The second inspects a local file without delivery, DNS or LLM call. It does not load the models. The message diagnosis displays the symbols under "Native Engine"; neither file name, private domain, URL or source text is added to these tags.

<a id="ressources-et-compatibilité"></a>
## Resources and compatibility

The rules are executed in the native worker Tokio blocking, under his semaphore and shared time. Additional limits: 200 MIME parts, 128 KiB accumulated HTML decoded, 8,192 DOM knots per part, 64 ancestors and 4,096 bytes per file name. Forms are indexed once, styles analyzed once and texts counted once. An overshoot makes the native module `limited`, without a comparative score; it does not block delivery.

The report becomes `native-filter-2`. Code and policy prints separate the observations. The lexical, OSB, MinHash and the 16 inputs of the adaptive classifier do not change; the twelve new symbols are not automatically added to the already trained models. The database retains the SQLite 2 schema and the old reports remain legible. Optional quality candidates linked to the code print must be re-entered and validated before activation with this version.

This feature’s original migration was additive. Current paired installations require storage schema 5 and a compatible release. Do not downgrade the database, remove its HA marker or restore an older backup over accepted mail. See [installation](installation.md) and [HA recovery](high-availability.md) for current upgrade and rollback procedures.

The tests cover legitimate counter-examples, MIME encoded, private suffixes, masked styles, separate forms, opposing entries, limits, weightings, absorption of contributions and invariance of the delivery score. The MIME buzzing harness also exercises this bank. This checks the software behavior, without demonstrating a catch rate on the real traffic.

<a id="sources-examinées"></a>
## Sources considered

Review Rspamd pinned: [`e2de26d28ce857d5c48ac82703cf26b681bd1d89`](https://github.com/rspamd/rspamd/tree/e2de26d28ce857d5c48ac82703cf26b681bd1d89).

- [HTML](https://github.com/rspamd/rspamd/blob/e2de26d28ce857d5c48ac82703cf26b681bd1d89/rules/html.lua): visibility, false HTTPS and structural inspection.
- [MIME](https://github.com/rspamd/rspamd/blob/e2de26d28ce857d5c48ac82703cf26b681bd1d89/src/plugins/lua/mime_types.lua): extensions, type inconsistencies and obfuscated Unicode.
- [Headers](https://github.com/rspamd/rspamd/blob/e2de26d28ce857d5c48ac82703cf26b681bd1d89/rules/headers_checks.lua) and [phishing](https://github.com/rspamd/rspamd/blob/e2de26d28ce857d5c48ac82703cf26b681bd1d89/src/plugins/lua/phishing.lua): displayed identity and destination domains.
- [GPT](https://github.com/rspamd/rspamd/blob/e2de26d28ce857d5c48ac82703cf26b681bd1d89/src/plugins/lua/gpt.lua): Consulted to compare architecture; no prompt, self-learning on verdict LLM, external context or additional call n

The form controls, URL data, meta refract and displayed names are NoiseFence adaptations of these families of techniques, without announced equivalence with a specific Rspamd symbol. Rust code, parameters and tests are project specific. The Apache-2.0 upstream license is kept with [third party notices](../THIRD_PARTY.md).
