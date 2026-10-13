<a id="suivi-des-urls"></a>
# URL redirect inspection

Available from **0.4.4** (and 0.5.0-dev.15) in additional protections. In **Filters → Additional protections**, activate **Follow link redirects**, then **Review and apply**. The revision is audited as other settings. Existing configurations keep tracking disabled.

New messages received by SMTP are then subject to automatic HTTP GET visits. Offline local processing does not open any links. A visit can trigger a tracking counter, reveal the server's IP to the site or consume a single-use link: this consequence is recalled in the console.

<a id="parcours-et-vérifications"></a>
## How inspection works

The engine extracts HTTP/HTTPS URLs from text, HTML anchors, and OCR/QR text. It follows 301, 302, 303, 307, 308, `Refresh` headers, and `meta refresh` HTML tags, with relative path resolution, HTML entities, and the first `base` tag. Valid refresh times do not cause waiting. Ambiguous loops and redirects interrupt the course.

Each URL visited, including the final destination, is compared exactly to the local phishing base if the link control is activated. The fields discovered join the CRDF and VirusTotal consultations when they are configured. The last destinations are given priority in the budget of twelve indicators per supplier; this does not guarantee a consultation if the quota or delay is exhausted. The complete paths and parameters remain local for these consultations: the connectors send domains, not URLs.

The engine does not execute JavaScript or load images, iframes, external scripts or style sheets. It does not submit forms, reuse cookies or forward authorization or referrers. Compressed content despite `Accept-Encoding: identity` and non-UTF-8 HTML remain incomplete. Non-HTML content ends the HTTP path without analysing its body. This resolver does not reproduce a full browser session.

Since `url-resolution-5` (0.30.2), one complete inline statement assigning a literal URL to `location` / `location.href`, or calling `location.assign()` / `location.replace()`, can supply the next destination. `window` and `document` prefixes are supported. Expressions, callbacks, comments, additional statements, external/module scripts, event handlers and competing navigation instructions remain unresolved. Inline `application/json` and `application/ld+json` blocks are data, following the [HTML script processing model](https://html.spec.whatwg.org/multipage/scripting.html#the-script-element); they do not alone imply executable navigation. Other scripts, including analytics, are not assumed harmless. The resolver follows every recognized destination through the same DNS, address, TLS, hop and time limits. Resolution is an observation, never a safe-site verdict.

Version `url-resolution-6` (0.31.3) also decodes escaped slashes and quotes, hexadecimal `\xHH`, Unicode `\uHHHH` and `\u{H…}` literals, including paired UTF-16 surrogates. For example, `location='https:\/\/example.com\x2fnext'` identifies `https://example.com/next`. Decoding follows the supported subset of [ECMAScript string-literal rules](https://tc39.es/ecma262/multipage/ecmascript-language-lexical-grammar.html#sec-literals-string-literals), without a JavaScript runtime. Each statement is limited to 4,352 UTF-8 bytes and its decoded destination to 4,096 bytes; braced Unicode escapes accept at most six hex digits. Unsupported escapes, unpaired surrogates, control characters, URL backslashes and ambiguous statements remain unresolved. Encoded private addresses still fail the normal network checks. URL parsing preserves non-ASCII characters rather than silently stripping Unicode whitespace from a path.

The console displays each hop's registrable domain, HTTP code, duration, stop reason and omitted checks. Reaching an HTTP destination is not a security verdict. Unavailable results and exhausted quotas are not evidence of spam. These observations do not add arbitrary score weights or change configured delivery actions.

<a id="limites-et-réseau"></a>
## Resource and network limits

Initial host defaults are shown below. Installed-module limits can subsequently be changed in **Filters → Advanced settings** and applied to future messages without restarting:

```toml
[protection.url_resolution]
timeout_ms = 1200
max_urls = 4
max_redirects = 5
max_parallel = 2
blocked_ips = []
```

The default 1.2-second budget covers all URLs and hops for a message; it is not renewed at each connection. The enclosing analysis deadline still applies. The shared default capacity is two concurrent URL chains; waiting for capacity consumes the same budget. Saturation and network deadlines are recorded separately. Each chain permits five redirects (six requests) by default. Each HTML response is limited to 64 KiB, even when streamed. Inspection stops after 8,192 elements or 1,024 navigation elements. Omitted URLs are reported, with a lower-bound count when the exact total is unavailable.

Before each connection, the engine resolves both A and AAAA records, validates every address and pins them in a new HTTP client. Automatic client redirects and environment proxies are disabled. Only HTTP on port 80 and HTTPS on port 443 are allowed, with certificate and hostname verification. URLs containing credentials are refused. Private, local and reserved addresses, cloud metadata services, IPv6 transition mechanisms and server interface addresses are excluded. A partially unavailable DNS response stops the chain.

`blocked_ips` also excludes public NAT or management addresses that do not appear on a local interface. These controls run in the NoiseFence process; they are not a separate network namespace. Configure exclusions for your topology and enforce internal-network isolation in outbound firewall rules, following the [OWASP SSRF guidance](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html).

## Retention and tests

HTML responses are discarded after inspection. Reports retain SHA-256 URL fingerprints, registrable domains without subdomains, HTTP codes and states, but no paths, query strings or downloaded pages. Access and retention follow the message's diagnostic permissions. Historical messages are not assigned visits that never occurred.

The tests only use local servers and synthetic messages: HTTP and HTML redirections, secretless queries, unreliable TLS responses, DNS changes between two jumps, private destinations, loops, ceilings, expiration, supplier quotas and exact match of the destination in the local base. They do not measure a catch rate on real traffic.

### Oversized HTML pages

Version `url-resolution-4` inspects at most 65,536 body bytes and may follow an
unambiguous, complete meta-refresh tag within that prefix. An incomplete tag
cannot provide a destination. A truncated page without a usable redirect remains
incomplete. `body_truncated` records truncation on any visited hop;
`reached_http_success` records receipt of a 2xx response at the latest HTTP hop.
Neither field establishes a safe URL or a complete final-page scan. Scripts
remain inert and all redirects undergo the existing DNS/address restrictions.
