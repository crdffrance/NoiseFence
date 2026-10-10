<a id="suivi-des-urls"></a>
# URL tracking

Available from **0.4.4** (and 0.5.0-dev.15) in additional protections. In **Filters → Additional protections**, activate **Follow link redirects**, then **Review and apply**. The revision is audited as other settings. Existing configurations keep tracking disabled.

New messages received by SMTP are then subject to automatic HTTP GET visits. Offline local processing does not open any links. A visit can trigger a tracking counter, reveal the server's IP to the site or consume a single-use link: this consequence is recalled in the console.

<a id="parcours-et-vérifications"></a>
## Tracks and audits

The engine extracts HTTP/HTTPS URLs from text, HTML anchors, and OCR/QR text. It follows 301, 302, 303, 307, 308, `Refresh` headers, and `meta refresh` HTML tags, with relative path resolution, HTML entities, and the first `base` tag. Valid refresh times do not cause waiting. Ambiguous loops and redirects interrupt the course.

Each URL visited, including the final destination, is compared exactly to the local phishing base if the link control is activated. The fields discovered join the CRDF and VirusTotal consultations when they are configured. The last destinations are given priority in the budget of twelve indicators per supplier; this does not guarantee a consultation if the quota or delay is exhausted. The complete paths and parameters remain local for these consultations: the connectors send domains, not URLs.

The engine does not execute JavaScript or load images, iframes, external scripts or style sheets. It does not submit forms, reuse cookies or forward authorization or referrers. Compressed content despite `Accept-Encoding: identity` and non-UTF-8 HTML remain incomplete. Non-HTML content ends the HTTP path without analysing its body. This resolver does not reproduce a full browser session.

Since `url-resolution-5` (0.30.2), one complete inline statement assigning a literal URL to `location` / `location.href`, or calling `location.assign()` / `location.replace()`, can supply the next destination. `window` and `document` prefixes are supported. Expressions, escapes, callbacks, additional statements, external/module scripts, event handlers and competing navigation instructions remain unresolved. Inline `application/json` and `application/ld+json` blocks are data, following the [HTML script processing model](https://html.spec.whatwg.org/multipage/scripting.html#the-script-element); they do not alone imply executable navigation. Other scripts, including analytics, are not assumed harmless. The resolver follows every recognized destination through the same DNS, address, TLS, hop and time limits. Resolution is an observation, never a safe-site verdict.

The console displays the recordable domains of jumps, HTTP codes, duration, reason for interruption, and omissions. "Achieved HTTP Destination" is not a security verdict. Unavailability or quota does not become a proof of spam. These observations remain consultative, like other complementary protections: they do not create arbitrary weight in the ranking. The stable branch retains already configured delivery models and actions.

<a id="limites-et-réseau"></a>
## Boundaries and Networking

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

Before each connection, the engine solves the A and AAAA families, controls all addresses and fixes them in a new HTTP client. Automatic redirections of the client and environment proxys are disabled. Only HTTP on 80 and HTTPS on 443 are allowed, with normal verification of the certificate and TLS name. URLs containing identifiers are refused. Private, local, reserved cloud metadata addresses, IPv6 transition mechanisms and server interface addresses are excluded. A partially unavailable DNS response interrupts the route.

`blocked_ips` also allows for the exclusion of public NAT or admin IPs that do not appear on a local interface. These controls run in the NoiseFence process; they do not constitute a separate network space. For deployment, complete exclusions according to topology and apply the same separation of internal networks to the output filtering. This operation is based on [OCASP recommendations against SSRF](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html).

## Retention and tests

HTML responses are abandoned after inspection. The report keeps SHA-256 URL fingerprints, registrable domains without subdomains, HTTP codes and states. It does not keep path, request, or downloaded page. It follows the authorizations and the retention of the diagnostics of the message; the old messages are not assigned an invented visit.

The tests only use local servers and synthetic messages: HTTP and HTML redirections, secretless queries, unreliable TLS responses, DNS changes between two jumps, private destinations, loops, ceilings, expiration, supplier quotas and exact match of the destination in the local base. They do not measure a catch rate on real traffic.

### Oversized HTML pages

Version `url-resolution-4` inspects at most 65,536 body bytes and may follow an
unambiguous, complete meta-refresh tag within that prefix. An incomplete tag
cannot provide a destination. A truncated page without a usable redirect remains
incomplete. `body_truncated` records truncation on any visited hop;
`reached_http_success` records receipt of a 2xx response at the latest HTTP hop.
Neither field establishes a safe URL or a complete final-page scan. Scripts
remain inert and all redirects undergo the existing DNS/address restrictions.
