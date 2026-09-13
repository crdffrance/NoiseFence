<a id="suivi-des-urls"></a>
# URL tracking

Available from **0.4.4** (and 0.5.0-dev.15) in additional protections. In **Filters → Additional protections**, activate **Follow link redirects**, then **Review and apply**. The revision is audited as other settings. Existing configurations keep tracking disabled.

New messages received by SMTP are then subject to automatic HTTP GET visits. Offline local processing does not open any links. A visit can trigger a tracking counter, reveal the server's IP to the site or consume a single-use link: this consequence is recalled in the console.

<a id="parcours-et-vérifications"></a>
## Tracks and audits

The engine extracts HTTP/HTTPS URLs from text, HTML anchors, and OCR/QR text. It follows 301, 302, 303, 307, 308, `Refresh` headers, and `meta refresh` HTML tags, with relative path resolution, HTML entities, and the first `base` tag. Valid refresh times do not cause waiting. Ambiguous loops and redirects interrupt the course.

Each URL visited, including the final destination, is compared exactly to the local phishing base if the link control is activated. The fields discovered join the CRDF and VirusTotal consultations when they are configured. The last destinations are given priority in the budget of twelve indicators per supplier; this does not guarantee a consultation if the quota or delay is exhausted. The complete paths and parameters remain local for these consultations: the connectors send domains, not URLs.

The engine does not run JavaScript and does not load images, iframes, scripts, or style sheets. It does not submit forms and does not reuse cookies, authentication, or HTTP referencing. An HTML page containing scripts without declarative redirection is reported as incomplete. The compressed content despite `Accept-Encoding: identity` and non-UTF-8 HTML are also incomplete. Non-HTML content ends the HTTP path without analysis of its body. This HTTP solver does not therefore reproduce all browser browsings.

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

The 1.2-second delay covers all URLs and their jumps for the same message; it is not renewed at each connection. The overall delay of message analysis remains applicable. No more than two messages perform this work at the same time; a saturation is immediately reported. Each URL receives no more than five redirects, i.e. six queries. Each HTML response is limited to 64 KiB, including when it arrives in pieces. The number of HTML navigation elements examined is limited. No more than eight URLs are retained at extraction; a clip is indicated, with a minimum number of omissions when the exact total is not available.

Before each connection, the engine solves the A and AAAA families, controls all addresses and fixes them in a new HTTP client. Automatic redirections of the client and environment proxys are disabled. Only HTTP on 80 and HTTPS on 443 are allowed, with normal verification of the certificate and TLS name. URLs containing identifiers are refused. Private, local, reserved cloud metadata addresses, IPv6 transition mechanisms and server interface addresses are excluded. A partially unavailable DNS response interrupts the route.

`blocked_ips` also allows for the exclusion of public NAT or admin IPs that do not appear on a local interface. These controls run in the NoiseFence process; they do not constitute a separate network space. For deployment, complete exclusions according to topology and apply the same separation of internal networks to the output filtering. This operation is based on [OCASP recommendations against SSRF](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html).

## Retention and tests

HTML responses are abandoned after inspection. The report keeps SHA-256 URL fingerprints, registrable domains without subdomains, HTTP codes and states. It does not keep path, request, or downloaded page. It follows the authorizations and the retention of the diagnostics of the message; the old messages are not assigned an invented visit.

The tests only use local servers and synthetic messages: HTTP and HTML redirections, secretless queries, unreliable TLS responses, DNS changes between two jumps, private destinations, loops, ceilings, expiration, supplier quotas and exact match of the destination in the local base. They do not measure a catch rate on real traffic.
