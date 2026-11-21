# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Real
**Verdict Confidence:** 66
**Synthetic-Confidence Score:** 29

## Executive Summary

The network records are mostly production-like: flow states, DNS resolution, proxy tunneling, TLS visibility, and protocol byte budgets form a coherent observation set. I found a mild duration-distribution concern, but no demonstrated impossible network event or source-native contradiction; the verdict is therefore tentative, since a sufficiently careful simulator could also produce these records.

## Evidence For Synthetic

- [weak_signal] Successful application flows have conspicuous lower duration bounds across substantial samples. In `zeek-dmz/conn.json`, all 3,305 `service=ssl`, `conn_state=SF` flows last at least 0.828989 seconds, while all 2,955 successful HTTP flows last at least 0.458486 seconds. The corresponding HTTP minimum in core is 0.458655 seconds across 2,690 flows, and the database sensor minimum is 0.485784 seconds across 14 flows. This could reflect bounded service-duration sampling, although shared observations are not independent samples and application/proxy behavior could explain it. It receives only a small score contribution.

## Evidence For Real

- The three sensors show differentiated traffic roles and genuinely varied connection outcomes. Core has 1,996 Kerberos, 1,190 LDAP, and 463 SMB-classified flows; the database sensor has 277 MySQL flows; the DMZ includes 2,368 `S0` connections alongside 7,703 `SF` connections and smaller reset/rejection populations.
- DNS includes A, AAAA, PTR, SRV, TXT, MX, NS, and SOA questions, negative answers, and resolver failures. Core contains 233 NXDOMAIN, 18 SERVFAIL, and five REFUSED responses rather than exclusively successful lookups.
- A concrete DNS-to-TLS sequence is physically coherent: `zeek-dmz/dns.json` at epoch `1793624431.468505` resolves `fonts.pingdom.app` to `104.16.122.118`, with RTT 0.068280 seconds. Its TCP connection starts at `1793624431.549214`, and TLS is recorded at `1793624431.771042`, with matching destination and SNI.
- TLS records respect passive visibility: none of the 2,411 TLS 1.3 SSL records across the sensors exposes a `cert_chain_fuids` list. TLS 1.2 records do provide certificate evidence where appropriate, and inspected certificate key types agree with RSA/ECDSA cipher authentication.
- HTTP CONNECT records explicitly describe the proxy leg rather than pretending encrypted browsing is ordinary cleartext HTTP. The proxy access log's first visible tunnel separately labels CONNECT control bytes and tunneled byte counters.
- All tested protocol-to-flow UID references and endpoint tuples match within each sensor. Protocol timestamps fall inside their visible connection intervals. Aggregate HTTP request/response bodies never exceed the corresponding transport payload counters, and visible certificate bytes never exceed their TLS connection's responder bytes.

## Detailed Analysis

### Scope and method

I examined only the supplied data, concentrating on all JSON records under `zeek-core`, `zeek-dmz`, and `zeek-db`, and sampled the supplied perimeter firewall, proxy, and Snort text. Counts below are observations, not unique network activities: overlapping sensors observe some of the same traffic under sensor-local identifiers and clocks.

The review covered 23,502 connection records: 12,450 core, 10,634 DMZ, and 418 database. The window spans approximately 2026-11-02 13:00–19:00 UTC. Protocol joins covered 4,496 DNS records, 5,808 HTTP records, 3,824 SSL records, 259 SMB file records, and 79 SMTP records. I also checked file and X.509 references and content identities. This is a six-hour daytime slice; it cannot establish overnight or weekend realism.

### Connections, states, and packet accounting

Core is 7,049 TCP, 4,976 UDP, and 425 ICMP observations. Its state distribution includes 10,018 SF, 1,688 S0, 443 OTH, 137 RSTO, 93 RSTR, 26 REJ, and smaller partial-establishment states. DMZ is more heavily TCP-oriented and contains more unanswered attempts, consistent with exposed services and scanning. The database sensor is dominated by the application/database path, with 221 successful MySQL connections among its 277 MySQL observations.

I found no SF TCP flow with fewer than two observed packets in either direction, no SF flow with zero responder packets, no direction whose payload bytes exceed its IP bytes, and no average IP-packet length above the IPv4 maximum. RSTO/RSTR histories contain the corresponding originator/responder reset character. Histories containing content-gap markers have nonzero `missed_bytes`.

Some flows have fewer captured IP bytes than sequence-derived payload bytes plus minimum headers. These coincide with missed data and are not inherently contradictory: Zeek transport payload estimates can include sequence-space bytes absent from the capture. I did not score that as synthetic.

Longer-lived traffic is present. Successful core SSH connections reach 13,321.734 seconds; SMB reaches 119.418 seconds, while short Kerberos activity has a roughly 20 ms median. These service differences argue against a single generic duration pool.

### DNS and resolver behavior

Core question counts are A 2,423, AAAA 320, TXT 270, PTR 160, SRV 99, MX seven, NS seven, and SOA three. DMZ DNS is primarily proxy-originated and has its own distribution: A 949, AAAA 137, PTR 69, SRV eight, and TXT one. The database sensor has 43 successful responses, mostly internal questions, which is reasonable for its much narrower view.

Examples include `_ldap._tcp.meridianhcs.local` returning both domain controllers at `1793624402.649837`, and `oldserver.meridianhcs.local` returning NXDOMAIN at `1793624694.347953`. Both short-name and suffixed WPAD questions occur. A representative `wpad.meridianhcs.local` negative reply appears in both DMZ and core with the same DNS transaction ID `30376` and source port `38115`, with sensor-specific timestamps. A clock difference between sensors is not, by itself, reversed network causality.

No A answer contained an IPv6 literal, no AAAA answer contained an IPv4 literal, and no NXDOMAIN response carried a positive answer list. Recorded originator bytes accommodate the DNS question sizes. The explicit DNS→TCP→TLS sequence cited above demonstrates that at least an independently selected example respects resolution completion before connection start. I did not require a new DNS question for every connection, since cached answers are normal.

### HTTP, proxying, and TLS

Core HTTP is dominated by 2,540 CONNECT requests; DMZ has 2,573 CONNECT requests. Raw HTTP record counts therefore cannot be interpreted as evidence that cleartext web browsing exceeds encrypted browsing. The connection toward `10.10.3.20:8080` is a client/proxy leg, while proxy-originated TLS flows represent external legs. The first proxy entry explicitly reports `byte_scope=connect-control-message` and `tunnel_duration_ms=1403`, avoiding an obvious conflation of CONNECT headers with total tunnel transfer.

Responses include authentication and policy failures, redirects, cache validation, and gateway failures. Core has 31 HTTP 407, 52 HTTP 403, 19 HTTP 304, and 28 combined 502/503/504 responses. No 204/304 response carries a positive response-body length. Multiple transactions on one connection occur: core UID `CQSFkjaC0RF9wgkvgi` has a GET `/` at `1793624919.631600` and a second transaction for `/assets/css/main.min.07b8945e.css` at `1793624920.724443`, with an appropriate referrer and increasing `trans_depth`.

DMZ SSL records include 2,210 TLS 1.3, 1,204 TLS 1.2, and five records without a negotiated version; core has 201 TLS 1.3, 186 TLS 1.2, and three without one. Database SSL is entirely TLS 1.2 and is concentrated on internal file/monitoring services. Ciphers include AES-GCM and ChaCha20, with a smaller legacy CBC component internally. That environment-dependent mix is plausible.

I checked certificate key/cipher compatibility, stable fields for repeated fingerprints, uniqueness of certificate identity under an issuer/serial pair, and consistent file sizes for repeated SHA-256 values. These checks found no conflicting identities. TLS 1.3 certificate invisibility is a particularly useful source-native detail; its absence is expected and was not treated as missing coverage.

### Timing texture and limits of inference

Hourly connection observations are uneven. Core counts are 1,741, 3,230, 1,732, 1,803, 2,211, and 1,733 from 13:00 through 18:00 UTC. DMZ similarly peaks at 14:00 but is not a fixed-count stream. This is compatible with bursts of shared activity, although aggregate hourly variation alone is weak evidence of authenticity.

The strongest reservation is the lower-bound texture of successful HTTP and DMZ TLS durations. The shortest DMZ HTTP observation is UID `CyNxDgL7pJSUi9BadO`, `10.10.1.35:51195 → 10.10.3.20:8080`, at `1793636366.574238`, lasting 0.458486 seconds. Core's matching tuple lasts 0.458655 seconds. The shortest successful DMZ SSL flow is UID `CyywEQRt2jFiCyqI6Lr` at `1793637664.383606`, lasting 0.828989 seconds. Across thousands of requests, an absence of very fast successful exchanges can resemble an artificial duration floor. However, transaction selection, connection-close policy, remote latency, and proxy behavior remain viable explanations. The overlapping core/DMZ measurements must not be counted as two independent discoveries.

I found no hard contradiction warranting a high synthetic-confidence score. Complete cross-source matching, domain sanitization, and absent source families were not used as synthetic indicators.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| weak_signal | Zeek HTTP/TLS connection durations | 2,955 successful DMZ HTTP and 3,305 successful DMZ SSL observations; core/database provide contextual comparison | Firm-looking lower tails could reflect bounded sampling, but possible application/collection explanations limit this to a small contribution. |

## Realism Score by Category

- **Field format accuracy:** 9 — Native-looking fields, valid payload budgets, consistent DNS families, and compatible TLS/certificate identities; no demonstrated schema contradiction.
- **Temporal patterns:** 8 — Bursty hourly counts and service-specific lifetimes are credible; HTTP/TLS lower duration bounds remain a mild concern.
- **Cross-source correlation:** 9 — Protocol/connection joins, proxy leg distinctions, and DNS-before-connect examples agree without visible causal inversion.
- **Behavioral realism:** 8 — A plausible mixture of infrastructure, web access, failed attempts, negative DNS, resets, and long-lived SSH is present.
- **Environmental consistency:** 9 — Sensor-specific service distributions fit client/core, exposed DMZ/proxy, and database observation paths.

## Recommendations

- If this were synthetic, validate the successful HTTP/TLS duration tails against a comparable proxy and application capture. Preserve genuinely fast exchanges where the service and network permit them, and model server/client close policy explicitly rather than imposing a common service-level duration floor. This recommendation addresses the measured lower-tail pattern; it is not a request to add arbitrary noise.
