# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 72
**Synthetic-Confidence Score:** 24

## Executive Summary

Across the three Zeek vantage points, connection, DNS, HTTP, and TLS records show coherent protocol behavior and strong UID/tuple integrity. I found no demonstrated source-native contradiction or impossible visible ordering; the only notable irregularities are expected partial handshakes and incomplete observations. Network evidence therefore looks production-like, though it cannot establish provenance by itself.

## Evidence For Synthetic

- [weak_signal] The busiest sensors show a fairly concentrated recurring application mix: in `zeek-core`, 2,063 of 2,334 HTTP rows are proxy `CONNECT`, while `zeek-dmz` has 2,104 of 2,571. This is plausible for an explicit-proxy environment and is not independently evidence of fabrication; it is a collection/environment assumption worth corroborating with other source families.
- [weak_signal] In `zeek-core`, 571 DNS queries for `DC-01.meridianhcs.local` and 535 for `DC-02.meridianhcs.local` occur in the six-hour view. Repeated domain-controller resolution is plausible in a Windows domain and does not show an artificial interval pattern on its own.

## Evidence For Real

- All DNS, HTTP, and SSL rows in each sensor have a matching `conn.log` UID, and all matching source/destination address and port tuples agree. This holds for 3,053 DNS, 2,334 HTTP, and 333 SSL rows in `zeek-core`; 37, 23, and 13 in `zeek-db`; and 908, 2,571, and 2,711 in `zeek-dmz`.
- Connection state distributions contain both completed and incomplete traffic. `zeek-core` records 9,870 `SF` and 1,885 `S0` connections, plus reset, reject, and partial states; `zeek-dmz` records 6,408 `SF` and 2,606 `S0`, with similar smaller reset and reject tails. External probes to the DMZ include SYN-only `S0` examples such as `185.220.233.25:41399 -> 10.10.3.10:8080` at 2026-11-02 13:00:35 UTC.
- DNS includes varied A, AAAA, PTR, SRV, TXT, MX, SOA, and NS requests, with successful responses, 199 `NXDOMAIN`, 13 `SERVFAIL`, and 8 `REFUSED` in `zeek-core`. Recorded response times range from sub-millisecond local lookups to a 2.113-second response for `static.amplitude.org`, consistent with a mix of local and external resolution.
- HTTP includes successful, cached, redirected, denied, and failed requests rather than only uniform success. In `zeek-core`, statuses include 200, 403, 407, 304, 504, 503, 301, 502, 206, and 302. The proxy `CONNECT` example for `ctldl.windowsupdate.com` returns 200, while other proxy requests receive 403/407 and upstream 5xx responses.
- TLS includes TLS 1.2 and TLS 1.3 with plausible modern cipher suites, resumed sessions, SNI values, and varied certificate issuers. The DMZ has 1,720 TLS 1.3 and 988 TLS 1.2 SSL records; TLS 1.3 rows have no certificate-chain file references, as expected for passive observation of TLS 1.3's encrypted certificate messages. TLS 1.2 certificate references are present for observed handshakes.
- Partial TLS handshakes align with their connection records. For example, the inbound `ehr-portal.meridianhcs.com` rows at 2026-11-02 13:14:23 UTC, 14:41:04 UTC, and 18:21:31 UTC carry only a ClientHello (`ssl_history: C`), no negotiated version/cipher, and matching short `S1` connections with no server payload. These are coherent failed or abandoned handshakes, not missing fields on completed sessions.
- The sensor mix reflects distinct network roles: `zeek-db` sees 262 MySQL connections and just 402 connections total; `zeek-core` carries domain services and internal traffic; `zeek-dmz` carries 2,711 SSL records and inbound DMZ traffic. This is a plausible workload split for a six-hour view.

## Detailed Analysis

### Connection state and transport behavior

The visible connection window is 2026-11-02 13:00:12–18:59:44 UTC for `zeek-core`, 13:01:38–18:58:54 UTC for `zeek-db`, and 13:00:35–18:59:22 UTC for `zeek-dmz`. TCP, UDP, and ICMP are represented. `SF` dominates completed traffic, while the DMZ has a meaningful `S0` tail from incomplete external probes. Reset/reject cases occur around LDAP, Kerberos, MySQL, and other ordinary service paths; for example, `zeek-db` records an outbound database connection ending `RSTO` at 2026-11-02 13:09:42 UTC. These states are not implausibly uniform.

Long-lived connections are also present. `zeek-core` records SSH UID `CCkwaBuG9kRDp7utdI` from `10.10.3.10:46631` to `10.10.2.30:22`, duration 13,346.297 seconds, ending `SF`; `zeek-dmz` sees the same SSH session as `CBa79iAEjc1CRbJKHx` with a near-identical duration. A multi-hour SSH session is possible, and the different sensor UIDs are expected for separate Zeek instances. The DMZ has many `S0` probes to exposed ports, while successful HTTPS requests and established TLS are present as well.

### DNS behavior and ordering

`zeek-core` records 3,053 DNS events, `zeek-dmz` 908, and the DB sensor 37. Internal A/PTR/SRV traffic to the domain controllers coexists with public application and certificate-status lookups. In the DMZ, for example, `metrics.signalwire.com` resolves at 13:05:56 UTC and `sdk.medflow.com` at 13:06:00 UTC; both have answers and plausible TTLs. The 2.113-second `static.amplitude.org` response appears consistently at the two sensors that observe that resolver exchange, with matching transaction ID, requester, query, answer, and response time to within 0.0001 seconds. I did not find a DNS-to-connection UID or tuple contradiction.

### HTTP and proxy activity

The two sensors observing the proxy path contain thousands of HTTP records, mostly `CONNECT` requests to `10.10.3.20:8080`, along with direct-looking GET/POST activity. User agents include browsers across Windows, Linux, macOS, and mobile profiles, plus `curl`, `Wget`, `python-requests`, and `Microsoft-CryptoAPI`. The repeated browser families are expected in enterprise web traffic. HTTP rows retain ordinary status variation and body metadata; a denied `fonts.newrelic.com` request in `zeek-db` returns 403 with a 617-byte HTML response, while successful tunnels generally have zero-byte CONNECT response bodies.

### TLS, certificates, and protocol companions

The DMZ SSL mix is 1,720 TLS 1.3 and 988 TLS 1.2 records. TLS 1.3 ciphers are `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, and `TLS_CHACHA20_POLY1305_SHA256`; TLS 1.2 includes ECDHE RSA/ECDSA GCM and some CBC suites. SNI includes public services and `ehr-portal.meridianhcs.com`. TLS 1.2 server certificates link to `x509.json` and `files.json`, including plausible Amazon, DigiCert, Sectigo, Google, and internal enterprise chains. For example, the `ehr-portal.meridianhcs.com` chain is issued by Amazon RSA 2048 M01 and chains to Amazon Root CA 1. TLS 1.3 lacks certificate FUIDs, which is consistent with passive Zeek visibility rather than a defect.

The internal server certificate evidence also fits the observed services. `zeek-core` TLS sessions to `LOG-MON-01.meridianhcs.local` and `FILE-LNX-01.meridianhcs.local` link to local leaf certificates issued by the Meridianhcs Enterprise Issuing CA, with 2048-bit RSA keys and corresponding issuer certificates. `zeek-db` has only 13 TLS records, mainly to those internal endpoints, matching its database-centered flow volume.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Score impact |
|---|---|---|---|
| `weak_signal` | Zeek HTTP | Two proxy-observing sensors; CONNECT dominates | Low. Concentration is explainable by the apparent explicit-proxy path and has no associated protocol contradiction. |
| `weak_signal` | Zeek DNS | Core resolver view | Low. Repeated domain-controller lookups could reflect routine domain activity; no fixed cadence or malformed answer behavior was established. |

## Realism Score by Category

- **Field format accuracy:** 9 — Zeek JSON fields, states, TLS versions, cipher names, DNS response fields, and certificate records are coherent.
- **Temporal patterns:** 9 — The six-hour view contains ordinary timing variation, incomplete sessions, and long-lived connections without impossible visible ordering.
- **Cross-source correlation:** 10 — DNS, HTTP, and SSL UIDs match connection UIDs and tuples across all three sensors; certificate file references are coherent where observable.
- **Behavioral realism:** 8 — Proxy, domain, database, and DMZ patterns fit their respective traffic roles, with both successful and failed activity.
- **Environmental consistency:** 8 — Internal domain services, a proxy, a database segment, and an externally reachable portal have plausible network-level evidence.

## Recommendations

- If this were synthetic, retain the observed SSL partial-handshake shape: the three inbound portal ClientHello-only records align with short incomplete connection records and should remain represented as incomplete attempts.
- If this were synthetic, preserve the distinction between the proxy's HTTP `CONNECT` records and the separate tunneled TLS connections. The current records show separate UIDs and coherent SNI/host evidence, so no network-layer repair is indicated.
- No change is recommended from the network logs alone. The two weak signals above should be checked against collection intent before changing any traffic behavior.
