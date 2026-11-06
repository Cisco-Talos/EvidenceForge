# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 72
**Synthetic-Confidence Score:** 23

## Executive Summary

The Zeek network records present a plausible six-hour enterprise traffic slice across core, database, and DMZ vantage points, with realistic connection outcomes, DNS responses, proxy activity, and TLS behavior. I found no concrete source-native contradiction or impossible visible ordering; the available network evidence looks production-like but cannot establish whether the source data is real or synthetic.

## Evidence For Synthetic

- No high-impact synthetic indicator was demonstrated from the network records. The concentration of proxy `CONNECT` requests and internal resolver lookups is explainable by the apparent network design and does not independently support a synthetic verdict.

## Evidence For Real

- `zeek-core`, `zeek-db`, and `zeek-dmz` each have matching `conn.log` UIDs and endpoint tuples for every DNS, HTTP, and SSL row reviewed. That covers 3,158 DNS, 2,400 HTTP, and 353 SSL records in core; 47, 21, and 9 in the database sensor; and 984, 2,610, and 2,921 in the DMZ sensor.
- The connection state mix includes ordinary successes and failures. Core has 10,294 `SF` and 1,869 `S0` records, plus `RSTO`, `RSTR`, `REJ`, `OTH`, `S1`, `S2`, and `S3`; DMZ has 6,816 `SF` and 2,805 `S0`, consistent with established service traffic mixed with external probes.
- DNS contains a broad request mix and normal resolver outcomes: core includes A, AAAA, PTR, SRV, TXT, NS, SOA, and MX requests, with 234 `NXDOMAIN`, 16 `SERVFAIL`, and 5 `REFUSED` responses. Observed RTTs range from 0.000011 seconds to 2.117442 seconds in core and include slower external resolution.
- HTTP status codes include success, denial, caching, redirection, partial content, and upstream failures. The core proxy records 2,197 `CONNECT`, 190 `GET`, and 13 `POST` rows; responses include 200, 403, 407, 304, 301, 502, 503, and 504.
- TLS has a plausible mix of TLS 1.2 and TLS 1.3 with ECDHE and modern TLS 1.3 ciphers. The DMZ records 1,953 TLS 1.3 and 966 TLS 1.2 SSL events, while the lower-volume DB sensor records nine TLS 1.2 events. TLS 1.3 records have no certificate FUIDs, consistent with passive visibility into TLS 1.3's encrypted certificate messages.
- Certificate references align with their SSL records. Every observed certificate FUID resolves to an `x509.json` record, and in all three sensors the leaf certificate subject matches the TLS SNI when both are present; each checked leaf certificate is valid at the handshake timestamp. The inbound `ehr-portal.meridianhcs.com` TLS 1.2 example at 2026-11-02 13:03:41 UTC links to an Amazon RSA 2048 M01 leaf and Amazon Root CA 1 issuer.
- Partial TLS handshakes have matching incomplete connection records. For example, the core connection at 2026-11-02 16:51:39 UTC from `10.10.2.30:55919` to `10.10.2.21:443` has only a ClientHello (`ssl_history: C`), no negotiated version or cipher, and a short `S1` connection with no responder payload. DMZ has similar inbound and outbound ClientHello-only attempts.
- Network volume tracks the apparent sensor roles: `zeek-db` records 296 MySQL service connections among 449 total connections; core carries domain and internal service traffic; and DMZ carries high-volume web/TLS and inbound portal traffic. This is a plausible distribution for the visible window.

## Detailed Analysis

### Connection patterns and collection window

The visible connection windows are 2026-11-02 13:00:12–18:59:31 UTC in `zeek-core`, 13:01:38–18:59:52 UTC in `zeek-db`, and 13:00:35–18:59:52 UTC in `zeek-dmz`. TCP, UDP, and ICMP are present. Core has 6,880 TCP, 5,240 UDP, and 412 ICMP connections; the database sensor has 385 TCP, 52 UDP, and 12 ICMP; DMZ has 8,475 TCP, 1,049 UDP, and 306 ICMP.

Incomplete TCP observations are internally consistent. DMZ UID `CleE3WjZqUbcc4i1GS` is a single inbound SYN from `185.220.233.25:41399` to `10.10.3.10:8080`, state `S0`, history `S`, with no reply. Established sessions include long-running SSH: core UID `CjiPmuaAp9ouIfKvVI` starts at 2026-11-02 15:15:10 UTC from `10.10.3.10:59707` to `10.10.2.30:22`, lasts 13,308 seconds, and ends `SF`; DMZ observes the same tuple and duration with its independent UID `CVpcCzUUX9xMSCDKo8`. A second core SSH session from `10.10.1.32` to `10.10.2.40:22` lasts about one hour and ends `SF`. These durations fit persistent administration sessions and are contained within the view.

### DNS and application-layer ordering

The three DNS sensors contain 3,158, 47, and 984 rows respectively. Internal A/PTR/SRV lookups for domain controllers coexist with public application, certificate-status, and web-service names. A DMZ resolver exchange for `metrics.signalwire.com` at 2026-11-02 13:05:56 UTC returns an A answer with a 30-second TTL; `sdk.medflow.com` follows at 13:06:00 UTC with an answer and 99-second TTL. The maximum observed RTT is approximately 2.117 seconds for an external lookup. DNS, HTTP, and SSL UIDs map to connection rows with matching endpoint tuples; I found no visible ordering contradiction.

### HTTP and proxy traffic

Core and DMZ both observe thousands of HTTP records, predominantly explicit-proxy `CONNECT` requests to `10.10.3.20:8080`. The core examples include `downloads.cloud.com` and `ctldl.windowsupdate.com`, both accepted with `200 Connection Established`. Denied requests appear as 403/407, and 502/503/504 responses provide an upstream-failure tail. Browser and client families include Windows/Linux/macOS/mobile browsers and command-line or library clients such as `curl`, `Wget`, and `python-requests`; the distinct user-agent families are compatible with a mixed enterprise fleet.

### TLS and certificate evidence

DMZ SSL records include 1,953 TLS 1.3 and 966 TLS 1.2 sessions. TLS 1.3 uses AES-GCM and ChaCha20-Poly1305 suites; TLS 1.2 includes ECDHE RSA/ECDSA GCM and some CBC suites. There are 2,917 established TLS records and four incomplete ones in DMZ. The incomplete portal handshake at 13:14:23 UTC from `50.192.228.8` has SNI `ehr-portal.meridianhcs.com`, no server payload, and a matching short `S1` connection. This is coherent with a client that disconnected after sending ClientHello.

For all SSL rows with certificate references, the referenced certificate records exist, their leaf subjects match SNI, and their validity intervals contain the handshake timestamp. Internal certificate chains use the Meridianhcs enterprise issuing CA; public chains include Amazon, DigiCert, Sectigo, and Google issuers. No malformed TLS or certificate relationship stood out.

## Synthetic Indicator Summary

No concrete synthetic indicators were supported by the inspected network records. Proxy concentration and repeated domain-controller resolution are plausible environmental characteristics and were not scored as synthetic evidence.

## Realism Score by Category

- **Field format accuracy:** 9 — Zeek connection, DNS, HTTP, SSL, and X.509 fields are coherent and source-native in shape.
- **Temporal patterns:** 9 — Incomplete attempts, multi-hour sessions, DNS response-time variation, and the bounded window are plausible.
- **Cross-source correlation:** 10 — DNS/HTTP/SSL UIDs and tuples match `conn.log`, and referenced certificates reconcile with SNI and validity.
- **Behavioral realism:** 8 — The traffic mix includes domain services, proxy traffic, database sessions, probes, failures, and ordinary TLS use.
- **Environmental consistency:** 8 — Core, DMZ, resolver, proxy, and database traffic volumes fit the apparent network roles.

## Recommendations

- No network-layer changes are indicated by this review. If this were synthetic, preserve the observed relationship between partial ClientHello-only SSL records and their short incomplete connection records, as well as the separation between proxy CONNECT traffic and the tunneled TLS flow.
