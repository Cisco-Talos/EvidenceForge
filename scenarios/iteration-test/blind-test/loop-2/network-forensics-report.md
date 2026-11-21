# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Real
**Verdict Confidence:** 62
**Synthetic-Confidence Score:** 29

## Executive Summary

The network evidence is mostly production-like: TCP states, protocol timing, proxy transport, certificate metadata, and firewall decisions remain mutually plausible under systematic checks. I lean toward real telemetry with modest confidence; the clearest concern is the late, broadly distributed onset of ordinary TXT queries across many client roles, rather than any demonstrated impossible connection or protocol field.

## Evidence For Synthetic

- [weak_signal] Ordinary TXT traffic has a conspicuous temporal boundary across otherwise different clients. Across `zeek-core/dns.json`, `zeek-dmz/dns.json`, and `zeek-db/dns.json`, all 43 TXT observations outside the `westbridge-services.cloud` namespace fall between 17:41:08.750279 and 18:45:16.181953 UTC on November 2, although connection and DNS collection begins around 13:00. These observations involve 19 client IPs, including workstations, the database host, monitoring host, and mail systems. Examples include `github.com` from `10.10.1.31` at 17:41:08.750279, `s1._domainkey.sendgrid.net` from `10.10.2.40` at 17:41:27.830759, and `okta.com` from `10.10.4.10` at 17:49:14.320921. This could reflect a scheduled DNS checking task or software rollout, so it is a limited distribution concern, not a contradiction. Counts are sensor observations and include repeated observation of some transactions.

## Evidence For Real

- TCP behavior is varied and internally consistent. Core observations include 9,885 `SF`, 1,650 `S0`, 163 `RSTO`, 101 `RSTR`, and 38 `REJ` records, alongside partial connections. Every TCP `SF` history examined includes FIN evidence in both directions; no `S0` record has responder packets. State counts also include UDP and ICMP where applicable, so they should not be read as a TCP-only failure rate.
- DNS has plausible infrastructure and failure texture. Core DNS includes 2,388 A, 283 AAAA, 177 PTR, 103 SRV, 296 TXT, 13 NS, five MX, and three SOA observations. There are 224 NXDOMAIN, 13 SERVFAIL, and one REFUSED response, with RTTs from 0.141 ms to 2.188489 seconds. For example, `printer01.meridianhcs.local` returns authoritative NXDOMAIN at `1793624457.123542`, and `isatap.meridianhcs.local` does so at `1793624599.896344`.
- All 13,466 DNS, HTTP, and SSL observations resolve to a same-sensor connection UID. Their transaction timestamps fit their connection intervals within the small tolerances described below. This is evidence of coherence, not evidence against authenticity through excessive completeness.
- TLS behavior follows the visibility differences between versions. DMZ SSL contains 2,068 TLS 1.3 and 1,041 TLS 1.2 records, plus four ClientHello-only failures without a version. TLS 1.3 histories are `Cs`, without fabricated plaintext certificate chains; TLS 1.2 includes full and resumed histories. Referenced leaf key types agree with RSA/ECDSA cipher authentication, and certificate validity intervals cover their observations.
- Firewall denial semantics agree with network observations. Of 440 parsed ASA TCP/UDP denial lines, 436 have matching sensor tuples within two seconds of the firewall timestamp; none of those matches is a successful `SF` connection or has responder payload. The four unmatched denials do not by themselves establish a collection defect.
- Activity is bursty rather than mechanically flat. In the 360 one-minute core bins, successful port-8080 traffic has a variance-to-mean ratio of 8.19, ranges from zero to 42 connections per minute, and leaves 27 empty minutes. The comparable DMZ port-443 ratio is 8.18, with zero to 47 successful connections per minute.

## Detailed Analysis

### Scope and method

I examined only the supplied data directory and the assigned instructions. I parsed all records in the three Zeek sensor directories, inspected proxy, ASA, and Snort examples, checked protocol and file relationships programmatically, and sampled endpoint FLOW records for observation context. I did not inspect repository, scenario, ground-truth, or other reviewer material.

The connection observations span approximately 2026-11-02 13:00–19:00 UTC. `zeek-core/conn.json` contains 12,307 records, `zeek-dmz/conn.json` 10,391, and `zeek-db/conn.json` 393: 23,091 observations, not necessarily unique connections because sensors overlap. All timestamps below are UTC or the raw numeric Zeek timestamps.

### Connections, packet accounting, and lifecycle

Core protocol counts are 6,922 TCP, 4,975 UDP, and 410 ICMP; DMZ counts are 8,861 TCP, 1,216 UDP, and 314 ICMP. The database segment is dominated by MySQL, with 240 explicitly identified MySQL connections among 393 observations. The DMZ combines proxy traffic, external TLS, incoming web traffic, and unsuccessful sensitive-port probes. Those differing distributions fit different observation paths.

I found no overlapping positive-duration TCP connections using the same directional five-tuple within one sensor. No established TLS record is attached to a `S0` or `REJ` transport. HTTP request/response bodies never individually exceed the corresponding TCP-direction byte totals, and HTTP file sizes do not exceed their corresponding flow direction totals.

A useful negative control is core UID `CKTSiRYBkGhKv7gsHs` at `1793624584.591890`: `10.10.3.20:43848` to `10.10.2.20:445` ends `RSTR`, with history `ShADadr`, 349 originator bytes and 6,288 responder bytes over 8.160092 seconds. This has actual bidirectional exchange before a responder reset; it is not merely a generic failed-connect template. The DMZ sees the same tuple with its own UID and slightly different timestamp.

Small apparent deficits obtained by subtracting logical TCP payload from observed IP bytes occur in records with `missed_bytes` and history gaps. Logical payload accounting can include sequence-space gaps, so I did not misclassify those as impossible header lengths.

### DNS semantics and timing

The DNS record mix includes directory-service lookups, internal names, reverse lookups, public services, suffix-search failures, and suspicious high-entropy query labels. Sanitized domains and real-world domain-to-address mappings were excluded from authenticity scoring.

For every DNS/HTTP/SSL record I compared its timestamp with the matching connection start and, where available, end. None preceded its connection by more than 10 ms or followed its end by more than 50 ms. That test concerns same-occurrence consistency; it does not assume that every later connection needs a newly visible DNS query, because caches, literal addresses, and collection boundaries can explain absent lookups.

The TXT boundary is the one notable residual distribution issue. Core has 296 TXT observations, 259 of which use the `westbridge-services.cloud` namespace. The remaining ordinary SPF/DKIM/DMARC/verification lookups and their observations on the other sensors start late across 19 IPs. The suspicious namespace's concentrated activity is not itself an authenticity defect. My limited concern is the simultaneous appearance of otherwise routine TXT behavior across unrelated roles, with no preceding ordinary TXT observations during roughly 4 hours 41 minutes of visible DNS collection. A coordinated task can explain this.

I reconstructed the multi-string DKIM answers by removing the source presentation prefixes and concatenating their strings. Nine distinct public-key values decoded to 294-byte RSA SubjectPublicKeyInfo structures with matching outer DER lengths, 2,048-bit moduli, and exponent 65,537; trial division found none of the small-prime defects that an arbitrary modulus string might introduce. This supports field care, although valid keys can also be generated synthetically.

### HTTP, proxying, and encryption

The high HTTP record count does not imply an implausibly cleartext modern network: 2,412 of 2,625 core HTTP observations and 2,453 of 2,890 DMZ HTTP observations are CONNECT requests to the explicit proxy. Most application payload beyond those requests travels in TLS.

The first proxy entry, at 13:00:50, records `10.10.1.22` using CONNECT to a CloudFront hostname, with control-message bytes separated from tunnel bytes and a 2,048-ms tunnel duration. Zeek observes the client-to-proxy control request and a separate proxy-originated TLS connection. I did not confuse a zero HTTP CONNECT response body with an empty encrypted tunnel.

Failure outcomes are credible: core HTTP includes 49 forbidden responses, 43 authentication challenges, and 502/503/504 failures. At `1793625610.331175`, core UID `Ci3O483QaxM7T08UJ0` records a 407 challenge with a 978-byte HTML response and a response file reference. The DMZ observes the same transaction with its own UID and FUID.

All referenced certificate-chain IDs resolve in the same sensor's X.509 records, and those X.509 IDs also resolve in its files records. Repeated certificate fingerprints have consistent subject, serial, validity, and key-length metadata. Every examined OCSP `thisUpdate`/`nextUpdate` interval covers its observed timestamp, and all OCSP IDs resolve to files records. These checks found no certificate or file-identity contradiction.

### Observation limits and alternative explanations

The window is only six daytime hours. It cannot establish overnight infrastructure behavior, weekend seasonality, or complete long-lived SSH/RDP closure. Missing pre-window initiators and post-window endings were not scored. Sparse sources or unobserved products were also not scored.

The repeated 0.1-second-scale differences between overlapping sensor observations are compatible with clock/collection differences. Separate UIDs between sensors are expected. Likewise, a proxy's outward socket can close after its client-facing socket; a modest difference alone is not impossible forwarding behavior.

Overall, the visible negative checks and protocol-specific details support the real-data hypothesis, while the ordinary TXT onset keeps confidence modest. A careful generator could produce this level of consistency, so the result is a lean, not a provenance determination.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `weak_signal` — late ordinary TXT onset across roles | Zeek DNS | 43 non-tunnel TXT sensor observations, 19 client IPs, all after 17:41:08 in a 13:00–19:00 window | Small upward adjustment for an abrupt source-family distribution change; coordinated checking or software deployment remains plausible. |
| No demonstrated high-impact contradiction | Zeek connection/protocol/file/TLS and matched ASA denials | Full programmatic checks described above | Keeps the score in the mostly realistic band; completeness itself was not penalized. |

## Realism Score by Category

- **Field format accuracy:** 9 — Protocol fields, certificate identities, file references, and HTTP byte relationships are consistent in the checks performed.
- **Temporal patterns:** 8 — Traffic is bursty and protocol timing fits flows; ordinary TXT lookups have a questionable shared late onset.
- **Cross-source correlation:** 9 — UID joins, proxy paths, certificate/file relationships, and matched denial outcomes are coherent.
- **Behavioral realism:** 8 — Service-dependent durations, DNS failures, resets, proxy challenges, and segmented traffic are plausible.
- **Environmental consistency:** 8 — Core, DMZ, and database traffic differ sensibly; broad ordinary TXT activity needs an operational explanation.

## Recommendations

- If this were synthetic, distribute ordinary TXT activity according to the responsible applications and client roles throughout their actual active periods, or provide a visible coordinated-task explanation for its late multi-host onset. Preserve the separately plausible burst of suspicious TXT traffic; its concentrated timing alone is not a defect.
- No additional changes are justified by the checks performed. In particular, do not add arbitrary missing sources, extra attack mistakes, or broken cross-source references merely to make the dataset seem less complete.
