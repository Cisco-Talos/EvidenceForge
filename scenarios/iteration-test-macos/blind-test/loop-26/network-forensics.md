# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 78
**Synthetic-Confidence Score:** 24

## Executive Summary

The network records are mostly production-like: TCP states, DNS shapes, proxy paths, TLS visibility, certificate identity, and protocol-to-flow relationships withstand representative checks. I found two limited accounting/distribution questions, but neither establishes synthetic origin without packet/header context; the supplied records do not support a high synthetic-confidence score.

## Evidence For Synthetic

- [weak_signal] Two HTTP connections have extracted file `seen_bytes` totals slightly above responder TCP payload: `zeek-core/conn.json:1996`, UID `CCHPoVRDFXWJq5Nhs`, has `resp_bytes=251826`, while `files.json:117-119` sum to 252730 observed file bytes; `zeek-dmz/conn.json:323`, UID `CSVPlnh3IfngZiKjoM`, has `resp_bytes=161870`, while `files.json:84-85` sum to 162795. These merit reconciliation but are **not demonstrated contradictions**: HTTP content decoding can change the relationship between extracted content and transport bytes, and response encoding headers are absent from these exports. Both flows also have visible capture-gap fields.
- [weak_signal] External successful DNS answers show a noticeable concentration at TTL 30: 194 of 708 answer-bearing, non-authoritative NOERROR records in `zeek-dmz/dns.json`, and 192 of 964 in `zeek-core/dns.json`, have all answer TTLs exactly 30. For example, DMZ lines 38 and 39 repeat `api.snapcraft.io` answers at timestamps `1793625819.528437` and `1793625824.363524`, both TTL 30. Common low-TTL services, resolver minimum-TTL behavior, and sanitization can explain this; it has little independent evidentiary weight.

## Evidence For Real

- Protocol records agree with their same-sensor flow tuples and timing. Across the three sensors, all 3986 DNS, 4431 HTTP, and 2937 SSL rows find their UID in that sensor's `conn.json`, with matching four-tuples. None falls more than 10 ms before the connection start or more than 100 ms after its recorded end. Completeness itself is neutral; the useful finding is absence of an actual ordering or tuple defect in these checks.
- DNS is not a uniform A-query stream. Core records contain 2222 A, 260 AAAA, 248 TXT, 163 PTR, 102 SRV, and smaller NS/SOA/MX populations, with NOERROR, NXDOMAIN, SERVFAIL, and REFUSED responses. Core DNS lines 2-4 distinguish LDAP SRV answers, an A answer, and a successful AAAA response without an IPv6 answer.
- Proxy relationships are credible. `zeek-dmz/http.json:1` records client `10.10.1.42:62846` requesting CONNECT through `10.10.3.20:8080`; `dns.json:1` records the proxy's corresponding destination lookup; `ssl.json:1` records proxy-originated TLS from `10.10.3.20:55786` to the returned `23.72.51.162:443`, retaining the hostname as SNI.
- TLS 1.3 observations correctly do not pretend that a passive observer can parse ordinary encrypted certificate exchanges: all 1924 TLS 1.3 rows across core and DMZ have no `cert_chain_fuids`, while TLS 1.2 full handshakes can have linked certificate files. Resumed TLS 1.2 and full handshakes have differentiated histories.
- Certificate identities remain stable across sensors and repeated observations. For example, `zeek-core/x509.json:1` and `zeek-db/x509.json:1` share FILE-LNX-01's fingerprint `8087310b139f1969a3ab19f455cd6df5886e6c07`, certificate attributes, and linked file hashes/lengths, despite sensor-local file IDs.
- Successful remote administration flows have substantial lifetimes rather than universally tiny placeholders: core successful SSH median duration is approximately 2008 seconds, and successful RDP median is approximately 1218 seconds.

## Detailed Analysis

### Scope and method

I restricted inspection to the supplied data directory. This review emphasizes its three Zeek sensors and uses source line numbers counted from one, excluding no JSON records. I inspected representative raw records and performed bounded in-memory consistency checks over the approximately six-hour network window, 2026-11-02 13:00:06.590170–18:59:27.999056 UTC. I did not inspect project information, scenario material, or other reviewers' reports.

There are 11853 core, 452 database, and 9158 DMZ connection rows. These are sensor observations, not necessarily distinct connections: matching four-tuples/start times occur across observation points. I did not add overlapping sensor counts to infer organizational traffic volume. A six-hour slice cannot establish overnight coverage or a full weekly business cycle.

### Transport and protocol behavior

Core connection states include 9678 SF, 1867 S0, 134 RSTO, 86 RSTR, and smaller REJ/OTH/S1/S2/S3 populations. DMZ has more unanswered attempts: 6158 SF and 2770 S0 among its 9158 rows. Database coverage is dominated by port 3306, with 289 observations, which fits the visible server address `10.10.4.10` rather than forcing workstation expectations onto it.

No S0 row has responder packets. No successful TCP row has fewer than two packets in either direction. IP byte totals satisfy the basic payload-plus-minimum-header lower bound. Histories carrying content-gap markers have nonzero `missed_bytes`; all individual HTTP request/response body lengths fit their corresponding directional connection byte totals. These are sanity checks, not packet-level proof that every TCP exchange is genuine.

Core and DMZ share 4606 four-tuple observations within one second of their start timestamps. All matched connection states agree, while some histories, packet counters, and byte counters differ. That is compatible with separate observation paths and limited packet loss. The approximately 89–140 ms timestamp offset is insufficient by itself to allege impossible inter-sensor ordering; uncalibrated sensor clocks are a material limitation.

### DNS and TLS

Authoritative internal answers retain stable TTLs for the same name/type/server/answer combination. For example, all 322 core responses from `10.10.2.10` for `DC-01.meridianhcs.local` A=`10.10.2.10` use TTL 300. Non-authoritative answers can show plausible cache aging: DMZ DNS lines 550 and 565 return the same `api.snapcraft.io` addresses with TTLs 790 and 686, approximately 104 seconds apart. This counterevidence limits the significance of the TTL-30 concentration.

Across linked TLS 1.2 chains, leaf key types agree with ECDHE_RSA versus ECDHE_ECDSA authentication, and each recorded child's issuer matches the next certificate's subject. Repeated certificate fingerprints have consistent serials, subjects, issuers, validity intervals, key types, file lengths, and hashes. Certificate records inspected are valid at their observation timestamps. Public CA names and domains were not verified against the outside world, and sanitized names were not used as authenticity indicators.

### HTTP and file accounting uncertainty

The extracted-content accounting candidates listed above are small excesses, not individually oversized files. For core UID `CCHPoVRDFXWJq5Nhs`, HTTP lines 258-260 show three GET transactions with body lengths 72557, 81188, and 99808. The linked file records include content gaps and slightly differing `seen_bytes`/`total_bytes`. Without original response encoding and packet data, I cannot safely collapse HTTP body size, extracted file size, and TCP byte size into a single invariant. I therefore retained the issue as a low-weight review question rather than assigning a hard-contradiction label.

### What this does not establish

The checks do not prove production provenance. A careful synthetic dataset can preserve these relationships. Conversely, unusual destinations, compact suspicious activity, selected source coverage, or fully matched UIDs are not evidence of fabrication. No confirmed impossible same-identity ordering or source-native value was demonstrated by this network review.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| weak_signal | Zeek HTTP/files/conn | Two identified connections across core and DMZ | Small unresolved content/transport accounting differences; possible decoding explanation prevents a contradiction finding. |
| weak_signal | Zeek DNS | TTL 30 in 194/708 DMZ and 192/964 core external successful answer-bearing observations | Limited texture concern; common service TTLs, resolver policy, and visible cache aging offer plausible explanations. |

## Realism Score by Category

- **Field format accuracy:** 9 — Types, hash lengths, protocol shapes, and certificate links withstand checks; raw packet/header context is unavailable.
- **Temporal patterns:** 9 — Same-sensor protocol events stay inside their flow lifetimes, and remote sessions have credible durations.
- **Cross-source correlation:** 9 — Matching tuples and stable certificate identities are coherent; the two HTTP accounting candidates remain unresolved.
- **Behavioral realism:** 9 — Proxy-mediated browsing, failed attempts, DNS errors, infrastructure traffic, and extended administration flows are plausible.
- **Environmental consistency:** 9 — Sensor-specific volumes and port profiles fit differing network observation points; the limited collection window constrains broader conclusions.

## Recommendations

- If this were synthetic, retain enough HTTP encoding/transfer metadata to make file-content versus TCP-byte accounting auditable for the two cited connections; preserve legitimate compression behavior rather than enforcing equality blindly.
- If this were synthetic, verify that repeated external DNS TTLs arise from a consistent resolver cache/minimum-TTL policy. Preserve the demonstrated aging behavior rather than independently choosing every answer TTL.
