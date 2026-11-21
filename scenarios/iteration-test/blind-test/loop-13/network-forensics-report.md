# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 82
**Synthetic-Confidence Score:** 68

## Executive Summary

The network telemetry is substantially production-like: TCP state diversity, DNS behavior, proxy tunneling, certificate metadata, and byte accounting hold up well to quantitative checks. The principal synthetic indicator is a repeated timing inconsistency between overlapping Zeek sensors: their connection timestamps establish a stable clock offset, but TLS timestamps for the same observed handshakes wander by hundreds of milliseconds independently of that offset. This supports a synthetic verdict, with uncertainty retained because an undocumented transformation of protocol timestamps could produce a similar artifact.

## Evidence For Synthetic

- [contract_gap] **The same TLS handshake has materially different placement within its connection at two sensors.** In `zeek-core/ssl.json`, UID `CsRRccCxXfTo8DezUC` for `10.10.1.36:62266 → 10.10.3.10:443` has `ts=1793643383.841366`; its `conn.json` starts at `1793643383.783014`, a 58.352 ms interval. The corresponding `zeek-dmz` records, UID `CJc4hFg29sHnWGCKLU`, place SSL at `1793643384.316977` and connection start at `1793643383.670110`, a 646.867 ms interval. The difference between these within-sensor intervals is 588.515 ms, despite identical packet/byte totals, zero missed bytes, and matching TLS version, cipher, server name, and handshake history.
- [contract_gap] **The discrepancy reverses direction on another matching TLS flow.** For `10.10.1.41:50836 → 10.10.3.10:443`, core UID `CMzBmWDFWZy1dMvx6Y` places SSL 606.129 ms after connection start, while DMZ UID `CsP39YgVfG1dRtOvUB` places it 119.522 ms afterward. The difference is 486.607 ms in the opposite direction from the preceding example. Both sensors report the same 3,481/4,292 directional payload bytes, seven packets per direction, zero missed bytes, and `ShADadR` connection history. A fixed sensor clock offset cannot explain this.
- [contract_gap] **This is a repeated protocol-timing pattern rather than an isolated timestamp outlier.** Among 40 matching core/DMZ SSL observations identified by endpoint tuple and nearby time, 25 differ by more than 50 ms in `ssl.ts − conn.ts`, and 21 differ by more than 100 ms. By comparison, 5,055 matching connection observations have a median DMZ-minus-core start offset of −114.171 ms; all but one have the same sign, and the negative offsets span approximately −118.113 to −110.167 ms. Matching DNS and HTTP observations retain this narrow offset range. The finding concerns the inconsistency of TLS timing with the connection observations, not the completeness of source matching.

## Evidence For Real

- All 5,180 HTTP, 3,433 SSL, and 4,237 DNS records reference a connection UID present at their own sensor. None of these protocol timestamps precedes its connection start by more than 1 ms or falls more than 50 ms beyond its recorded connection end. This is positive coherence evidence, not a synthetic indicator.
- TCP state and history diversity are credible. Core includes 9,654 `SF`, 1,631 `S0`, 454 `OTH`, 151 `RSTO`, 102 `RSTR`, and 41 `REJ` connections, with additional `S1`/`S2`/`S3` states. One-way UDP traffic uses `D`, bidirectional UDP uses `Dd`, TCP probes use `S`, and rejected TCP commonly uses `Sr`.
- DNS has useful production texture. Core has A, AAAA, PTR, SRV, TXT, NS, MX, and SOA queries, including 207 NXDOMAINs and nine SERVFAILs. `oldserver.meridianhcs.local` receives an authoritative NXDOMAIN at `1793624694.347953`; reverse lookups and WPAD failures also occur. External answer TTLs include non-round remaining-lifetime values rather than only a fixed TTL pool.
- Proxy traffic explains the high apparent HTTP volume. Most HTTP rows are explicit-proxy CONNECT requests, rather than evidence of an implausibly cleartext enterprise: core has 2,202 CONNECT records out of 2,444 HTTP rows; DMZ has 2,243 out of 2,712. Successful CONNECT responses have zero response body length, while denials/errors have small HTML bodies.
- Payload and lifecycle checks found no TCP tuple overlap, HTTP body totals exceeding corresponding directional connection payload, or certificate-file totals exceeding corresponding response payload. Apparent IP-header accounting deficits were all explainable by recorded missed bytes; I did not count them as defects.
- TLS versions and ciphers are credible for a mixed environment, including TLS 1.3 AES-GCM/ChaCha20 and TLS 1.2 ECDHE suites. Examined leaf-certificate key algorithms were compatible with their negotiated authentication suites; repeated certificate fingerprints and serials did not acquire contradictory metadata, and observed certificate validity windows covered their timestamps.

## Detailed Analysis

### Scope and method

I examined only the supplied data directory. The principal sources were every JSON record under `zeek-core`, `zeek-dmz`, and `zeek-db`, with sample checks of perimeter ASA, Snort, and proxy access logs. The three sensors contain 22,408 connection rows: 12,080 core, 9,839 DMZ, and 489 database observations. These are observations, not a count of unique network connections, because sensor visibility overlaps.

The network window is approximately 2026-11-02 13:00–19:00 UTC. This is a six-hour slice; it cannot establish daily business-hour behavior, weekend behavior, or the absence of pre-window session beginnings. I did not penalize missing source families, absent Sysmon event types, sanitized names, or complete cross-source linkage.

### TCP state, tuple ownership, and payload accounting

I grouped connections by source IP/port, destination IP/port, and protocol within each sensor. No consecutive TCP observations of the same directional tuple had overlapping recorded lifetimes exceeding a 10 ms tolerance. Zero-packet directions did not contain positive payload byte counts, and IP-byte counters were never smaller than their payload counters.

Some IP-byte-minus-payload values were less than 40 bytes per observed TCP packet. This is not independently contradictory: Zeek payload sequence accounting can include unobserved bytes, and every such deficit was covered by the row's `missed_bytes`. For example, core UID `CRU4kpUSxtqCSeNgPv` reports a large SMB transfer with 32,768 missed bytes and an uppercase gap marker in `ShADadfFG`. I excluded these cases from the synthetic score.

Service durations are varied and generally credible. Core SSH has a median duration around 2,136 seconds and a maximum around 13,322 seconds; core RDP has a median around 951 seconds. Database MySQL observations have a median around 2.624 seconds and a maximum around 29.447 seconds. HTTP and SSL flows include short exchanges and longer tails approaching several minutes. Nothing in these durations alone establishes an authenticity defect.

### DNS and infrastructure behavior

Core's 3,147 DNS rows include 2,392 A, 284 AAAA, 216 TXT, 139 PTR, and 95 SRV queries, plus smaller NS/MX/SOA counts. DMZ has 1,051 DNS rows, including 128 NXDOMAINs and two SERVFAILs. The database sensor has only 39 DNS records, which is compatible with its narrower observed scope and is not an independent coverage concern.

The records show both authoritative internal answers and recursive external answers, with fast internal RTTs and a wider external range. For example, core UID `Cz3NMJPqehAd3ATCiW2` has a 9.835 ms A lookup for `DC-02.meridianhcs.local`, an authoritative `10.10.2.11` answer, and matching connection duration. DHCP records include REQUEST/ACK renewal pairs with explicit leases and host identities. The absence of other infrastructure protocols in a particular slice is not evidence against authenticity.

### HTTP, proxy, and TLS semantics

Explicit-proxy behavior is apparent in both Zeek HTTP records and `PROXY-01.meridianhcs.local/proxy_access.log`. The proxy log distinguishes CONNECT control-message byte scope from tunnel byte totals. A 13:01:41 UTC request for `pypi.org:443`, for example, records control-message bytes separately from `tunnel_cs_bytes=4704`, `tunnel_sc_bytes=33664`, and `tunnel_duration_ms=3103`.

HTTP error and cache behavior is present, including 301/302 redirects, 304 responses, 403/407 proxy refusals, and 502/503/504 errors. No examined 304 response carried a positive response body. Summed per-UID HTTP request and response bodies stayed within the corresponding connection payload counters.

TLS 1.3 forms the majority of DMZ SSL observations: 2,107 of 2,998 rows. TLS 1.2 remains visible, including internal services and mail-related sessions. Resumption appears in 1,068 DMZ SSL rows and 149 core SSL rows. Certificate identity and byte accounting checks did not expose contradictions. I did not require readable certificate chains from TLS 1.3 or interpret their absence as missing evidence.

### Repeated cross-sensor TLS timestamp discrepancy

The important timing test subtracts each sensor's own connection start from its own SSL timestamp. This removes any fixed clock offset between sensors. Matching was based on the same endpoint tuple, nearby timestamps, and corroborating protocol/counter fields; sensor-local UIDs are correctly allowed to differ.

For the 18:16 UTC example, both sensors report an SF flow with 3,344 originator bytes, 22,668 responder bytes, 11 originator packets, 20 responder packets, no missed bytes, and TLS 1.2 `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256`. Their connection starts differ by the usual approximately 113 ms. Their SSL timestamps instead differ in the other direction by approximately 476 ms, producing the 589 ms relative-timing discrepancy described above.

The 18:22 UTC example reverses the discrepancy. A third example at approximately 13:04:27 UTC, `10.10.1.32:56526 → 10.10.3.10:443`, places SSL 467.341 ms after connection start at core but 48.285 ms afterward at DMZ, despite identical packet and byte counts and zero loss. The effect occurs across TLS versions and multiple clients.

An isolated retransmission, partial capture, or fixed clock offset would be a possible explanation for one mismatch. The repeated independent movement of TLS-relative timestamps, alongside stable connection/DNS/HTTP sensor offsets and identical complete packet counts in the cited examples, makes that explanation substantially weaker. I interpret this as a protocol timestamp construction or transformation defect. Without packet capture or collection configuration, I stop short of calling it an absolutely proven physical impossibility.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on synthetic-confidence score |
|---|---|---|---|
| `contract_gap` | Zeek SSL versus conn, core/DMZ | 25/40 matching TLS observations exceed 50 ms relative-timing disagreement; 21 exceed 100 ms | Principal upward driver: one repeated source-native timing inconsistency, supported by matching packet/byte counts and stable timing in other protocol families. |
| `contract_gap` | Zeek SSL versus conn, core/DMZ | Opposite-direction discrepancies of 588.515 ms and 486.607 ms on two cited flows | Rules out a single fixed inter-sensor clock offset as the explanation; these are examples of the same underlying issue, not separately accumulated defects. |

## Realism Score by Category

- **Field format accuracy:** 9 — Zeek field shapes, state/history vocabulary, proxy controls, and certificate metadata are convincing in the checks performed.
- **Temporal patterns:** 7 — Service durations and traffic variation are plausible, but TLS-relative sensor timing has a repeated inconsistency.
- **Cross-source correlation:** 6 — UID integrity and payload accounting are strong; overlapping sensors disagree materially on TLS handshake placement.
- **Behavioral realism:** 8 — DNS failures, probe states, proxy errors, renewals, and long administrative sessions provide credible operational variation.
- **Environmental consistency:** 9 — The observed core/DMZ/database split and proxy-mediated external access form a coherent network collection view.

## Recommendations

- If this were synthetic, derive each observed TLS handshake timestamp from one underlying packet/event time and apply the sensor's clock/observation transformation coherently to connection and protocol observations. Preserve legitimate sensor differences without independently moving the same handshake by hundreds of milliseconds.
- If this were synthetic, use matching-flow checks of `(ssl.ts − conn.ts)` across sensors as a regression condition, including TLS 1.2 and TLS 1.3, reset flows, and zero-loss examples. Treat the cited 18:16 and 18:22 UTC tuples as concrete reproductions.
- If the supplied records were deliberately transformed during collection or normalization, document whether `ssl.ts` has a different meaning from native observed handshake time. That information would directly affect the weight of the one principal finding; adding unrelated log sources would not resolve it.
