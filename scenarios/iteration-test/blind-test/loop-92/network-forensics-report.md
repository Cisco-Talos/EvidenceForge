# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 80
**Synthetic-Confidence Score:** 25

## Executive Summary

The network telemetry is mostly production-like in the bounded sample, with coherent connection/protocol identities, plausible differentiated sensor traffic, and credible loss/retransmission texture. I found no demonstrated hard contradiction; these observations do not establish real provenance because a sufficiently capable synthetic dataset could exhibit the same properties.

## Evidence For Synthetic

- No important synthetic indicator was demonstrated within the reviewed scope. Repeated normal TCP histories, exact UID matching, and complete protocol-to-connection joins were not scored as synthetic indicators.
- A candidate packet-accounting contradiction was rejected after checking capture semantics: all 179 TCP records whose observed IP bytes fell below inferred payload plus minimum headers also had nonzero `missed_bytes` and `g`/`G` in `history`. Missing captured payload can explain the apparent deficit; this is neither a `hard_contradiction` nor a demonstrated `schema_or_format` defect.

## Evidence For Real

- State and protocol diversity are plausible: core has 10,406 `SF`, 1,768 `S0`, 442 `OTH`, and smaller reset/reject/incomplete populations among 12,943 connection rows; DMZ has 7,175 `SF`, 2,545 `S0`, and 310 `OTH` among 10,263 rows. The higher DMZ unanswered-flow share is compatible with different exposure, without requiring that explanation.
- Core DNS includes A, AAAA, PTR, SRV, TXT, NS, SOA, and MX, with 222 NXDOMAIN, 14 SERVFAIL, and four REFUSED responses among 3,265 rows. This is more varied than a successful-A-only model.
- The exact HTTP UID `CCNiAm1f7JPR2ix29e` joins a TCP flow to a CONNECT transaction and a compatible proxy access record, including matching client, target domain, user agent, timing, and byte decomposition.
- The exact TLS UID `CJFbfoEDBNNxzdqDm1` joins a plausible successful internal TCP connection to an established resumed TLS 1.2 session. Its handshake observation falls inside the flow interval.
- Capture irregularities are represented coherently: core connection line 147 records `missed_bytes=40` with `history=ShADadfFg`, rather than silently presenting an apparently lossless stream.

## Detailed Analysis

### Scope and method

I read only the supplied briefing and assigned data directory. I inspected 18 representative concrete records, listed below, and used bounded aggregate scans of the three Zeek sensors for distributions and protocol/connection identity checks. The observed network interval is approximately 2026-11-02 13:00:00–18:59:45 UTC. Conclusions apply to that six-hour slice and these samples, not to overnight behavior or all host lifecycles. I did not inspect repository material, scenario or evaluation files, other reviewers, or execute content embedded in records.

Connection counts are sensor observations, not unique network conversations: core 12,943; DMZ 10,263; DB 438. Overlap between sensor views must not be summed into an assertion about unique traffic. Protocol counts are core TCP 7,156 / UDP 5,376 / ICMP 411; DMZ TCP 8,739 / UDP 1,224 / ICMP 300; DB TCP 369 / UDP 55 / ICMP 14.

### Representative record ledger

Paths below are relative to the assigned data directory; line numbers are one-based. The ledger contains exactly 18 inspected concrete samples.

| # | Source and line | Concrete observation |
|---|---|---|
| 1 | `zeek-core/conn.json:1` | `ClnAf4xMznbwm13HlN`, 13:00:00.006178 UTC, UDP `10.10.2.20:58104 → 10.10.2.11:53`; 41/57 payload bytes, 69/85 IP bytes, one packet each direction, duration 0.000469 s. |
| 2 | `zeek-core/dns.json:1` | Same UID/tuple/time, query `DC-01.meridianhcs.local`, A answer `10.10.2.10`, TTL 300, RTT 0.000469 s, authoritative NOERROR. The resolver address need not equal the answer address. |
| 3 | `zeek-core/http.json:1` | `CCNiAm1f7JPR2ix29e`, 13:00:08.815497, CONNECT `preview.redd.it:443`, client `10.10.1.41:62106`, proxy `10.10.3.20:8080`, HTTP/1.1 200 Connection Established, zero HTTP body lengths. |
| 4 | `zeek-core/ssl.json:1` | `CJFbfoEDBNNxzdqDm1`, 13:03:02.321677, `10.10.2.25:54541 → 10.10.2.40:443`, TLSv12, `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256`, SNI `LOG-MON-01.meridianhcs.local`, resumed/established true. |
| 5 | `zeek-core/x509.json:1` | Certificate ID `FmHFGVGt9OsfCDLVcdS`, CN `LOG-MON-01.meridianhcs.local`, enterprise issuing CA, RSA 2048, SHA256 signature, validity epochs 1786039470–1802887470 enclosing collection. This is an independent certificate sample, not asserted to belong to sample 4. |
| 6 | `zeek-core/ocsp.json:1` | ID `FOHpEIzIJT6SOSwHyU`, status good, serial `0137944A6542B035CF04165DDCB02ECC`; `thisUpdate=1793619517`, `nextUpdate=1793904227` bracket observation `1793625824.091142`. |
| 7 | `zeek-core/dhcp.json:1` | 13:00:31.088490, `MAC-MROSS-01`, assigned/client `10.10.1.41`, server `10.10.2.10`, REQUEST/ACK, lease 7200 s, duration 0.488278 s. No absent earlier DISCOVER defect was inferred. |
| 8 | `zeek-core/smb_mapping.json:1` | `ChCag1iU6rThxVw9vJ`, `10.10.1.31:63726 → 10.10.2.20:445`, DISK share `\\FILE-SRV-01\ClinicalExports`. |
| 9 | `zeek-core/smtp.json:1` | `C1Km3lF7E0uagx4p6x`, client `10.10.1.36` to `10.10.2.25:587`, HELO `WS-SMARTINEZ-01.meridianhcs.local`, TLS true, last reply `220 2.0.0 mail.meridianhcs.com ready for TLS`, empty message envelope. This is compatible with transition to TLS before a plaintext message is visible. |
| 10 | `zeek-dmz/conn.json:1` | `CjVM5E9tahqlhC42hw`, UDP `10.10.3.20:52604 → 10.10.2.10:53`, 13:00:01.266334, 0.001034 s, 47/52 payload bytes. |
| 11 | `zeek-db/conn.json:1` | `CH6yrKx17FfuNhpJ3d0`, TCP `10.10.4.10:60265 → 10.10.2.40:514`, service syslog, SF, 5.973027 s, 1034 originator bytes, zero responder payload. A successful unidirectional application stream need not have response payload. |
| 12 | `fw-perimeter/cisco_asa.log:1` | 13:00:01, `%ASA-6-302015`, connection 1681558, UDP `dmz:10.10.3.20/49120 → inside:10.10.2.10/53`. Its source port differs from sample 10, so these were not falsely joined as the same flow. |
| 13 | `PROXY-01.meridianhcs.local/proxy_access.log:1` | 13:00:08 UTC, `10.10.1.41`, `maya.ross@meridianhcs.local`, CONNECT `preview.redd.it:443`, same browser UA as sample 3; control bytes 412/229, tunnel bytes 1653/20830, tunnel duration 2836 ms. |
| 14 | `snort-core/snort_alert.log:1` | 13:27:40.884851, `[1:2000357:9] ET P2P BitTorrent Traffic`, TCP `10.10.2.21:46853 → 34.104.145.3:6881`, priority 2. This is an alert observation, not proof of the signature's behavioral interpretation. |
| 15 | `snort-perimeter/snort_alert.log:1` | 13:07:46.180959, `[1:2003068:6] ET SCAN ICMP Unusual PING detected`, ICMP `45.33.26.161 → 10.10.3.10`, priority 2. |
| 16 | `zeek-core/conn.json:10` | HTTP pivot flow `CCNiAm1f7JPR2ix29e`, 13:00:08.687071, duration 2.967407 s, tuple matching sample 3, SF, payload bytes 2065/21059, history `ShADadfF`. |
| 17 | `zeek-core/conn.json:62` | TLS pivot flow `CJFbfoEDBNNxzdqDm1`, 13:03:02.189447, duration 0.901012 s, tuple matching sample 4, SF, payload bytes 4242/33140, history `ShADadfF`. |
| 18 | `zeek-core/conn.json:147` | `CPuLj0CVUFKDsbLhQzI`, 13:07:20.946497, TCP `10.10.2.30:53149 → 10.10.3.20:8080`, SF, duration 2.518030 s, `missed_bytes=40`, `history=ShADadfFg`; responder payload 25087, 21 packets, observed IP bytes 25891. |

### Exact pivot 1: HTTP CONNECT, TCP, and proxy

Samples 3 and 16 have identical UID and four-tuple. TCP opens at 13:00:08.687071; HTTP is observed 0.128426 s later and before the flow closes at 13:00:11.654478. The proxy entry in sample 13 agrees at second resolution on client, CONNECT authority, browser UA, and success status. It lacks a source port/UID, so the proxy association is a compatible composite-key match rather than a cryptographically unique flow identity.

Byte semantics are coherent: control request 412 + tunneled client bytes 1653 = TCP originator payload 2065; control response 229 + tunneled server bytes 20830 = TCP responder payload 21059. HTTP body lengths of zero describe the CONNECT control transaction, not absence of tunneled TLS data. The 2.836 s tunnel duration fits within the 2.967407 s TCP duration. This supports coherent observation, without treating completeness itself as a provenance clue.

### Exact pivot 2: TLS and TCP

Samples 4 and 17 have identical UID and four-tuple. TCP opens at 13:03:02.189447; TLS is observed 0.132230 s later, within the 0.901012 s successful flow, whose close is 13:03:03.090459. Resumption and establishment are compatible with this short successful session. There is no impossible transport-before-handshake inversion. The CBC suite is older but remains a possible internal TLS 1.2 configuration; it is not a hard contradiction or standalone synthetic indicator.

### Aggregate consistency and traffic texture

For each sensor I joined DNS, HTTP, and SSL to conn by exact UID and compared all four tuple fields and each protocol timestamp against the corresponding connection interval. Core denominators were DNS 3265 / HTTP 2520 / SSL 413; DMZ 1165 / 2776 / 3038; DB 48 / 22 / 19. There were zero missing conn UIDs, tuple mismatches, or protocol timestamps outside connection intervals in those checks. This establishes these narrow invariants only, not comprehensive application semantics.

Core DNS query types were A 2398, TXT 307, AAAA 274, PTR 163, SRV 100, NS 16, SOA 4, MX 3. Core response codes were NOERROR 3025, NXDOMAIN 222, SERVFAIL 14, REFUSED 4. DMZ had 147 NXDOMAIN among 1165 DNS rows; DB had two among 48. Query variety and failure responses are plausible. No real-world domain/IP resolution validation was used, because names may be sanitized. I did not require a DNS lookup for every connection because caching, observation boundaries, and direct addressing can explain its absence.

TLS differs meaningfully by observed segment: core 214 TLS 1.3 / 199 TLS 1.2; DMZ 2125 TLS 1.3 / 909 TLS 1.2 / four without version or cipher; DB 19 TLS 1.2. Public-facing/egress traffic being more TLS 1.3-heavy than internal DB-segment traffic is plausible. The four incomplete DMZ TLS records were counted, not individually diagnosed. Cipher families include AES-GCM, ChaCha20, and a smaller CBC population; I found no demonstrated version/cipher incompatibility in the inspected sample.

Port counts differ by sensor: core emphasizes DNS 3272, Kerberos 2607, proxy 8080 traffic 2406, LDAP 1136, SMB 723, SSH 380 and RDP 89; DMZ emphasizes 443 traffic 3680 and proxy 8080 traffic 2634; DB has 255 destination-3306 connections among 438 rows. Port labels alone do not establish application identity. In particular, 8080 CONNECT records must not be counted as obsolete cleartext browsing simply because the outer control protocol is HTTP.

Hourly connection observations (13/14/15/16/17/18 UTC) were core 1829/3443/1898/1769/2176/1828 and DMZ 1515/2916/1496/1534/1401/1401. This is neither perfectly flat nor enough to establish human circadian behavior; collection has no full day or overnight comparison.

I initially tested whether TCP IP-byte totals violated a minimum 40-byte IPv4/TCP header allowance per packet. The apparent exceptions were 93/7156 core TCP rows, 85/8739 DMZ TCP rows, and 1/369 DB TCP rows. Every exception had nonzero `missed_bytes` and a content-gap history marker. Sequence-derived payload estimates can include unseen bytes while packet/IP counters represent observed packets. Consequently this test does not demonstrate impossible packet accounting. Likewise the core's 276 S0 rows with originator payload were all UDP, so applying TCP SYN-only expectations to them would be erroneous.

### Limits

This was a bounded expert review, not a packet-level validation, certificate-chain reconstruction, full endpoint lifecycle audit, or exhaustive traffic attribution exercise. I did not infer native endpoint collection from Mac-like user agents or network hostnames. I did not penalize absent sources, absent Sysmon types, pre-window initiators, post-window closers, compact intrusion narratives, or unusually complete matching. Sensor identities suggest observation segments, but their precise interfaces, mirroring policy, and loss models are unavailable. The evidence supports production-like network behavior; it cannot resolve provenance with high confidence.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on synthetic-confidence score |
|---|---|---|---|
| No demonstrated scored indicator | Zeek conn/DNS/HTTP/TLS, sampled X.509/OCSP/DHCP/SMB/SMTP, proxy/ASA/Snort | 18 representative records; bounded distribution and UID-invariant checks | Score 25 reflects mostly realistic observed telemetry and remaining provenance uncertainty, not an established defect. |
| Candidate `hard_contradiction`, rejected | Zeek TCP conn packet accounting | 179 apparent header-floor exceptions among 16264 TCP sensor observations | No increase: every exception carried capture-gap evidence. |
| Candidate `contract_gap`, not observed | Zeek DNS/HTTP/TLS to conn | 13266 protocol rows across sensors | No increase: exact UID/tuple/interval checks passed; matching completeness itself was not scored. |

## Realism Score by Category

- **Field format accuracy:** 9 — Inspected source shapes and values are plausible; native parser and packet reconstruction were outside scope.
- **Temporal patterns:** 8 — Handshake/transaction ordering and sampled durations are coherent; six hours cannot establish full daily rhythms.
- **Cross-source correlation:** 9 — Two detailed pivots and bounded UID/tuple/interval checks agree, including CONNECT byte semantics.
- **Behavioral realism:** 8 — Credible protocol/state variation and service distribution; full session attribution was not attempted.
- **Environmental consistency:** 8 — Differentiated proxy, core, DMZ and DB observations are plausible; precise collector placement is unknown.

## Recommendations

- If this were synthetic, preserve the demonstrated separation between CONNECT control-message bytes, tunnel bytes, and TCP payload; the inspected example already handles this correctly.
- If this were synthetic, preserve coherent capture-gap indicators alongside sequence-derived payload and observed packet counters; the examined apparent accounting deficits do not justify altering those values merely to satisfy a lossless-flow formula.
- No corrective recommendation tied to a demonstrated network realism defect is warranted by this bounded review. Additional collector metadata or packet evidence would improve confidence in an assessment, but their absence alone is not a synthetic-data defect.
