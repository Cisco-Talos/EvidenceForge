# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Real
**Verdict Confidence:** 64
**Synthetic-Confidence Score:** 24

## Executive Summary

The sampled network telemetry is mostly production-like: protocol records agree with their exact connection identities, failed TCP attempts retain appropriately sparse evidence, and the DNS and TLS populations contain credible variation. I found no demonstrated impossible ordering, impossible packet accounting, or required missing companion in this bounded review; the real verdict is tentative because a well-modeled synthetic collection could reproduce these properties.

## Evidence For Synthetic

- [weak_signal] Successful TCP history texture is similar across sensors: `ShADadfF` appears in 3,492/5,306 core TCP `SF` connections (65.8%), 4,028/6,002 DMZ TCP `SF` connections (67.1%), and 163/274 database TCP `SF` connections (59.5%). This repeated dominant shape could reflect shared modeling, but the remaining histories vary and common operating-system TCP behavior plus overlapping collection can explain it. It receives only slight weight, not treatment as a demonstrated defect.
- No strong synthetic indicator was established. High reference integrity and complete-looking joins were not counted as synthetic evidence. Neither sanitized names nor the visible activity's narrative shape contributed to the score.

## Evidence For Real

- Exact UID `CCNiAm1f7JPR2ix29e` joins `zeek-core/conn.json:10` to `zeek-core/http.json:1`: the same `10.10.1.41:62106 → 10.10.3.20:8080` tuple carries a successful CONNECT for `preview.redd.it:443`; its HTTP timestamp falls inside the transport interval.
- Exact UID `CJFbfoEDBNNxzdqDm1` joins `zeek-core/conn.json:62` to `zeek-core/ssl.json:1`: `10.10.2.25:54541 → 10.10.2.40:443` has an established resumed TLS 1.2 session inside the matching TCP lifetime. Certificate references are not required merely because this resumed record has none.
- DNS has credible outcome and query diversity. Of 3,265 core DNS rows, 2,398 are A, 274 AAAA, 163 PTR, 100 SRV, 307 TXT, 16 NS, four SOA, and three MX. Outcomes include 222 NXDOMAIN, 14 SERVFAIL and four REFUSED, alongside 3,025 NOERROR rows.
- `zeek-dmz/conn.json`, UID `CMqVDGDEGOP76UgYg`, shows a single SYN with `S0`, `history="S"`, zero payload and no response packets; it does not invent an application service for an unanswered attempt.
- The database sensor's first connection, UID `CH6yrKx17FfuNhpJ3d0`, is one-way application payload over a successfully closed TCP syslog connection: `orig_bytes=1034`, `resp_bytes=0`, but three response-side packets and 164 response IP bytes. Payload absence is properly distinguished from transport response absence.
- TLS populations differ by observation location: DMZ has 2,125 TLS 1.3 and 909 TLS 1.2 rows plus four rows without a negotiated version; the database sensor's 19 TLS records are all TLS 1.2. This is compatible with differing external and infrastructure software populations.

## Detailed Analysis

### Scope, sampling, and visible window

I examined only the assigned data directory and this briefing. I read 16 unique representative records in detail: two core connections, two core DNS rows, two core HTTP rows, two core TLS rows, two core X.509 rows, the two additional core connection records supporting the exact UID pivots, a DMZ failed connection, a DMZ DNS row, a DMZ TLS row, and a database connection. Reprinting a record during a pivot did not increase that sample count. Aggregate scans were restricted to the network files and supported the counts below; this was not an exhaustive lifecycle audit.

The union of the observed connection timestamps runs from `1793624400.006178` to `1793645984.793219`, approximately **2026-11-02 13:00:00–18:59:44 UTC**. This six-hour slice cannot establish overnight traffic, daily business-hour cycles, or whether a session whose endpoint lies outside the slice should have an additional record. No such absence was scored.

| Sensor | Connections | DNS | HTTP | TLS | X.509 |
|---|---:|---:|---:|---:|---:|
| zeek-core | 12,943 | 3,265 | 2,520 | 413 | 246 |
| zeek-dmz | 10,263 | 1,165 | 2,776 | 3,038 | 1,010 |
| zeek-db | 438 | 48 | 22 | 19 | 26 |

These are per-file observation counts, not deduplicated network activity. Different sensors can observe the same underlying transaction; summing their rows would overstate independent activity.

### Exact cross-source pivot 1: proxy CONNECT and TCP transport

`zeek-core/conn.json:10` has `ts=1793624408.687071`, UID `CCNiAm1f7JPR2ix29e`, TCP service `http`, `duration=2.967407`, and state `SF`. Its tuple is `10.10.1.41:62106 → 10.10.3.20:8080`; the resulting close boundary is `1793624411.654478`.

`zeek-core/http.json:1` has the exact UID and tuple at `1793624408.815497`, **128.426 ms after transport open**, within that interval. `method=CONNECT`, `host=preview.redd.it`, `uri=preview.redd.it:443`, `status_code=200`, and `status_msg="Connection Established"` are mutually compatible. Zero HTTP request/response body lengths are compatible with the CONNECT exchange; the TCP connection can carry tunnel bytes beyond those HTTP body lengths. The connection records 2,065 originator payload bytes and 21,059 responder payload bytes with five and 19 packets respectively. I found no packet-count impossibility in this sample.

This is affirmative correlation evidence, not evidence against authenticity because the join is complete. It also explains why the numerous HTTP rows cannot simply be interpreted as a predominance of cleartext web browsing: many represent proxy negotiation for encrypted destinations.

### Exact cross-source pivot 2: resumed TLS and TCP transport

`zeek-core/conn.json:62` records UID `CJFbfoEDBNNxzdqDm1`, tuple `10.10.2.25:54541 → 10.10.2.40:443`, `ts=1793624582.189447`, `duration=0.901012`, and `SF`. The transport close boundary is `1793624583.090459`.

`zeek-core/ssl.json:1` records that same identity at `1793624582.321677`, **132.230 ms after open**. It has `version=TLSv12`, `cipher=TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256`, `server_name=LOG-MON-01.meridianhcs.local`, `resumed=true`, `established=true`, and `ssl_history="CsiI"`. This is a plausible legacy internal service and resumed handshake. The lack of certificate references on this particular record is not a contradiction.

As an aggregate boundary check, all 413 core, 3,038 DMZ, and 19 database TLS UIDs have a connection row in their own sensor file, and none has a TLS timestamp later than its matching connection's open plus duration plus a 1 ms tolerance. This supports internal timing consistency but does not verify every handshake, source-native schema detail, or certificate chain.

### DNS, protocol population, and TLS texture

The first core DNS row is authoritative A resolution of `DC-01.meridianhcs.local` to `10.10.2.10`, with `rtt=0.000469` and TTL 300. The second is a nonauthoritative recursive A answer for `data.fastreach.com` to `52.84.46.244`, with `rtt=0.001234` and TTL 77. The sampled DMZ DNS row shares that latter query, transaction ID `24809`, and answer; separate sensor timing and UID are not inherently contradictory. I did not use real-world resolution of the potentially sanitized domain as a test.

Core DNS contains 2,722 distinct RTT values across 3,265 rows, and DMZ contains 1,111 across 1,165 rows. Common core answer TTLs include 300 (1,106 occurrences), 30 (409), 1,800 (262), 1 (133), 86,400 (132), and 3,600 (125). TTL uniformity and response-time quantization are not conspicuous in these aggregates. I did not establish whether each external connection had a necessary preceding uncached lookup; cache state and observation scope prevent such a blanket requirement.

The sampled external TLS record, UID `CG295AL9K2PwDjLsPO`, targets `52.84.46.244:443` from `10.10.3.20:42181`, has SNI `data.fastreach.com`, negotiated TLS 1.2 with an AES-GCM cipher, and two certificate-file references. The sampled core certificate pair includes an RSA-2048 leaf for `LOG-MON-01.meridianhcs.local` and an RSA-2048 enterprise issuing CA, with distinct serials and validity intervals. These are plausible shapes; cryptographic signature validity was not tested.

### Connection state and environment interpretation

The core state population is 10,406 SF, 1,768 S0, 442 OTH, 162 RSTO, 101 RSTR, 29 REJ, 15 S3, 11 S2, and nine S1. DMZ is 7,175 SF, 2,545 S0, 310 OTH, 118 RSTO, 62 RSTR, 23 REJ, 15 S2, ten S1, and five S3. Database is 329 SF, 38 RSTO, 23 OTH, 18 RSTR, 13 S0, nine REJ, five S2, two S3, and one S1. The high DMZ failed-attempt fraction could reflect filtering or scans; without endpoint/packet attribution it is not a defect.

Core common destination ports include DNS 53 (3,272), Kerberos 88 (2,607), proxy 8080 (2,406), LDAP 389 (1,136), SMB 445 (723), HTTPS 443 (642), and SSH 22 (380). Database port 3306 dominates its sensor with 255/438 connections. These observations support differentiated infrastructure, directory, proxy and database traffic rather than requiring every host to exhibit every protocol. Of the TCP SF populations—5,306 core, 6,002 DMZ, and 274 database—none has fewer than three packets in either direction. That narrow check finds no obvious two-sided TCP closure/count contradiction, while leaving detailed TCP sequence validation outside scope.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| weak_signal | Zeek connection history | Dominant SF history in 3,492/5,306 core, 4,028/6,002 DMZ, 163/274 DB TCP flows | Small upward contribution; similar dominant history could arise from common stacks and overlapping sensors, so it does not establish generation. |
| No demonstrated strong indicator | Network sources sampled | 16 records, two exact UID pivots, stated aggregates | No hard contradiction, required-companion gap, or verified schema defect supported a high synthetic score. |

## Realism Score by Category

- **Field format accuracy:** 9 — Sampled tuples, TCP accounting, DNS fields and TLS negotiation shapes are credible; no full parser or cryptographic validation was performed.
- **Temporal patterns:** 8 — Both exact application pivots fall inside transport lifetimes, and TLS boundary aggregates pass; longer-period behavior is unobservable.
- **Cross-source correlation:** 9 — Two exact UID/tuple joins are coherent; this does not establish the correctness of every companion source.
- **Behavioral realism:** 8 — Query/error diversity, failure states, proxy tunneling and legacy internal TLS are plausible; detailed actor intent was outside this review.
- **Environmental consistency:** 9 — Sensor-specific directory, external TLS and database distributions support differentiated observation paths and roles.

## Recommendations

- If this were synthetic, examine the reported successful-TCP history proportions against distinct endpoint TCP stacks and service populations before changing them. Any added variation should follow packet and lifecycle behavior; this weak observation alone does not justify arbitrary randomization.
- No concrete correction to source-native fields, companion coverage or transport ordering is supported by this bounded sample. Retain the distinction between CONNECT message-body lengths and tunneled transport bytes, and between absent application response payload and present TCP response packets.
