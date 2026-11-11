# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Real
**Verdict Confidence:** 58
**Synthetic-Confidence Score:** 18

## Executive Summary

The bounded network review found plausible protocol diversity, internally consistent connection accounting, and coherent early, middle, and late network evidence. I lean Real with modest verdict confidence: no substantiated synthetic defect emerged, but twenty inspected records and selected aggregates cannot establish provenance or rule out sophisticated synthesis.

## Evidence For Synthetic

- No demonstrated hard contradiction, contract gap, format defect, or distribution artifact in the bounded sample.
- [weak_signal] `zeek-db/ssl.json` has 19/19 TLS 1.2 sessions and 11/19 using `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256`, versus 2,125/3,038 TLS 1.3 rows in `zeek-dmz/ssl.json`. This comparatively narrow legacy profile could be curated, but equally fits a legacy server segment. It carries negligible authenticity weight; cipher age alone does not establish fabrication.

## Evidence For Real

- The middle-window TLS pivot has a consistent tuple, sensible handshake lag, and matching certificate identity: UID `CfXsGkkuG9lcJw887K`, `10.10.1.21:42707 → 10.10.2.21:443`, conn start `1793635200.175663`, TLS `1793635200.230940`, SNI `FILE-LNX-01.meridianhcs.local`, with a matching enterprise-issued leaf and CA.
- The late-window DNS answer for `metrics.dataforge.io` is `54.230.136.90` at `1793645947.079644`; a proxy-originated connection to that address begins `1793645949.241425`, followed by TLS SNI at `1793645949.297238`. This is plausible resolution-before-connect-before-handshake ordering.
- DNS includes unsuccessful resolution and multiple query types. Core has 222 NXDOMAIN, 14 SERVFAIL and four REFUSED among 3,265 records, with A, AAAA, PTR, SRV, TXT, NS, SOA and MX queries.
- Capture imperfections are represented coherently. All 179 TCP records triggering a naive minimum-header accounting screen also have positive `missed_bytes` and gap-bearing history; no flagged record has IP-byte totals below its sequence-derived payload total. These are explainable capture/sequence differences, not demonstrated contradictions.

## Detailed Analysis

### Scope and bounded sample

Only the assigned data directory and briefing were read. Twenty individual records were inspected, with aggregate calculations over the three sensors' conn, DNS, HTTP, TLS, certificate and file tables. No endpoint-schema audit, exhaustive lifecycle audit, packet examination, hostname resolution or scenario inference was performed. The network window is approximately 2026-11-02 13:00–19:00 UTC; overnight or multi-day behavior cannot be judged.

The twenty records were: five core middle-window records (conn `CVNUNvEWkplKKgj318`, DNS `CMAK59U0DCnDtKGZmPx`, CONNECT `CcWaxAYQjc7El3HI2J`, TLS `CfXsGkkuG9lcJw887K`, certificate `FQZbIN8FkEszdLt0qAz`); seven early records (core conn `CKXtZNjRpm3SaGWIID`, DB conn `CKKCW6MAiFBEIjMugn`, DMZ HTTP `CaiLpetsCscL19fgK`, DMZ TLS `C1c41TiuTd6CDcPjdUI`, core DNS `C1TvGMZR2piJeHeDjT`, DHCP UID `Ci9uZXKbGBH4gF8uuWh`, DMZ file `FQsAdfFUiyDy4spKsce`); four middle-window pivot companions (the exact TLS conn, its two certificates `FQKBEGjxMFg4aE9tahU` and `FAg1hiFlqkGBwA3VphH`, and the exact CONNECT conn); one early proxy-access row; and three late records (TLS and conn `CJYh8OOzK0Ihtqgqj0`, DNS `CJVrZrBLBkUgvPcxQc`). Epoch timestamps below preserve the recorded precision.

### Connection states, traffic shape and accounting

Core contains 12,943 connections, DB 438, and DMZ 10,263. State distributions differ plausibly by observation path: core SF 10,406, S0 1,768, OTH 442; DB SF 329, S0 13, OTH 23; DMZ SF 7,175, S0 2,545, OTH 310. Resets, rejections and partially observed TCP states also occur. S0 is not interpreted uniformly as failed TCP: the inspected `CKXtZNjRpm3SaGWIID` is one-way UDP syslog, two originator packets, no responses, history `D`.

The successful DB MySQL example at `1793624671.123845` connects `10.10.3.10:34724 → 10.10.4.10:3306`, lasts 1.239587 seconds, and transfers 724/4,188 payload bytes with four/six packets. Its `ShADadfF` history and header-inclusive totals are plausible. The minimum IPv4/TCP header screen flagged 93/7,156 core TCP rows, 1/369 DB rows, and 85/8,739 DMZ rows. Every flag coincides with positive capture gaps; it would be wrong to score this screen as impossible packet accounting without compensating for sequence-derived payload lengths.

Hourly counts are not flat: core has 1,829, 3,443, 1,898, 1,769, 2,176 and 1,828 connections for UTC hours 13–18. DMZ has 1,515, 2,916, 1,496, 1,534, 1,401 and 1,401. This six-hour slice supports variation but is insufficient to establish diurnal realism or call the quieter bins overly smooth. Sensor totals are not summed as independent traffic because overlapping observation is possible.

### DNS and TLS

The inspected NXDOMAIN query `isatap` at `1793624510.824572` has no answers and a 2.442 ms RTT. The middle successful internal A query resolves `DC-02.meridianhcs.local` to `10.10.2.11` with TTL 300 and 1.149 ms RTT. Core query-type counts are A 2,398, AAAA 274, TXT 307, PTR 163, SRV 100, NS 16, SOA four and MX three. These distributions alone neither prove nor disprove authenticity.

Core TLS is mixed: 214 TLS 1.3 and 199 TLS 1.2; DMZ has 2,125 TLS 1.3, 909 TLS 1.2 and four rows without a negotiated version. The early TLS 1.3 example to `preview.redd.it` has no certificate-chain fields, consistent with passive visibility limits. Early plaintext HTTP includes an OCSP GET to port 80, so HTTP does not automatically imply unrealistic unencrypted user browsing.

Certificate/file SHA1 comparisons match for all joinable certificate file rows: 246/246 core, 26/26 DB and 1,010/1,010 DMZ. All inspected-table certificate observation times fall inside the recorded validity periods. Completeness of these joins is not scored as synthetic evidence.

### Exact cross-source pivots

1. **Middle TLS → conn → X.509:** `zeek-core/ssl.json` UID `CfXsGkkuG9lcJw887K` joins `conn.json` on the exact tuple above. TLS begins 55.277 ms after connection start and inside its 14.185937-second interval. Its leaf `FQKBEGjxMFg4aE9tahU` has CN/SAN matching SNI; its issuer matches CA subject `FAg1hiFlqkGBwA3VphH`. Certificate observations occur at `1793635200.238519` and `.246587`.
2. **Middle CONNECT → conn:** `zeek-core/http.json` UID `CcWaxAYQjc7El3HI2J` joins `conn.json` at `10.10.1.22:38139 → 10.10.3.20:8080`. The flow starts `1793635511.892404`, HTTP occurs `.965834`, within duration 0.990148 seconds. `CONNECT drive.google.com:443`, status 200 `Connection Established`, and zero HTTP body lengths are consistent with tunnel-control semantics; connection byte totals can include tunneled bytes.
3. **Late TLS → conn and contextual DNS:** `zeek-dmz` UID `CJYh8OOzK0Ihtqgqj0` joins exactly at `10.10.3.20:35467 → 54.230.136.90:443`. The conn lasts 1.162251 seconds, TLS starts 55.813 ms later, and SNI is `metrics.dataforge.io`. DNS UID `CJVrZrBLBkUgvPcxQc` is a separate transaction, not the same UID, resolving that name/address for the same originating host 2.161781 seconds before connection start.

The early proxy sample at 13:00:08 UTC explicitly distinguishes control-message bytes from tunnel bytes and records a 2,836 ms tunnel duration. I did not claim it as an exact tuple join because its text lacks the required ports/UID.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| weak_signal | DB TLS | 19/19 TLS 1.2; 11/19 CBC | Negligible; plausible legacy service profile, not a demonstrated defect |
| None substantiated | Reviewed network sources | Twenty records, three pivots, selected aggregates | No verified contradiction or contract gap supports a high synthetic score |

## Realism Score by Category

- **Field format accuracy:** 9 — Sampled JSON, tuples, protocol fields and hash joins are plausible; not a complete native-schema validation.
- **Temporal patterns:** 9 — All inspected protocol timing is coherent; only a six-hour window is visible.
- **Cross-source correlation:** 9 — Exact UID/tuple/certificate pivots agree, including the late window.
- **Behavioral realism:** 8 — Diverse protocol/state/DNS behavior; bounded sampling cannot validate the long tail.
- **Environmental consistency:** 8 — Internal enterprise services, proxy traffic and legacy DB TLS are plausible; roles inferred only from visible network evidence.

## Recommendations

No corrective recommendation is justified by a demonstrated defect in this bounded review. If this were synthetic, preserve the coherent capture-gap semantics and tuple/timing relationships already observed; the limited legacy TLS population would merit comparison with an actual deployment inventory before changing it. A larger authorized sample or packet evidence would be needed before recommending accounting or protocol changes.
