# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 85
**Synthetic-Confidence Score:** 66

## Executive Summary

The network records are substantially production-like: connection states, byte accounting, DNS diversity, TLS visibility, certificate reuse, and sensor clock relationships mostly withstand cross-checking. The strongest contrary evidence is a repeated request-identity inconsistency: the proxy and both Zeek sensors attribute different User-Agent values to otherwise matching client-to-proxy requests, including updater traffic being represented as browser traffic. This is a recurring cross-source contract defect, rather than proof of impossible TCP behavior, so the score stays below the hard-contradiction band.

## Evidence For Synthetic

- [contract_gap] **Different User-Agent values for the same apparent HTTP request, repeated across seven client IPs.** Matching client IP, method, exact request target, response status, and timestamp within 1.5 seconds, with exactly one candidate in each sensor, produces 1,598 proxy/core matches and 1,639 proxy/DMZ matches. Each sensor has 59 substantive User-Agent disagreements after treating proxy `-` and an absent Zeek field as equivalent; the same affected proxy records appear in both sensor comparisons, so these are not 118 independent defects. For example, `PROXY-01.meridianhcs.local/proxy_access.log:2` records Chrome/121 for `CONNECT cf-assets.www.cloudflare.com:443` from `10.10.1.36` at 13:01:18 UTC, while `zeek-core/http.json:2` and `zeek-dmz/http.json:3` record Chrome/120 for that request.
- [contract_gap] **The disagreement changes application identity, beyond a version digit.** Proxy line 526 records `Microsoft-CryptoAPI/10.0` for `10.10.1.34` requesting `CONNECT ctldl.windowsupdate.com:443` at 14:05:02 UTC; core HTTP line 352 and DMZ HTTP line 413 instead record a Chrome/120 browser. Proxy line 1533 records `Google Update/1.3.36.372;winhttp` for `10.10.1.32` requesting `CONNECT update.googleapis.com:443` at 16:04:55 UTC; core HTTP line 1009 and DMZ HTTP line 1149 instead record Firefox/121. These are examples of the same defect family, not separately scored independent indicators.

## Evidence For Real

- Connection outcomes include successful sessions, unanswered attempts, refusals, resets, partial traffic, and one-sided shutdowns. Across core/DB/DMZ respectively, `SF` counts are 9,865/374/6,427, `S0` counts are 1,741/11/2,637, and `OTH` counts are 420/20/325. This is materially richer than a single repeated successful-flow pattern.
- All 11,950 DNS/HTTP/SSL rows across the three sensors have a corresponding connection UID within their own sensor. All 3,041 TLS rows and 4,713 HTTP rows have timestamps inside the associated connection interval in the checks performed. This supports coherence; completeness itself was not treated as evidence against authenticity.
- All 1,200 connection rows containing a `g`/`G` history marker also have nonzero `missed_bytes`; there were no gap-marker/zero-loss inconsistencies. Basic packet/IP-byte checks and conservative TCP history minimum-packet checks found no violations.
- DNS includes A, AAAA, PTR, SRV, TXT, NS, MX, and SOA in core, with NOERROR, NXDOMAIN, SERVFAIL, and REFUSED outcomes. No direct IP answers used the wrong address family for their A/AAAA query in the checks performed. DNS RTTs did not exceed the associated connection duration by more than the 1 ms tolerance used.
- TLS 1.3 rows consistently omit certificate-chain FUIDs and have short `Cs` histories, while full and resumed TLS 1.2 handshakes have distinct history shapes. RSA/ECDSA authentication ciphers match the available leaf key types, all 613 checked certificate parent links have matching issuer/subject names, and repeated services reuse stable certificate identities.
- Client-to-proxy CONNECT control traffic, proxy-to-origin TLS connections, and source-local proxy accounting are distinguishable. Proxy line 1 explicitly separates `cs_bytes=520`, `wire_sc_bytes=213`, and tunneled bytes `4274`/`34835`; their sums match the associated client/proxy connection's 4,794/35,048 payload bytes. This avoids confusing the CONNECT response with the subsequent tunnel payload.

## Detailed Analysis

### Input provenance and limits

I read the supplied neutral briefing and enumerated files only inside `/private/tmp/log-study-0sx5q8_q/data`. I parsed the three Zeek sensor directories, the supplied proxy access log, the perimeter ASA log, and both Snort alert files. Endpoint filenames were visible during the in-scope inventory, but endpoint records, shell histories, scenario files, project source, roadmap/worklogs, prior assessments, and neighboring reviewers' files were not examined. The inherited generic operating instructions are an environment limitation and were not used as evidence of origin.

Read-only parsing used system `python3` with `/private/tmp` as the explicit working directory. No logged commands were executed. Public reference checks used direct official Zeek documentation URLs and direct upstream Zeek repository URLs, with no general web searches or task-project pages. One attempted upstream baseline URL did not resolve; it contributed no evidence.

All line references are one-based physical lines in the named files. Timestamps in this report are UTC on 2026-11-02. There is no packet capture, sensor configuration, proxy log-format definition, or complete deployment inventory, so unusual behavior is distinguished from demonstrated contradiction. The verdict is a network-source assessment, not an exhaustive endpoint review.

### Volume, timing, topology, and service mix

Core has 12,382 connection records, DB 498, and DMZ 9,629: 22,509 sensor observations, not necessarily distinct network sessions. They span approximately 13:00–19:00 UTC. Core hourly record counts are 1,779, 3,113, 1,724, 1,856, 2,192, and 1,718; DMZ counts are 1,561, 2,701, 1,143, 1,485, 1,449, and 1,290. The window is too short to judge a full daily or overnight activity cycle.

The role distribution is sensible: core sees substantial DNS, Kerberos/88, LDAP/389, SMB/445, and proxy/8080 traffic; DB sees 345 destination-port-3306 observations; DMZ sees many TLS/443 and client/proxy connections, with substantial unanswered traffic across other ports. The 66 core and 114 perimeter Snort alerts include DNS policy notices, scans, and application policy alerts; the sample is not a homogeneous stream of high-severity exploit alerts.

Sensor-relative timestamps are also plausible. Matching the five-tuple and nearest start time within 0.5 seconds gives 4,759 core/DMZ connection pairs. The median core-minus-DMZ offset is 114.227 ms, with 2.611 ms overall standard deviation; the first client/proxy pair differs by 115.093 ms. Such a stable clock offset is a reason to align sensors before alleging causality inversions. I did not score that offset as synthetic.

### TCP, transport accounting, and lifecycle

The common histories generally agree with their connection states: successful bidirectional sessions use histories such as `ShADadfF`, rejected attempts use `Sr`, and incomplete sessions have appropriate one-sided patterns. TCP packet counts meet conservative lower bounds implied by visible handshake/data/close history markers. Payload bytes do not exceed IP bytes, positive payload does not appear with zero observed packets, and packet IP totals meet a minimum IP-header bound.

The official [Zeek connection schema](https://docs.zeek.org/en/current/scripts/base/protocols/conn/main.zeek.html) distinguishes sequence-based TCP payload estimates, observed IP byte totals, content-gap markers, and packet counts. It also cautions that connection duration may omit trailing nonproductive packets. I therefore did not require bit-for-bit equality between counters from different sensors or treat a marginal trailing-close timestamp as automatically impossible.

Successful SSH connections have broad, service-appropriate durations: core median 2,237.669 seconds, DB median 1,091.945 seconds, with core maximum 13,298.584 seconds. Core RDP successful connections have median 1,546.466 seconds. Very short records on a sensitive port were not automatically interpreted as successful interactive sessions. No visible same-identity transport-before-auth contradiction was established in this review; endpoint authentication was outside my examined data.

### DNS and TLS

Core DNS has 3,180 rows: 2,282 A, 283 AAAA, 129 PTR, 102 SRV, 362 TXT, and small NS/MX/SOA tails. Core outcomes are 2,948 NOERROR, 210 NXDOMAIN, 19 SERVFAIL, and 3 REFUSED. The substantial TXT volume could be suspicious traffic, but is not itself an authenticity defect. Core DNS line 5 shows `printer01.meridianhcs.local` returning NXDOMAIN; line 29 shows `wpad` returning NXDOMAIN. Those fit common stale-name and search behavior without requiring every host to use Windows naming conventions.

TLS observations total 316 core, 16 DB, and 2,709 DMZ. Core has 151 TLS 1.3 and 164 TLS 1.2 rows; DMZ has 1,750 TLS 1.3 and 954 TLS 1.2 rows; the remaining six rows have no negotiated version. All 16 DB TLS observations use TLS 1.2. The mixture of GCM, ChaCha20, and limited internal TLS 1.2 CBC usage is possible for mixed-age applications. A legacy suite is not an authenticity contradiction by itself.

The [official Zeek TLS discussion](https://docs.zeek.org/en/current/reference/logs/ssl.html) explains the reduced passive visibility in TLS 1.3. Here, no TLS 1.3 record carries certificate-chain FUIDs, so I found no claim to passive observation of encrypted TLS 1.3 certificates. Available TLS 1.2 leaf certificates have compatible authentication key types. All 95 core, 9 DB, and 509 DMZ checked chain links have matching issuer/parent-subject identities. File payload totals associated with a connection do not exceed that connection's directional payload in the aggregate checks performed.

### HTTP request identity: the decisive weakness

The match procedure uses a proxy record's client IP, HTTP method, exact request target, response status, and timestamp, then accepts a sensor match only when exactly one HTTP row falls within 1.5 seconds. This is deliberately narrower than joining only a hostname and an approximate time. The quoted examples also have independent agreement between both Zeek sensors on the client-side source tuple.

For the first mismatch, core `C7IwMpVCzJLNjcYhSz` and DMZ `CEiycmgUpElscBuV6P` both describe `10.10.1.36:52809 -> 10.10.3.20:8080`, CONNECT to `cf-assets.www.cloudflare.com:443`, status 200, at `1793624478.162617` and `1793624478.047064`. Their request User-Agent says Chrome/120. The proxy records Chrome/121 for that client, target, method, status, and second. Core HTTP line 44/DMZ line 55 and proxy line 75 repeat the same version discrepancy for `media.akamai.net:443` at 13:10:10.

The 59 substantive mismatches in core cover `10.10.1.34` (24), `10.10.1.32` (17), `10.10.1.33` (8), `10.10.1.36` (5), `10.10.1.42` (2), `10.10.1.35` (2), and `10.10.1.31` (1). They comprise 52 CONNECTs and 7 GETs. A sixtieth raw comparison is only proxy `-` versus missing Zeek User-Agent and is excluded. The 11 uniquely matched DB/proxy requests have no disagreement.

This pattern suggests two representations choosing application identity differently. A proxy can legitimately rewrite headers or log a derived value, so without its configuration I classify this as a `contract_gap`, not an absolutely impossible field value. However, these are client-to-proxy observations on port 8080, and the supplied proxy rows provide no indication of deliberate User-Agent transformation. Recurrent discrepancies affecting both browser versions and application families materially shift the assessment toward synthetic data.

I did not score browser version changes alone, the cleanliness of the intrusion narrative, domain-to-public-IP mappings, lack of optional log families, absent ALPN fields, or complete reference matching. Those observations do not establish a concrete authenticity defect under the collection assumptions.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `contract_gap` | Proxy access log versus core/DMZ Zeek HTTP | 59 substantive uniquely matched request disagreements across seven client IPs; replicated in both sensors | Primary reason for score 66: repeated incompatible request application identity, including updater/browser substitutions. Qualified by unknown proxy rewrite/logging configuration; not counted twice for two sensors. |

## Realism Score by Category

- **Field format accuracy:** 9 — Native JSON types, protocol fields, histories, certificates, and transport counters largely withstand checks.
- **Temporal patterns:** 9 — Varied flow/session durations, uneven hourly volumes, consistent sensor clock offsets, and no established visible lifecycle inversion.
- **Cross-source correlation:** 6 — UID and payload relationships are strong, but the repeated proxy/Zeek User-Agent disagreement compromises shared request identity.
- **Behavioral realism:** 8 — Plausible mixed infrastructure, browsing, update, admin, scan, and DNS behaviors; a six-hour slice limits cadence assessment.
- **Environmental consistency:** 8 — Segmented services and explicit proxy traffic are plausible; exact sensor and proxy configuration remain unknown.

## Recommendations

- If this were synthetic, preserve the exact request User-Agent as one shared request fact across proxy and sensor representations. Retain distinct identities for CryptoAPI, Google Update, Adobe Application Manager, Google Drive, and interactive browsers.
- If intentional rewriting explains the discrepancies, represent or document the observation point and transformation explicitly so a client-side sensor and proxy log can be compared correctly.
- Add a bounded consistency check using the supplied examples and uniquely matched IP/method/target/status/time relationships. Treat a missing User-Agent and a log-format `-` placeholder as equivalent rather than manufacturing an extra mismatch.
