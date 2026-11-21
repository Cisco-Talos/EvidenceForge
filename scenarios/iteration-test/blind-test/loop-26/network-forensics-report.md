# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 80
**Synthetic-Confidence Score:** 38

## Executive Summary

The network evidence is mostly production-like: connection states, application timing, byte accounting, DNS diversity, proxy behavior, and observable TLS certificate relationships withstand substantial consistency checking. A conspicuously narrow browser vocabulary across distinct external HTTP clients provides a concrete but limited distribution concern; I did not establish a hard protocol contradiction or impossible visible ordering that would justify a confident synthetic verdict.

## Evidence For Synthetic

- [distribution_texture] In `zeek-dmz/http.json`, the external-origin HTTP subset contains 101 transactions from 99 distinct source IPs. Exactly 99 transactions use just three Windows browser strings: Chrome/120.0.0.0 (36), Chrome/120.0.0.0 with Edg/120.0.0.0 (33), and Firefox/121.0 (30); the other two use AhrefsBot/7.0. Such a small, nearly balanced browser pool across many apparently separate public clients suggests a constrained traffic vocabulary. Examples include UID `CSM22nkheZLsmcRnrG` at `1793624414.846370` (Firefox), `CRhnhVBWXTsK3zCLmr` at `1793624953.713427` (Edge), and `CYVXBHNa3dTLDi3Mw` at `1793625039.278200` (Chrome). This is suggestive rather than conclusive: browser strings can be spoofed, a portal can serve a specialized audience, and the visible subset is modest. I do not treat the IP ranges, hostname substitutions, or any domain's real-world resolution as authenticity evidence.

## Evidence For Real

- All 23,141 connection records have unique UIDs within their respective sensors. Every examined DNS, HTTP, SSL, SMTP, and SMB-file application UID resolves to a local connection with matching four-tuple and an application timestamp inside the recorded connection interval. This is positive coherence, not evidence that completeness itself implies authenticity.
- Connection-state diversity is substantial. Core contains 9,787 SF, 1,670 S0, 435 OTH, 156 RSTO, 104 RSTR, 44 REJ, and smaller S1/S2/S3 populations. The DMZ has 2,464 S0 connections alongside 7,453 SF connections, consistent with different exposure from the core.
- DNS has multiple meaningful query types and outcomes rather than only successful A queries: core has 297 AAAA, 158 PTR, 103 SRV, 264 TXT, and smaller MX/NS/SOA populations; its outcomes include 206 NXDOMAIN, 12 SERVFAIL, and five REFUSED responses. TTLs range from one to 86,400 seconds.
- Loss indicators explain initially concerning packet-accounting differences. Across all three sensors, the 147 direction-level cases whose TCP payload-plus-minimum-headers estimate exceeded captured IP bytes all belonged to connections marked with capture gaps; no such deficit occurred in a connection without gap evidence.
- Observable TLS chains resolve, issuer/subject links agree, certificate validity periods cover their corresponding handshakes, and checked TLS 1.2 authentication suites agree with leaf key types. TLS 1.3 lacks falsely exposed plaintext certificate chains in the examples examined.
- HTTP includes proxy authentication failures, policy denials, gateway failures, redirects, cache responses, partial content, and persistent-connection transaction depths. The collection distinguishes explicit proxy CONNECT control traffic from separately observed TLS upstream connections.

## Detailed Analysis

### Scope and method

I examined only logs under the supplied data directory. I parsed all JSON records in the three Zeek sensor directories and inspected representative perimeter firewall, Snort, and proxy text records. I did not inspect scenario material, provenance files, repository code, previous assessments, or endpoint histories. All timestamps below are log values; calendar examples are UTC on November 2, 2026.

The network observation window is approximately 13:00–19:00 UTC. Connection counts are 12,230 for `zeek-core/conn.json`, 10,481 for `zeek-dmz/conn.json`, and 430 for `zeek-db/conn.json`. The dataset is a six-hour slice, so it cannot support an overnight-versus-business-hours or day-of-week judgment.

I tested UID resolution, tuple agreement, application timestamps against connection intervals, cumulative HTTP response-body accounting, packet/IP-byte bounds, overlapping successful TCP tuple reuse, DNS answer forms, TLS key/cipher compatibility, certificate-chain references, and selected multi-sensor protocol-field agreement. These tests establish bounded consistency; they do not prove origin.

### Connection states, duration, and packet accounting

The sensors have different service mixes rather than an identical distribution. Core records 2,106 Kerberos-service and 1,143 LDAP-service connections; the database sensor has 273 MySQL-service connections among its 430 records. DMZ includes 3,312 SSL-service connections and extensive unanswered connection attempts. This is compatible with distinct network segments and host functions inferred from the traffic itself.

Durations also differ by activity. Successful core DNS connections have a median duration of about 0.00391 seconds; core LDAP's median is about 2.93 seconds. Successful database-sensor MySQL connections have a median of about 2.97 seconds and maximum of 29.41 seconds. Successful core SSH durations range from 0.258 seconds to 13,320.856 seconds, with a median of 2,188.134 seconds. Brief and persistent sessions coexist; a long session crossing the collection boundary is not an error.

I found no overlapping successful TCP connections with the same exact directional four-tuple within one sensor. Connections whose TCP history is only `S` do not simultaneously claim responder packets or responder payload in the tested records.

A naive byte check initially identified 71 core, eight database, and 68 DMZ direction-level deficits when comparing captured IP bytes to sequence-derived payload plus 40 bytes per TCP packet. Every case had `missed_bytes > 0` or gap characters in history; all lossless cases passed. These must not be reported as impossible packet accounting. Across TCP records, positive missed-byte counts and `G`/`g` history indicators also agree.

For a concrete lossless example, core UID `C48vC73LynYi2GtPwPK` starts at `1793624405.356666`, from `10.10.1.31:53486` to `10.10.2.20:445`. It records 119,613,292 originator payload bytes, 87,951 originator packets, and 123,131,332 originator IP bytes over 5.921422 seconds. The large transfer is internally feasible; the 3,518,040-byte header difference is exactly 40 bytes per originator packet. The matching SMB mapping occurs later, at `1793624405.476774`, for `\\FILE-SRV-01\ClinicalExports`.

### DNS behavior and causality

The three DNS files contain 3,188 core, 1,152 DMZ, and 45 database records. Internal discovery, reverse lookups, public names, IPv6 answers, successful responses without address answers, and negative responses all appear. I did not require every destination to have a new visible lookup because caches and direct addresses are legitimate.

A clearly ordered example is core UID `CmN2OeyFuu5qT4yxIk`: at `1793624403.868779`, `10.10.1.31` asks `10.10.2.11` for `FILE-SRV-01.meridianhcs.local`, receives `10.10.2.20` with TTL 1,800, and subsequently connects to that address on port 445 at `1793624405.356666`. The DNS connection has one packet each direction, 58/86 UDP payload bytes, and 86/114 IP bytes, consistent with IPv4/UDP overhead.

SRV answers name the domain controllers, PTR answers map internal addresses to the corresponding service hostnames, and observed AAAA answers contain IPv6 addresses. I found no DNS question shorter than the minimum wire length implied by its logged query in the tested connection-payload bounds.

The core TXT population includes high-entropy names under `ns1.westbridge-services.cloud`, such as UID `C20ICHN5IECEQwki4E` at `1793641499.536308`, with a 0.059791-second RTT and TTL 10. Suspicious DNS content is an incident characteristic, not an authenticity defect. Its presence or apparent narratability did not increase the synthetic score.

### HTTP, proxying, and external client texture

HTTP counts are 2,614 core, 2,907 DMZ, and 26 database transactions. Core includes 2,265 successful CONNECT transactions, plus 55 CONNECT 403, 52 CONNECT 407, and smaller 502/503/504 populations. These distinctions are useful collection realism: not every attempted proxy tunnel succeeds.

The first proxy text example records `10.10.1.33` issuing CONNECT for `spoprod-a.akamaihd.net:443` at 13:00:37, with separate control-message and tunnel byte counts. The network view also contains the proxy's upstream TLS connection from `10.10.3.20` to a public address. I did not incorrectly require the proxy's TLS transport to share the client's CONNECT UID.

Every individual and cumulative set of logged HTTP response bodies fits within the responder TCP payload of its associated connection. Persistent transaction depths extend through seven in both core and DMZ, providing more than a single request per modeled connection. An apparent multi-sensor URI mismatch under nearest-time matching disappeared as a valid concern once distinct `trans_depth` values were considered; adjacent transactions on one persistent connection must not be equated solely by nearby timestamps.

The external-client browser distribution is the principal reservation. Ninety-nine browser transactions from a 99-client external subset use just three exact Windows browser strings in counts of 36, 33, and 30. The two non-browser transactions account for the remaining records. The issue is the concentration across distinct external clients, not that any individual browser string is invalid. Internal HTTP has a much richer vocabulary, including Linux browsers, several macOS browsers, command-line clients, service-health clients, and software-update clients; this makes the external population's small pool more noticeable. It remains compatible with curated or specialized real traffic.

### TLS and certificates

The three SSL files contain 348 core, 3,303 DMZ, and 17 database observations. DMZ has 2,288 TLS 1.3 observations, 1,011 TLS 1.2 observations, and four without a negotiated version. Internal database-sensor traffic is TLS 1.2 dominated and commonly uses the CBC suite `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256`; that is dated but technically possible, not an impossible value.

Core UID `C88XNNT8XEjEET1urze` has its connection start at `1793624539.005649` and SSL observation at `1793624539.052892`, on `10.10.2.26:43842 -> 10.10.2.10:636`. The record negotiates TLS 1.3/AES-128-GCM with SNI `DC-01.meridianhcs.local`. Its handshake observation is inside the transport interval and its role is compatible with LDAPS.

An ECDSA example is DMZ UID `C5M2VgZEKfVHF3F2sO`, at `1793625994.220643`, using `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`. Its leaf FUID `FtbIV2jRgiEzBLGUjt` resolves to an `id-ecPublicKey`, 256-bit ECDSA key. The leaf's RSA certificate signature is compatible with an RSA issuer and does not contradict its ECDSA subject key. All checked chain issuer/subject links and certificate validity intervals agree. Repeated fingerprints did not map to conflicting certificate identities within a sensor.

Some full TLS 1.2 handshakes lack a certificate FUID list. Several have explicit packet loss or resets, and this could also reflect extraction or observation choices. I do not score absent certificate records alone as a synthetic indicator.

### Cross-sensor and source coverage limits

Matching nearby observations by tuple and protocol fields found 1,148 core/DMZ DNS pairs and 48 SSL pairs with no disagreement in tested DNS answers/TTLs or TLS version/cipher/SNI/resumption fields. Core/database matching similarly found 45 DNS and 17 SSL pairs without those disagreements. These are valid shared observations, not a "too complete" synthetic tell.

One core SMB mapping, UID `C4bqaKVpaYQLPkuTrz` at `1793640924.871449`, lacks its connection UID in that sensor's supplied connection file. It describes `10.10.1.22:59392 -> 10.10.2.20:445`, share `\\FILE-SRV-01\ClinicalExports`. A single absent companion could result from collection boundaries or filtering; without a demonstrated complete-connection collection contract, this does not establish a defect and did not raise the score.

I did not infer absence of required QUIC, NTP, endpoint events, or additional network analyzers from their absence in the supplied files. Nor did I penalize full cross-source alignment, domain sanitization, filesystem timestamps, or the completeness of suspicious activity.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | DMZ Zeek HTTP | 99 of 101 external-origin HTTP transactions; only three exact Windows browser strings, with counts 36/33/30 | Limited upward pressure: a constrained vocabulary across many distinct external clients, with legitimate alternative explanations |
| hard_contradiction | Network sources examined | No demonstrated case | No contribution |
| contract_gap | Network sources examined | No established inconsistency after accounting for gaps, persistent transactions, and collection uncertainty | No contribution |

The score of 38 reflects mostly realistic telemetry with a bounded distribution concern. The confidence of 80 applies to the judgment that the available evidence is insufficient for a decisive origin verdict, not to an 80% probability that the dataset is synthetic.

## Realism Score by Category

- **Field format accuracy:** 9 — JSON structures, protocol fields, DNS answer forms, and checked TLS key/cipher relationships are coherent.
- **Temporal patterns:** 9 — Application observations fit transport intervals; duration diversity is plausible, though six hours cannot establish a full daily cycle.
- **Cross-source correlation:** 9 — Tested tuple, payload, certificate, and multi-sensor relationships agree; one orphan SMB mapping remains collection-ambiguous.
- **Behavioral realism:** 7 — Service traffic, proxy failure modes, and persistent HTTP look plausible; external browser diversity is noticeably constrained.
- **Environmental consistency:** 8 — Segment/service differences and proxy routing are credible, with insufficient collection documentation to make stronger coverage claims.

## Recommendations

- If this were synthetic, broaden the external HTTP client population beyond the observed three browser strings, assigning stable client profiles and a plausible version/OS/device long tail. The goal would be to address the measured 99-transaction concentration, rather than introduce random headers independently on every request.
