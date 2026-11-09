# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Real
**Verdict Confidence:** 62
**Synthetic-Confidence Score:** 27

## Executive Summary

The network evidence is mostly production-like: multiple observation points have plausible clock offsets, protocol records agree with their flow identities and visible intervals, and DNS, TLS, proxy, and transport behavior have meaningful variation. I lean real with limited confidence; the strongest adverse finding is a single in-window SMB conversation whose protocol records lack a corresponding same-sensor connection record, which could also result from collection or filtering.

## Evidence For Synthetic

- [contract_gap] `zeek-core/smb_mapping.json:89` and `zeek-core/smb_files.json:153-154` use UID `Cr7mRCkac27kS4mWeXo`, tuple `10.10.1.32:61160 → 10.10.2.21:445`, at epochs `1793639424.505224` through `1793639425.484617`. No row in `zeek-core/conn.json` has that UID or the same tuple. This is a specific source-local reference gap well inside the six-hour window, rather than a general complaint about unavailable sources. Its weight is low: selective connection logging, dropped log delivery, or independent export filtering could explain it. It is not a demonstrated impossible network event.
- [weak_signal] The above conversation is the only missing connection identity among the examined protocol joins, making it worth investigating as a local lifecycle/export inconsistency. I do not count its three affected rows as three independent defects, and I found no second sufficiently strong network indicator to support a high synthetic-confidence score.

## Evidence For Real

- The transport mix includes successful connections, unanswered attempts, resets, rejections, partial connections, and one-sided closure. For example, `zeek-core/conn.json` has 9,865 `SF`, 1,741 `S0`, 171 `RSTO`, 106 `RSTR`, 45 `REJ`, 420 `OTH`, and smaller `S1/S2/S3` populations; this is not a set containing only successful flows.
- DNS has multiple response and question types with source-native flags, answers, and latency variation. Examples include an internal NXDOMAIN at `zeek-core/dns.json:5`, an IPv6 answer at line 12, and a reverse lookup at line 16. Core responses include SERVFAIL and REFUSED as well as NOERROR and NXDOMAIN.
- The visible proxy path distinguishes client-to-proxy HTTP CONNECT from proxy-to-server TLS. `zeek-dmz/http.json:1`, `zeek-dmz/ssl.json:1`, `zeek-dmz/conn.json:1-2`, and `PROXY-01.meridianhcs.local/proxy_access.log:1` provide a concrete example with separate tuples and separate control-message/tunnel byte accounting.
- TLS metadata distinguishes TLS 1.2 certificate-bearing handshakes, resumed sessions, TLS 1.3 sessions without visible certificate records, and failed negotiations. For example, `zeek-dmz/ssl.json:2` is TLS 1.3 with `TLS_AES_128_GCM_SHA256`, history `Cs`, and no certificate chain; `zeek-core/ssl.json:56` is an unestablished client-hello-only attempt.
- Shared traffic at different sensors exhibits an approximately 114 ms core-versus-DMZ offset, while DB-versus-DMZ offsets vary slowly over a wider range. Those offsets should be accounted for before claiming cross-sensor causality errors.

## Detailed Analysis

### Inputs, scope, and method

I read the supplied neutral briefing and inspected only files under `/private/tmp/log-study-kl_ep_px/data`. I used system `python3` from explicit working directory `/private/tmp`, with no repository tools, project files, scenarios, prior reports, or other reviewers' output. Generic inherited operating instructions were not used as evidence of provenance. Protocol-reference checks used official Zeek documentation and Zeek's upstream source only.

Every JSON row in all three Zeek directories was parsed. The firewall, proxy, and IDS families were inventoried and sampled for native layout and path interpretation; their entire event semantics were not exhaustively audited. This assessment principally concerns the Zeek network evidence and does not claim a complete endpoint lifecycle review.

| Source | Connection rows | DNS rows | HTTP rows | TLS rows |
|---|---:|---:|---:|---:|
| zeek-core | 12,382 | 3,180 | 2,223 | 316 |
| zeek-dmz | 9,629 | 980 | 2,479 | 2,709 |
| zeek-db | 498 | 36 | 11 | 16 |

These are observation counts, not unique network conversations: several sensors observe the same traffic. The core flow window runs from `2026-11-02 13:00:02.512987 UTC` to the latest represented close at `18:59:49.989282 UTC`.

I joined protocol records to connections by UID within each sensor, checked four-tuple equality and whether protocol timestamps fell inside their connection intervals, and examined DNS RTTs, HTTP body sizes, TLS certificate identities, TCP tuple reuse, and minimum IP-header accounting. Connection timestamps describe first packets, and duration has specific TCP close semantics, so I allowed 1 ms tolerance rather than treating tiny boundary differences as impossible ordering. These meanings follow the [official Zeek connection schema](https://docs.zeek.org/en/current/scripts/base/protocols/conn/main.zeek.html).

### Connections, states, and service behavior

Across the 22,509 connection observations, the services and states fit distinct observation paths. Core carries DNS, Kerberos, LDAP, SMB, proxy traffic, syslog, and administrative sessions. DB has 329 `mysql` service observations among 498 connections. DMZ has substantial HTTP/TLS and unanswered connections, including ports beyond the web services. The DMZ `S0` count of 2,637 alone is not a defect; unanswered scanning and filtered attempts are visible network behavior.

Core service counts include 3,194 DNS, 2,556 Kerberos, 2,166 HTTP, 1,124 LDAP, 466 SMB, 370 syslog, 306 SSL, 79 SMTP, 62 SSH, 60 DHCP, and 18 RDP observations. They do not require every host to be Windows or every network flow to have native endpoint telemetry.

The duration distributions are service-dependent. Core SSH's median is approximately 2,229 seconds, versus 2.17 seconds for HTTP and 0.0198 seconds for Kerberos. DB MySQL's median is about 2.24 seconds with a tail approaching 30 seconds. A short connection is not necessarily a successful login: `zeek-core/conn.json:3153` is a roughly 5.7 ms SSH `RSTR` flow with 132 originator bytes and 24 responder bytes, consistent with an interrupted early exchange. Similarly, the roughly 77 ms `rdp` flow at core line 2479 is insufficient by itself to establish a successful desktop session.

I found no repeated TCP four-tuple with more than one second of overlap within a sensor. No TCP/UDP IP-byte total was smaller than the minimum IP-plus-transport headers required by its recorded packet count. These checks do not reconstruct packets and cannot prove all packet accounting correct, but they rule out several common hard contradictions.

### Protocol joins and the isolated SMB gap

All 4,713 HTTP rows, 4,196 DNS rows, and 3,041 TLS rows found their same-sensor connection UIDs; their four-tuples matched, and their timestamps fell inside the represented flow intervals with the stated tolerance. SMTP rows also passed these checks. No DNS RTT extended beyond its flow duration by more than 1 ms. No individual HTTP request or response body exceeded the corresponding connection-direction payload total.

These successful joins are evidence of internal coherence, not a synthetic tell from completeness. Conversely, the SMB gap is bounded: one missing connection identity underlies one mapping and two file rows. The file at issue is `Templates\\team-roadmap-final.txt`, reported read size 100,562 bytes. Because the activity is in-window, window truncation does not naturally explain it; independent filtering or log loss remains possible. Other SMB read/write sizes did not exceed the appropriate responder/originator payload totals for the matched flows.

### DNS content and timing

Core question/response combinations include 2,095 successful A queries, 283 successful AAAA, 115 successful PTR, 102 successful SRV, 331 successful TXT, 174 A/NXDOMAIN, and smaller failure and other-type populations. The TXT volume is not itself proof of artificiality or misuse; contents and application context matter.

At `13:00:12.324914 UTC`, `zeek-core/dns.json:5` records `printer01.meridianhcs.local`, A/NXDOMAIN, with RTT `0.000971`. At `13:01:54.629533`, line 12 records AAAA for `www.redditstatic.com`, answer `2a04:4e42::396`, TTL `2070`. At `13:02:45.947370`, line 16 records PTR for `11.2.10.10.in-addr.arpa`, answer `DC-02.meridianhcs.local`, TTL `7200`, RTT `0.009599`. Domain spelling and public DNS correspondence were not authenticity indicators because sanitization is explicitly possible.

TTLs include short values and larger authoritative/internal values rather than one universal constant. For instance, repeated `ocsp.digicert.com` queries to `10.10.2.10` have different residual TTL values. I did not infer that a connection without a fresh lookup is defective: caches, pre-window resolution, literal addresses, and proxy-side resolution all matter.

### TLS, certificates, and HTTP proxying

For certificate-bearing TLS rows, I checked the offered leaf key type against RSA/ECDSA cipher authentication and found no mismatch. Within each sensor, a repeated certificate fingerprint did not change the certificate's substantive fields, and one issuer/serial pair did not identify different fingerprints. There were no established TLS rows with implausibly near-empty directional byte counts under the simple 100-byte screening threshold used here.

`zeek-dmz/ssl.json:1` uses `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`; its first chain FUID maps to `zeek-dmz/x509.json:1`, whose leaf key type is `ecdsa`, key length 256. The RSA signature algorithm on that leaf is not a contradiction: certificate signing and the leaf's authentication key are separate properties. TLS 1.3's lack of visible certificate chains was not penalized. The interpretation of SNI, establishment, and handshake-history fields follows the [official Zeek TLS schema](https://docs.zeek.org/en/current/scripts/base/protocols/ssl/main.zeek.html).

For the first proxy exchange, the client is `10.10.1.32:57530 → 10.10.3.20:8080`; the proxy's upstream connection is `10.10.3.20:34135 → 142.250.190.110:443`. CONNECT targets `clients6.google.com:443`. The proxy row reports `cs_bytes=520`, `wire_sc_bytes=213`, `tunnel_cs_bytes=4274`, and `tunnel_sc_bytes=34835`; the downstream connection payload totals are 4,794/35,048, exactly control plus tunnel in this example. Its upstream TLS SNI is `clients6.google.com`. Correct accounting in this example supports the path interpretation and is not scored as suspicious completeness.

HTTP also has non-success and persistent-connection behavior. Core line 24 contains a `407 Authentication Required` response, and line 1350 is transaction depth 7 on UID `CMLCE0NpWY6USJQCMT`, serving `/assets/img/hero.webp` with response body length 387,266. Thus, one transaction per TCP connection is not a universal assumption in the observed records.

### Timing and observer interpretation

Matching core and DMZ connection observations by tuple, state, and directional payload totals produced 4,757 unambiguous pairs within a three-second window. Core timestamps minus DMZ timestamps ranged from about 110.3 to 118.4 ms, median 114.2 ms. For 346 DB/DMZ pairs the corresponding range was 168.5–187.5 ms, median 179.6 ms. This is compatible with distinct sensor clock offsets and modest drift; it does not justify millisecond-precision cross-sensor ordering allegations without clock correction.

Core hourly connection counts from 13:00 through 18:59 UTC were 1,779, 3,113, 1,724, 1,856, 2,192, and 1,718. There is meaningful temporal variation. This six-hour slice cannot establish overnight, weekend, or full business-day behavior, so I made no authenticity deduction from their absence.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| contract_gap | Zeek SMB versus same-sensor conn | One UID, one mapping row, two file rows | Small increase: an in-window local reference gap; filtering or delivery loss remains a viable explanation. |
| weak_signal | Zeek export consistency | The same single conversation | Qualifier only, not additional independent evidence. Insufficient to overcome the largely coherent network evidence. |

No demonstrated hard contradiction, generator identity leak, or dataset-wide timing/distribution defect was established in this review.

## Realism Score by Category

- **Field format accuracy:** 9 — Parsed source-like Zeek fields and sensible typed protocol values; no demonstrated native format contradiction.
- **Temporal patterns:** 9 — Service-specific lifetimes, variable hourly load, and plausible sensor offsets; the limited window prevents full-day assessment.
- **Cross-source correlation:** 8 — Protocol tuples and visible timing agree; one SMB conversation has a source-local connection-reference gap.
- **Behavioral realism:** 8 — Proxy tunneling, authentication failures, partial connections, resets, and protocol persistence are represented plausibly.
- **Environmental consistency:** 8 — Core, DMZ, and DB paths have differentiated service mixes; no inference of mandatory platform telemetry was needed.

## Recommendations

- If this were synthetic, preserve the same-sensor connection record for UID `Cr7mRCkac27kS4mWeXo`, or make its omission part of an explicit collection-loss/filtering model that consistently governs the SMB mapping and file companions. The visible issue is the orphaned conversation, not generally thin coverage.
- Preserve the current distinction between proxy control bytes, tunnel bytes, and upstream/downstream tuples when making changes. The first visible CONNECT exchange provides a concrete working example against which corrections can be checked.
