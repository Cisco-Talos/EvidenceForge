# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 85
**Synthetic-Confidence Score:** 38

## Executive Summary

The network evidence is mostly production-like: connection states, protocol timestamps, proxy tunnels, TLS visibility, certificate relationships and packet accounting withstand several direct consistency checks. Browser user-agent versions switch on several individual Windows clients in a way that could reflect independent template pools, but the logs do not establish that these requests belong to one browser installation; that weak concern is insufficient for a reliable real-versus-synthetic classification.

## Evidence For Synthetic

- [weak_signal] Several clients alternate between otherwise identical Chrome user-agent strings differing only in major version. In `zeek-core/http.json`, client `10.10.1.36` uses Chrome 121 at line 2 (`13:01:18.162617Z`), Chrome 120 at lines 4, 6, 7 and 9, and Chrome 121 again at line 44 (`13:10:10.860359Z`). Client `10.10.1.34` uses Chrome 119 at lines 72 and 117, Chrome 120 at lines 198–201, Chrome 119 at line 206, and Chrome 120 again at lines 221–222. Across that file, `10.10.1.32` has 25 Chrome-121 and 20 Chrome-120 rows; `10.10.1.34` has 21 Chrome-119 and 34 Chrome-120 rows; `10.10.1.36` has 10 Chrome-121 and 104 Chrome-120 rows. Reversible version switching across several clients is compatible with separate browsing-generation pools. However, parallel browser installations, embedded Chromium clients and deliberate user-agent overrides are plausible alternatives, so this remains weak evidence rather than a demonstrated contradiction.

## Evidence For Real

- Protocol records have coherent local flow ownership. All 11,925 DNS, HTTP and SSL records across the three sensors resolve to a same-sensor `conn.json` UID with the same four-tuple; their timestamps fall within the corresponding connection interval. None of these records was attached to an `S0` or `REJ` connection.
- Connection outcomes are varied and not uniformly successful. Core has 9,765 `SF`, 1,663 `S0`, 136 `RSTO`, 116 `RSTR`, 26 `REJ`, and additional partial/midstream states; DMZ has 6,354 `SF`, 2,467 `S0`, 121 `RSTO`, 63 `RSTR`, and 31 `REJ`. These counts include a sensible failed-connection population alongside productive service traffic.
- DNS contains A, AAAA, PTR, SRV and TXT queries, negative responses and empty AAAA answers. `zeek-core/dns.json:5` records `printer01.meridianhcs.local` returning NXDOMAIN; line 29 records `wpad` returning NXDOMAIN. This is more credible than a resolver view containing only successful forward lookups.
- TLS 1.3 observations consistently omit certificate chains and show limited `ssl_history=Cs`, while full TLS 1.2 handshakes expose certificate evidence. For example, `zeek-dmz/ssl.json:2` has `TLSv13`, `TLS_AES_128_GCM_SHA256`, and no certificate-chain fields; line 1 has TLS 1.2 with a two-certificate chain.
- Proxy and flow byte accounting is internally useful rather than merely sharing names. `PROXY-01.meridianhcs.local/proxy_access.log:1` gives 520 control-request bytes, 213 control-response bytes, and tunnel payloads of 4,274/34,835 bytes. These sum to the 4,794/35,048 transport payload bytes in `zeek-dmz/conn.json:1`; the corresponding HTTP CONNECT has zero message bodies, as expected for a successful tunnel control exchange.
- Long-lived administrative transport differs from brief web and directory traffic. `zeek-core/conn.json:7` records a 3,659.196919-second SSH connection from `10.10.1.35:65202` to `10.10.2.30:22`, with asymmetrical 22,872/150,847 payload bytes; SSH is not represented solely by short generic web-like connections.

## Detailed Analysis

### Scope, provenance and method

I read the supplied neutral reviewer briefing and files under `/private/tmp/log-study-boe6lty3/data` only. Parsing used system `python3` from `/private/tmp`. I did not inspect repository code, scenarios, roadmap/worklogs, previous assessments, other reviewers' reports or project web pages. Generic inherited operating instructions were not used as evidence of origin. No external research was needed for the findings below.

The bulk analysis covered every JSON record in the three Zeek sensor directories. I also sampled firewall, proxy and IDS records to interpret the observation path and compare concrete tuples and accounting. I did not attempt a comprehensive endpoint lifecycle assessment. All line references are one-based physical lines within the named file; timestamps below are UTC.

There are 21,936 connection rows: 12,162 core, 392 DB and 9,382 DMZ. Protocol populations are 4,235 DNS rows, 4,631 HTTP rows and 3,059 SSL rows. Sensor observations are counted separately; these totals are not unique physical flows. The core connection slice runs from `2026-11-02T13:00:02.512987Z` to `18:59:50.133776Z`. A six-hour daytime slice cannot establish overnight or weekend behavior, and I did not penalize the lack of those periods.

### Flow identities, timing and accounting

I joined each DNS, HTTP and SSL row to its sensor-local connection by UID, compared originator/responder addresses and ports, and checked that its event timestamp fell between connection start and start plus duration, allowing one millisecond of numerical tolerance. There were no missing joins, tuple mismatches or out-of-interval observations. This is evidence of coherent construction or collection, not proof of either authenticity class.

For each sensor I grouped TCP connections by directed four-tuple and compared visible intervals. I found no overlapping distinct TCP connections reusing the same tuple. I also found no connection with `orig_ip_bytes < orig_bytes` or `resp_ip_bytes < resp_bytes`. Every HTTP request and response had sufficient transport payload bytes for its reported body and a conservative lower bound on visible HTTP start-line/header text. Every DNS question had at least the minimum wire length required by its visible name, and successful A/AAAA answers had enough response bytes for a compressed answer representation. Summed visible certificate-file bytes never exceeded the corresponding TLS responder payload.

Connection histories include normal closure, reset and retransmission/gap variants. I did not treat a majority of normal `ShADadfF` histories as suspicious: common TCP exchange histories are naturally repetitive. A single core SMB flow (`conn.json:8939`, UID `CccRMsIb0QC3sGpNYG`) has roughly 1,471 originator payload bytes per packet. That is not a demonstrated defect without knowing link MTU, capture/offload behavior and how the counters were derived, so it does not affect the score.

### DNS and name use

Core DNS has 2,311 A, 260 AAAA, 163 PTR, 100 SRV, 330 TXT, 10 NS, seven MX and two SOA rows. Its responses include 218 NXDOMAIN, 21 SERVFAIL and six REFUSED records. DMZ has 138 NXDOMAIN, nine SERVFAIL and one REFUSED. Address-valued answers matched their A/AAAA address family throughout the inspected files. Empty successful AAAA results occur rather than being incorrectly replaced by IPv4 answers.

The first core DNS row queries `_ldap._tcp.meridianhcs.local`, gets two domain-controller names with 300-second TTLs, and owns a short UDP connection. `zeek-dmz/dns.json:1` and `zeek-core/dns.json:3` show the same resolver transaction for `ocsp.pki.goog` using sensor-local UIDs, matching transaction ID 20487 and matching answer addresses. Their timestamps differ by approximately 115 milliseconds. Without sensor clock-calibration information, that difference is not an impossible causal ordering.

Resolver answers include short CDN-style TTLs, longer internal TTLs and variable values. I did not test public domain resolution or use domain spelling as origin evidence, because sanitization is explicitly possible. Nor did I require a fresh DNS row before every connection: caching, application reuse and collection boundaries make that requirement invalid.

### HTTP, explicit proxying and TLS

Most HTTP observations are CONNECT control exchanges: 1,965 of 2,176 core HTTP rows and 2,019 of 2,441 DMZ rows. Thus, an HTTP-to-HTTPS ratio based simply on file row counts would misclassify encrypted proxy traffic. The first core and DMZ HTTP rows show the same `10.10.1.32:57530 -> 10.10.3.20:8080` tunnel request for `clients6.google.com:443`, while a separate DMZ connection carries the proxy's outward TLS leg. `fw-perimeter/cisco_asa.log:1–3` supplies a translation and distinct connection records for the proxy-side and external legs. That separation is operationally plausible.

TLS versions differ by environment: core has 181 TLS-1.3, 168 TLS-1.2 and one incomplete-version observation; DMZ has 1,834 TLS-1.3, 859 TLS-1.2 and three incomplete-version observations; DB's 13 SSL rows are all TLS-1.2. Modern AEAD ciphers coexist with older internal CBC suites. The older suites are possible within an enterprise and do not constitute a contradiction.

I checked every available leaf certificate attached to an SSL chain against observation time and cipher authentication type. None was visibly expired/not-yet-valid, none of the RSA-authenticated ECDHE handshakes had an ECDSA leaf, and none of the ECDSA-authenticated ECDHE handshakes had an RSA leaf. Adjacent chain subjects/issuers and signing-key algorithm families agreed. Repeated certificate fingerprints retained the same visible certificate attributes across sensors. TLS-1.3 records did not unexpectedly expose cleartext certificate chains. These findings materially reduce the case for a high synthetic-confidence score.

The user-agent version alternation described above remains the principal concern. I can show repeated version reversals, but cannot establish a common executable, browser profile or installation identity from network requests alone. The user-agent concern consequently receives limited weight.

### Volume and environmental interpretation

Core hourly connection counts are 1,779, 2,978, 1,801, 1,771, 2,112 and 1,721, rather than an identical count every hour. DB observations are much smaller and predominantly MySQL: 260 service-labelled MySQL connections out of 392 total, with median duration 2.183742 seconds and a maximum of 29.182290 seconds. Core has substantial Kerberos, LDAP and SMB activity; DMZ combines proxy traffic, external service traffic and failed probes. These role-dependent differences are plausible.

The available period is too short to determine whether traffic cadence across days, certificate renewal over months, or resolver cache behavior over longer periods is production-like. I found no reason to require QUIC, Bonjour or a particular endpoint collection product merely because some observed clients use macOS. Thin source families were not scored as defects.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
| --- | --- | --- | --- |
| `weak_signal` | Zeek HTTP and corroborating proxy user-agent strings | Chrome-version reversals on three Windows client IPs in the core HTTP file | Suggests independently chosen version pools, but parallel installations or embedded clients remain plausible; limited upward weight only. |

No demonstrated hard contradiction, required-companion gap or native format defect emerged from the network checks. The score remains in the mostly-realistic band because this review cannot distinguish well-constructed synthetic telemetry from a coherent sanitized production slice.

## Realism Score by Category

- **Field format accuracy:** 9 — Parsed Zeek structures, TLS/certificate attributes and protocol byte lower bounds were coherent.
- **Temporal patterns:** 8 — Variable traffic counts and service-specific durations; no same-identity interval contradictions found, with only six hours available.
- **Cross-source correlation:** 9 — Protocol/connection ownership and sampled proxy/firewall flow relationships agree; this is supportive, not proof of origin.
- **Behavioral realism:** 7 — Diverse network activity and failures, tempered by repeated browser-version switching on individual clients.
- **Environmental consistency:** 8 — Distinct core, DMZ and database traffic profiles and a plausible explicit-proxy path; collection limitations prevent stronger claims.

## Recommendations

- If this were synthetic, bind browser user-agent versions to stable executable/profile identities and use explicit update events or separate installed-client identities to explain version changes. Review `zeek-core/http.json:2,4,44` and `72,117,198,206` as concrete examples; preserve legitimate multi-client behavior where it is intended.
- If this were synthetic, preserve the existing separation between CONNECT control bytes, encrypted tunnel payloads and independent proxy egress connections. The first proxy-access and DMZ connection rows provide a sound accounting contract to retain when changing traffic behavior.
