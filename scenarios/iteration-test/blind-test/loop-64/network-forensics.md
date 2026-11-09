# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 82
**Synthetic-Confidence Score:** 25

## Executive Summary

The network slice is broadly production-like: transport states, protocol records, proxy behavior and certificate relationships withstand the specific consistency checks performed. A concentration of DNS answers at a 30-second TTL is a weak distribution concern, but it has plausible resolver-policy explanations; I found no demonstrated hard contradiction that establishes synthetic origin.

## Evidence For Synthetic

- [weak_signal] **Repeated DNS TTL floor.** In `zeek-dmz/dns.json`, 189 of 656 A-answer records whose query did not end in `.local` or `.arpa` have every returned TTL equal to 30; the corresponding core count is 192/771. For example, DMZ lines 4, 34, 56 and 119 repeatedly return `[30.0,30.0]` for `pypi.org` from resolver `10.10.2.10`, interspersed with `[38.0,38.0]` at line 28 and `[54.0,54.0]` at line 86. This could reflect a clipped cache-aging model, but minimum-TTL policy, short authoritative TTLs, refreshes and cache behavior are viable alternatives. It is a limited texture signal, not impossible DNS behavior, and receives little weight.

## Evidence For Real

- **Transport failures have compatible packet evidence.** `zeek-dmz/conn.json:2` is a TCP/5985 attempt with `conn_state=S0`, `history=S`, one originator packet and zero responder packets. `zeek-dmz/conn.json:595` is a rejected TCP/443 attempt with `history=Sr`, one packet each way and zero payload. `zeek-core/conn.json:11` has `RSTO`, `history=ShADaR`, client payload and no server payload. These represent different failure mechanisms rather than interchangeable failure labels.
- **Actual HTTP semantics survive correlation.** `zeek-core/http.json:3` is a 304 response with zero body, on the same connection as preceding object requests. Its DMZ counterpart at `zeek-dmz/http.json:3` preserves that behavior while using the DMZ sensor's distinct UID. Across all HTTP records, no checked 304 or successful CONNECT record claims a response body, and summed request/response bodies never exceed the corresponding connection's directional payload count.
- **TLS details are internally compatible.** `zeek-core/ssl.json:1` negotiates TLS 1.2 with `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`; the referenced leaf at `zeek-core/x509.json:1` has an RSA key and matching internal hostname SAN. `zeek-db/ssl.json:7` records a resumed TLS 1.2 session with the abbreviated `ssl_history=CsiI`. TLS 1.3 records do not require visible plaintext certificates.
- **DNS includes multiple realistic outcomes and record types.** Core DNS contains 208 NXDOMAIN, 13 SERVFAIL and four REFUSED results alongside successful A, AAAA, PTR, SRV, TXT, SOA, NS and MX observations. `zeek-db/dns.json:35` shows authoritative NXDOMAIN for `wpad.meridianhcs.local`; `zeek-dmz/dns.json:3` separately shows NXDOMAIN for bare `wpad`.
- **Infrastructure and observation differences fit the visible paths.** Database-sensor TCP traffic is dominated by MySQL; core traffic contains Kerberos, LDAP and SMB; DMZ traffic contains substantial proxy and TLS activity. These are positive coherence observations, not claims that complete matching proves authenticity.

## Detailed Analysis

### Scope, method and actual input provenance

I read the complete supplied neutral briefing, `/private/tmp/log-study-pifdrjj7/network-prompt.md`, then inventoried only its `data` directory. I parsed every supplied Zeek JSON file using system `python3`, with explicit working directory `/private/tmp/log-study-pifdrjj7`. The main network population comprises 22,296 connection records, 4,239 DNS records, 4,667 HTTP records, 3,116 SSL records, 1,227 X.509 records and 2,318 file-analysis records, plus the supplied DHCP, SMB, SMTP, OCSP and PE records. I also inspected the first six displayed lines of the supplied ASA, core Snort and proxy-access files. The endpoint files were inventoried by pathname and size but their contents were not examined.

No project source, scenario, TODO, worklog or previous assessment files were accessed. Generic inherited project operating instructions were present as an environment limitation and were not used as authenticity evidence. External references were direct upstream Zeek source/documentation only, listed alongside the relevant interpretations below; no task-project public material or general web search was accessed. There was no forbidden-input exposure during this review.

All file/line references in this report are relative to `/private/tmp/log-study-pifdrjj7/data`, with one-based physical line numbers. Counts are sensor observations, not deduplicated global sessions.

The connection-start window is approximately 2026-11-02 13:00–18:59 UTC. This is insufficient to assess overnight or weekend cadence. Connections can extend beyond the last observed start; missing post-window closure or pre-window initiators were not scored.

### Connection state, timing and byte accounting

| Sensor | Connections | SF | S0 | RSTO | RSTR | REJ | OTH |
|---|---:|---:|---:|---:|---:|---:|---:|
| Core | 12,489 | 9,995 | 1,685 | 156 | 106 | 32 | 471 |
| Database | 468 | 372 | 2 | 32 | 27 | 6 | 24 |
| DMZ | 9,339 | 6,321 | 2,462 | 106 | 71 | 30 | 326 |

These totals include UDP and ICMP; TCP-only judgments were applied only to TCP rows. S1/S2/S3 also occur. The sizable DMZ S0 population is compatible with visible external probing, including line 2, and is not independently an authenticity defect.

For each sensor I checked referenced protocol UIDs against its own connection table, endpoint tuples, and protocol timestamps against the connection interval. DNS, HTTP and SSL had no orphan UIDs, tuple mismatches, or protocol timestamps before connection start or beyond its visible duration within the stated tolerances. The same start/interval checks passed for supplied file, SMB, SMTP and DHCP relationships. Distinct TCP connection rows did not overlap on an identical directional four-tuple within any sensor.

I also checked history against terminal states: TCP SF rows had both FIN directions; RSTO/RSTR had the corresponding reset direction; S0 lacked a responder history; TCP OTH lacked an originator SYN. These checks found no contradiction. They are bounded consistency checks, not a complete packet reconstruction.

An apparent small IP-header budget on gap-bearing rows was deliberately **not** scored. For example, `zeek-core/conn.json:307` reports responder payload 32,799, responder IP bytes 33,552, 28 responder packets, `missed_bytes=375`, and history ending in `g`. TCP payload totals can derive from sequence numbers while IP-byte totals reflect observed packets, so capture gaps can explain the apparent discrepancy. The [official connection-field documentation](https://docs.zeek.org/en/current/scripts/base/protocols/conn/main.zeek.html) supports that distinction.

Hourly starts are uneven: core counts for hours 13–18 are 1,818, 3,299, 1,686, 1,718, 2,073 and 1,895; DMZ counts are 1,256, 2,990, 1,046, 1,197, 1,281 and 1,569. TCP durations range from short transactions to sessions lasting hours; the core maximum is 13,302.522346 seconds. I did not find a fixed-count cadence that warrants scoring.

### DNS and application protocols

The DNS population contains both fast internal answers and slower external resolutions. Core SRV line 1 answers `_ldap._tcp.meridianhcs.local` with two DC hostnames; its UID matches `zeek-core/conn.json:1`, a one-packet-each-way UDP exchange. An AAAA NOERROR response without an address, such as core DNS line 7, can be NODATA and was not treated as a defect. Domain real-world resolution was not investigated because sanitization is permitted.

TXT answers containing `TXT <length> <text>` and SRV answers containing target names are legitimate Zeek representations; I verified these against [upstream DNS logging code](https://raw.githubusercontent.com/zeek/zeek/master/scripts/base/protocols/dns/main.zeek). The lower-bound DNS query/answer size checks performed did not reveal impossible packet sizes. The 30-second concentration remains the sole weak concern described above; the data does not establish its cause.

Most HTTP records are CONNECT transactions: 2,005/2,209 on core, 21/28 on database and 2,059/2,430 on DMZ. Accordingly, raw HTTP-row counts do not imply that the environment predominantly browses over unencrypted HTTP. Core HTTP line 4 is a successful CONNECT for `th.bing.com:443` directed to `10.10.3.20:8080`; proxy-access line 1 describes that connection as a tunnel and distinguishes control-message bytes from tunneled bytes. This is a plausible explicit-proxy path.

HTTP includes 301/302/304/403/407/502/503/504 responses, partial-content responses and persistent connections with multiple transaction depths. No duplicate transaction depth within an HTTP UID was found. I did not assume that optional protocol-source coverage, such as absent MySQL application logs, was mandatory.

### TLS, certificates and lateral traffic

DMZ SSL comprises 1,877 TLS 1.3, 789 TLS 1.2 and four records without a negotiated version. Database SSL is TLS 1.2. The cipher population includes AES-GCM, ChaCha20 and some TLS 1.2 CBC suites; internal legacy TLS is plausible rather than intrinsically synthetic.

I checked every supplied leaf referenced by an SSL chain for RSA/ECDSA cipher compatibility where the TLS 1.2 cipher imposed that requirement. Chain issuer/next-subject names matched. Repeated certificate fingerprints retained consistent certificate fields, including across sensors; X.509 fingerprints agreed with the matching file SHA-1 values. Repeated SHA-256 file identities did not disagree on total size. TLS history meanings were checked against [upstream SSL logging code](https://raw.githubusercontent.com/zeek/zeek/master/scripts/base/protocols/ssl/main.zeek).

Core includes 54 SSH and 21 RDP service observations, together with SMB and directory services. These are plausible lateral-service classes, but classifying every session as authorized or malicious would require business and endpoint context beyond this network review. Their existence and compactness were not scored as synthetic indicators.

## Synthetic Indicator Summary

| Indicator | Category | Affected source family | Scope | Score effect and alternatives |
|---|---|---|---|---|
| Concentration at TTL 30 | weak_signal | Zeek DNS | 189/656 qualifying DMZ A-answer rows; 192/771 core rows; repeated same-resolver examples cited above | Small upward influence only. Could be clipping in a synthetic cache model, but resolver policy and real short-lived answers remain viable. |
| Hard contradictions | None established | Tested network relationships | The checks described above | No high-score basis found; passing checks do not prove production origin. |

## Realism Score by Category

- **Field format accuracy:** 9 — Parsed source structures and tested protocol fields are credible; untested native details remain.
- **Temporal patterns:** 8 — Varied rates and durations, with no demonstrated same-identity inversion; six hours cannot establish full daily behavior.
- **Cross-source correlation:** 9 — Checked UID, tuple, file and certificate relationships are coherent; this supports consistency, not origin proof.
- **Behavioral realism:** 9 — Proxy negotiation, cached HTTP responses, DNS failures and diverse transport outcomes are plausible.
- **Environmental consistency:** 9 — Sensor-specific service distributions fit the visible network placement without imposing absent source requirements.

## Recommendations

- If this were synthetic, validate the repeated TTL-30 population against an explicit resolver cache/minimum-TTL policy. If no such policy is intended, derive returned TTLs from cache insertion, expiry and refresh state instead of an unexplained common floor.
- No other corrective change is justified by a demonstrated network defect in this review. Packet captures and sensor configuration would help resolve the TTL interpretation, but their absence is not itself a realism penalty.
