# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Real
**Verdict Confidence:** 65
**Synthetic-Confidence Score:** 18

## Executive Summary

The network telemetry is consistent with production collection across core, DMZ, and database observation points. Broad checks of connection state, packet accounting, protocol timing, certificate identity, HTTP payloads, and DNS behavior revealed no demonstrated hard contradiction or material synthetic indicator. The Real verdict is moderately confident: this is an assessment of observable network authenticity, and a sufficiently careful simulation could reproduce the same properties.

## Evidence For Synthetic

- No material synthetic indicator was established in the network sources examined. In particular, I found no impossible visible protocol ordering, conflicting concurrent TCP five-tuples, incompatible TLS cipher/certificate key pairs, invalid certificate observation dates, or file/body byte totals exceeding their associated connection payloads after accounting for source semantics.
- The visible interval is roughly six hours on one day. This limits conclusions about longer operational cycles; it does not count as evidence for synthetic generation and does not increase the score.

## Evidence For Real

- `zeek-core/conn.json`, `zeek-dmz/conn.json`, and `zeek-db/conn.json` contain materially different traffic profiles appropriate to their apparent observation paths: core has substantial Kerberos/LDAP/SMB traffic; DMZ is dominated by proxy/web/TLS traffic and scans; the database sensor has 296 MySQL connections among 445 total connections.
- TCP states include successful connections, unanswered SYNs, rejections, resets, partially closed connections, and ongoing sessions. Core has 9,607 `SF`, 1,583 `S0`, 157 `RSTO`, 95 `RSTR`, and 28 `REJ` rows; these are not all successful placeholder flows. Protocol and byte-count checks respect these state distinctions.
- DNS includes positive responses, IPv6 answers and empty AAAA responses, PTR/SRV records, NXDOMAINs, SERVFAILs, and REFUSED responses. Core has 282 AAAA, 155 PTR, and 98 SRV transactions alongside 2,342 A queries and 190 TXT queries.
- A concrete DNS-to-TLS relationship is plausible: in `zeek-dmz/dns.json`, `CA2HG10SRDtRJ6Ky1Gj` at epoch `1793624671.818962` resolves `static.xx.fbcdn.net` to `31.13.65.38` and `.39`; the DNS RTT is `0.056902`. TLS connection `CYXPznEWXaAeiDyFTd` subsequently reaches `.38:443` with that SNI at `1793624672.002183`, after the response could have arrived.
- TLS metadata respects important visibility differences. No TLS 1.3 SSL row exposes `cert_chain_fuids`; visible certificate chains are associated with TLS 1.2. Where certificate chains are linked, issuer/subject relationships, file SHA1/fingerprint values, validity intervals, and authentication cipher/key types agree.
- HTTP browsing includes persistent connections with multiple transaction depths, referers, multiple asset types, redirects, cache responses, proxy authentication failures, and gateway errors. CONNECT control-message lengths are kept distinct from tunneled application traffic.
- Packet loss is represented coherently. For example, core SSH connection `CiZgO1p8sZ07CstyvB` has `missed_bytes=129` and history `ShADadfFg`, whereas its DMZ view `CwgG7zAF0i92sW9N9w` has no missed bytes and a different observed responder packet count.

## Detailed Analysis

### Scope and method

I examined only the supplied data directory. I parsed all JSON records in the three Zeek sensor directories, including connection, DNS, HTTP, SSL, X.509, and files logs, plus the available DHCP, SMTP, SMB, OCSP, and PE companions. I also inspected the ASA firewall format and representative proxy and Snort records. The strongest conclusions below come from complete structured checks of the Zeek connection and protocol families, rather than claims of exhaustive semantic review of every firewall or endpoint record.

There are 22,613 connection rows: 11,964 core, 10,204 DMZ, and 445 database. The core connection-start interval is November 2, 2026, `13:00:01.808746–18:59:43.470888 UTC`; the other sensors cover essentially the same slice. Connections can legitimately close outside that interval, so I did not require all lifecycles to terminate inside the collection window.

I checked all 4,244 DNS, 5,467 HTTP, 3,580 SSL, 238 SMB-file, and 79 SMTP rows against the connection UID in their own sensor. Every checked protocol UID resolved; its four address/port fields matched the parent connection; and its timestamp fell within the connection interval using a small rounding tolerance. This supports coherence, but completeness of matching is not itself evidence against synthetic origin.

### Connection states, transport accounting, and lateral sessions

Connection-state distributions vary by network role rather than remaining identical across sensors. The database sensor has 355 `SF`, 31 `RSTO`, 21 `RSTR`, eight `S3`, four `S2`, two `S0`, and one `REJ` row, alongside 23 `OTH` observations. DMZ has 2,386 `S0` rows, consistent with visibly substantial scanning: 1,529 originate at `10.10.3.10`, and several external addresses contribute additional probe traffic. Most of these are single-SYN observations. That is compatible with scanning and is not an authenticity defect by itself.

I found no overlapping visible TCP connection intervals sharing the same directional five-tuple within one sensor. Successful TCP connections have both originator and responder packet observations; `S0` rows do not contain contradictory responder packet counts.

For each connection, payload bytes do not exceed observed IP bytes. Some captured IP totals are smaller than logical stream bytes plus a minimum per-packet header allowance; every such shortfall is covered by the row's `missed_bytes`. These are consistent with Zeek's stream accounting across capture gaps, rather than impossible negative transport overhead. I did not count those rows as defects.

Long sessions are supported rather than replaced with uniformly tiny connections. The SSH flow from `10.10.3.10:44919` to `10.10.2.30:22`, DMZ UID `CwgG7zAF0i92sW9N9w`, starts at `1793632498.565312` and lasts `13320.892689` seconds. Its core counterpart has the same endpoint tuple and stream byte totals but a small observation-time offset and different loss/packet metadata. Such observation differences are plausible and do not require identical sensor clocks or captures.

### DNS behavior

Core response outcomes are 2,838 NOERROR, 226 NXDOMAIN, 11 SERVFAIL, and three REFUSED. AAAA queries include both genuine IPv6 answer strings and NOERROR responses without addresses. I found no IPv4 literals masquerading as AAAA answers and no error responses carrying contradictory positive answer lists.

Suffix-search behavior is visible without needing to assume it on every platform. For example, core UID `Cz8RW15bkG2cGY5nrs` at `1793624929.862894` queries `mail.meridianhcs.com.meridianhcs.local` and receives authoritative NXDOMAIN. Other records include `isatap` and reverse lookups. These are plausible operational failures rather than a dataset consisting entirely of successful preconnection resolutions.

TTLs and answers are internally consistent where infrastructure stability is expected. All 18 visible `_ldap._tcp.meridianhcs.local` transactions directed to `10.10.2.10` in core return the same two domain-controller targets with TTLs of 300 seconds. External lookups also show short TTLs and a broader response-time range. No DNS RTT exceeds the corresponding connection's recorded duration beyond rounding tolerance.

The TXT activity near `1793641498.760807` includes variable subdomains of `ns1.westbridge-services.cloud` and low TTLs. That is suspicious network behavior worth investigating, but suspicious behavior is not a synthetic indicator and I did not score it as one.

### HTTP, proxying, and file transfer

Core HTTP contains 2,389 CONNECT, 176 GET, and 14 POST records. DMZ includes 2,435 CONNECT, 415 GET, and 18 POST records; the database sensor has 20 CONNECT records. Proxying explains why a large proportion of visible HTTP is CONNECT while external application sessions appear as TLS; a raw HTTP/HTTPS row ratio would otherwise be misleading.

For example, core UID `CXI6ZjPM8yTrX7JOnlj` from `10.10.1.41:49624` to `10.10.3.10:80` has seven HTTP transactions from `1793624726.213800` through `1793624730.931412`. It requests a page, CSS, JavaScript, favicon, WebP image, and SVG image, with increasing transaction depths and appropriate referers. Repeated versioned CSS/JavaScript assets retain stable sizes and hashes across observations.

I summed request and response body lengths by HTTP UID; neither directional total exceeds its connection's payload. Likewise, aggregate `seen_bytes` for file records sharing a connection and direction never exceeds that directional stream payload. I found no nonzero response bodies for status 304/204, and no successful CONNECT rows with control-message body lengths incorrectly populated by tunneled payloads.

The proxy access log explicitly distinguishes CONNECT control-message scope from tunnel byte counts. This is a custom logging choice, not by itself evidence of a native format violation or generator identity.

### TLS and certificate evidence

DMZ has 2,187 TLS 1.3 rows and 974 TLS 1.2 rows, plus one negotiation without a recorded version. Its ciphers include AES-GCM and ChaCha20 TLS 1.3 suites, ECDHE RSA/ECDSA GCM suites, and a smaller CBC legacy component. That is plausible for mixed browser, service, and enterprise application traffic; I do not infer synthetic origin merely from legacy cryptography being present.

Of 3,580 SSL rows overall, 1,267 are marked resumed. Some negotiations are incomplete, with `established=false` and reduced history/metadata. Visible TLS 1.2 certificates retain stable identities across repeated observations, and I found no fingerprint associated with conflicting certificate metadata within a sensor.

All linked chain issuers match the next certificate's subject. All observed X.509 timestamps fall inside their stated validity intervals. ECDHE-ECDSA suites do not present an RSA leaf in the linked certificates, and ECDHE-RSA suites do not present an ECDSA leaf. All certificate-file SHA1 values match the corresponding X.509 fingerprints where both are present. TLS 1.3's encrypted certificate exchange is not incorrectly exposed as a passive certificate chain.

### Traffic timing and collection limits

Core hourly connection-start counts are 1,689, 3,190, 1,765, 1,752, 1,798, and 1,770 from 13:00 through 18:00 UTC. DMZ likewise has a larger 14:00 hour than its surrounding hours. Visible scan traffic supplies a concrete explanation for a shared activity spike; the spike alone is not evidence of scripted generation.

This window does not support claims about weekend suppression, overnight maintenance, or full business-day volume. I have not penalized the data for sources, protocol families, or initiators that could legitimately be outside the collection profile or time window.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on synthetic-confidence score |
|---|---|---|---|
| No substantiated material indicator | Zeek connection/protocol/file/certificate families | Full structured checks described above | No upward adjustment for contradiction, lifecycle, or schema defects |
| Assessment limitation; not an indicator | Network collection overall | Approximately six-hour slice; no packet capture supplied | Limits verdict confidence, without treating limited coverage as synthetic evidence |

The score of 18 reflects production-like observable network behavior, not certainty that the source must be real. Complete source matching, domain identities, suspicious narrative structure, and filesystem copy timestamps were not used as synthetic indicators.

## Realism Score by Category

- **Field format accuracy:** 9 — Parsed network records have coherent types, hash lengths, DNS answers, HTTP semantics, and certificate metadata.
- **Temporal patterns:** 9 — Protocol transactions fit connection intervals; DNS-to-connect examples and persistent HTTP sequences are plausible.
- **Cross-source correlation:** 9 — Tuples, file hashes, certificate chains, directional byte budgets, and differing sensor observations agree where checked.
- **Behavioral realism:** 9 — Traffic includes ordinary services, proxy failures, DNS failures, scans, persistent browsing, resumption, and long remote sessions.
- **Environmental consistency:** 9 — Core, DMZ, and database protocol mixes support distinct observation roles without requiring identical coverage.

## Recommendations

- If this were synthetic, retain the demonstrated separation of CONNECT control messages, TLS sessions, and passive TLS 1.3 visibility, along with coherent capture-gap accounting and stable file/certificate identity.
- No specific network realism repair is justified by a demonstrated defect in this review. A longer time slice or packet capture would allow additional validation of operational cycles and transport details; their absence here is a limitation on assessment, not a flaw requiring a synthetic-data score penalty.
