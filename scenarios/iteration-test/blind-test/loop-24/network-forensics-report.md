# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 82
**Synthetic-Confidence Score:** 49

## Executive Summary

The network evidence is substantially coherent: connections, protocol records, files, certificate identities, and visible SSH authentication have plausible relationships, and the checks performed did not establish an impossible protocol lifecycle. Repetitive TCP accounting texture and repeated DNS lookups within positive-answer TTLs raise questions, but neither establishes fabrication without packet-level evidence or knowledge of resolver behavior. I cannot reliably distinguish a carefully modeled dataset from a production capture with these collection assumptions.

## Evidence For Synthetic

- [distribution_texture] TCP byte/packet accounting has a conspicuous low-dimensional texture across sensors and services. For clean TCP histories `ShADadfF` or `ShADadFf`, with `missed_bytes=0`, define each direction's residual as `ip_bytes - bytes - 52*pkts`. Both residuals belong to the tiny set `{4,8,12}` in 1,923/3,735 core records, 116/204 database records, and 2,452/4,691 DMZ records. In the core records the nine possible residual pairs each occur 193–233 times. This resembles small independent adjustments to a common accounting model. It is suggestive texture, not an impossible field value: TCP options, control packets, and ACK behavior can create structured overhead, and observations repeated across sensors are not independent samples.
- [weak_signal] `zeek-core/dns.json` contains 446 consecutive same-client/same-query/same-qtype positive-answer repetitions with a gap greater than one second and less than the preceding minimum TTL, out of 3,188 DNS rows. For example, `10.10.1.34` asks for `mail-fin.meridianhcs.com` at `1793636082.147973` and `1793636083.365718`, obtains `10.10.2.27` both times, and receives TTL 300 both times, switching from resolver `.10` to `.11`. This can reflect over-eager dependency lookup modeling, but multiple resolver libraries, direct application DNS, independent processes, and retries are plausible production explanations. It receives little weight by itself.

## Evidence For Real

- Protocol joins are coherent. In each sensor, every examined DNS, HTTP, SSL, files, SMTP, and SMB-files UID reference resolves to that sensor's connection record; protocol rows with connection tuple fields agree with their connection tuple. No tested protocol row falls more than 200 ms outside the associated visible connection interval.
- TCP states include normal completions, unanswered SYNs, resets in either direction, rejections, and partially closed connections. Every TCP `S0` checked has zero responder packets and zero originator payload, and every TCP `SF` checked contains handshake and both-direction FIN evidence in its history. No overlapping TCP connections with the same four-tuple were found within an individual sensor using a 10 ms overlap threshold.
- DNS is more than an A-record lookup list. Core DNS includes A 2,348, AAAA 297, TXT 264, PTR 158, SRV 103, NS 9, MX 7, and SOA 2; response outcomes include NXDOMAIN, SERVFAIL, and REFUSED. Answer and TTL array lengths match throughout the three sensors.
- The explicit proxy observation path is plausible. Core HTTP is dominated by CONNECT, while the DMZ includes proxy-to-external TLS, externally initiated portal HTTP, and proxy-control HTTP. Successful CONNECT controls can have zero response body, whereas authentication failure can carry an HTML body and file record.
- Certificate identities are internally consistent: repeated fingerprints did not identify conflicting certificate content, and the TLS 1.2 cipher authentication/key-type checks found no RSA/ECDSA leaf mismatch. TLS 1.3 rows avoid exposing certificate chains, consistent with encrypted handshake content in passive observation.
- SSH sessions have genuinely long transport durations rather than uniformly short generic flows. For example, DMZ UID `CWO3ZQWKkMNB3fiGCb` starts at `1793624405.748486` from `10.10.1.31:49670` to `10.10.3.20:22`, lasts 3,682.836674 seconds, and has plausible bidirectional payload. The receiver's `PROXY-01.meridianhcs.local/syslog.log` accepts `marcus.chen` from that source tuple at `2026-11-02T13:00:15.802864Z`, after transport initiation.

## Detailed Analysis

### Scope and method

I examined only files beneath the supplied data directory, with emphasis on all JSON records in `zeek-core`, `zeek-db`, and `zeek-dmz`. I also sampled ASA, Snort, proxy, and Linux SSH records to interpret observation paths and session ownership. This assessment does not infer the presence of an endpoint collector from network records, require absent source families, or use filesystem timestamps, domain resolvability, attack narrative neatness, or completeness of correlation as authenticity indicators.

The connection files contain 12,230 core, 430 database, and 10,481 DMZ observations. These are sensor observations, not a count of distinct enterprise connections; overlapping visibility exists. Their starts span approximately 2026-11-02 13:00–19:00 UTC. This six-hour weekday slice cannot support conclusions about overnight baselines, weekend behavior, or session initiators outside the window.

### Transport behavior and traffic mix

Core traffic contains 6,826 TCP, 4,988 UDP, and 416 ICMP records; database traffic contains 359 TCP, 51 UDP, and 20 ICMP; DMZ traffic contains 8,965 TCP, 1,217 UDP, and 299 ICMP. ICMP echo type/code representation is plausible: the examined records use `id.orig_p=8`, `id.resp_p=0`, and include both answered and unanswered probes.

Core destination-port counts include DNS 3,200, proxy/8080 2,487, Kerberos/88 2,106, LDAP/389 1,143, SMB/445 703, and TCP/443 530. The database sensor is dominated by 3306, with 273 observations, while the DMZ has 3,844 port-443 and 2,753 port-8080 observations. This is compatible with an AD environment using an explicit proxy and a separately observed application/database segment. I do not interpret the small number of some other infrastructure protocols as a defect without a collection contract requiring them.

Core state counts are SF 9,787, S0 1,670, OTH 435, RSTO 156, RSTR 104, REJ 44, S3 14, S2 11, and S1 9. DMZ has substantially more S0 observations, 2,464/10,481, which can reasonably result from visible scanning or filtered destinations. A high failed-connection proportion is not itself evidence of synthetic data.

Connection volume is not flat: core hourly counts for hours 13–18 UTC are 1,681, 3,138, 1,770, 1,758, 2,146, and 1,737; DMZ counts are 1,575, 2,825, 1,508, 1,532, 1,545, and 1,496. The busy 14:00 hour is visible in multiple observation paths. The supplied window does not allow a full business-hours cycle assessment.

The TCP residual pattern described above is my strongest reason for hesitation. It persists within endpoint pairs, not merely across a heterogeneous enterprise: among 281 clean `ShADadfF` records from `185.70.41.45` to `10.10.3.10:443`, all nine `{4,8,12}` residual pairs occur, with counts of 14–24 each. Repeated fixed TCP-stack overhead is normal; the near Cartesian spread of tiny bidirectional variations is the suspicious element. It remains a distribution observation requiring packet capture or TCP-option fields to resolve, and I have not called it a protocol contradiction.

### DNS behavior and caching

Core DNS has 2,965 NOERROR, 206 NXDOMAIN, 12 SERVFAIL, and 5 REFUSED responses. DMZ has 1,023 NOERROR, 126 NXDOMAIN, 2 SERVFAIL, and 1 REFUSED. Database DNS has 44 NOERROR and one NXDOMAIN. Internal and external names, forward and reverse lookups, and service discovery coexist.

There is evidence of realistic TTL aging as well as repeated pre-expiry client lookups. In DMZ, `10.10.3.20` queries `ocsp.digicert.com` via `10.10.2.10` at `1793639789.990476`, with TTLs `[1304,1304]`, and again 142.360079 seconds later at `1793639932.350555`, with TTLs `[1162,1162]`. The nearly exact 142-second TTL decrement is consistent with cached answers. This materially weakens the alternative explanation that the entire DNS stream ignores cache state.

Conversely, database client `10.10.4.10` queries `WEB-EXT-01.meridianhcs.local` at `1793641704.672584` and `1793641705.942636` in `zeek-db/dns.json`, changing resolver and receiving TTL 7200 twice. I cannot identify the application resolver from these records. Treating these repetitions as impossible would overstate the evidence.

### HTTP, proxy, TLS, and files

Core HTTP has 2,405 CONNECT, 199 GET, and 10 POST rows. The DMZ has 2,450 CONNECT, 440 GET, and 17 POST rows. Thus raw HTTP-to-TLS record ratios would be misleading: most of the HTTP is proxy negotiation, not necessarily cleartext page retrieval.

A concrete failure path is database HTTP UID `CejGkF1Vxdvx1XEH8` at `1793624609.745278`: `10.10.4.10:42023` requests `CONNECT security.ubuntu.com:443` through `10.10.3.20:8080`; status is 407, response body is 753 bytes, and `resp_fuids` names `FQ0iz2f8E8pfvGFcC`. That file appears at `1793624609.803541` as HTTP, MIME `text/html`, transmitting from the proxy to the database client with 753 seen/total bytes. The matching connection has 1,083 responder payload bytes, leaving room for headers. This is a coherent control-message/error-body relationship.

Across all tested HTTP rows, response body sizes do not exceed associated connection responder payload plus missed bytes. File and protocol timestamps remain within connection intervals under the stated tolerance. Incomplete sensor observations with nonzero `missed_bytes` can legitimately show sequence-space payload exceeding captured IP payload after headers; I did not misclassify those as impossible byte arithmetic.

DMZ SSL has 2,288 TLS 1.3, 1,011 TLS 1.2, and four incomplete-handshake rows. The core is approximately evenly divided between TLS 1.2 and 1.3, and database SSL is largely TLS 1.2. TLS 1.3 ciphers include AES-GCM and ChaCha20; TLS 1.2 includes ECDHE/AES-GCM and some CBC. Older TLS 1.2 CBC on internal systems is possible and is not sufficient to infer synthesis. I found no demonstrated cipher/key authentication mismatch in available chains and no conflicting content for repeated certificate fingerprints.

### Limits of the conclusion

The strongest positive results are consistency checks, which demonstrate plausibility rather than production provenance. The strongest suspicious observations are distribution-level and have realistic alternative explanations. I therefore place the synthetic-confidence score near the rubric's uncertain midpoint, rather than converting absence of detected contradictions into proof of real data or elevating weak texture into a confident synthetic verdict.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | Zeek TCP conn accounting | Roughly half of clean, non-gap normal-close records in each sensor have both 52-byte-overhead residuals in the same three-value set; nine pair counts are notably balanced | Main reason to retain uncertainty; suggests aggregate modeling but does not prove invalid packets |
| weak_signal | Zeek DNS | 446 core consecutive repeated client/query/type lookups occur inside prior positive TTL, with examples also at database sensor | Small upward influence only; application resolver behavior and retries can explain it, and external TTL aging is realistic |

## Realism Score by Category

- **Field format accuracy:** 9 — Native-looking tuples, histories, protocol fields, body accounting, and certificate identities; no established impossible field values.
- **Temporal patterns:** 8 — Varied hourly loads, plausible long SSH sessions, compatible protocol lifetimes; full day/night behavior is outside scope.
- **Cross-source correlation:** 9 — All tested sensor-local joins and tuples agree, and sampled SSH/proxy relationships are causally plausible.
- **Behavioral realism:** 7 — Plausible infrastructure, proxy failures, and scanning, with unresolved TCP accounting texture and resolver repetition.
- **Environmental consistency:** 8 — AD, proxy/DMZ, and database observation paths fit the visible roles; limited collection context prevents stronger attribution.

## Recommendations

- If this were synthetic, derive transport byte and packet totals from explicit segment/header/ACK behavior or a measured per-stack model. Validate whether the repeated `{4,8,12}` bidirectional residual lattice and balanced pair frequencies resemble captures from the represented endpoint stacks.
- If this were synthetic, give DNS generation application-aware resolver and cache behavior. Retain direct-query clients and retries when appropriate, while making rapid repeated positive-answer lookups distinguishable from ordinary shared OS-cache use. Preserve the already plausible recursive TTL aging visible in external queries.
- To resolve the existing uncertainty, retain selected packet-level exemplars or TCP-option/ACK summaries for the cited accounting groups, and resolver attribution for the cited repeated DNS requests. These additions would substantiate the current fields rather than merely expand source coverage.
