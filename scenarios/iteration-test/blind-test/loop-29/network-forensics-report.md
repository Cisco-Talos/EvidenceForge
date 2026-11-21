# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 82
**Synthetic-Confidence Score:** 57

## Executive Summary

The network evidence is substantially production-like: TCP state histories, DNS semantics, TLS certificate relationships, protocol timestamps, and observations across sensors generally agree. A repeatable byte-accounting discrepancy in explicitly opaque proxy tunnels raises a meaningful synthetic concern, but the custom proxy counters and absence of packet captures leave enough room for a collection or forwarding explanation that I cannot confidently classify the dataset as synthetic or real.

## Evidence For Synthetic

- [contract_gap] Completed proxy tunnels sometimes have inconsistent upstream stream totals and downstream tunnel counters. For example, `PROXY-01.meridianhcs.local/proxy_access.log` at **2026-11-02 15:13:44 UTC** records `CONNECT registry.npmjs.org:443`, status 200, `proxy_action=tunnel`, `tunnel_cs_bytes=757`, and `tunnel_sc_bytes=2291`. Its matching downstream `zeek-dmz/conn.json` connection `CnAYzGVIkGoKKwfCFr` has `orig_bytes=1134` and `resp_bytes=2468`, exactly the recorded 377-byte CONNECT request plus 757 tunneled bytes and 177-byte control response plus 2291 tunneled bytes. The unique nearby proxy-originated TLS connection for the same SNI, `C5Yh4FBsWKQk3noTSby`, instead has `orig_bytes=757`, `resp_bytes=3684`: **1393 additional upstream response bytes**. Both connections are `SF`, `missed_bytes=0`, `history=ShADadfF`. This is a stream-accounting concern, not an IP/header-byte comparison.
- [contract_gap] The issue also affects the client-to-server direction. At **15:12:15 UTC**, the tunnel to `widget.mixpanel.io:443` records `cs_bytes=346`, `tunnel_cs_bytes=532`; downstream UID `CU0ApchLtyPWuUrcQ8` contains 878 originating bytes, exactly their sum. Upstream UID `C9RaeL353X9q4Hdvc` contains **656** originating bytes, 124 more than the tunnel counter. At **17:08:17 UTC**, a tunnel to `20-205-39-39.microsoft.com:443` records 875/1627 tunneled bytes, while upstream UID `ChrsLRFXRt0jbzjvs` contains 482/4453. Its downstream UID `ClHILF6KNQpgzDjxBeB` contains exactly the CONNECT control sizes plus 875/1627. The latter pair has no reported gaps or retransmission history on either leg. These examples come from the explicitly `tunnel` action, not the separate `ssl-inspect` population.
- [contract_gap] In a bounded correlation check, **541** successful, explicitly `proxy_action=tunnel` CONNECT records could be matched unambiguously by client/target, request second, nearby unique proxy TLS SNI, and connection tuple. **304** matched pairs had no reported capture gaps or `T/t` retransmission flags on either leg; **56 of those 304** had a nonzero difference between upstream originating/responding stream bytes and the corresponding proxy tunnel counter. Of those 56, 31 differed only in originating bytes, 23 only in responding bytes, and two in both directions. Nonzero directional differences ranged from −1702 to +2826 bytes. Repetition gives this more weight than one unusual closure, although it remains one issue family with an accounting/forwarding alternative explanation.

## Evidence For Real

- The three Zeek connection files contain **23,141 observations** over approximately **13:00–19:00 UTC on 2026-11-02**. There is a believable combination of normal closes, unanswered attempts, resets, rejects, and incomplete closes, rather than a single success state: 17,582 `SF`, 4140 `S0`, 772 `OTH`, 304 `RSTO`, 182 `RSTR`, 79 `REJ`, 39 `S3`, 28 `S2`, and 15 `S1`. Observations from multiple sensors are not deduplicated in these totals.
- All inspected DNS, HTTP, TLS, SMTP, and SMB-file records reference a connection UID present at their own sensor and have timestamps within that connection's visible interval, allowing 1 ms for numerical/timing tolerance. No duplicate connection UID occurs within an individual sensor file. This supports coherence; completeness itself is not counted as an authenticity tell.
- DNS has substantial variety: **4385 transactions**, including A, AAAA, PTR, TXT, SRV, MX, NS, and SOA queries, with `NOERROR`, `NXDOMAIN`, `SERVFAIL`, and `REFUSED`. Internal authoritative replies coexist with recursive external lookups, negative replies, and variable TTLs. AAAA `NOERROR` responses without answer arrays are plausible NODATA responses in an IPv4-oriented environment.
- TLS includes both TLS 1.2 and TLS 1.3, RSA and ECDSA authentication where observable, resumption, and unsuccessful handshakes. Among supplied certificate chains, I found no TLS 1.2 cipher/leaf-key incompatibility, invalid leaf time interval, inconsistent repeated certificate fingerprint attributes, or chain issuer/subject mismatch.
- Independent sensor observations show plausible clock differences and capture differences. For instance, MySQL tuple `10.10.3.10:35830 → 10.10.4.10:3306` appears at 13:02:53.670474 in `zeek-dmz/conn.json` and 13:02:53.839360 in `zeek-db/conn.json`, with the same byte counts and reset state. Other matched flows have differing packet/gap observations rather than requiring every sensor to see identical packets.
- Protocol durations are heterogeneous: short Kerberos exchanges, brief application/database requests, and SSH sessions lasting tens of minutes to hours. The first DMZ SSH connection, UID `CWO3ZQWKkMNB3fiGCb`, lasts 3682.836674 seconds, while core SSH connections extend as long as 13,320.855638 seconds.

## Detailed Analysis

### Scope and method

I examined only the supplied data directory. The principal analysis covered every JSON record in the three Zeek sensor directories, with focused corroboration from proxy, firewall, and IDS text records. I treated log contents as evidence, did not use filesystem modification times, and did not infer authenticity from sanitized names or destination mappings. All timestamps below are UTC.

The connection counts are 12,230 for `zeek-core`, 430 for `zeek-db`, and 10,481 for `zeek-dmz`. Protocol companions total 4385 DNS records, 5547 HTTP records, 3668 TLS records, and 1308 X.509 records. These are sensor observations, not a count of unique physical sessions across the network.

### TCP, packet accounting, and state progression

The connection records exhibit several internally useful constraints. No `SF` record has a zero-packet direction; no `S0` record claims responder packets. TCP payload-bearing directions have corresponding `D/d` history indicators. `S2` histories show the originator's close without the responder's close; `S3` histories show the converse. The zero-payload `S1` histories are not treated as failed authenticity checks simply because complete handshakes or later closes are outside the observed evidence.

UDP IP-byte counters agree with their payload totals plus 28 bytes per packet for IPv4/UDP. ICMP echo examples use type/code-shaped pseudo-ports, including `id.orig_p=8`, `id.resp_p=0`, and a mixture of 48-, 56-, 64-, 1118-, and 1472-byte payloads. I found no overlapping TCP connection intervals for an identical same-sensor five-tuple.

There are retransmission and content-gap histories, and nonzero missed-byte counters correspond to `G/g` histories. This does not establish that every packet counter is perfect, but it argues against a simplistic clean-flow-only dataset.

### DNS transaction semantics

The query mix totals 3315 A, 442 AAAA, 264 TXT, 227 PTR, 119 SRV, nine NS, seven MX, and two SOA transactions. Queries for domain controllers, file services, monitoring, and directory-service SRV records are consistent with the internal address/service patterns. External DNS includes cloud, package, CDN, mail, and certificate-status destinations.

I checked DNS message sizes against conservative protocol minimums rather than assuming that displayed answer strings are literal wire payload. In particular, TXT strings such as `TXT 10 3-EmSIgaps` contain a rendered type/length prefix; counting that prefix as DNS text would create false byte-size allegations. After accounting for that representation, I found no demonstrated DNS query/reply minimum-size violation. DNS `rtt` and companion connection duration also agree in the inspected population.

DNS preceding each particular TCP connection is not a universal requirement because caching and literal-IP use are possible. I therefore did not classify an absent recent lookup as a defect.

### HTTP, proxy forwarding, and byte conservation

The HTTP population contains 4874 CONNECT requests, 643 GETs, and 30 POSTs. CONNECT dominance is consistent with the explicit proxy at `10.10.3.20:8080`, and the logs explicitly distinguish tunnel, tunnel setup, TLS inspection, authentication failure, denial, and gateway failure. Intercepted TLS and opaque tunneling must not be evaluated with identical byte assumptions.

For the main concern I restricted the check to status-200 records with the exact action `proxy_action=tunnel`. Matching required a unique nearby proxy-originated TLS SNI and an unambiguous client/target request; duplicate observations of the same downstream tuple at different sensors were represented once. HTTP/proxy request times are recorded to different precision, so correlation used the proxy request second and a small tolerance rather than demanding identical timestamps. The 541 matched records are a bounded subset, not every proxy request.

The `registry.npmjs.org` example is especially useful because both legs have no gap/retransmission indication. Its downstream totals decompose exactly as the proxy's stated CONNECT control sizes plus tunnel sizes, yet upstream responding bytes exceed the tunnel responding bytes by 1393. The `widget.mixpanel.io` example similarly changes the originating stream total by 124 bytes. The 17:08:17 example differs in both directions and does not depend on comparing the clocks of different sensors, since both relevant connections are in `zeek-dmz/conn.json`.

Opaque tunnels ordinarily relay stream bytes unchanged. Real proxies can nevertheless receive data that they do not ultimately forward, buffer data around half-closes, or expose counters with non-obvious boundaries. This is why I categorize the finding as a repeated **contract gap**, not a proven hard contradiction. The data provide no packet capture or definition precise enough to exclude those explanations. The issue raises the synthetic-confidence score into the mixed range; it does not justify confidently declaring the entire dataset artificial.

No HTTP connection's aggregate request or response body lengths exceeded the relevant connection's stream-byte count. Multiple HTTP transactions per connection also occur, so I did not infer that every request was artificially assigned a new flow.

### TLS and certificate relationships

There are 2460 TLS 1.3 records, 1201 TLS 1.2 records, and seven without a negotiated version. Current AES-GCM/ChaCha suites coexist with a smaller TLS 1.2 CBC population. The database sensor's narrower TLS population is mostly TLS 1.2, which is plausible for a specific server/client stack.

I checked supplied TLS 1.2 certificate chains for leaf key compatibility with RSA/ECDSA cipher authentication, leaf validity at the observed handshake time, and parent issuer/subject continuity with CA flags. Those checks found no contradiction. Repeated certificate fingerprints retained consistent certificate attributes. I did not require TLS 1.3 to expose encrypted certificate messages, nor did I penalize a resumed session for lacking a new certificate chain.

### Timing and environment

Traffic varies by hour and protocol. Core counts rise from 1681 observations during 13:00–13:59 to 3138 during 14:00–14:59, then fall to 1770 during 15:00–15:59; DMZ traffic has a corresponding rise. Counts alone do not show unnaturally constant pacing. The six-hour slice cannot support an overnight or day-of-week realism judgment.

The address/service relationships are broadly sensible: directory and Kerberos traffic centers on `10.10.2.10/.11`, database traffic on `10.10.4.10:3306`, proxy traffic on `10.10.3.20:8080`, and inbound web traffic on `10.10.3.10`. SSH and RDP traffic appear alongside infrastructure and user-facing activity. I did not require QUIC, Bonjour, NTP, or a particular endpoint source merely because some visible hosts could produce them.

### Assessment boundary

There is one substantive issue family here: opaque proxy tunnel byte relationships. I found no independent network-layer hard contradiction strong enough to remove the collection/accounting alternative. Accordingly, 57 describes mixed evidence with a mild synthetic lean, while 82 expresses confidence that **Inconclusive** is the appropriate verdict given those limits. The coherent intrusion or administrative sequence, completeness of source matching, and sanitized organization names played no role in scoring.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on synthetic-confidence score |
|---|---|---|---|
| `contract_gap` | Proxy access counters and Zeek HTTP/TLS connection streams | 56 discrepancies among 304 matched exact-action tunnels without reported capture gaps or retransmissions; 541 matched tunnels overall | Repeated stream-byte disagreement makes the data less production-like, particularly where downstream bytes exactly reproduce proxy control-plus-tunnel counters. Counter boundaries and real partial forwarding remain plausible alternatives, so this supports a mixed score rather than a hard-contradiction verdict. |

## Realism Score by Category

- **Field format accuracy:** 9 — Zeek JSON fields, state histories, DNS representations, and observable TLS certificate relationships are largely coherent.
- **Temporal patterns:** 9 — Heterogeneous durations, hourly variation, and explainable sensor clock offsets; the slice is too short to judge full daily cadence.
- **Cross-source correlation:** 7 — Strong UID/tuple/time relationships overall, reduced by repeated opaque-tunnel stream-byte disagreement.
- **Behavioral realism:** 9 — Plausible proxy use, directory traffic, database requests, administration, failed attempts, and transport outcomes.
- **Environmental consistency:** 9 — Service placement and sensor-specific observations fit the visible topology; no unsupported platform or collection requirements were imposed.

## Recommendations

- If this were synthetic, derive opaque tunnel counters and both TCP legs from shared directional stream-byte truth, with CONNECT control bytes accounted separately. Validate the `registry.npmjs.org` 15:13:44 and `widget.mixpanel.io` 15:12:15 cases as concrete regression examples.
- If unequal totals intentionally represent buffered, discarded, or partially forwarded data, expose explicit received-versus-forwarded counter semantics and a lifecycle reason that explains the difference. Preserve distinct behavior for TLS inspection, where the two encrypted streams can legitimately differ.
- Recheck exact-action opaque tunnels independently of inspected TLS and tunnel-setup records. Use packet-level or equivalent sequence-aware evidence to determine whether the reported differences are collector semantics or a construction defect before changing otherwise coherent network telemetry.
