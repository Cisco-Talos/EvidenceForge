# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Real
**Verdict Confidence:** 65
**Synthetic-Confidence Score:** 32

## Executive Summary

The network evidence is mostly production-like: TCP states, DNS results, TLS negotiations, proxy tunneling, packet accounting, and sensor-specific observations remain coherent under record-level checks. Two traffic-texture concerns warrant scrutiny, but neither establishes a contradiction, and neither outweighs the realistic protocol behavior; the Real verdict is a modest-confidence judgment rather than an attribution proof.

## Evidence For Synthetic

- [distribution_texture] ICMP diagnostics occasionally resemble independently sampled packet-size pools. In `zeek-core/conn.json:1701–1706`, `10.10.2.10 → 10.10.2.11` generates six separate one-request/one-reply connections between `2026-11-02T13:54:55.072333Z` and `13:54:55.652130Z`, with respective payload sizes `64, 1472, 1242, 32, 813, 1125` bytes. A size-varied diagnostic tool could do this, but the rapid, irregular changes are less typical of ordinary fixed-size monitoring. This is a limited texture concern, not an impossible ICMP exchange or a proven connection-grouping defect.
- [environment_or_collection_plausibility] The web-to-database path has conspicuous short-connection churn. All 331 MySQL-labeled connections in `zeek-db/conn.json` originate at `10.10.3.10` and terminate at `10.10.4.10:3306`; their median duration is `2.624040 s`, maximum `29.446534 s`, and none lasts 60 seconds. There are 37 responder resets and 31 originator resets, plus ten S2/S3 connections and three OTH connections. This combination deserves explanation for an application/database path, although a non-pooled client, checks, and genuine application instability can explain it. I assign it limited weight because the logs do not establish that pooling should exist.

## Evidence For Real

- Across all three Zeek sensors, every DNS, HTTP, and SSL UID resolves to a same-sensor connection with the identical endpoint tuple. No examined protocol timestamp falls more than one millisecond before its connection start or more than 100 milliseconds after its connection end. Complete matching is favorable correlation evidence, not a synthetic indicator.
- DNS includes successful A/AAAA/PTR/SRV/TXT lookups, NXDOMAIN, SERVFAIL, and successful empty AAAA responses. The core sensor has 3,147 DNS rows, including 284 successful AAAA responses, 95 SRV responses, and multiple negative-response classes; it is not limited to successful A lookups.
- TCP histories and states include failed handshakes, refusals, resets, retransmissions, capture gaps, and partially closed connections. Completed TCP connections have sufficient packets for establishment and closure, and every SF TCP history includes both FIN directions.
- Successful HTTP CONNECT transactions correctly have zero HTTP response body length despite potentially substantial tunneled traffic. The proxy log separately identifies CONNECT control-message bytes and tunneled byte counts; it does not mistake the encrypted tunnel payload for an HTTP response body.
- TLS 1.2 and TLS 1.3 use compatible cipher families. Resumed sessions do not carry certificate chains, and examined TLS 1.2 ECDSA negotiations with visible certificates have ECDSA leaf keys. Files and X.509 records agree on certificate SHA-1 identity.
- Cross-sensor differences are plausible rather than mechanically identical. For example, the LDAP flow at `1793628631.756314` in `zeek-dmz/conn.json:1728` has `resp_bytes=9556`, `missed_bytes=19`, and history `ShADadrg`; its core observation at `1793628631.870667` in `zeek-core/conn.json:1984` has `resp_bytes=9575`, `missed_bytes=0`, and history `ShADadr`. The 19-byte shortfall is accompanied by the appropriate capture-gap evidence.
- Visible SSH and RDP connections have substantial duration variation, including multi-hour SSH sessions. The dataset is not composed exclusively of short request/response stubs.

## Detailed Analysis

### Scope, volumes, and method

I examined only files within the supplied data directory. The primary analysis parsed every JSON record in the three Zeek sensor directories and performed same-sensor connection/protocol joins, state/history checks, tuple-overlap checks, certificate/file identity checks, body-size checks, and selected cross-sensor joins. I also sampled the firewall, proxy, and IDS logs. I did not use source scenarios, ground truth, filesystem modification times, outside context, or domain-resolution assumptions.

The visible network records cover approximately `2026-11-02 13:00–19:00 UTC`. The connection totals are 12,080 core, 9,839 DMZ, and 489 database observations. These are sensor observations, not unique network-wide flow counts; a connection can appear at multiple sensors.

The source-family distributions fit different observation locations. The core sensor has substantial DNS, Kerberos, LDAP, SMB, and explicit-proxy traffic. The DMZ sensor includes proxy egress, external HTTPS, and the web/database path. The database sensor is dominated by the latter path. I do not penalize absent sources, absent QUIC, missing Zeek SSH logs, or missing application payloads because the collection policy is unspecified.

### Connection states, packet accounting, and lifetimes

Core TCP has 6,821 connections: 5,082 SF, 1,369 S0, 151 RSTO, 102 RSTR, 41 REJ, and smaller OTH/S1/S2/S3 populations. DMZ TCP has 8,407 connections: 5,782 SF, 2,335 S0, 117 RSTO, 97 RSTR, 42 REJ, and smaller incomplete/other groups. The large S0 population warrants security investigation, but failed probes are not an authenticity defect by themselves.

I found no connection reporting positive payload with zero packets in that direction, no payload total exceeding the corresponding IP-byte total, and no overlapping TCP intervals with the same oriented four-tuple within one sensor. All SF TCP records have at least three originator packets and two responder packets, and their histories contain both `F` and `f`.

Raw `ip_bytes - bytes` cannot be treated as pure header overhead when retransmissions or missing data are present. After excluding histories with retransmission/gap markers and records with nonzero `missed_bytes`, I found no TCP header-accounting failures under IPv4/TCP minimum/maximum header bounds and four-byte alignment. Thus the large overhead seen on some retransmitting rows is not evidence of malformed accounting.

Lifetimes are varied by service. Core SSH durations extend to `13,322.033479 s`, with median `2,136.417213 s`; RDP extends to `3,431.450073 s`, with median `950.632750 s`. SMB includes 72 observations longer than a minute. These are useful counterexamples to a blanket claim that all connections have canned short durations.

The narrower MySQL lifetime distribution is the main service-level concern. Its frequent reset population is log-visible, but the application architecture and server health are unknown. It supports a qualified plausibility concern rather than a hard assertion that the database behavior cannot occur.

### DNS behavior

The core sensor records 2,197 successful A responses, 284 successful AAAA responses, 204 successful TXT responses, 130 successful PTR responses, and 95 successful SRV responses. It also records 189 A NXDOMAIN responses, nine PTR NXDOMAIN responses, nine TXT NXDOMAIN responses, and nine SERVFAIL responses across A/TXT. The DMZ has 119 A NXDOMAIN and two A SERVFAIL responses, among other results.

Two hundred of the core successful AAAA rows have no answers, which is compatible with NOERROR/NODATA. Successful answered AAAA rows contain IPv6-shaped addresses. I found no error response carrying a conflicting positive answer set in the checked rows.

RTT distributions have a fast local majority and a meaningful tail. Core DNS deciles span roughly `0.000673–0.087629 s` for the first through ninth deciles; the earliest DMZ DNS example has a `1.608179 s` RTT. TTLs include fixed internal values and variable external values rather than a single universal constant.

I did not require every TCP connection to have a fresh DNS query: caching, direct IP use, and a proxy's separate resolver behavior make that invalid. Same-UID DNS observations stay within their UDP/TCP connection intervals.

### HTTP and explicit proxy behavior

There are 2,444 core HTTP rows, 2,712 DMZ rows, and 24 database HTTP rows. HTTP counts should not be read as plaintext Internet use: much of the HTTP evidence is explicit-proxy CONNECT control traffic.

The 2,065 successful core CONNECT rows, 2,102 successful DMZ CONNECT rows, and 19 successful database CONNECT rows all have `response_body_len=0`. Failed CONNECT requests include 403, 407, 502, 503, and 504 outcomes. GET traffic includes redirects, 304 responses, and partial content; no 204/304 row reports a positive response body. No individual HTTP request/response body length exceeds the corresponding connection-direction payload total.

As a concrete example, `zeek-dmz/http.json:3` records `CONNECT pypi.org:443` at `1793624501.510331`, from `10.10.1.22:49648` to `10.10.3.20:8080`, returning 200 with zero body. The associated proxy access entry separately reports `tunnel_cs_bytes=4704`, `tunnel_sc_bytes=33664`, and `tunnel_duration_ms=3103`. The outward TLS connection to `151.101.0.223:443` reports the same application-direction byte totals. This is coherent tunnel accounting, not a response-body contradiction.

User-agent strings include browsers on multiple platforms, request libraries, command-line clients, update agents, health checking, and rare entries. I did not treat a small enterprise's repeated browser strings as sufficient evidence of generation.

### TLS, certificates, and files

There are 414 core, 2,998 DMZ, and 21 database SSL records. The DMZ TLS distribution includes modern TLS 1.3 AEAD suites and TLS 1.2 GCM suites, with some TLS 1.2 CBC use. The database sensor's TLS observations are mostly TLS 1.2. Different service populations make that variation plausible.

Every visible certificate file MD5/SHA-1/SHA-256 value has the expected hex-string length, as do X.509 fingerprints and OCSP issuer hashes. Matching certificate file SHA-1 and X.509 fingerprint values agree. Repeated fingerprints do not acquire conflicting certificate attributes within a sensor.

Resumed TLS observations have no certificate-chain FUIDs. TLS 1.3 histories predominantly show only the cleartext hello exchange, which is consistent with encryption of subsequent handshake messages. I found no demonstrated cipher/key mismatch among TLS 1.2 ECDSA negotiations with visible leaf certificates.

Failed or incomplete TLS setup is not incorrectly forced into successful established sessions. Several `established=false` rows correspond to S1 transport records. I do not interpret certificates absent from an abbreviated or encrypted handshake as missing mandatory evidence.

### Sensor clocks, visibility, and cross-source consistency

Matching by protocol and four-tuple within a half-second window yields 5,040 core/DMZ pairs and 352 DMZ/database pairs. Core timestamps are typically about 114 milliseconds later than DMZ timestamps; database timestamps are typically about 180 milliseconds later than DMZ timestamps. Such stable offsets can reflect clock alignment and capture-path differences. I did not call raw inter-sensor timestamp inversion impossible without accounting for those offsets.

Only one matched core/DMZ pair differs in payload bytes, and its difference has explicit gap evidence. Thirteen matched DMZ/database pairs differ in payload bytes; none is a clean SF/SF, zero-missed-byte counterexample. Independent UIDs across sensors are appropriate.

The firewall samples include distinct built/teardown message IDs, interface zones, and visible public/private translation for inbound traffic. The IDS samples use recognizable fast-alert structure and distinguish TCP/UDP tuples from ICMP endpoint-only notation. Their presence and exact volume are not independently decisive for origin.

### ICMP texture concern and limits

The sensors contain 423 core, 315 DMZ, and 21 database ICMP observations, each with one originator packet. There are 178 core, 70 DMZ, and 21 database observations with one reply; another 245 core and 245 DMZ observations have no reply. These are overlapping sensor populations, not independent network-wide counts. Core payload sizes have a dominant 64-byte population (281 records), common diagnostic sizes, and a tail of unusual sizes. The six-packet burst cited above stands out because the same peer pair changes size rapidly and irregularly, including values near the Ethernet-MTU boundary and arbitrary intermediate sizes.

That is compatible with a deliberate diagnostic or probe program. The logs do not expose ICMP identifier fields or the generating command for those particular packets, so I cannot prove they should have been grouped into one Zeek connection or that their size selection is impossible. The finding therefore contributes limited distribution weight, and I do not generalize it into an ICMP schema defect.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | Zeek ICMP connection observations | Most concrete example is core lines 1701–1706, one peer pair, six exchanges in approximately 0.58 seconds | Limited upward pressure: irregular per-probe payload changes look sampled, but diagnostics are a credible explanation. |
| environment_or_collection_plausibility | Zeek MySQL connection observations | 331 database-sensor rows; 330 corresponding DMZ observations | Limited upward pressure: uniformly short lifetimes and frequent resets warrant an application explanation, but do not establish an impossible service pattern. |

No hard contradiction, verified native schema error, or demonstrated lifecycle contract gap was established. The score reflects mostly realistic evidence with explainable concerns, not confidence that the origin is known.

## Realism Score by Category

- **Field format accuracy:** 9 — Parsed Zeek JSON, hash lengths, endpoint types, and checked protocol shapes are consistent.
- **Temporal patterns:** 8 — Varied service lifetimes and hour-to-hour volume, with a questionable short ICMP diagnostic burst and narrow MySQL lifetimes.
- **Cross-source correlation:** 9 — Tuple/UID joins, certificate identities, tunnel accounting, and explicit sensor-gap differences are coherent.
- **Behavioral realism:** 8 — Plausible proxy, directory, lateral administration, and failed-connection behavior; MySQL churn and ICMP size selection merit explanation.
- **Environmental consistency:** 8 — Sensor-specific source distributions and mixed service populations fit the visible roles; application connection-management intent remains uncertain.

## Recommendations

- If this were synthetic, make ICMP size and grouping behavior derive from a specific diagnostic client or monitoring job. Preserve unusual sizes where a concrete MTU test or size-sweep behavior explains the burst, rather than choosing a new arbitrary size for each adjacent probe.
- If this were synthetic and `10.10.3.10 → 10.10.4.10:3306` represents a pooled production application, model persistent database sessions and distinguish their lifetimes from health checks, short-lived scripts, and actual reset/error conditions. If it represents a deliberately non-pooled or unstable application, the current short-session behavior can be legitimate and should not be changed solely to broaden a histogram.
- Preserve the demonstrated protocol constraints: zero CONNECT response bodies, separate tunnel bytes, sensor-specific gap accounting, cipher/key compatibility, and source-local UID relationships. These checks supplied stronger evidence than general impressions of neatness or coverage.
