# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 93
**Synthetic-Confidence Score:** 84

## Executive Summary

The network evidence has convincing protocol diversity, proxy routing, TLS certificate handling, and source-local UID and timing integrity. The decisive defect is repeated, physically implausible packet-loss accounting between sensors: the same TCP flow loses one captured packet while its total IP-byte count decreases by as little as three or four bytes. This is a concrete measurement contradiction, rather than an objection to complete coverage or an orderly activity narrative.

## Evidence For Synthetic

- [hard_contradiction] Cross-sensor packet accounting models sub-header-sized lost TCP packets. At `2026-11-02T13:17:49Z`, `zeek-dmz/conn.json:190` records `10.10.2.30:52295 -> 10.10.3.20:8080` with `orig_pkts=4`, `orig_ip_bytes=679`, `orig_bytes=463`, `missed_bytes=0`; `zeek-core/conn.json:448` records the same tuple with `orig_pkts=3`, `orig_ip_bytes=675`, `orig_bytes=460`, `missed_bytes=3`, and an added originator gap marker `G`. The apparent missing packet therefore accounts for only four IP bytes, including three payload bytes. An IPv4 TCP packet requires at least 40 bytes before payload.
- [contract_gap] This defect is repeated across observation paths. Matching five-tuples within one second finds 318 core/DMZ directional comparisons in which the positive packet-count difference is accompanied by an IP-byte difference smaller than 40 bytes per packet; there are six such core/DB comparisons and 34 DMZ/DB comparisons. These are comparisons, not necessarily independent underlying flows. Examples include `zeek-core/conn.json:472` versus `zeek-dmz/conn.json:209`, where a responder packet disappears for only three IP bytes, and `zeek-dmz/conn.json:724` versus `zeek-db/conn.json:58`, where an originator packet disappears for three IP bytes. The repeated relationship among packet count, byte count, `missed_bytes`, and gap history is much harder to explain as incidental capture differences than one anomalous row would be.

## Evidence For Real

- Source-local linkage is coherent. Across all three sensors, all 4,002 DNS rows, 2,947 SSL rows, and 4,573 HTTP rows reference a local connection UID with the same four endpoint fields. No tested protocol timestamp preceded its connection by more than 10 milliseconds or exceeded its end by more than 100 milliseconds. DNS response RTTs also fit the connection intervals.
- DNS includes realistic diversity instead of only successful A queries. Core DNS has A, AAAA, PTR, SRV, TXT, MX, SOA, and NS queries; 208 NXDOMAIN, 19 SERVFAIL, and eight REFUSED responses occur among 3,026 rows. DMZ DNS separately has 134 NXDOMAIN responses among 943 rows. For example, `zeek-core/dns.json:1` is a low-latency authoritative internal answer for `DC-01.meridianhcs.local`, while `zeek-dmz/dns.json:1` is a recursive external-name answer with a shorter TTL and higher RTT.
- The apparent HTTP/HTTPS balance has a plausible explicit-proxy explanation. Core HTTP contains 1,935 CONNECT requests, mostly to port 8080; DMZ SSL contains 2,610 handshakes, with the proxy making outbound TLS connections. `zeek-core/http.json:1`, `zeek-dmz/http.json:1`, and `zeek-dmz/ssl.json:1` show a matching destination name across the client-facing CONNECT and proxy-originated TLS legs.
- TLS certificate visibility follows protocol constraints: the supplied certificate-file references occur on TLS 1.2 connections, not TLS 1.3 connections. Inspected leaf key types agree with RSA versus ECDSA TLS 1.2 authentication suites, and repeated certificate fingerprints retain consistent metadata. `zeek-dmz/ssl.json:4`, `files.json:1`, and `x509.json:1` provide a linked example.
- Connection states include success, no response, rejection, resets, and partial closes. Core has 9,774 SF, 1,837 S0, 134 RSTO, 95 RSTR, and 28 REJ connections, plus smaller partial-state groups. DMZ has a higher no-response count, consistent with its visible unsolicited traffic.

## Detailed Analysis

### Scope and method

I examined only the supplied data, emphasizing all records in `zeek-core`, `zeek-dmz`, and `zeek-db`. The connection totals are 11,927, 9,167, and 379 respectively. Their visible start times span approximately `2026-11-02T13:00Z` through `19:00Z`; this is a six-hour bounded window, so I did not require overnight traffic or closures beyond the visible window.

I joined protocol records to connections by source-local UID, checked endpoint tuples, compared protocol timestamps and DNS response times with connection intervals, inspected cipher/certificate relationships, and compared the same five-tuples between sensors within one second. Sensor UIDs are appropriately different for independently observed copies of a connection. Differences in sensor clocks, connection duration, or capture loss are not intrinsically suspicious.

### Decisive problem: packet loss is not represented as whole packets

The clearest case is the HTTP flow at `13:17:49Z`:

| Field | DMZ connection line 190 | Core connection line 448 |
|---|---:|---:|
| Originator packets | 4 | 3 |
| Originator IP bytes | 679 | 675 |
| Originator payload bytes | 463 | 460 |
| Missed bytes | 0 | 3 |
| History | `ShADadfF` | `ShADadfFG` |

The timestamps differ by roughly 114 milliseconds, consistent with the general inter-sensor offset; responder counters are identical. The core record expressly identifies an originator content gap. A packet-loss explanation would require the missing packet's IP total length to be four bytes, although even an empty TCP packet is at least 40 bytes for the displayed IPv4 addresses. The payload deficit is three bytes, leaving one byte for both IP and TCP headers.

An independent example at `13:18:22Z` uses `10.10.1.31:54091 -> 10.10.3.20:8080`. `zeek-dmz/conn.json:209` has `resp_pkts=4`, `resp_ip_bytes=1086`, `resp_bytes=870`; `zeek-core/conn.json:472` has `resp_pkts=3`, `resp_ip_bytes=1083`, `resp_bytes=868` and a responder gap. The missing packet would contain two payload bytes and one header byte.

At `13:40:18Z`, `10.10.3.10:39389 -> 10.10.4.10:3306` appears in `zeek-dmz/conn.json:724` and `zeek-db/conn.json:58`. The DB observation has one fewer originator packet, two fewer originator payload bytes, and only three fewer originator IP bytes. The DB history adds gap markers and its `missed_bytes=305` decomposes into the two-byte originator deficit and 303-byte responder deficit. The recurrence on a different service and observation path strengthens the conclusion.

For aggregate reproducibility, join each sensor pair by `id.orig_h`, `id.orig_p`, `id.resp_h`, `id.resp_p`, and `proto`, require absolute timestamp difference below one second, retain TCP, and compare each direction. Among comparisons where packet and IP-byte differences have the same sign, count `abs(delta_ip_bytes) < 40 * abs(delta_pkts)`. This yields 318 core/DMZ, six core/DB, and 34 DMZ/DB directional comparisons. The corresponding numbers of directional comparisons with same-sign, nonzero packet/IP-byte differences are 548, seven, and 58.

Different capture points can lose different packets, and unusual packet rewriting could alter accounting. However, the illustrated no-gap versus gap observations, retained successful connection histories, identical opposite-direction counters, tiny byte differences, and broad repetition make ordinary loss an inadequate explanation. This is the main basis for the high synthetic-confidence score.

### Protocol and timing realism

Protocol mix follows the visible network segments. Core traffic includes 2,543 Kerberos, 1,157 LDAP, 437 SMB, and 60 DHCP connections. DMZ includes 2,712 SSL, 2,336 HTTP, and 236 MySQL connections. DB includes the corresponding 236 MySQL connections, which supports a segmented web/application-to-database path.

The apparent quantity of HTTP should not be mistaken for obsolete cleartext browsing: 1,935 of 2,158 core HTTP transactions are CONNECT requests. HTTP 304 responses have zero response-body length in the supplied rows. HTTP and SSL UIDs do not overlap, consistent with separate proxy-facing and server-facing connections rather than indiscriminate parsing of encrypted payloads.

All tested DNS, HTTP, and SSL rows fall inside their referenced connection intervals within the stated small tolerance. File observation intervals likewise fit their connection intervals within 100 milliseconds. DNS record shapes include matching AAAA answer syntax, negative answers, internal authoritative responses, and variable TTLs. Certificate-file linkage is coherent, and TLS 1.3 certificate opacity is respected. These are substantive strengths.

Connection volume varies by hour rather than appearing uniform: core counts are 1,428, 3,087, 1,745, 1,815, 2,033, and 1,819 from hours 13 through 18 UTC. I did not interpret the bounded window as evidence for or against after-hours behavior.

### Limits

I did not use domain resolvability, sanitized naming, filesystem modification times, absent endpoint event families, source completeness, or the ease of reconstructing suspicious behavior as authenticity indicators. I found some aggregate HTTP file-size versus stream-byte discrepancies, but did not score them because decoded entities and content encoding complicate that comparison without packet/header evidence. I also did not infer that every sensor-visible platform had a native endpoint collector.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `hard_contradiction` | Zeek TCP connection accounting | Explicit four-byte and three-byte apparent lost TCP packets in matched sensor observations | Strong positive evidence: IP/TCP headers alone exceed the alleged whole-packet length |
| `contract_gap` | Multi-sensor Zeek observation/loss accounting | 318 core/DMZ, six core/DB, and 34 DMZ/DB directional comparisons fail the minimum whole-packet delta check | Repetition across services and paths makes an isolated export or capture anomaly much less persuasive |

These two entries describe one related defect family and are not counted as independent unrelated failures.

## Realism Score by Category

- **Field format accuracy:** 9 — Convincing Zeek record shapes, endpoint types, TLS suites, certificate metadata, and HTTP/DNS fields; the principal defect is joint measurement semantics.
- **Temporal patterns:** 9 — Protocol and file intervals fit their transports, with varied connection durations and hourly volumes.
- **Cross-source correlation:** 5 — UID and endpoint integrity are strong, but cross-sensor packet-loss byte accounting repeatedly contradicts the measured packet counts.
- **Behavioral realism:** 9 — Plausible explicit proxy use, internal infrastructure protocols, varied failures, segmented database access, and mixed DNS responses.
- **Environmental consistency:** 9 — Sensor roles, proxy-originated external TLS, internal naming, and transport/service distributions are mutually plausible.

## Recommendations

- If this were synthetic, construct sensor-specific loss from actual packet-sized units. Removing a TCP packet must remove its full IP length, including at least 40 bytes of IPv4/TCP headers plus payload, while preserving the source-native meanings of stream bytes, captured IP bytes, packet counts, and missed bytes.
- If this were synthetic, derive all affected fields from the same lost-packet observations rather than applying separate small decrements to payload and IP-byte totals. Cover the three- and four-byte examples above and the wider sensor-pair checks.
- If this were synthetic, retain the current protocol timing, proxy leg separation, TLS 1.2 certificate relationships, and TLS 1.3 opacity while correcting the observation-accounting defect.
