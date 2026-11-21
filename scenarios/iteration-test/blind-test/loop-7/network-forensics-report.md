# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Real
**Verdict Confidence:** 64
**Synthetic-Confidence Score:** 30

## Executive Summary

The network telemetry is mostly production-like: connection states, packet accounting, protocol timing, TLS visibility, and proxy behavior withstand detailed consistency checks. I lean toward real data with moderate confidence; the principal reservations are weak timing and software-version distribution signals, rather than demonstrated protocol contradictions.

## Evidence For Synthetic

- [weak_signal] Initial DHCP renewal phases cluster near the beginning of collection. In `zeek-core/dhcp.json`, seven of eight clients first appear between 13:00:31.903696 and 13:08:10.373206 UTC on November 2, 2026, although their leases span 3,600–14,400 seconds. This could reflect scheduling initialized near a collection boundary, but a common workday startup or maintenance event also explains it. It carries little score weight.
- [weak_signal] HTTP user-agent versions have a pronounced platform split. `zeek-core/http.json` contains 357 Linux Chrome/120 observations, 254 Windows Chrome/120 observations, 190 Ubuntu Firefox/121 observations, and 338 Mac Chrome/155 observations. Such version concentrations could come from a small predefined agent pool; managed images and differing update policies are credible alternatives. Counts are HTTP transaction observations, not unique installations, and repeated requests amplify them. This is a minor texture concern only.
- No defensible `hard_contradiction` was found in the network checks described below. Neither suspicious activity nor complete correlation was used as a synthetic indicator.

## Evidence For Real

- Connection behavior varies materially by sensor. `zeek-core/conn.json` has 9,825 `SF`, 1,659 `S0`, 183 `RSTO`, and 81 `RSTR` records out of 12,265; `zeek-dmz/conn.json` has 6,846 `SF` and 2,496 `S0` records out of 9,917. The DB sensor has only two `S0` observations among 465 connections. The edge-heavy unsuccessful traffic and quieter DB segment are coherent.
- DNS includes useful operational diversity: core records contain 2,425 A, 311 AAAA, 292 TXT, 175 PTR, 101 SRV, 11 NS, six MX, and three SOA queries, with 238 NXDOMAIN, 13 SERVFAIL, and three REFUSED outcomes. DNS is not represented solely by successful browsing lookups.
- TLS visibility respects encryption boundaries: all 2,294 TLS 1.3 observations across the three sensors have `ssl_history="Cs"` and no `cert_chain_fuids`; TLS 1.2 includes observable certificate chains and distinct resumed-handshake shapes. No TLS version/cipher or leaf-key/cipher-authentication contradiction was found.
- Byte and artifact relationships are coherent. No individual or aggregate per-direction file `seen_bytes` total exceeds its joined connection's directional payload count, and no HTTP body exceeds its connection's directional byte count. Repeated SHA-256 file hashes retain consistent complete-file sizes within each sensor.
- IDS and DNS agree on concrete transactions. `snort-core/snort_alert.log` reports a `.to` query from `10.10.1.21:39391` at 13:34:02.561385; `zeek-core/dns.json` records the same tuple querying `cdn-s8iwwmqc.to` at 13:34:02.329556, UID `CvUmY3YF6M4iflaiGx`, with NXDOMAIN. The `.tk` alert at 13:35:43.131439 likewise matches `lookup-vnroi9pg.tk`, source `10.10.1.32:63104`, at 13:35:42.890991.
- SSH transport can be reconciled with endpoint authentication. In `zeek-db/conn.json`, UID `CXlGFtugFWa2ez5a1v` opens `10.10.1.35:63586 → 10.10.4.10:22` at 14:26:33.426055. `DB-PROD-01.meridianhcs.local/syslog.log` subsequently records that source tuple at 14:26:36.944465 and public-key acceptance for `aisha.johnson` at 14:26:43.129876, preserving transport-before-authentication order.

## Detailed Analysis

### Scope and method

I parsed the supplied Zeek JSON and checked the records directly, supplemented by selected proxy, firewall, IDS, and SSH syslog records inside the supplied data directory. No origin metadata, scenario, ground truth, or other analyst report was consulted. All clock times in this report are UTC on November 2, 2026.

The sensors cover approximately 13:00–19:00. Their connection counts are 12,265 core, 9,917 DMZ, and 465 DB: 22,647 sensor observations, not necessarily unique network sessions. Other totals are 4,517 DNS, 5,016 HTTP, 3,542 TLS, 1,314 X.509, and 2,537 file observations. Overlapping sensor coverage makes adding these counts unsuitable for estimating unique enterprise traffic volume.

Checks included UID/tuple consistency; protocol-event timestamps within connection intervals; TCP state/history plausibility; payload versus IP-byte accounting with gaps and retransmissions considered; DNS answer address families, TTL-vector lengths and minimum message sizes; TLS cipher/key compatibility and certificate reuse; HTTP transaction ordering/body sizes; and file sizes/hashes versus their carrier flows.

### Connection states, packet counts, and duration

The core sees 6,857 TCP, 4,981 UDP, and 427 ICMP records. The DMZ sees 8,410 TCP, 1,203 UDP, and 304 ICMP records, while DB traffic is dominated by TCP/MySQL. These observations describe distinct network positions rather than three copies of an identical workload.

All TCP `SF` rows include both FIN directions in `history`, and none has fewer than three packets in either direction. No `SF` row has zero responder packets. `S0` rows commonly contain one-sided histories such as `S` for TCP or `D` for unidirectional UDP, while resets and partial sessions retain distinct histories. UDP syslog traffic is one-way `S0`; TCP syslog has established, reset, and partial variants. I did not mistakenly require an application response to a UDP syslog datagram.

Some logical TCP payload totals initially appear too large for captured IP-byte totals. These rows have nonzero `missed_bytes`/gap histories, which explains why stream-length accounting can exceed observed packet payload. For example, core UID `CRU4kpUSxtqCSeNgPv` has `missed_bytes=32768` and history `ShADadfFG`. I did not classify these as impossible byte accounting. Among TCP rows without gap or retransmission markers and with zero missed bytes, no IP-byte total exceeded logical payload plus the conservative maximum IP/TCP header allowance of 120 bytes per packet.

Durations are service-dependent. Successful core SSH connections have a median around 2,390 seconds; RDP around 1,825 seconds; port 443 around 4.89 seconds; and Kerberos/88 around 0.021 seconds. The ranges include both short failures and lengthy sessions, rather than applying one common duration distribution to every protocol.

### DNS behavior and causality

Core DNS median RTT is 3.6165 ms, compared with 11.734 ms in the DMZ and 1.58 ms at DB. These are credible mixtures of local authoritative responses and more distant resolution. Internal SRV queries and AAAA NODATA responses coexist with public A/AAAA records and negative/error outcomes. TTLs include short 30-second public responses, longer internal values, and varied residual public TTLs.

For UID `Cy7bKJVXGBLSw4N5M0b`, core DNS records `_ldap._tcp.meridianhcs.local` at 13:00:02.649837, RTT 1.111 ms, SRV answers naming both DCs, and TTLs of 300 seconds. Its UDP carrier has 46 originator and 167 responder bytes, one packet in each direction, and matching timing.

There are no A answers containing IPv6 literals or AAAA answers containing IPv4 literals, no NXDOMAIN rows with positive answer lists, and no unequal answer/TTL vector lengths. Query payload counts meet uncompressed question-size minima, and A/AAAA answer counts meet conservative compressed-response size minima.

I found 12 DMZ TLS cases with a nearby first visible matching DNS response after the connection opened. For example, the proxy's `js.fullstory.com` connection UID `CxxcHL8l6kpklFbgXB` starts at 13:52:53.058564, while a same-client lookup is logged at 13:52:53.724640. This is not a proven causality error: an address cached before the slice, concurrent refresh, or another resolution path could support the connection. I did not score these cases as synthetic.

### TLS and certificate handling

Across all sensors there are 2,294 TLS 1.3 and 1,246 TLS 1.2 rows, plus two without a negotiated version. Negotiated suites include AES-GCM and ChaCha20 for TLS 1.3, and RSA/ECDSA authenticated ECDHE suites for TLS 1.2. The DB sensor's 39 TLS rows are all TLS 1.2, a plausible service-specific distinction.

TLS 1.3 rows omit cleartext certificate artifacts, as expected from passive observation. TLS 1.2 observations include full and resumed handshake shapes, occasional no-SNI cases, and one- or two-certificate chains. For example, DMZ UID `CFDRlXUClv3bBe8WQeF` negotiates `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` for `api.fastreach.com` and references two certificate files.

Every referenced TLS certificate FUID joins to both a file record and X.509 record in the same sensor. Repeated issuer/serial pairs do not change fingerprint, and repeated fingerprints do not change certificate fields. Leaf key types match the negotiated RSA/ECDSA authentication suites. None of the supplied X.509 records is outside its own validity interval at observation time. These checks establish internal plausibility, not independent verification of real public certificates or domains.

### HTTP, explicit proxying, and file carriage

Most HTTP records are explicit proxy control traffic. Core has 2,157 CONNECT transactions among 2,366 HTTP rows; DMZ has 2,198 among 2,632. The apparent abundance of HTTP therefore does not imply that users mostly browse the public web without TLS. There are also 403/407 decisions, upstream errors, redirects, cache responses, and partial-content transfers.

For `images.mediquant.app`, DMZ client-side UID `CJoJmhUP53lTgLj1SF0` carries a CONNECT from `10.10.2.40:42373` to `10.10.3.20:8080`. Its connection has 1,404 originator and 15,957 responder bytes. Upstream UID `CIShibItCGPg0kygHD` carries 950 and 15,784 bytes, respectively, to port 443. The proxy access log separately records 454 client control bytes and 173 server control bytes; these exactly account for the directional differences. This is a sensible distinction between CONNECT control messages and opaque tunneled traffic.

I paired 1,405 successful DMZ CONNECT transactions to a unique same-SNI proxy-originated TLS connection starting within five seconds. Upstream connection starts lagged downstream starts by a median of about 164 ms, and upstream teardown followed downstream teardown by a median of about 254 ms. A proxy closing an upstream socket after its client disconnects is not an impossible ordering. The pairing is analytical, not a claimed explicit application-level identifier.

For repeated HTTP transactions on one UID, transaction-depth order never reverses timestamp order. No connection contains more than one successful CONNECT transaction. File artifacts fit carrier-direction byte budgets individually and in aggregate, including certificate chains and SMB transfers. No same-SHA-256 complete-file group changes file size within a sensor.

### Lateral sessions, observation differences, and window limits

Sensitive-port traffic includes SSH, SMB, RDP, LDAP, and Kerberos, not just generic TCP/443. The DB SSH example above preserves transport-before-auth ordering and lasts about 2,050 seconds. Core UID `CYyThnb1wgs51otvM3` is another lengthy SSH flow, running from 13:20:18.624834 to 14:00:24.169086 with moderate two-way traffic and a small capture gap. These are compatible with administration; network evidence alone cannot establish whether every such session is authorized.

Cross-sensor matched tuples show stable clock offsets rather than identical timestamps. Among 5,063 nearby DMZ/core connection matches, core starts are 109.693–118.829 ms later, median 114.229 ms. Among 293 DMZ/DB matches, DB starts are 167.208–187.385 ms later. Such offsets can arise from independent sensor clocks, so I do not score the offsets or strong matching itself as synthetic.

One core SMB mapping, UID `CAnp4j3WF1faosJPWi`, at 17:35:24.869922 lacks a matching connection row in the supplied files. It is not sufficient to prove a defect: a long-lived connection may originate before the collection slice or terminate after it. I did not score that absence. Similarly, I did not require QUIC, NTP, additional endpoint sources, or overnight workload in a six-hour daytime slice.

### Traffic texture and alternate interpretation

Core hourly connection counts are 1,836, 3,162, 1,732, 1,821, 2,055, and 1,659 for hours 13–18. DMZ counts are 1,488, 2,688, 1,278, 1,666, 1,368, and 1,429. The shared hour-14 rise is consistent with real shared activity and does not by itself prove either origin. The visible window is insufficient to test overnight patterns or day-of-week seasonality.

The clearest reservations are the first-renewal DHCP phase concentration and browser-version clustering. The renewals themselves respect differing lease policies: 3,600-second leases renew near 1,800 seconds, 7,200-second leases near 3,600 seconds, and 14,400-second leases near 7,200 seconds, with variation. A workday startup cohort and separately managed Mac fleet plausibly explain both weak signals. Because a sophisticated synthetic source could reproduce the successful checks, the real verdict remains moderate-confidence rather than certain.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on synthetic-confidence score |
|---|---|---|---|
| `weak_signal` | Zeek DHCP | Seven of eight first client renewals fall in the first 8 minutes 11 seconds of collection | Small upward contribution for boundary-phase clustering; common startup is a credible explanation. |
| `weak_signal` | Zeek HTTP user agents | Hundreds of Chrome/120 and Firefox/121 transactions on Windows/Linux versus Chrome/155 on Mac | Small upward contribution for concentrated software-version pools; transaction repetition and management policies weaken the inference. |
| No demonstrated hard contradiction | Network protocols and selected companion logs | All three supplied Zeek sensors | Prevents an 81–100 or otherwise high synthetic score; plausible protocol behavior supports the lower score without proving real provenance. |

## Realism Score by Category

- **Field format accuracy:** 9 — JSON field shapes, DNS values, TLS visibility and packet/file accounting are internally plausible.
- **Temporal patterns:** 8 — Service-dependent durations and uneven volume are credible; initial DHCP phase clustering is a weak reservation.
- **Cross-source correlation:** 9 — Protocol UIDs/tuples, certificate references, proxy byte budgets and sampled IDS/SSH relationships agree without impossible demonstrated ordering.
- **Behavioral realism:** 8 — Explicit proxying, failed scans, varied DNS outcomes and long-lived administration sessions form a credible network workload.
- **Environmental consistency:** 8 — Sensor-specific service mixes fit segmented infrastructure; concentrated browser versions have plausible fleet-policy explanations.

## Recommendations

- If this were synthetic, initialize DHCP renewal phases from individual prior lease histories, including leases already active before the collection slice, so first observations need not concentrate near the start. Preserve the existing lease-dependent renewal cadence.
- If this were synthetic, associate HTTP user-agent versions with explicit host/application inventories and update histories. The observed Windows/Linux versus Mac version split could remain if it represents deliberate fleet policy; avoid drawing agents independently from small platform pools.
- Preserve the existing distinction between proxy control bytes and tunnel bytes, passive TLS 1.3 visibility, and packet-capture gap accounting. These concrete behaviors are major reasons the data appears production-like.
