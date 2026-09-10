# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 94
**Synthetic-Confidence Score:** 83

## Executive Summary

The network telemetry is unusually strong in its ordinary traffic mix, DNS cache behavior, TLS vocabulary, proxy semantics, scan noise, and multi-sensor clock behavior. However, several packet-derived fields contradict one another in ways a passive Zeek deployment should not produce: single-request UDP DNS connections continue for seconds after their only visible response, and file-level gaps appear on fully observed TCP streams, causing different HTTP body lengths at two sensors for the same packets. Those hard, repeated inconsistencies outweigh the substantial production-like detail.

## Evidence For Synthetic

- `[hard_contradiction]` In `zeek-core/conn.json` and `zeek-core/dns.json`, 36 of 2,851 UDP DNS transactions with exactly one originator packet, one responder packet, and `history="Dd"` have more than 100 ms of connection duration after the logged DNS response; 34 exceed 500 ms and 29 exceed one second. For UID `CnA0fgsux7FTIYnT8` at 2024-03-18 12:54:06.317817 UTC, `conn.duration=4.908873`, while the DNS record begins 0.005713 seconds after connection start and has `rtt=0.000358`; the unexplained tail is 4.902802 seconds despite there being no third packet.
- `[hard_contradiction]` The same DNS defect is reproduced across sensors. The 2024-03-18 15:25:07.966419 UTC core record (`CHwHRyqlP0LkVmy9wNl`) and 15:25:08.034090 UTC DB record (`CnUgF9srLXeysF950Fq`) represent the same `10.10.4.10 -> 10.10.2.11` query for `DC-02.meridianhcs.local`: each has one request packet, one response packet, `rtt=0.003302`, and roughly 4.92 seconds of connection duration, leaving about 4.88 seconds after the only possible final packet. Six of only 41 DB DNS transactions show this greater-than-500-ms contradiction.
- `[hard_contradiction]` Five HTTP file records report missing file bytes even though their parent TCP connection reports `missed_bytes=0`, starts from a SYN, closes normally, and has no packet/accounting difference that can create a content gap. At 2024-03-18 13:19:32.732233 UTC, core UID `CtXyNtZhqiSFHPVBBMu` records `/assets/img/logo.svg` as 13,733 response bytes and file FUID `F2qrQeSJEaMDCk7NGG` as `seen_bytes=13733`, `total_bytes=13861`, `missing_bytes=128`; the parent connection has `missed_bytes=0`. The mirrored DMZ stream (`CvxrsRyuQ5ln5Mg9NGu`) sees all 13,861 bytes, while both sensors report exactly 676,023 responder bytes and 472 responder packets for the connection.
- `[hard_contradiction]` Four mirrored HTTP transactions have different `response_body_len` values even though their paired core/DMZ connection records have identical byte counts, packet counts, and `missed_bytes=0`. Besides the logo example, `/assets/js/app.bundle.d8a74c0f.js` is 131,677 bytes in core UID `C2IwJbBxFhOJwkHCem` but 130,508 in DMZ UID `Cny9M8qoQIr622PuHe` at about 15:21:45 UTC; the two parent streams both report 699,978 responder bytes and 588 responder packets. Similar unexplained splits occur at 16:28:20 UTC (292,039 versus 291,168) and 16:56:09 UTC (131,677 versus 130,837).
- `[distribution_texture]` All 910 matched core/DMZ DNS transactions and all 41 matched core/DB DNS transactions copy `rtt` exactly to six decimal places, even though each sensor has a distinct UID and timestamp, the sensor clock offset drifts, and matched connection durations are independently perturbed. Exact DNS RTT identity across every mirrored transaction is a generator-like shared-value boundary rather than the small path- and sensor-local variation expected at separate observation points.
- `[distribution_texture]` The concentrated scan from `10.10.3.10` at 13:40:28–13:41:05 UTC sends the same five unanswered TCP probe types across a `/24`, yet the one-packet SYN observations randomly alternate among 40-, 52-, 60-, and 64-byte IP packets. Among 1,241 unanswered TCP SYNs, the counts are 115, 940, 128, and 58 respectively, with the sizes mixed across target and destination port. A single scanner stack and scan invocation would normally have stable TCP-option/header construction unless explicit evasion were in use; there is no other visible feature indicating such an evasion mode.

## Evidence For Real

- All 33,080 Zeek JSON records across the core, DMZ, and DB sensor directories parsed cleanly. Core identifiers and tuples link correctly within each sensor: every DNS, HTTP, and TLS UID has a corresponding connection, all checked tuples agree, all HTTP transaction depths are ordered, and all checked protocol and file timestamps remain inside their connection interval.
- Multi-sensor observation is modeled with convincing detail. I matched 4,095 core/DMZ connection tuples; their median DMZ-minus-core start offset is about -114 ms and drifts over the six-hour window. Among 2,255 pairs with durations, only two durations are bit-identical, and longer flows differ by realistic sub-millisecond amounts. Sensors also allocate independent Zeek UIDs.
- Packet-loss behavior is often excellent. The Duo MSI transfer at about 12:25:43 UTC is complete on DMZ UID `CUGexQTmGmbuMkCIqG` (`response_body_len=71777707`, `missed_bytes=0`) but short by exactly 32,768 bytes on core UID `CuFxv86EUvHjF8bBgZ`; the core connection and file record both report a 32,768-byte gap, and only the complete DMZ file receives a SHA-1. That is a realistic sensor-local degradation pattern.
- DNS has an appropriate mix of A, AAAA, PTR, SRV, TXT, NS, SOA, and MX queries, plus 188 core and 119 DMZ NXDOMAIN responses. Examples such as `wpad`, `wpad.local`, `wpad.meridianhcs.local`, `isatap`, stale internal names, and suffix-appended external names resemble real Windows and mixed-platform resolver noise.
- Recursive-cache TTL behavior is notably coherent. On the core sensor, `api.snapcraft.io` through resolver `10.10.2.10` falls from TTL 1,652 at 12:26:16 to 1,014 at 12:36:54—exactly the approximately 638 elapsed seconds. `registry.npmjs.org` falls from 499 at 17:12:32 to 408 at 17:14:03, matching the 91-second elapsed time, and then refreshes only after expiration.
- The connection-state and protocol mix has useful messiness. Core contains 8,744 `SF`, 1,980 `S0`, 139 `RSTO`, 85 `RSTR`, 25 `REJ`, and smaller `S1/S2/S3/OTH` populations. DMZ has substantial unsolicited inbound noise and scanner inter-arrival coefficients of variation near one, rather than fixed cadence; DB traffic is much smaller and dominated by MySQL as expected for a segmented database view.
- The explicit-proxy model is coherent. Core HTTP is dominated by 1,451 `CONNECT` requests to `10.10.3.20:8080`; successful 200 tunnels have zero response bodies, while 403/407/502/503/504 failures carry varied HTML bodies. DMZ also observes proxy-origin DNS, TLS, and direct HTTP activity. The six-hour slice has 2,147 DMZ TLS records and only 336 non-CONNECT clear-HTTP records, a plausible HTTPS-heavy balance.
- TLS fields are source-native and internally consistent. DMZ shows 1,415 TLS 1.3 and 732 TLS 1.2 sessions with current AES-GCM and ChaCha20 suites; core is more mixed at 145 TLS 1.3 and 175 TLS 1.2. All 571 TLS sessions for which I could validate a leaf certificate had SNI matching a SAN, every certificate-chain FUID resolved to `x509.json`, and no observed certificate was outside its validity interval.

## Detailed Analysis

### Scope, inventory, and visible window

I restricted inspection to the supplied `data` directory. I parsed all Zeek JSON files under `zeek-core`, `zeek-dmz`, and `zeek-db`, totaling 33,080 records, and performed detailed joins over every `conn.json`, `dns.json`, `http.json`, `ssl.json`, `x509.json`, and `files.json` record. I also sampled the full specialty-adjacent Zeek families (`dhcp.json`, `smtp.json`, `smb_mapping.json`, `smb_files.json`, `ocsp.json`, and `pe.json`). The principal hosts examined included the DMZ web host `10.10.3.10`, proxy `10.10.3.20`, database host `10.10.4.10`, infrastructure in `10.10.2.0/24`, and multiple workstation addresses in `10.10.1.0/24`.

Record timestamps establish a six-hour collection window. DMZ connections run from 2024-03-18 12:00:12.042077 to 17:59:39.084525 UTC; core connections run from 12:00:34.456825 to 17:59:55.510344; DB connections run from 12:00:49.440001 to 17:55:16.822116. Because this is only a daytime slice, I did not score overnight traffic, full-day diurnal shape, lifecycle tails beyond the boundary, or rare-event absence.

### Connection states, flows, and sensor visibility

The sensor-specific distributions are plausible on first inspection. Core has 11,036 connections: 5,834 TCP, 4,783 UDP, and 419 ICMP. Its leading services are DNS (2,897), Kerberos (2,295), HTTP (1,582), LDAP (1,120), SMB (405), TLS (319), and syslog (288). DMZ has 8,192 connections, led by TLS (2,277), HTTP (1,807), DNS (921), and MySQL (285), while DB has 436 connections, 285 of them MySQL. These differences align with a core aggregation point, an Internet/DMZ boundary, and a low-volume DB segment.

State/history combinations are also varied and mostly valid: normal `SF` flows include several close/retransmission histories, while `S0`, `REJ`, `RSTO`, `RSTR`, `S1`, `S2`, `S3`, and `OTH` are all present. I found no reused TCP four-tuple overlapping a still-live connection. Local-origin/local-response flags agree with the configured private/public address character in every connection, and no packet-byte total is smaller than its application-byte count.

The conspicuous 13:40 scan is behaviorally coherent at the macro level. Core observes `10.10.3.10` touching 253 addresses in `10.10.2.0/24` over roughly 37 seconds on TCP/22, 80, 443, 445, and 3306 plus ICMP echo; open, rejected, reset, and unanswered outcomes appear. What weakens it is the randomly changing SYN header length noted above. That packet-construction texture is more consistent with independently sampled record fields than one real scanning stack.

Mirrored sensor records otherwise look convincing. Core/DMZ clock offsets are stable but not perfectly fixed, and packet loss sometimes changes histories, counts, and application visibility in sensible ways. This is why I did not treat broad cross-source completeness or strong correlation as synthetic evidence.

### DNS behavior and causality

Core DNS has 2,071 A, 256 AAAA, 123 PTR, 94 SRV, 327 TXT, and a small NS/SOA/MX tail. Response codes include 2,679 NOERROR, 188 NXDOMAIN, 14 SERVFAIL, and 3 REFUSED. Answer types match their query types in every checked record; AAAA answers are IPv6, A answers are IPv4, and PTR answers are names. Internal authoritative replies use stable TTLs, while external recursive answers show cache countdown and refresh behavior.

For ordinary transactions, timing is good: 2,406 of 2,884 core DNS connections end within 1 ms of `dns.ts + rtt`, and 2,733 end within 5 ms. The defect is a distinct tail of internal-name lookups in which connection duration is independently inflated. On a UDP flow with one `D` request and one `d` response, `conn.duration` can only end at the response packet. The 36 core and six DB cases with unexplained tails over 100 ms therefore cannot be dismissed as a missing companion log or bounded-window effect; the packet counts themselves rule out later packets.

Cross-sensor DNS copies all non-UID/non-timestamp fields exactly for 951 matched transactions, including RTT. Identical query, response, transaction ID, answer, and TTL are expected for the same packets. The universal microsecond-exact RTT identity is less natural because the absolute timestamps and connection durations carry sensor-specific perturbations. I treat this as a dataset-wide generator fingerprint, but not as strong as the impossible one-request/one-response durations.

### HTTP, proxying, and file transfer

Core contains 1,620 HTTP records; 1,451 are explicit-proxy CONNECT requests, 155 are GETs, and 14 are POSTs. DMZ contains 1,830 records with 1,494 CONNECTs, 313 GETs, and 23 POSTs. Successful tunnels are correctly bodyless, failed tunnels carry plausible status/body combinations, direct internal browsing reuses TCP connections with monotonic transaction depths up to seven, and every HTTP timestamp lies within its parent connection.

Packet-loss-aware transfers are a major strength. The 71.8 MB Duo MSI example correlates the core shortfall across `conn.json`, `http.json`, and `files.json`, while the DMZ sensor retains the complete stream and hash. Most other HTTP/file size differences are similarly explainable by a nonzero TCP content gap and were not scored as defects.

Five exceptions are not explainable that way. Their file records claim 128, 1,630, 1,169, 871, or 840 missing bytes while the corresponding parent connection reports no missed TCP bytes. Four have a paired sensor with the full body and identical parent connection accounting. Since `overflow_bytes=0` and `timedout=false`, these are not file-analysis limits or timeout truncation. The strongest examples involve static assets from `WEB-EXT-01`, making an in-path content transformation especially implausible, and they directly produce contradictory `response_body_len` values for a single observed byte stream.

### TLS and certificates

TLS is one of the most realistic areas. DMZ's two-thirds TLS 1.3 share is believable for Internet-facing modern clients, while internal/core TLS has more TLS 1.2. Version/cipher pairings are valid: TLS 1.3 uses AES-GCM or ChaCha20 suites, and TLS 1.2 uses ECDHE RSA/ECDSA AES suites. Resumed sessions omit chains, full TLS 1.2 handshakes usually carry one- or two-certificate chains, and chain FUIDs resolve correctly.

The certificate corpus has believable key and issuer diversity: RSA-2048 dominates, with RSA-4096 and ECDSA-256 present externally; validity periods include roughly 85–90-day leaf certificates, longer enterprise leaves, and multi-year intermediates/roots. I checked SNI-to-SAN matching for 96 core, 465 DMZ, and 10 DB leaf-bearing TLS sessions and found no mismatch. I found no TLS timestamp outside its parent connection and no certificate observed outside its validity dates.

### Timing, volume, and alternative hypothesis

Fifteen-minute connection counts are bursty, not smooth. Core's bins range from 256 to 1,980 and DMZ's from 146 to 1,779, with both peaks explained by the short `/24` scan. External unsolicited S0 sources on DMZ have broad inter-arrival distributions: the four largest sources produce 169–216 attempts each, with inter-arrival coefficients of variation around 1.06–1.27. Long-lived SSH and RDP sessions coexist with short web, DNS, Kerberos, LDAP, and MySQL traffic, and the visible window includes DHCP, SMTP, SMB, syslog, ICMP, OCSP, and executable transfers.

The strongest case for real data is that many subtle mechanisms are present together: recursive TTL aging, stable-but-drifting sensor clocks, independent UIDs, sensor-local packet loss, realistic TCP histories, proxy error bodies, TLS resumption, certificate reuse, and noisy external scans. A real deployment with unusual Zeek analyzer behavior was considered. That alternative does not adequately explain seconds of post-response UDP duration with only two packets, or file gaps that have no TCP gap and change parsed HTTP body sizes between sensors while all parent connection counters remain identical. Those defects are localized rather than pervasive, but they are packet-level contradictions, so they carry disproportionate weight.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---:|---|
| `hard_contradiction` | Zeek conn + DNS | 36/2,851 eligible core UDP DNS records; 6/41 DB records | One request and one response cannot yield seconds of later connection duration with no later packet; repeated and cross-sensor. |
| `hard_contradiction` | Zeek conn + HTTP + files | 5 file gaps; 4 mirrored body-length contradictions | File loss is asserted without a TCP content gap; paired sensors parse different body lengths from otherwise identical streams. |
| `distribution_texture` | Zeek DNS across sensors | 951/951 matched DNS transactions | RTT is copied exactly to six decimals despite independently shifted/perturbed sensor observations. |
| `distribution_texture` | Zeek conn scan traffic | 1,241 unanswered TCP SYNs in one 37-second campaign | One scanner's SYN header size changes randomly among four values across targets and ports. |

## Realism Score by Category

- **Field format accuracy:** 8 — Zeek schemas, protocol values, histories, TLS fields, certificates, and references are largely source-native, but file-gap accounting contains hard inconsistencies.
- **Temporal patterns:** 7 — Traffic and scanner timing are convincingly bursty, yet a repeated UDP DNS duration tail violates packet-derived timing.
- **Cross-source correlation:** 6 — Most joins and sensor-local loss are excellent, but mirrored HTTP body contradictions and universally copied DNS RTTs are high-impact failures.
- **Behavioral realism:** 8 — Proxy use, web sessions, TLS resumption, infrastructure protocols, lateral/admin sessions, and unsolicited scanning form a plausible network workload.
- **Environmental consistency:** 9 — Sensor visibility, subnet roles, service placement, DNS authority/recursion, and DB segmentation remain coherent throughout the bounded window.

## Recommendations

- If this were synthetic, derive UDP `conn.duration` from actual packet timestamps. For one-request/one-response DNS, connection end must coincide with the response used to calculate `dns.rtt`; any later duration requires another counted packet and matching history.
- If this were synthetic, make observation loss one coherent sensor-local decision. A file may report `missing_bytes>0` only when the parent TCP stream has a compatible content gap, packet/history effect, or an explicit source-native analyzer-limit field such as overflow/timeout. Recompute HTTP body length, file seen/total bytes, hashes, packet counts, and `conn.missed_bytes` from that same loss model.
- If this were synthetic, calculate DNS RTT independently at each sensor from that sensor's request and response timestamps. Preserve the same DNS transaction and answers, but include path-position and clock-rate effects rather than copying a canonical RTT verbatim.
- If this were synthetic, keep SYN option/header construction stable for each scanner stack and scan invocation. Vary it only when the visible traffic supports a tool/mode change, decoy source, or deliberate packet-evasion profile.
- Preserve the existing recursive TTL countdown, explicit-proxy semantics, TLS/certificate model, sensor clock drift, protocol mix, and correctly correlated packet-loss examples; those materially improve realism.
