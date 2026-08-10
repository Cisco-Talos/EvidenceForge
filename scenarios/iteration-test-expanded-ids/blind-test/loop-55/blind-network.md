# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Real  
**Verdict Confidence:** 74  
**Synthetic-Confidence Score:** 32

## Executive Summary

The network telemetry is largely production-like: 11,472 Zeek connections show credible protocol/state diversity, sensor-local UIDs, independent clock drift, packet-loss texture, and valid child-log timing. The main synthetic concerns are environmental rather than contradictory: no UDP/123 traffic appears anywhere in this active six-hour enterprise slice, and public scanner cohorts are unusually cleanly partitioned into narrow port families.

## Evidence For Synthetic

- `[environment_or_collection_plausibility]` Neither `zeek-core/conn.json` nor `zeek-dmz/conn.json` contains a UDP/123 connection among 11,472 flows, despite 69 DHCP renewals, 2,800 DNS records, 1,095 Kerberos-labeled connections, and activity from at least 18 internal addresses. A six-hour slice can miss some long-poll clients, but complete absence of network time synchronization across this otherwise broad collection is a concrete protocol-distribution weakness.
- `[distribution_texture]` External scanning is divided into unusually tidy source-specific port palettes. In `zeek-dmz/conn.json`, `45.33.74.51` generated 182 flows primarily to 445/3389/135/5985/139, while `37.75.195.175` generated exactly 182 primarily to 23/22/2323/80/8080; 180 and 178 of their respective flows were `S0`. Other scanners show similarly narrow profiles, such as `38.186.148.245` concentrating 130 of 138 `S0` flows on mail ports.
- `[weak_signal]` The observed TLS handshake population is highly curated. All 1,780 `ssl.json` records are `established=true`, use only TLS 1.2 or 1.3, and draw from seven ciphers. This is plausible for managed clients, and 110 additional `service:"ssl"` connections without SSL rows supply failed/partial-handshake texture, so it only modestly affected the score.
- `[weak_signal]` DNS is heavily concentrated on the domain controller hostname: `DC-01.meridianhcs.local` accounts for 561 of 2,106 core DNS records (26.6%). Active Directory traffic can explain much of this, but more cache suppression and service-discovery variety would create a less model-like distribution.

## Evidence For Real

- The connection-state mix changes plausibly by vantage point. Core traffic has 5,994 `SF`, 75 `RSTO`, 40 `RSTR`, 32 `REJ`, and 19 `S0` records; the perimeter has 3,829 `SF`, 1,225 `S0`, 99 `RSTO`, 62 `RSTR`, and 27 `REJ`, as expected where unsolicited external scans become visible.
- Zeek state/history pairs are source-native and varied: `S0/S`, `REJ/Sr`, `RSTO/ShADaR`, `RSTR/ShADadr`, UDP `SF/Dd`, and many realistic retransmission/gap variants such as `ShADadTtFfGg`.
- Packet collection is imperfect rather than pristine. `missed_bytes` is nonzero in 415 of 6,189 core connections and 413 of 5,283 DMZ connections; packet counts/history differ between the two sensors for 230–243 of 1,772 matched transit flows.
- The two Zeek sensors assign distinct UIDs to the same traffic and exhibit a credible drifting clock offset. Across 1,772 matched five-tuples, DMZ timestamps trail core timestamps by 26.9–66.3 ms, median 56.2 ms, rather than sharing generator-identical timestamps.
- All 2,800 DNS, 2,156 HTTP, 1,780 SSL, 67 SMTP, and 880 file records with connection references resolve to a sensor-local UID. None occurs before its referenced connection or after its visible close.
- DNS texture is broad and plausible. Core contains 1,349 A, 259 AAAA, 140 PTR, 66 SRV, 281 TXT, plus MX/NS/SOA; it has 213 NXDOMAIN, 8 SERVFAIL, and 7 REFUSED responses. DMZ has 555 A, 78 AAAA, 51 PTR, 135 NXDOMAIN, and 4 SERVFAIL records. Median response times are 4.24 ms and 6.62 ms, with 2.486-second tails.
- The unusual TXT volume is behaviorally coherent rather than random: repeated high-entropy subdomains and low TTLs come from `10.10.2.30` toward `ns1.westbridge-services.cloud`, while ordinary SPF/DKIM queries have conventional answer shapes.
- TLS semantics are internally sound. TLS 1.3 represents 1,277 of 1,780 rows and TLS 1.2 the other 503; 602 sessions are resumed. Every referenced certificate exists, every leaf is valid at observation time, and no SNI-to-SAN mismatch was found.
- TLS certificate visibility tracks protocol and capture behavior: TLS 1.3 rows have no visible chain, while TLS 1.2 non-resumed rows lacking a chain all correspond to nonzero `missed_bytes`. This is more convincing than uniform certificate fan-out.
- HTTP has realistic operational texture: CONNECT dominates explicit-proxy traffic, but GET/POST coexist; statuses include 200, 206, 301, 302, 304, 403, 404, 407, 502, 503, and 504. User agents span Windows and Linux browsers, update clients, Python, Go, Java, Wget, curl, VPN, and device-management software.
- All 186 Snort alerts match visible flows. Perimeter alerts consistently precede DMZ Zeek starts by a median 44.6 ms because of sensor clock skew, while core alerts have a median 15.9 ms offset; this is not impossible same-clock ordering.
- DHCP renewal behavior is coherent within the bounded window. Sixty-nine `REQUEST/ACK` records cover eight dynamic clients, with lease durations of 3,600–14,400 seconds and stable but host-specific renewal ratios of 0.470–0.549 of lease time.

## Detailed Analysis

### Scope and flow behavior

The visible interval runs from `2024-03-18T12:00:11Z` to `17:59:49Z`. `zeek-core/conn.json` contains 6,189 records: 3,211 TCP, 2,909 UDP, and 69 ICMP. `zeek-dmz/conn.json` contains 5,283: 4,522 TCP, 721 UDP, and 40 ICMP.

Core is dominated by DNS, Kerberos, SMB, HTTP/proxy, LDAP, SSH, DHCP, TLS, SMTP, and RDP. DMZ appropriately shifts toward TLS, HTTP/proxy, DNS, MySQL, SSH, and unsolicited scans. Durations are service-sensitive: core DNS has a 4.3 ms median; SMB 3.19 seconds; proxy TCP/8080 3.14 seconds; and SSH 1,046.8 seconds, with a 15,394-second tail. No negative counters, negative durations, or cases where payload bytes exceed IP bytes were found.

### DNS

Every DNS UID resolves to a `conn.json` row with identical request timestamp. The query mix contains ordinary AD service discovery, suffix-search failures such as `wpad`, `isatap`, and `oldserver`, PTR traffic, cloud/CDN lookups, mail records, and a distinct high-entropy TXT family. Response times range from roughly 0.1 ms to 2.486 seconds.

The principal weakness is concentration rather than validity. `DC-01.meridianhcs.local` appears 561 times, though those requests are distributed across many clients and A/AAAA types. The absence of any UDP/123 traffic is more consequential because active DHCP, DNS, Kerberos, and server traffic prove broad network visibility.

### TLS, HTTP, and files

The TLS version split is credible for a modern managed environment: 71.7% TLS 1.3 and 28.3% TLS 1.2. Cipher choice tracks version; no obsolete SSL/TLS versions, expired certificates, broken references, or hostname mismatches appear. Missing certificate chains are explained by TLS 1.3 encryption, resumption, or nonzero packet loss.

HTTP and proxy traffic are diverse in hostnames, clients, methods, status codes, transfer sizes, and timing. All `files.json` rows occur within their connection intervals. Core file observations comprise 227 SMB, 82 TLS certificate, 22 SMTP, and 7 HTTP records; DMZ has 502 TLS and 40 HTTP records, with nonzero `missing_bytes` in 43 and 80 rows respectively.

### Cross-sensor and IDS consistency

The two Zeek sensors independently describe 1,772 common five-tuples. Their UIDs never match, their clock difference drifts over the window, and sensor-specific packet loss changes history and accounting without changing the broad state classification. This is strong production-like multi-sensor behavior.

All Snort records match a visible tuple. For example, the `.top` DNS alert at `03/18-12:06:34.282671` in `snort-perimeter/snort_alert.log` maps to the same `10.10.3.10:43347 → 10.10.2.10:53` transaction visible in DMZ Zeek, while the core sensor sees the corresponding transaction with its own clock offset. The timing differences remain milliseconds, not impossible lifecycle inversions.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---:|---|
| `environment_or_collection_plausibility` | Zeek connection/protocol mix | Dataset-wide | Zero UDP/123 traffic in 11,472 flows is the clearest realism gap. |
| `distribution_texture` | DMZ scanning traffic | Repeated | Public sources occupy narrow, cleanly separated scan-port families with overwhelmingly `S0` outcomes. |
| `weak_signal` | Zeek TLS | Dataset-wide | The successful TLS population is compact and uniformly established, though failed service-only flows mitigate this. |
| `weak_signal` | DNS | Repeated | One internal hostname contributes 26.6% of core DNS records. |

## Realism Score by Category

- **Field format accuracy:** 9 — Zeek schemas, UIDs, state/history pairs, TLS metadata, and byte/packet accounting are consistently source-native.
- **Temporal patterns:** 8 — Bursty flow counts, long-tail durations, packet loss, and independent sensor drift are convincing; scanner cohorts remain somewhat patterned.
- **Cross-source correlation:** 9 — Protocol/file children stay inside connection intervals and dual-sensor/IDS timing is coherent without shared identities.
- **Behavioral realism:** 8 — User, proxy, mail, AD, scanner, and suspicious-DNS behavior are technically plausible, with some cohort templating.
- **Environmental consistency:** 7 — Internal services and DMZ roles fit, but the total absence of network time traffic is difficult to reconcile with the otherwise broad collection.

## Recommendations

- If this were synthetic, add sparse, host-specific NTP polling for eligible clients and servers, including occasional unanswered UDP/123 flows. If the collection intentionally excludes NTP, make that exclusion consistent as a collection-profile decision.
- Broaden external scanner families with overlapping-but-not-identical port choices, varied scan completion, revisit intervals, source rotation, and occasional application-handshake evidence. Preserve the current realistic mix of `S0`, reset, and successful outcomes.
- Allow a small number of parseable TLS handshakes to produce `established=false` SSL records where the observed packets justify them; retain service-only rows for handshakes that never progressed far enough for `ssl.log`.
- Reduce repetitive direct DC hostname lookups through client/resolver cache state and more varied SRV-driven discovery, without suppressing the legitimate AD traffic that explains much of the current volume.
