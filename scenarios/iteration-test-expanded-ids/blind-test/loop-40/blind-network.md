# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 72  
**Synthetic-Confidence Score:** 63

## Executive Summary

The network telemetry is technically strong: connection states, UID linkage, TLS behavior, packet accounting, and dual-sensor observations are mostly source-native and coherent. The deciding issue is a collection-boundary inconsistency in which Zeek records complete SSH sessions extending as late as 18:50 UTC although every visible source stops before 18:00 UTC and the corresponding ASA records contain only connection builds; regularized DHCP renewal timing and a narrowly templated Internet-scan population provide secondary synthetic signals.

## Evidence For Synthetic

- `[contract_gap]` Six `zeek-core/conn.json` SSH records start before the apparent 18:00 UTC collection cutoff but contain completed `SF` lifecycles extending beyond it, including UID `CgymVjlC5CBI9q9RIH2`, which starts at 17:55:23.944978 and has duration `3279.403103`, placing its close at 18:50:03.348081. No log records timestamped after 18:00 were present in the inspected dataset.
- `[contract_gap]` The corresponding ASA connections are left open. Connection `1295901` for `10.10.1.32:49361 -> 10.10.3.20:22` has only a build at 17:11:55, while both Zeek sensors report an `SF` close around 18:01:18. Connection `1306392` for `10.10.1.31:50283 -> 10.10.3.10:22` has only a build at 17:55:23, while Zeek reports its close around 18:50:03. This looks like connection durations were generated beyond the event-start window while timestamped sources were truncated at the window boundary.
- `[distribution_texture]` DHCP renewal schedules are almost fixed per client but use conspicuously different client-specific fractions of the advertised lease time. For example, five clients with 3,600-second leases renew every approximately 1,693, 1,788, 1,930, 1,941, or 1,970 seconds, each with only about one second of jitter across 10–12 consecutive intervals. Comparable deterministic offsets occur for the 7,200- and 14,400-second leases. A server-assigned T1 can explain stable intervals, but this many neatly individualized ratios is generator-like.
- `[distribution_texture]` The unsolicited DMZ scan population is unusually compact and archetypal. Seven principal external sources produce most of 1,009 failed inbound SYNs across nearly the entire six-hour window, with duplicated service profiles: two predominantly Telnet/SSH sources, two mail-service sources, and two Windows-administration sources, plus one broad scanner. This remains plausible botnet traffic but has a curated-pool texture.
- `[weak_signal]` The visible flow-start window is exceptionally exact: normal activity begins at 12:00:28 and new records stop at 17:59:51, while several long-lived SSH records retain post-window durations. A bounded query alone is normal; it matters here because of the inconsistent lifecycle treatment across sources.

## Evidence For Real

- All 6,298 core and 5,490 DMZ connection UIDs are unique.
- Every DNS, HTTP, SSL, and SMTP UID resolves to a same-sensor connection record with an identical tuple. No protocol timestamp occurs before its connection start or after its recorded close.
- All 955 referenced file-transfer connection UIDs resolve successfully.
- TCP state mechanics are convincing. Core traffic contains `SF`, `RSTO`, `RSTR`, `REJ`, `S0`, `S1/S2/S3`, and `OTH` states with appropriate histories and packet directions. For example, all 40 core `REJ` records use `Sr` with one originating and one responding packet, while ordinary core `S0` records have one SYN and no response.
- Packet accounting is internally valid: IP-byte totals never fall below payload-byte totals. UDP and ICMP overhead is consistently 28 bytes per packet, while TCP overhead varies realistically with headers and options.
- The two sensors do not merely duplicate rows. Among 1,907 matched five-tuples, start-time offsets range from 37.4 to 66.4 milliseconds with a 54.8-millisecond median; 227 matches have different packet counts/history, and some show plausible sensor loss. The SSH flow on source port `49361`, for example, has `missed_bytes=1061` at core but zero at DMZ.
- DNS has good breadth: core contains 1,356 A, 299 AAAA, 163 PTR, 69 SRV, and 308 TXT queries, with 213 NXDOMAINs and smaller SERVFAIL/REFUSED populations. Queries include realistic `wpad`, `isatap`, suffix-appended names, PTR lookups, mail/service discovery, and low-TTL malicious-looking TXT activity.
- DNS connection timing is source-native: for single UDP exchanges, `conn.duration` equals DNS RTT to rounding precision.
- TLS behavior is especially convincing. DMZ telemetry contains 1,112 TLS 1.3 and 522 TLS 1.2 sessions across seven modern cipher suites. TLS 1.2 certificate references appear exactly on non-resumed sessions, while TLS 1.3 has no visible certificate chain, consistent with encrypted TLS 1.3 certificate messages.
- All 352 inspectable leaf certificates match their SNI through subject-alt names; all inspected certificates are valid at observation time. Missing X.509 records correspond to certificate files with nonzero `missing_bytes`, a plausible parser-loss mechanism rather than arbitrary broken references.
- OCSP timestamps fall inside their `thisUpdate`/`nextUpdate` windows, and all statuses are `good`.
- Source-port ranges are OS-consistent. Apparent Windows systems use ports at or above 49152, while Linux systems use the broader 32768-range ephemeral space.
- Explicit-proxy behavior is coherent. Core HTTP contains 812 CONNECT transactions out of 1,006 rows, while the DMZ view contains client-to-proxy and proxy-egress activity. Proxy access rows distinguish CONNECT control-message bytes from tunneled byte counts.
- ASA lifecycle handling is strong apart from the cutoff issue: 4,873 of 4,875 parsed TCP/UDP connection IDs have exactly one ordered build and teardown; the two exceptions are precisely the SSH sessions whose Zeek durations cross the cutoff.

## Detailed Analysis

### Coverage and observation window

The core sensor contains 6,298 connections; the DMZ sensor contains 5,490. Connection starts occupy approximately 12:00–18:00 UTC on 2024-03-18. The core protocol logs include 2,208 DNS, 1,006 HTTP, 112 SSL, 67 SMTP, 69 DHCP, 348 file, 72 X.509, 12 OCSP, and one PE record. DMZ includes 767 DNS, 1,200 HTTP, 1,634 SSL, 607 file, 488 X.509, 34 OCSP, and two PE records.

Hourly core connection counts are 928, 958, 966, 1,017, 1,327, and 1,102. DMZ counts are 1,050, 919, 891, 894, 818, and 918. This is neither flat nor obviously periodic; the core rise around 16:00 UTC is attributable largely to visible activity rather than a simple hourly multiplier.

### Connection states and services

Core is dominated by successful internal traffic: 6,063 `SF` connections, followed by 93 `RSTO`, 52 `RSTR`, 40 `REJ`, and 29 `S0`. Its main services are DNS (2,213), Kerberos (1,081), HTTP (956), SMB (906), LDAP (608), and SSH (107).

DMZ has a materially different and credible perimeter profile: 3,980 `SF`, 1,262 `S0`, 115 `RSTO`, 61 `RSTR`, and 40 `REJ`. SSL (1,731), HTTP (1,173), DNS (771), and MySQL (318) dominate classified traffic. The state transition histories fit their states, including `ShADadfF`-family clean closes, originator and responder resets, incomplete closes, and rejected SYNs.

No overlapping TCP reuse of the same five-tuple was found. The few apparent overlaps are ICMP echo records, for which the displayed pseudo-ports do not expose all tracker-disambiguating fields.

### DNS behavior

Core DNS consists of 757 distinct names across 2,208 transactions. The type and result mixtures are credible for a mixed Windows/Linux network:

- A: 1,356
- AAAA: 299
- PTR: 163
- SRV: 69
- TXT: 308
- NXDOMAIN: 213
- SERVFAIL: 18
- REFUSED: 5

The large TXT population is concentrated around encoded subdomains beneath `ns1.westbridge-services.cloud`, with rapidly changing labels, TXT answers, low TTLs, and RTTs ranging through tens or hundreds of milliseconds. This resembles DNS tunneling rather than accidental protocol noise.

For DMZ outbound non-`S0` TCP flows, 792 of 1,048 have a prior same-client DNS answer for the destination IP in the visible window, 418 within five seconds. The unmatched remainder is compatible with caching, direct-IP connections, and capture-window boundaries.

### TLS and certificate behavior

The DMZ SSL mix is 68% TLS 1.3 and 32% TLS 1.2, with AES-GCM and ChaCha20 suites predominating. Core TLS is smaller and somewhat more TLS 1.2-heavy, consistent with internal mail and service traffic.

The relationship between TLS version, resumption, and certificate visibility is unusually accurate:

- DMZ TLS 1.2: 522 sessions, 369 certificate-bearing and 153 resumed.
- DMZ TLS 1.3: 1,112 sessions and no visible certificate-chain references.
- Core TLS 1.2: 46 sessions, 44 certificate-bearing and two resumed.
- Core TLS 1.3: 66 sessions and no certificate-chain references.

All inspected SNI-to-SAN comparisons match, and certificate validity periods cover the connection timestamps. Missing referenced X.509 rows are explainable by partial certificate files with nonzero missing-byte counts.

### HTTP and proxy behavior

Core HTTP comprises 812 CONNECT, 181 GET, and 13 POST transactions. Statuses include successful tunnel setup as well as 407 authentication requests, 403 denials, 502/503/504 failures, redirects, and cache responses. User agents include multiple Windows and Linux browsers, update clients, Wget, curl, Python requests, and Go clients.

The proxy access format explicitly separates CONNECT control exchange bytes from tunneled bytes and durations. This avoids a common contradiction where proxy response bytes are incorrectly equated with the full TLS payload. The shared client-to-proxy and proxy-to-origin evidence is coherent across Zeek and ASA.

### Cross-sensor behavior

A tuple-and-time match identifies 1,907 shared connections. Their state and service classifications agree in every case, but sensor-native differences remain:

- Median timestamp separation: 54.8 ms.
- Different packet counts/history on 227 matches.
- Slight duration differences on 968 matches.
- Byte differences on 237 matches.
- Sensor-specific missed-byte behavior on affected flows.

This is one of the strongest production-like properties in the dataset.

### DHCP behavior

There are 69 DHCP transactions covering eight clients, all renewal-style REQUEST/ACK exchanges. Lease identity, IP, hostname, MAC, server, connection UID, and tuple all correlate.

The concern is timing texture. Each client repeats a nearly invariant interval, but the interval varies by a seemingly randomized fraction of lease length. A 3,600-second lease renews every approximately 1,693 seconds for one client and 1,970 seconds for another, while each client's interval barely changes across the whole window. Although DHCP servers may provide explicit T1 values, the combination resembles a deterministic per-entity jitter function more than a shared production DHCP policy.

### Internet scans and lateral traffic

The DMZ sensor records 1,009 failed SYNs targeting `10.10.3.10`. The scanners have randomized source ports and bursty interarrival times, so the traffic is not mechanically periodic. However, the population is restricted to a small set of full-window actors with paired service-specific profiles:

- `37.75.195.175` and `145.78.103.167`: Telnet/SSH-heavy.
- `38.186.148.245` and `74.172.69.175`: SMTP/SMTPS/IMAP/POP-heavy.
- `45.33.74.51` and `175.29.181.188`: SMB/RDP/RPC-heavy.
- `156.32.3.55`: broader common-service scanning.

This could be coordinated scanner infrastructure, but it lacks the broader long tail of one-off sources commonly seen at an exposed perimeter.

Internal sensitive-port traffic includes SSH, SMB, LDAP, Kerberos, RDP, MySQL, and proxy administration. Success, reset, reject, and timeout outcomes are mixed rather than uniformly successful.

### Collection-boundary inconsistency

The strongest authenticity defect appears at 18:00 UTC. No inspected log has a record timestamp after that point, yet Zeek contains completed `SF` SSH sessions extending up to 50 minutes past it.

Two examples cross the perimeter firewall:

- `10.10.1.32:49361 -> 10.10.3.20:22`: Zeek starts at 17:11:55 and closes around 18:01:18; ASA has only build connection `1295901`.
- `10.10.1.31:50283 -> 10.10.3.10:22`: Zeek starts at 17:55:23 and closes around 18:50:03; ASA has only build connection `1306392`.

A query performed later and filtered by Zeek's connection-start `ts` could technically produce this shape. However, combined with every other source ending at 18:00, the more natural explanation is that flow durations were allowed to execute beyond a generation window while event-emitting sources were clipped at that boundary.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Impact |
|---|---|---:|---|
| `contract_gap` | Zeek conn / Cisco ASA | 6 core SSH sessions exceed the cutoff; 2 have matching build-only ASA records | Strongest indicator: lifecycle completion uses inconsistent window semantics |
| `distribution_texture` | Zeek DHCP | 69 transactions across 8 clients | Stable but individualized renewal ratios resemble deterministic per-client scheduling |
| `distribution_texture` | Zeek DMZ conn | Most of 1,009 inbound `S0` scans | Small, paired set of service-archetype scanners looks curated |
| `weak_signal` | Dataset-wide timestamps | Six-hour start window | Exact cutoff is ordinary alone, but amplifies the post-window-duration inconsistency |

## Realism Score by Category

- **Field format accuracy:** 9 — Zeek, ASA, TLS, DNS, packet, and certificate fields are internally credible.
- **Temporal patterns:** 6 — Normal flow timing is varied, but the post-cutoff Zeek lifecycles and DHCP schedules are notable.
- **Cross-source correlation:** 9 — UIDs, tuples, protocol timing, proxy paths, and dual-sensor differences are exceptionally coherent.
- **Behavioral realism:** 8 — Browsing, infrastructure, scanning, tunneling, and lateral-service traffic have useful diversity.
- **Environmental consistency:** 7 — Host source-port behavior and service placement are plausible, but cutoff semantics and scanner breadth reduce confidence.

## Recommendations

- If this were synthetic, apply one consistent acquisition-window policy. Either truncate open Zeek connections at 18:00 with a source-native incomplete state, include post-window firewall/session-close records, or extend all source outputs through the latest lifecycle completion.
- Model DHCP T1 explicitly as a server/pool policy. Use the advertised T1 when available; otherwise center renewal near the RFC default and add realistic scheduler, suspend/resume, link-change, and occasional retry effects instead of a fixed randomized ratio per client.
- Expand unsolicited perimeter noise with a larger long tail of one-off scanners, short campaigns, repeated retransmissions, distributed sources sharing one campaign, and sources that enter or leave during the window.
- Preserve the existing sensor-specific packet loss, timing offsets, UID independence, TLS visibility rules, and source-native packet accounting; these materially improve realism.
