# Network Forensics — Authenticity Assessment

## Verdict

**Assessment:** Real
**Verdict Confidence:** 76
**Synthetic-Confidence Score:** 30

## Executive Summary

The corpus is strongly production-like at the network layer: connection semantics, packet accounting, protocol fan-out, NAT/firewall views, endpoint port behavior, DNS caching, and TLS certificate identity are internally coherent at substantial volume. The main synthetic concern is unusually uniform scan texture—every observed TCP S0 attempt is a single SYN with no retransmission—plus a rather small, archetypal scanner population; these are notable but still explainable by stateless scanning tools and the six-hour window.

## Evidence For Synthetic

- `[distribution_texture]` All 1,118 TCP `S0` records in `zeek-dmz/conn.json` have exactly `history:"S"`, `orig_pkts:1`, `resp_pkts:0`, and zero payload. This includes repeated external probes and internal `10.10.3.10` probes toward inside services. For example, at `1710763218.587865`, `145.78.103.167:27418 -> 10.10.3.10:22` has one 52-byte SYN and no retry; at `1710763508.048526`, `10.10.3.10:50281 -> 10.10.2.10:445` likewise has one 52-byte SYN. Stateless Internet scanners can produce this, but zero retransmission diversity across the entire failed-TCP population is unusually clean.
- `[distribution_texture]` Failed scanning is concentrated into a small set of stable, strongly specialized sources. Of 1,132 DMZ `S0` records, only 16 source IPs appear; nine sources account for most activity. Examples include `37.75.195.175` with 151 attempts mainly to 23/22/2323, `45.33.74.51` with 149 attempts mainly to 445/3389/135/5985, and `38.186.148.245` with 135 attempts mainly to 25/587/465. This resembles a curated set of scanner archetypes more than the broader, messier source churn often seen on an Internet-facing service.
- `[weak_signal]` The two Zeek vantage points are extremely deterministic for overlapping traffic. I matched 1,645 records by tuple and byte counts; every pair has identical payload bytes, packet counts, IP-byte counts, state, and history, while DMZ timestamps are always 41.5–66.0 ms later than core timestamps. A stable clock offset and lossless taps explain this, so completeness itself was not scored as a defect, but the narrowly bounded delay texture is unusually controlled.

## Evidence For Real

- Packet accounting is physically plausible throughout all 11,663 Zeek connection rows. There are zero records with positive payload but zero packets, zero records where IP bytes are below payload bytes, zero TCP rows whose payload exceeds 1,460 bytes per packet, and zero TCP/UDP header-underflow cases.
- Zeek state/history combinations are source-native and varied: core has `SF` 6,179, `RSTO` 93, `RSTR` 64, `REJ` 17, `S0` 12, plus partial states; DMZ has `SF` 3,909, `S0` 1,132, `RSTO` 106, `RSTR` 54, and `REJ` 23. `REJ` records consistently use `Sr`; TCP `S0` uses `S`; UDP unanswered traffic uses `D`/`DD`.
- All tested Zeek protocol children preserve UID, tuple, and timing contracts. Across core DNS/HTTP/SSL/SMTP (3,428 rows) and DMZ DNS/HTTP/SSL (3,623 rows), there are zero missing parent UIDs, zero tuple mismatches, zero child timestamps before connection open, and zero child timestamps after connection close. All 935 Zeek `files.json` records likewise reference existing connection UIDs and occur inside their connection intervals.
- Cross-device views are convincing. For `10.10.1.34:49463 -> 10.10.3.20:8080`, core UID `CnchkJ7HwIg2db6iz1Q` starts at `1710763205.841123`; DMZ UID `CBf7qwknKqkNZ5ntobD` starts at `1710763205.886365`; both report 801/18,412 payload bytes and 5/18 packets. ASA connection `1218002` records build at `12:00:05` and teardown at `12:00:10`, with 20,361 bytes—exactly the two Zeek IP-byte totals, 1,005 + 19,356.
- ASA semantics include direction, interfaces, NAT, lifecycle, and reasons. For example, external probe connection `1218203` is built inbound from `145.78.103.167:27418` to DMZ `10.10.3.10:22` at `12:00:18`, then torn down 30 seconds later with zero bytes and `SYN Timeout`. The corpus contains 4,737 unique, monotonically increasing built connection IDs, 4,735 teardowns, and only two still open at the end of the capture.
- Endpoint source-port behavior reflects operating-system families. Windows-looking clients `10.10.1.31`–`.36` use only ports 49,152–65,535; Linux-looking `.21`, `.22`, and `.99` use the 32,768+ range. Examples: `.31` has 437 flows with ports 49,215–65,522, while `.21` has 364 flows with ports 32,778–64,625.
- DNS behavior has realistic breadth and consistency: core contains 2,221 transactions spanning A, AAAA, TXT, PTR, SRV, NS, MX, and SOA; response codes include 1,977 NOERROR, 230 NXDOMAIN, 11 SERVFAIL, and 3 REFUSED. There are zero answers on nonzero rcodes and zero answer/TTL cardinality mismatches.
- DNS caching is visibly modeled rather than blindly emitting a lookup per connection. For positive `DC-01.meridianhcs.local` A records with TTL 300, major clients show no requery inside TTL: `10.10.1.35` has 38 queries with a minimum interval of 304.922 seconds, while `10.10.2.20` has 47 with a minimum of 326.257 seconds. Some PTR lookups do recur within TTL, providing useful application-level exception texture.
- DHCP renewal timing is host-specific and consistent with T1 behavior. One-hour leases renew around 30 minutes with jitter, two-hour leases around one hour, and four-hour leases around two hours; MAC, address, hostname, and server identity remain stable.
- TLS/X.509 coherence is unusually strong without hard contradictions. Across 567 X.509 rows there are 144 unique fingerprints and 144 unique issuer/serial pairs, with zero fingerprint-field conflicts, zero serial-to-multiple-fingerprint conflicts, zero not-yet-valid certificates, and zero expired certificates. TLS versions, ciphers, resumed sessions, and chain visibility also vary plausibly.

## Detailed Analysis

### Connection and Packet Semantics

The core sensor contains 6,407 connection records and the DMZ sensor 5,256, spanning six hours. Protocol mixes differ appropriately by vantage point: core is dominated by DNS, Kerberos, SMB, LDAP, and proxy HTTP; DMZ is dominated by TLS, public HTTP, proxy traffic, DNS, and scan attempts.

Packet-level arithmetic is sound. The initial proxy flow at `1710763205.841123` has 801 origin payload bytes in five packets and 1,005 origin IP bytes, plus 18,412 response payload bytes in 18 packets and 19,356 response IP bytes. No corpus-wide MTU, header, zero-packet, or IP-byte contradiction was found.

Connection lifecycles contain clean closes, resets from both sides, refusals, partial closes, no-response states, and ICMP. Histories such as `ShADadTtFf`, `ShADadr`, `ShADadTR`, `Sr`, `S`, and `Dd` agree with the associated state and direction.

### Multiple Network Vantage Points

There are 1,645 exact cross-sensor connection matches. They use sensor-local UIDs, as real independent Zeek instances would, but preserve tuple and packet truth. Core-to-DMZ timestamp offsets have median 55.146 ms; DMZ-origin traffic has median 53.471 ms. The sign is stable, suggesting clock offset or collection latency rather than independent random timestamps.

ASA adds a third source-native view with real/mapped address pairs, interface direction, build/teardown records, durations, byte totals, TCP close reasons, and ACL denies. Two built sessions lack teardown solely because they remain active at the corpus boundary.

### DNS, DHCP, and Addressing

DNS responses correctly distinguish authoritative internal answers from recursive external answers, include NODATA-style NOERROR AAAA responses, varied RTTs from 0.1 ms to 2.432 seconds, and realistic TTL breadth. An SRV record at `1710763417.993545` resolves `_ldap._tcp.dc._msdcs.meridianhcs.local` to `0 100 389 DC-01.meridianhcs.local` with an authoritative answer.

DHCP comprises 69 REQUEST/ACK renewals with stable client identities. For `WS-OHADDAD-01` (`10.10.1.22`, MAC `a4:1f:72:e2:11:af`), successive one-hour lease renewals occur near half-lease intervals with jitter rather than fixed exact timestamps.

### HTTP, Proxy, TLS, and Files

Proxy access contains 1,918 rows: 846 CONNECT, 1,038 GET, and 34 POST, with varied 2xx/3xx/4xx/5xx outcomes and actions including `ssl-inspect`, `tunnel`, `tunnel-setup`, `forward`, `deny`, `gateway-error`, and `auth-required`. Multi-resource page loads, referrers, browser-specific user agents, authenticated and unauthenticated traffic, tunnel reuse, and mixed response status appear.

At `12:00:06`, the client proxy CONNECT to `aws.amazon.com:443`, Zeek HTTP transaction, proxy access row, proxy-origin DNS, external TLS flow, X.509 certificate, two Zeek taps, and ASA lifecycle align without an impossible ordering or tuple mismatch.

TLS uses both 1.2 and 1.3 and several appropriate cipher suites. The DMZ view has 1,671 established TLS sessions, including 609 resumed sessions. Certificate reuse is stable by identity rather than regenerated per connection.

### Scan and Failure Texture

The public-facing system receives sustained probes of SSH, Telnet, SMB, SMTP, RDP, WinRM, HTTP, and alternate ports. Source-specific SYN IP-byte sizes remain stable—40, 48, 52, or 60 bytes depending on source—providing plausible remote-stack fingerprints.

The weakness is that every TCP S0 flow is exactly one SYN. Even if the dominant scanners use raw stateless probes, a production mixture would normally include at least some retransmitting TCP stacks, repeated SYNs, or less clean aggregation. The small set of sources also separates into nearly textbook scan families.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect |
|---|---|---:|---|
| `distribution_texture` | Zeek DMZ TCP failures | 1,118 TCP S0 rows | Every failed attempt is one SYN with no retransmission diversity; largest negative signal. |
| `distribution_texture` | Zeek DMZ scan population | 1,132 S0 rows, 16 sources | A few sources exhibit sharply separated port-family archetypes and dominate the full six-hour window. |
| `weak_signal` | Core/DMZ Zeek overlap | 1,645 matched flows | Exact accounting plus a tightly bounded one-direction clock delta feels controlled, though a stable sensor clock offset explains it. |

## Realism Score by Category

- **Field format accuracy:** 9 — Zeek, ASA, proxy, HTTP, DNS, DHCP, TLS, X.509, and file records are structurally and semantically convincing.
- **Temporal patterns:** 8 — Lifecycle ordering, DHCP T1 timing, DNS caching, sensor offsets, and ASA durations are strong; failed scan timing lacks retransmission texture.
- **Cross-source correlation:** 10 — No tested UID, tuple, timing, byte-accounting, certificate-identity, or lifecycle contradiction was found.
- **Behavioral realism:** 7 — User/proxy, infrastructure, mail, and scan behavior are varied, but scanner archetypes and one-SYN failures are conspicuously clean.
- **Environmental consistency:** 9 — Address roles, NAT/interface semantics, OS-specific ephemeral ports, internal DNS, and service placement form a coherent environment.

## Recommendations

If this were synthetic, the highest-value improvements would be:

1. Add packet-level failure diversity to TCP scans and blocked connects: include source-specific SYN retransmission policies, retry backoff, occasional changed source ports, delayed RSTs, and capture loss. Preserve one-shot behavior for stateless scanners, but do not apply it to 100% of TCP S0 records.
2. Broaden public scan ecology: increase low-volume one-off sources, vary source lifetimes and port-selection strategies, mix broad and targeted campaigns, and reduce the near-textbook partition between Telnet, mail, and Windows-service scanner identities.
3. Introduce slightly more observation texture between sensors while preserving physical ordering: occasional sensor-local loss, asymmetric packet counts where placement permits it, and clock drift or source-specific collection delay rather than one narrow global offset band. This should be sparse; the current correlation quality is a major strength.
