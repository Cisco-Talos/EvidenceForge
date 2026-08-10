# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 84
**Synthetic-Confidence Score:** 41

## Executive Summary

The six-hour network slice is technically coherent and highly source-native: Zeek protocol rows remain inside their parent connection intervals, TLS versions and ciphers agree, and sampled ASA/proxy byte accounting reconciles exactly or within normal sensor-loss tolerances. The main authenticity concern is distributional rather than causal: public-DMZ scan noise is concentrated into a very small set of recurring sources whose port sets repeat in conspicuous profiles, leaving the data mostly realistic but just over the mixed/inconclusive threshold.

## Evidence For Synthetic

- `[distribution_texture]` In `zeek-dmz/conn.json`, 1,040 external-origin `S0` connections come from only 11 source IPs. The top eight sources account for 1,020 (98.1%) of them, and several unrelated IPs repeat identical fixed port profiles: `38.186.148.245` and `74.172.69.175` target exactly 25/110/143/465/587; `45.33.74.51` and `175.29.181.188` target exactly 80/135/139/445/3389/5985; and `37.75.195.175`, `145.78.103.167`, and `185.249.5.220` share essentially the same 22/23/80/2323/8080 profile. Common bot families can share target lists, but this degree of source concentration and profile reuse is a visible generator-like texture for six hours of an Internet-facing DMZ.
- `[weak_signal]` All 1,714 TLS observations across `zeek-core/ssl.json` (112) and `zeek-dmz/ssl.json` (1,602) have `established=true`. The corresponding cipher/version combinations are valid and failed SYNs correctly do not become TLS rows, so this is not a contradiction; it is only a mildly clean distribution for a mixed client/server environment.
- `[weak_signal]` DHCP renewal timing is nearly invariant per client. For example, the 13 `WS-OHADDAD-01` records have gaps of only 1,787-1,788 seconds, 12 `WS-PPATEL-01` records have 1,692-1,694-second gaps, and 11 `WS-MCHEN-01` records have 1,969-1,970-second gaps. Stable T1 behavior is expected, making this weak evidence only, but the per-host jitter has a notably narrow one-to-two-second texture over repeated renewals.

## Evidence For Real

- The corpus has credible source breadth and volume over 2024-03-18 12:00-18:00 UTC: core Zeek contains 6,174 connections, 2,258 DNS rows, 931 HTTP rows, 112 TLS rows, 69 DHCP rows, 67 SMTP rows, and 339 file rows; DMZ Zeek contains 5,230 connections, 751 DNS rows, 1,120 HTTP rows, 1,602 TLS rows, and 566 file rows. The ASA has 11,670 records, the two Snort sensors have 68 and 119 alerts, and the explicit proxy has 1,668 access rows.
- Connection states are service- and placement-aware rather than globally uniform. Core traffic is 5,975 `SF`, 82 `RSTO`, 44 `RSTR`, 22 `REJ`, 16 `S0`, and smaller `OTH`/`S1`/`S2`/`S3` populations. DMZ traffic includes 3,759 `SF` and 1,240 `S0`, consistent with an exposed segment receiving unanswered scans.
- Every checked Zeek protocol record has a valid parent connection. Across both sensors there are zero missing UIDs, zero tuple mismatches, zero protocol records before connection open, and zero DNS/HTTP/TLS records after visible close (2,258/931/112 core and 751/1,120/1,602 DMZ rows). The same checks pass for 905 `files.json` rows and all 67 SMTP rows.
- ASA accounting is convincingly network-native. The inbound 12:00:01 flow `135.191.40.96:51815 -> 10.10.3.10:443` closes at 12:00:03 with 16,661 ASA bytes, exactly equal to Zeek IP bytes `1,088 + 15,573`; the 17:58:57 outbound flow `10.10.3.20:43694 -> 13.107.42.15:443` closes with 24,172 bytes, exactly equal to `1,232 + 22,940`. Of numeric ASA connection IDs, 4,731 have both build and teardown records; the only three build-only IDs occur at 17:34:39, 17:47:33, and 17:57:23 near the slice boundary, so they are not treated as contradictions.
- Explicit-proxy accounting preserves distinct control and tunnel bytes. At 12:01:40, the proxy logs a CONNECT to `registry.npmjs.org:443` with `cs_bytes=231`, `sc_bytes=190`, tunnel bytes 4,726/5,120, and 5,013 ms duration. Both Zeek sensors observe the client-proxy tuple for 5.0126 seconds with application bytes 4,957/5,310, exactly the control-plus-tunnel totals.
- DNS has realistic protocol diversity: core includes 1,367 A, 296 AAAA, 151 PTR, 68 SRV, 365 TXT, plus low-volume NS/MX/SOA; response codes include 227 NXDOMAIN, seven REFUSED, and seven SERVFAIL. RTTs range from 0.1 ms to 2.432 seconds across 294 rounded-millisecond values. Visible suffix-search artifacts include `wpad`, `isatap`, `printer01.meridianhcs.local`, and `cdn.typekit.org.meridianhcs.local` NXDOMAINs.
- TLS uses valid source-native combinations: TLS 1.3 is restricted to AES-GCM/ChaCha20 TLS 1.3 ciphers, while TLS 1.2 uses ECDHE suites. All 531 certificate-chain FUID references resolve to x509 rows; no observed certificate is not-yet-valid, expired at observation, or has an inverted validity interval.
- Snort alerts line up with visible flows. The 12:02:59.841232 `.cloud` DNS alert matches the exact Zeek tuple/port/timestamp and an NXDOMAIN query for `telemetry-xjh7czzv.cloud`. The perimeter 12:05:44.461852 LibreSSL alert matches a Zeek TLS flow beginning about 42 ms later from `10.10.3.20:58612` to `23.45.144.124:443`, a plausible inter-sensor clock offset.

## Detailed Analysis

### Scope and bounded-window method

I treated the data as a six-hour slice, not a complete lifecycle capture. I first compared per-hour aggregates, then inspected bounded windows at the beginning (12:00-12:15), middle (around 14:00-16:00), and end (17:34-18:00), with focused UID/tuple joins across protocol files. Core hourly connection counts are 855, 934, 1,036, 1,033, 1,300, and 1,016; DMZ counts are 1,197, 791, 917, 687, 831, and 807. These are variable enough to avoid a simple fixed-rate signature.

### Connection state, timing, and accounting

The core sensor is split almost evenly between UDP (3,043) and TCP (3,042), with 89 ICMP records; the DMZ sensor has 4,411 TCP, 772 UDP, and 47 ICMP. Top core destinations reflect internal infrastructure and proxy use (2,265 DNS/53, 1,020 Kerberos/88, 955 SMB/445, 759 proxy/8080, and 599 LDAP/389), while the DMZ emphasizes 443 (1,860), proxy/8080 (908), DNS/53 (766), HTTP/80 (317), and DB/3306 (284).

State/history/accounting combinations are coherent in sampled rows: `S0` uses history `S`, zero payload, one origin packet, and no response packets; successful TCP rows use histories such as `ShADadfF`; UDP request/response traffic uses `Dd`. No record has negative byte counts, IP-byte totals below application-byte totals, or payload bytes with zero packets. ASA examples also demonstrate that firewall byte counts are based on IP-byte totals rather than Zeek payload totals, which is the correct cross-source relationship.

The concentrated scanner population is the main weakness. Interarrival times within the large scanner sources are not metronomic—the 186 gaps for `37.75.195.175`, for example, range from 0.267 to 1,030 seconds and all are distinct at millisecond precision—so the problem is not timestamp regularity. It is the small source pool and repeated, nearly categorical port profiles across unrelated IPs.

### DNS, DHCP, and infrastructure traffic

All 3,009 DNS rows use the same UID and four-tuple as their UDP/53 parent and occur at the parent opening timestamp, consistent with Zeek logging the observed request. No DNS row extends beyond its connection duration. The qtype/rcode mix, response latency range, dynamic TTLs, reverse lookups, AD SRV queries, suffix-search NXDOMAINs, and low-volume failure responses give the resolver traffic credible texture. The 365 core TXT records are not intrinsically suspicious as an authenticity issue; bounded inspection shows both ordinary mail-policy records and a concentrated low-TTL encoded-query sequence, with coherent answers and RTTs.

All 69 DHCP rows resolve to UDP 68->67 `SF` parent connections and carry plausible REQUEST/ACK transactions, assigned addresses, MACs, hostnames, domains, and lease lengths of 3,600-14,400 seconds. Because renewals are periodic by design, their stable cadence was down-weighted to a weak signal rather than treated as a defect. No NTP rows are present, but source absence alone is neutral under the collection assumptions and was not scored.

### HTTP, explicit proxy, and origin traffic

HTTP method/status diversity is plausible. Core has 715 CONNECT, 207 GET, and nine POST requests; statuses include 200, 403, 304, 407, 504, 301, 502, 206, 302, and 503. DMZ has 752 CONNECT, 352 GET, and 16 POST requests with a similarly varied status set. All CONNECT URIs use authority form (`host:port`), and non-200 CONNECT outcomes are represented (82 core and 88 DMZ).

The dual-sensor proxy example at 12:01:40 is particularly convincing: the core and DMZ sensors assign different UIDs and show about a 44 ms observation offset while preserving the same five-tuple and byte totals. A later 12:04:09 Windows Update tunnel includes small differences between core and DMZ application/IP accounting plus nonzero `missed_bytes`, which looks more like independent sensor observation than copied rows. For forwarded cleartext requests, the DMZ also records the proxy-to-origin leg separately from the client-to-proxy absolute-URI request.

### TLS, certificates, and file evidence

Core TLS is 67 TLS 1.3 and 45 TLS 1.2; DMZ TLS is 1,072 TLS 1.3 and 530 TLS 1.2. Session resumption appears in 16 core and 549 DMZ rows. SNI is absent in 10 core and five DMZ observations, so the fields are not universally overfilled. Certificate chains are selectively present (37 core and 323 DMZ TLS rows), and every referenced FUID resolves through `files.json`/`x509.json`. Repeated certificate fingerprints always retain the same subject, and the certificate/key/signature combinations inspected are structurally coherent.

The one clean-looking feature is that every emitted TLS row is established. Since 1,240 DMZ S0 attempts never reach TLS analysis and since successful connections dominate legitimate client traffic, this remains plausible; it is not an impossible protocol state or missing required companion.

### IDS and firewall visibility

The core IDS has a varied 68-alert population led by `.top` (15), `.cloud` (13), `.bit` (11), and `.to` (eight) DNS policies, plus STUN, BitTorrent, HTTP CONNECT, ping, and scan alerts. The perimeter's 119 alerts include rapid connection attempts, ICMP variants, user-agent/policy signatures, external-IP lookup, and cloud/messaging domains. Bounded tuple checks found the alerting packet at or just before the matching Zeek connection/protocol record; the roughly 40 ms DMZ sensor offset recurs in ordinary flows and is not an inversion.

Firewall lifecycle semantics are likewise credible: SYN-only scans produce 30-second `SYN Timeout` teardowns with zero bytes, successful TCP flows use FIN teardown reasons and IP-byte accounting, UDP DNS transactions build and tear down in the same displayed second with nonzero bytes, and outbound NAT translations are separately created and removed. The three numeric build-only connections near the end are treated as right-censored by the collection window.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---:|---|
| `distribution_texture` | DMZ Zeek / ASA scan background | Dataset-wide public-DMZ noise: 1,040 external S0 rows, 11 sources, repeated fixed port profiles | Highest-impact clue; suggests a small templated scanner pool despite realistic per-event timing |
| `weak_signal` | Zeek TLS | 1,714/1,714 TLS rows established | Slightly cleaner than expected, but fully compatible with only completed handshakes reaching the analyzer |
| `weak_signal` | Zeek DHCP | Repeated per-client renewal gaps vary by only 1-2 seconds | Minor periodic texture; substantially mitigated because DHCP T1 behavior is inherently periodic |

No `hard_contradiction`, `contract_gap`, or `schema_or_format` issue was found in the bounded network review.

## Realism Score by Category

- **Field format accuracy:** 9 — Zeek, ASA, Snort, and proxy fields are source-native, with valid protocol/state/cipher combinations.
- **Temporal patterns:** 8 — Hourly load and user/protocol timing vary credibly; DHCP recurrence is somewhat narrow but expected to be periodic.
- **Cross-source correlation:** 10 — UID, tuple, timing, and byte-accounting checks found no visible contradiction across Zeek companions, sensors, ASA, IDS, and proxy.
- **Behavioral realism:** 8 — Service mix, DNS failures, proxy outcomes, scans, and TLS sessions are plausible, but scanner identities/port profiles lack production-scale diversity.
- **Environmental consistency:** 8 — Internal infrastructure and exposed-DMZ behavior are coherent; the public scan source population is the main collection-plausibility concern.

## Recommendations

- If this were synthetic, expand public-DMZ background scanning from the current 11 S0-producing sources to a broader long tail, with source churn and overlapping but non-identical port-selection strategies. Preserve the current bursty interarrival behavior, which already looks credible.
- If this were synthetic, introduce a small source-native tail of post-connect TLS failures (for example, negotiation alerts or `established=false` SSL observations tied to connections that reached handshake bytes) without turning unanswered SYN scans into TLS records.
- If this were synthetic, retain standards-based DHCP T1 periodicity but add modest renewal-timer drift across successive cycles or expose server-provided T1/T2 semantics, so each client's repeated gaps do not remain confined to one or two adjacent seconds.
