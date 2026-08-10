# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Real
**Verdict Confidence:** 78
**Synthetic-Confidence Score:** 27

## Executive Summary

The network telemetry is mostly production-like: it has coherent Zeek protocol fan-out, credible TCP state and traffic distributions, sensor-specific observation differences, and consistent firewall, IDS, and proxy relationships without a visible hard contradiction. The main residual concern is a weak distribution artifact in DHCP renewal timing, where each client repeats an almost fixed host-specific interval with only about one second of jitter; this is noticeable but not sufficient to outweigh the broader entropy and source-native consistency.

## Evidence For Synthetic

- `[distribution_texture]` DHCP renewal cadence is unusually smooth per client. In `zeek-core/dhcp.json`, 10 successive gaps for `10.10.1.21` are all about 1,940 seconds (1,939.565-1,941.414), 12 gaps for `10.10.1.22` are 1,786.704-1,788.571 seconds, and 11 gaps for `10.10.1.32` are 1,691.740-1,693.341 seconds. Stable T1 renewal behavior is normal, but the repeated host-specific interval plus only roughly one second of jitter across the full six-hour slice is smoother than many real client/server/network stacks.
- `[weak_signal]` Several high-volume application families recur from compact pools. For example, core DNS has 545 queries for `DC-01.meridianhcs.local` and 136 for `FILE-SRV-01.meridianhcs.local`, while proxy traffic includes 80 requests to `ctldl.windowsupdate.com`. This did not materially drive the verdict because the per-origin gaps were highly varied (529 unique rounded gaps among the 545 DC lookups) and the behavior fits enterprise dependencies.
- `[weak_signal]` The successful TLS analyzer population is clean: all 113 core and all 1,655 DMZ `ssl.json` rows have `established=true`. This is only a weak signal because failed/partial 443 connections remain visible in `conn.json` without necessarily producing an SSL analyzer row, so it is not a source-native contradiction.

## Evidence For Real

- Zeek connection texture is varied and plausible. Core has 6,106 connections with 5,908 `SF`, 73 `RSTO`, 55 `RSTR`, 23 `S0`, 17 `OTH`, 12 `S3`, 9 `REJ`, 8 `S2`, and 1 `S1`. DMZ has 5,279 with 3,886 `SF`, 1,162 `S0`, 121 `RSTO`, 54 `RSTR`, 17 `OTH`, 14 each `S2`/`REJ`, 10 `S3`, and 1 `S1`. Histories agree with those states: DMZ `S0` is predominantly `S`, `REJ` is `Sr`, and reset/half-close states carry appropriate mixed histories.
- Protocol UIDs and tuples are internally sound. All 2,194 core DNS, 955 core HTTP, 113 core SSL, and 66 core SMTP rows resolve to a `conn.json` UID with an identical four-tuple; the same is true for all 751 DMZ DNS, 1,142 DMZ HTTP, and 1,655 DMZ SSL rows. None precedes its connection or falls after the recorded close interval.
- The two Zeek sensors behave independently rather than as duplicated exports. There are zero shared connection UIDs. I found 1,801 same-tuple observations within one second across sensors; all have different UIDs, timestamps differ from -22.1 to +66.5 ms, only 1,561 have exactly equal directional payload counts, and only 970 have exactly equal durations.
- Packet accounting is coherent. Across both sensors no record has `orig_ip_bytes < orig_bytes` or `resp_ip_bytes < resp_bytes`. Nonzero capture loss is present rather than universally perfect: 314 core connections total 91,484 `missed_bytes`, and 422 DMZ connections total 160,652.
- DNS is diverse and source-native. Core has A/AAAA/PTR/SRV/TXT/MX/NS/SOA traffic, 213 NXDOMAINs, 6 SERVFAILs, and 4 REFUSED responses; DMZ has A/AAAA/PTR/SRV/TXT, 125 NXDOMAINs, 2 REFUSED, and 1 SERVFAIL. Core RTTs span sub-millisecond LAN answers through 2.321 seconds, with median 4.655 ms and 99th percentile 343.901 ms. Answer address families match A versus AAAA types, including legitimate NOERROR/NODATA AAAA responses.
- TLS details are contemporary and varied. DMZ records include TLS 1.3 (1,192) and TLS 1.2 (463), several AES-GCM and ChaCha20 suites, 519 resumed sessions, and 318 SNI values. All 448 DMZ and 82 core X.509 observations were valid at observation time; 119 unique DMZ leaf fingerprints show a broad validity-period distribution rather than one repeated certificate template.
- Perimeter logging has credible lifecycle and policy evidence. `cisco_asa.log` contains 3,931 TCP builds and exactly paired teardowns, 765 UDP builds and teardowns, 1,022 dynamic translation builds and teardowns, and 215 ACL denies. Teardown reasons are mixed (`TCP FINs` 2,841, `SYN Timeout` 954, `TCP Reset-O` 101, `TCP Reset-I` 35). Of 4,696 parsed ASA TCP/UDP builds, 4,641 match a DMZ Zeek tuple within two seconds; the unmatched examples are chiefly inside-only paths not necessarily visible at that sensor.
- IDS timing is credible. All 55 parseable non-ICMP core Snort alerts and all 86 parseable non-ICMP perimeter alerts matched a Zeek tuple within one second; offsets vary rather than being copied exactly, with maxima about 68-70 ms. Alert vocabulary is also mixed (DNS TLD policy, STUN, P2P, rapid connection attempts, executable download, JA3, ICMP, and SSH scanning).
- Proxy telemetry contains believable success and failure texture. Its 1,611 rows include 811 CONNECT, 773 GET, and 27 POST requests; status codes include 1,425 `200`, 78 `304`, 33 `403`, 23 `407`, and a smaller mix of `206`, `301/302`, `400/404`, `502`, `503`, and `504`. Actions include 764 `ssl-inspect`, 504 `tunnel`, 233 `tunnel-setup`, 33 `forward`, 31 `deny`, 23 `auth-required`, and 23 `gateway-error`, with 17 client IPs and both authenticated and service/unattributed traffic.

## Detailed Analysis

### Scope and traffic distribution

The visible window is approximately 2024-03-18 12:00-18:00 UTC. Core hourly connection counts are 815, 1,010, 942, 1,001, 1,248, and 1,090; DMZ counts are 1,032, 724, 888, 840, 824, and 971. This is active but not clockwork-flat. Core traffic is balanced between TCP (3,044) and UDP (2,976), with 86 ICMP records; DMZ is TCP-heavy (4,469 TCP, 772 UDP, 38 ICMP), as expected for a web-facing/perimeter segment.

The port and service mix supports the inferred placement. Core is dominated by DNS/53 (2,203), Kerberos/88 (1,016), SMB/445 (897), explicit proxy/8080 (812), LDAP/389 (638), and SSH/22 (107). DMZ is dominated by TLS/443 (1,889), proxy/8080 (979), DNS/53 (765), MySQL/3306 (347), HTTP/80 (290), plus visible unsolicited or administrative traffic on 23, 22, 445, 25, 3389, 2323, 587, and 465. External inbound traffic includes 1,883 connections from 296 source IPs, with both rapid scanners and a long tail; this avoids a single tiny scanner pool.

### TCP state, duration, and accounting

Durations have broad tails. Core median is 0.154 seconds, 90th percentile 6.967 seconds, 99th percentile 1,046.829 seconds, and maximum 15,384.873 seconds. DMZ median is 1.200 seconds, 90th percentile 5.537 seconds, 99th percentile 77.487 seconds, and maximum 15,384.888 seconds. The two very long tails are compatible with sessions crossing the slice boundary. State-specific histories and directional packet counts are coherent: `S0` has no response packets, `REJ` carries response reset packets but no payload, and successful `SF` records contain response traffic.

The first DMZ TLS flow, UID `CmD1AopVFaFuhyEGqv`, begins at `1710763201.704309` from `10.10.3.20:39573` to `104.18.43.244:443`, lasts 1.393195 seconds, and records 898/21,851 payload bytes with 21 missed bytes. The ASA builds the corresponding translated connection at 12:00:01 and tears it down at 12:00:03 with TCP FINs and 24,082 bytes. The slight timestamp precision and accounting differences are credible independent-observer effects.

### DNS, HTTP, and TLS contracts

Protocol fan-out is especially convincing. DNS rows share exact connection start timestamps and durations consistent with RTT, while HTTP can occur later in a persistent flow (core HTTP offsets range 0-5.195 seconds). SSL analyzer events occur after the connection opens (core 5.8-633.1 ms; DMZ 3.2-651.8 ms) and remain within the transport interval. Every checked companion preserves its connection tuple.

DNS includes common enterprise patterns: internal authoritative A/AAAA lookups, `_ldap._tcp.meridianhcs.local` SRV discovery, reverse lookups, external SaaS/CDN queries, NODATA AAAA responses, and a concentrated TXT stream from `10.10.2.30`. The latter has 291 queries beneath `westbridge-services.cloud`, but that is an observable suspicious behavior, not itself evidence of synthetic generation; its record semantics remain coherent.

TLS 1.2/1.3 versions and cipher pairing are reasonable. The x509 rows have correctly formatted 40-character SHA-1-style fingerprints, reuse fingerprints across repeated certificate observations while assigning observation-specific file IDs, distinguish leaf from CA certificates, and remain within validity periods. The proxy boundary also explains the different TLS volume between sensors: client-to-proxy CONNECT evidence dominates core HTTP while proxy-origin TLS dominates the DMZ sensor.

### Firewall, IDS, and proxy correlation

Firewall connection IDs have complete visible build/teardown lifecycles and mixed close reasons. NAT is applied where expected for DMZ-to-outside flows, while ACL deny records occur without pretending to be successful sessions. The 4,641 ASA-to-DMZ Zeek matches show close tuple/timing agreement without exact timestamp cloning.

Snort alerts likewise occur shortly around matching flow starts rather than at a universal fixed offset. For example, core and perimeter alerts include DNS policy signatures, STUN, P2P, scanning, TLS/JA3, and HTTP download behavior. The observed alert-to-flow offsets vary by tens of milliseconds, which is a realistic signature-processing relationship.

Proxy access logs distinguish CONNECT control-message bytes from tunnel bytes and inspected request bytes. The opening examples show a CONNECT for `outlook.office365.com` with `tunnel_cs_bytes=8316` and `tunnel_sc_bytes=70031`, followed by an inspected GET carrying `cs_bytes=8316` and `sc_bytes=70031`. Denies, authentication challenges, and gateway failures terminate at the proxy rather than being rendered as successful inspected requests. This is strong contract-level evidence.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `distribution_texture` | Zeek DHCP | Repeated across eight clients; strongest on 3,600-second leases | Host-specific renewal intervals have only about one second of jitter for many consecutive cycles; this is the clearest synthetic-looking texture, but still operationally possible. |
| `weak_signal` | Zeek DNS / proxy | Repeated high-volume destination families | Large counts concentrate on a few enterprise dependencies, but high per-origin timing entropy and plausible roles make this low impact. |
| `weak_signal` | Zeek SSL | Dataset-wide among emitted SSL rows | All emitted SSL analyzer rows are established, though failed 443 flows remain represented at the connection layer and need not emit SSL records. |

No `hard_contradiction`, `contract_gap`, or material `schema_or_format` indicator was found in the bounded and focused checks.

## Realism Score by Category

- **Field format accuracy:** 9 — Zeek, ASA, Snort, and proxy fields are source-native and internally typed; no impossible values were found.
- **Temporal patterns:** 8 — Connection/protocol/firewall/IDS ordering is coherent and hourly activity is uneven, with DHCP renewal smoothness the main deduction.
- **Cross-source correlation:** 9 — UIDs, tuples, intervals, and independent-sensor observations correlate without exact-clone artifacts or visible contradictions.
- **Behavioral realism:** 8 — Service, state, error, scanner, DNS, TLS, and proxy distributions have credible breadth, though a few repeated families remain visible.
- **Environmental consistency:** 9 — Core, DMZ, proxy, firewall, and IDS volumes and roles form a plausible segmented enterprise network.

## Recommendations

- If this were synthetic, increase DHCP renewal texture by modeling client/server-specific T1 behavior, scheduling latency, sleep/wake delays, missed renewals, and occasional lease rebinds. Preserve valid T1 semantics while avoiding nearly identical successive gaps for every lease on a client.
- Add a small number of parseable failed or incomplete TLS analyzer observations where the connection state supports them, if that matches the intended Zeek collection profile. This would diversify the all-`established=true` SSL population without manufacturing contradictions.
- Continue widening low-frequency destination and error-path pools while retaining the strong existing per-origin timing entropy. The goal should be a longer tail around common DC, file-server, update, and SaaS dependencies, not removal of those realistic high-volume services.
