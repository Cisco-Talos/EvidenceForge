# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 87
**Synthetic-Confidence Score:** 74

## Executive Summary

The network telemetry is sophisticated and frequently production-like, with coherent TCP state histories, realistic DNS diversity, independent sensor UIDs, and strong firewall/Zeek accounting. Nevertheless, copied DNS timing measurements across nominally separate sensors, incomplete SSL lifecycle rendering, universally absent TLS negotiation fields, and templated inbound HTTP behavior collectively make synthetic generation more likely.

## Evidence For Synthetic

- `[contract_gap]` All 2,429 records in the three `ssl.json` files have `established:true`, while 176 `conn.json` records classified as `service:"ssl"` have no SSL companion. Eighteen omissions are completed `SF` connections with zero `missed_bytes`, including `zeek-core` UID `CTsMkOr2tO1hRVgRUB` at `2024-03-18 16:18:48.701536 UTC`, which transferred 51,896 payload bytes and closed normally.

- `[distribution_texture]` DNS `rtt` values are copied exactly between sensors for every matched transaction: all 931 core/DMZ matches and all 40 core/DB matches have bit-identical RTTs. For example, the query for `telemetry-40qc7n9f.cloud` appears at `12:05:00.777944` on core and `12:05:00.664299` on DMZ with different UIDs but exactly `rtt:0.000908`. Sensor-specific connection durations vary by hundreds of microseconds, making the complete absence of sensor-level variation in derived DNS RTT conspicuous.

- `[schema_or_format]` None of 2,429 TLS records contains `next_protocol`, `curve`, `validation_status`, or `last_alert`. Zero ALPN observations across 1,406 DMZ TLS 1.3 sessions and substantial modern browser/cloud traffic is difficult to reconcile with ordinary contemporary Zeek TLS telemetry.

- `[distribution_texture]` The DMZ HTTP stream contains 71 public-origin requests to `10.10.3.10`, from exactly 71 distinct source IPs and 71 distinct UIDs. Every public client appears once, while most use a narrow pool of current desktop browser strings. This lacks the repeated clients, connection reuse, bot/scanner user-agent tail, and uneven client-frequency distribution normally expected on a public web endpoint.

- `[schema_or_format]` Redirect response MIME types appear to follow the requested filename rather than the redirect entity body. Twenty DMZ redirects carry non-HTML MIME types—for example, `/assets/main.css` receives `301`, a 277-byte body, and `text/css` at `12:03:06.249661`; `/assets/app.js` repeatedly receives `301`, a 285-byte body, and `application/javascript`. This is technically possible but strongly resembles URI-derived synthetic rendering.

- `[distribution_texture]` TLS negotiation vocabulary is unusually bounded: only three TLS 1.3 ciphers, four TLS 1.2 ciphers, and eight exact version/history combinations occur. Combined with the universal successful-handshake logging, this looks more like a curated state pool than natural protocol variation.

## Evidence For Real

- Connection states are varied and source-native: core contains 8,638 `SF`, 1,952 `S0`, 118 `RSTO`, 86 `RSTR`, plus `S1`, `S2`, `S3`, `REJ`, and `OTH`. Their histories generally agree with the state, including `S0/S`, `REJ/Sr`, `RSTR/ShADadr`, and successful bidirectional histories.

- The large `13:51 UTC` spike has a coherent cause rather than smooth background inflation. Host `10.10.3.10` makes approximately 1,268 attempts across five ports and a `/24`, producing 1,238 `S0` records, 20 `REJ`, and a small number of successes. Inter-arrival times vary around a few milliseconds.

- DNS has credible breadth. Core includes 2,097 A, 252 AAAA, 129 PTR, 93 SRV, 314 TXT, and smaller MX/SOA/NS populations, with 210 NXDOMAIN, 18 SERVFAIL, and three REFUSED responses. Queries such as `wpad`, `isatap`, stale hostnames, reverse lookups, and AD SRV names give the environment realistic texture.

- DHCP renewals occur near T/2 with meaningful jitter. One-hour leases renew roughly every 30 minutes, two-hour leases around one hour, and four-hour leases around two hours. All-visible `REQUEST/ACK` pairs are plausible in a bounded window containing ongoing leases.

- Multi-sensor identity handling is realistic in important respects. There are no shared connection UIDs between core, DMZ, and DB, while the same flows receive distinct UIDs and stable clock offsets. Packet/byte counts sometimes differ between sensors, consistent with observation-position effects and loss.

- Firewall accounting correlates convincingly with Zeek. The ASA connection built at `12:00:03` from `76.44.118.248:53672` to `10.10.3.10:443` tears down with 808,317 bytes; the corresponding DMZ Zeek record’s `orig_ip_bytes + resp_ip_bytes` is exactly 808,317.

- Zeek byte accounting handles observed loss plausibly. UID `CSBMReILR36ahgb6Kg` at `14:08:37.936220` has 5,476 `missed_bytes`; its three HTTP bodies total 526,578 bytes, while observed TCP responder payload is 521,723 bytes. The apparent excess is smaller than the declared loss and is therefore coherent.

- TLS versions and ciphers are mutually compatible. Certificate-bearing sessions have valid chains, all inspected certificates cover their SNI names, and none is observed outside its validity interval.

- Locality fields are consistent across all 19,215 connection records: private addresses are marked local and public addresses non-local, including correct inbound/outbound behavior at the DMZ sensor.

## Detailed Analysis

### Connection and Flow Behavior

The observation window spans approximately six hours, from `2024-03-18 12:00 UTC` to just before `18:00 UTC`. The sensors contain 10,877 core, 7,918 DMZ, and 420 DB connection records.

The overall transport mix is plausible:

- Core: 5,721 TCP, 4,770 UDP, 386 ICMP.
- DMZ: 6,623 TCP, 1,000 UDP, 295 ICMP.
- DB: 339 TCP, 64 UDP, 17 ICMP.

Core traffic includes substantial DNS, Kerberos, LDAP, proxy HTTP, SMB, TLS, syslog, SSH, DHCP, and SMTP. The DB sensor is appropriately dominated by MySQL—264 service-classified connections—while DMZ traffic emphasizes TLS, HTTP, proxy traffic, and inbound scans.

Durations are non-uniform and service-sensitive. Median duration is approximately 53 ms on core, 1.54 seconds on DMZ, and 1.79 seconds on DB. The data includes short transactions, multi-second application sessions, resets, and long-lived connections. Packet and IP-byte values are arithmetically sound; no record reports payload exceeding IP bytes or payload with zero packets.

The `13:51 UTC` scan is especially convincing. It produces approximately 254 attempts each against ports 22, 80, 443, 445, and 3306 across an internal `/24`, with mostly unanswered SYNs but some resets and successful connections. This explains the otherwise extreme one-minute volume and elevated `S0` share.

### DNS

All 2,910 core, 935 DMZ, and 40 DB DNS records join to a same-sensor connection UID and fall within the associated connection interval. Query types, return codes, recursion flags, TTLs, and internal AD naming are generally realistic.

The most consequential defect is cross-sensor RTT duplication. All 971 transactions matched across sensor views have exactly identical `rtt` values despite distinct Zeek UIDs and sensor-specific timestamps. Core/DMZ connection starts differ by a median of about 114.3 ms, and their connection durations commonly differ by several hundred microseconds. Real independent observations can have stable clock skew, but their request-to-response measurements should retain some capture-position or timestamp noise. Exact six-decimal equality across every transaction suggests a canonical RTT was copied into each rendered sensor view.

### HTTP and Proxy Traffic

HTTP UID and tuple correlation is structurally strong. All HTTP records match a connection, transaction depths progress correctly on reused connections, and no `304` response has a body. Successful CONNECT responses correctly have zero HTTP body length, while tunnel byte counts are represented separately in the proxy log.

The main weakness is public-facing traffic texture. On DMZ, all 71 public-origin requests come from unique IPs and each source appears once. The clients draw heavily from a small modern desktop browser pool. A real public endpoint would usually show some repeated clients or NAT sources, plus a longer tail of crawlers, scanners, mobile clients, malformed requests, and uncommon user agents.

Redirect content also appears templated. Repeated `301` responses to CSS and JavaScript paths use fixed body lengths and MIME types corresponding to the requested extension. Because Zeek MIME classification should describe the observed response body, this pattern suggests that MIME was selected from URI metadata.

### TLS, Certificates, and OCSP

The TLS version and cipher distribution is credible at a high level:

- Core: 158 TLS 1.3 and 173 TLS 1.2.
- DMZ: 1,406 TLS 1.3 and 661 TLS 1.2.
- DB: 31 TLS 1.2.

TLS 1.3 uses AES-GCM and ChaCha20 suites; TLS 1.2 uses compatible ECDHE RSA/ECDSA suites. Certificate chains have valid time ranges and correct SNI/SAN relationships. OCSP timestamps and status intervals are plausible.

The lifecycle coverage is not credible without an undocumented filter. The connection logs identify 2,574 SSL sessions, but only 2,429 SSL records exist. The 176 missing companions include resets and incomplete states, yet Zeek’s SSL schema explicitly supports unsuccessful sessions. More importantly, 18 omissions are normal `SF` connections with no packet loss and significant bidirectional payload. Simultaneously, every emitted SSL row is established successfully, with no alerts or failed-handshake state anywhere.

No TLS record has an ALPN or curve value. While these fields are optional and policy-dependent, total absence across thousands of modern TLS sessions materially reduces source-native realism.

### Cross-Sensor and Cross-Source Correlation

The same flows are observed with different Zeek UIDs, which is correct for separate sensor instances. Approximately 4,070 connections match between core and DMZ by tuple and near timestamp, 137 between core and DB, and 282 between DMZ and DB. State and service classifications agree, while histories, loss, packet counts, and durations show limited sensor-specific differences.

ASA lifecycle evidence aligns particularly well with DMZ Zeek telemetry. NAT directions, source and destination zones, ports, teardown reasons, and byte counts are coherent. Snort alerts also align temporally with relevant DNS, scan, STUN, and HTTP events. These details weigh strongly toward realism, although they do not erase the copied derived values and incomplete TLS lifecycle.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---:|---|
| `contract_gap` | Zeek SSL/conn | 176 SSL-classified connections; 18 completed lossless flows | Strong: required SSL lifecycle evidence is selectively absent while every logged SSL session succeeds |
| `distribution_texture` | Zeek DNS across sensors | All 971 matched multi-sensor DNS transactions | Strong: derived RTT values are exactly copied despite sensor-specific timing differences |
| `schema_or_format` | Zeek SSL | All 2,429 SSL records | Moderate-to-strong: no ALPN, curve, validation, alert, or unsuccessful-session variation |
| `distribution_texture` | DMZ HTTP | 71 public clients/71 requests | Moderate: every source appears exactly once and draws from a narrow user-agent pool |
| `schema_or_format` | DMZ HTTP/files | 20 redirects | Moderate: response MIME repeatedly follows requested asset extension |
| `distribution_texture` | Zeek SSL | Dataset-wide | Weak-to-moderate: small fixed cipher/history vocabulary and universally successful logged handshakes |

## Realism Score by Category

- **Field format accuracy:** 8 — Zeek, ASA, Snort, DNS, certificate, and byte-accounting fields are mostly source-native, with weaknesses in TLS completeness and redirect MIME behavior.
- **Temporal patterns:** 8 — Activity is bursty, DHCP renewals are jittered, and scans have credible pacing, but cross-sensor DNS RTTs are unnaturally identical.
- **Cross-source correlation:** 7 — UID joins, tuples, firewall bytes, and IDS timing are excellent; missing SSL companions and copied derived timing lower the score.
- **Behavioral realism:** 7 — Service mix, scans, AD traffic, proxy use, and resets are credible, but public web-client and TLS-outcome distributions are too constrained.
- **Environmental consistency:** 8 — Sensor placement, locality flags, DMZ exposure, proxy routing, and DB traffic are internally coherent.

## Recommendations

If this were synthetic, the following changes would improve it:

- Generate an `ssl.json` record whenever the Zeek SSL analyzer has classified a connection as SSL, including unsuccessful handshakes with `established:false` and appropriate `last_alert` or partial history. Conversely, do not label a connection `service:"ssl"` when insufficient protocol evidence exists.

- Derive DNS RTT separately from each sensor’s request and response timestamps. Preserve realistic clock skew, propagation delay, capture delay, and per-sensor timestamp noise rather than copying one canonical RTT.

- Populate TLS ALPN and curve fields according to client/server capabilities. Include realistic failed negotiations, alerts, validation outcomes, and limited parser visibility while keeping them consistent with connection histories.

- Increase public HTTP client recurrence and frequency skew. Add repeated visitors, NAT-shared addresses, persistent HTTP transactions, bot/scanner user-agent tails, and uncommon or malformed requests.

- Determine HTTP MIME type from the rendered response body and status-specific representation, not from the requested URI extension. Redirect templates should generally produce HTML or empty bodies unless a deliberately unusual server behavior is modeled.

- Broaden TLS history and cipher distributions according to endpoint age, application stack, and operating system, while retaining the current valid version/cipher pairings.
