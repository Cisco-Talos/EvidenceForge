# Network Forensics Analyst — Authenticity Assessment

## Verdict

- Assessment: Synthetic
- Verdict Confidence: 82/100
- Synthetic-Confidence Score: 65/100 — likely synthetic

## Executive Summary

The telemetry is technically strong and, at the individual-record level, often resembles real Zeek collection. Connection states, packet and byte accounting, loss indicators, DNS behavior, TLS chains, DHCP renewals, proxy routing, scanning, and multi-sensor visibility are generally coherent. I found no decisive schema failure or impossible packet-level contradiction.

The synthetic verdict is instead driven by two repeated timing distributions that are difficult to reconcile with independently observed production TCP and browser behavior. First, 29 of 32 matched cleartext proxy transactions had client-to-proxy and proxy-to-origin connections whose calculated end times agreed to within one microsecond, despite different start times and durations. Second, 27 of 59 within-connection HTTP transaction intervals in `zeek-core/http.json` were within 10 microseconds of exactly 0.600000 seconds, including runs of five consecutive exact intervals across different web objects. These are concrete, log-visible scheduling signatures rather than judgments based on sanitized domains, missing source types, filesystem timestamps, or unusually complete correlation.

The result falls in the lower half of “likely synthetic,” not “confidently synthetic,” because the remaining traffic has substantial production-like texture: realistic Zeek state/history combinations, capture-loss accounting, TTL aging, TLS certificate relationships, proxy success/failure behavior, and independently delayed endpoint flow observations.

## Evidence For Synthetic

- **Proxy-leg end times are repeatedly locked together** (`distribution_texture`, high weight). I matched 32 cleartext HTTP transactions between a client-to-proxy connection (`10.10.3.20:8080`) and the corresponding proxy-to-origin connection (`10.10.3.20` to destination port 80), using client identity, method, body lengths, and transaction content. In 29 of 32 pairs, the two TCP end times—`ts + duration`—were equal to within one microsecond. Independent TCP legs can be causally close, but systematic microsecond equality is not a normal consequence of proxying; each leg ordinarily has its own response completion, FIN exchange, retransmission, and capture timing.

  A representative case is visible in `zeek-dmz/conn.json`:

  - Line 149, UID `CS002AEh6XAKwU6u1`: `2024-03-18T12:12:00.859232Z`, `10.10.2.10:52559 -> 10.10.3.20:8080`, duration `7.663730`, response bytes `118846194`. Calculated end: `2024-03-18T12:12:08.522962Z`.
  - Line 152, UID `CVmjK49GmSNHt6Ly2`: `2024-03-18T12:12:01.476075Z`, `10.10.3.20:56538 -> 52.84.140.36:80`, duration `7.046887`, response bytes `118846208`. Calculated end: the same `2024-03-18T12:12:08.522962Z`.
  - The corresponding `zeek-dmz/http.json` records are lines 40–41: two GET observations for `dl.duosecurity.com` with the same URI and `response_body_len=118845978`, first as an absolute proxy request and then as the origin request.

- **Persistent HTTP requests exhibit a fixed 600 ms scheduler cadence** (`distribution_texture`, high weight). Among 59 transaction-to-transaction intervals on multi-request UIDs in `zeek-core/http.json`, 27 (45.8%) were within 10 microseconds of exactly `0.600000` seconds. For UID `CdgbJ2WGIwMQpVyyEIN`, lines 1374–1378 and 1380 occur at:

  - `2024-03-18T17:09:51.325284Z` — `/assets/js/vendor.757467b6.js`
  - `2024-03-18T17:09:51.925284Z` — `/assets/img/logo.svg`
  - `2024-03-18T17:09:52.525284Z` — `/favicon.ico`
  - `2024-03-18T17:09:53.125284Z` — `/assets/js/app.bundle.d8a74c0f.js`
  - `2024-03-18T17:09:53.725284Z` — `/assets/css/main.min.07b8945e.css`
  - `2024-03-18T17:09:54.325284Z` — `/assets/img/hero.webp`

  This is five consecutive exact 600 ms steps on one HTTP/1.1 connection. Browser parsing, object size, RTT, server response time, and connection reuse ordinarily produce visibly irregular intervals. The same pattern recurs beyond this example, making a deterministic event scheduler more likely than a chance application timer.

- **A small number of explicit file references have no referenced file record** (`contract_gap`, low-to-medium weight). Five of 1,958 inspected protocol-level file references lack their sensor-local `files.json` FUID despite the associated connection reporting no `missed_bytes`:

  - `zeek-core/http.json` line 1246: `2024-03-18T16:38:45.339341Z`, UID `CyJv...`, GET `/assets/img/content/a956ddb4.webp`, `response_body_len=44932`, missing FUID `FpjoaSr7TpZDgauAoF`.
  - `zeek-core/http.json` line 1387: failed npm-registry CONNECT, status `407`, `response_body_len=1133`, missing FUID `FOG2F0IrL0Zaal45eq`.
  - `zeek-core/smb_files.json` line 142: `2024-03-18T16:50:06.752182Z`, SMB `FILE_READ` from `\\DC-02\SYSVOL`, file `User\2027\startup-review.ini`, size `212367`, missing FUID `FEPJIENeNLjvXCrJBe`.
  - `zeek-dmz/http.json` line 497: CONNECT to `res.cdn.office.net`, status `502`, response length `875`, missing FUID `FGI5kCqMApTN53P8c`.
  - `zeek-dmz/http.json` line 1394: HTTP JPEG response length `92011`, missing FUID `FvJDayWpRyaUPFOCO9`.

  At roughly 0.26% of references, this is not decisive; selective export loss could produce it. It is nevertheless a concrete referential-integrity gap.

- **One STARTTLS observation lacks its usual TLS companion** (`contract_gap`, low weight). `zeek-core/smtp.json` line 42, UID `CMrD1LpYsa9lE2CaUN`, at `2024-03-18T17:09:24.902591Z`, records `tls=true` and reply `220 2.0.0 TLS go ahead`, but has no same-UID `ssl.json` record. Its `zeek-core/conn.json` entry at line 9799 is `SF`, duration `3.231191`, `missed_bytes=0`, and history `ShADadTFf`. Thirty of the other 31 SMTP rows marked TLS had a matching SSL record. A client abort immediately after STARTTLS remains a plausible real-world explanation, so this carries little weight.

## Evidence For Real

- **Zeek connection semantics are highly coherent.** Across 20,069 connection records, UIDs are unique within each sensor and are sensor-local across sensors. `S0` TCP records have SYN-only-style history and no completed duration; `REJ` records use reset/reject history; successful `SF` traffic has bidirectional histories. Packet and IP-byte minima are respected. Every one of the 1,106 connections with nonzero `missed_bytes` also carries a `g` or `G` history marker, and no zero-loss connection has such a marker. This is strong source-native behavior.

- **Capture viewpoints differ in realistic ways.** For the same tuple `10.10.1.22:43000 -> 10.10.3.10:80`, `zeek-core/conn.json` line 4 (UID `C8dc...`, `2024-03-18T12:01:12.731112Z`) reports `orig_bytes=605`, `orig_pkts=4`, and no missed bytes. `zeek-dmz/conn.json` line 6 (UID `CaV...`, `2024-03-18T12:01:12.615412Z`) reports `orig_bytes=598`, `orig_pkts=3`, `missed_bytes=7`, and history ending in `G`. The independent UID, sensor clock offset, packet count, and exact loss accounting resemble separate collection points rather than duplicated rows.

- **Protocol-to-connection contracts are otherwise excellent.** DNS, HTTP, SSL, SMTP, SMB, and file records join a sensor-local connection UID with matching tuples, and their timestamps remain inside the connection interval. HTTP transaction depths are monotonic and gap-free. Where HTTP body totals exceed captured connection payload, the excess is covered by that connection's `missed_bytes`. SMB file sizes agree with the corresponding file-analysis totals.

- **DNS contains realistic cache aging and failure texture.** Across 3,897 DNS records, query types include A, AAAA, TXT, PTR, SRV, NS, MX, and SOA; response codes include 3,527 `NOERROR`, 347 `NXDOMAIN`, 16 `SERVFAIL`, and 7 `REFUSED`. Address families and answer/TTL counts are consistent. A particularly strong example is `ctldl.windowsupdate.com` in `zeek-core/dns.json`: line 1210 at `2024-03-18T14:48:25.539033Z` returns `52.114.132.73` and `52.114.128.40` with TTL `1874`; line 1342 repeats the same query and answers `1511.884747` seconds later with TTL `362`, a decrease of exactly 1,512 seconds after integer rounding. Similar aging occurs for several other destinations.

- **TLS and X.509 relationships are internally credible.** The data contains 1,615 TLS 1.3 and 881 TLS 1.2 sessions, seven cipher suites, and both resumed and full handshakes. Certificate FUIDs join file-analysis rows; SHA-1 fingerprints agree between `files.json` and `x509.json`; certificate contents remain stable by fingerprint; issuer-to-subject chain links resolve; validity windows cover the observed sessions; and checked SNI values agree with leaf SANs. For example, `zeek-dmz/ssl.json` line 4 records a TLS 1.2 connection from the proxy to `185.125.188.60:443` with SNI `api.snapcraft.io`, cipher `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`, and two certificate FUIDs. The corresponding `files.json` and `x509.json` records form an `api.snapcraft.io -> R3 -> ISRG` chain whose validity covers the event.

- **Proxy behavior has causal and failure-state realism.** Successful CONNECTs usually lead to outbound TLS shortly afterward; failed `403`, `407`, `502`, `503`, and `504` CONNECTs generally do not. For cleartext HTTP, the client sends an absolute URI to `10.10.3.20:8080`, while the proxy sends the corresponding relative URI to the origin, preserving request and response semantics. This is realistic proxy transformation even though the repeated exact TCP close alignment is not.

- **Traffic behavior is not uniformly clean.** The internal burst around `13:40–13:41Z` contains an Nmap-like sweep from `10.10.3.10` across 254 addresses using ICMP and TCP ports 22, 80, 443, 445, and 3306. It produces mostly `S0` results plus `REJ`, replies, and varied source ports. DMZ traffic also includes unsolicited inbound sources with mixed `SF`, `S0`, `RSTO`, and `RSTR` outcomes, while outbound traffic is dominated—but not exclusively populated—by proxy HTTPS. Long-lived SSH/RDP flows, database traffic, and variable connection durations add plausible operational texture.

- **Endpoint flow observations are not timestamp clones.** Of the ECAR FLOW rows that could be matched to Zeek TCP/UDP tuples, the endpoint-to-Zeek time difference ranged from approximately `-0.849` to `+3.750` seconds, with a median near `+0.178` seconds. That range is consistent with source-specific observation and publication latency.

## Detailed Analysis

The three Zeek views contain 11,258 core, 490 database-segment, and 8,321 DMZ connection rows. Their state distributions are plausible for their positions: core and DMZ include substantial `S0` scan or failed-connect traffic alongside dominant `SF`; the database view is smaller and more heavily successful, with some resets. Durations are broad rather than integer-quantized: medians are approximately `0.043439` seconds in core, `1.575184` seconds in the database segment, and `1.670834` seconds in the DMZ, with long sessions extending to roughly `13,320` seconds.

Cross-sensor tuple matches exhibit stable clock offsets: database minus core has a median near `+0.061939` seconds, DMZ minus core near `-0.114227` seconds, and DMZ minus database near `-0.178820` seconds. A stable offset is entirely plausible for imperfectly synchronized sensors and was not scored as synthetic. Matching observations preserve state and service while still showing viewpoint-specific packet loss and byte differences.

DHCP records show six hosts renewing at approximately half their lease period with per-host jitter rather than at one global interval. DNS includes coherent internal A, PTR, and SRV records as well as realistic negative answers. Protocol volume is environment-shaped: explicit proxy CONNECT traffic dominates HTTP, TLS is split between TLS 1.2 and 1.3 with resumption, SMB is concentrated on internal file/DC paths, MySQL links the application and database segments, and SSH/RDP appear as longer administrative sessions.

No dedicated firewall, IDS-alert, or standalone proxy-access file is present in the reviewed directory. I did not reduce the score for that absence. The available `http.json` CONNECT records provide proxy visibility, while Zeek connection records and ECAR FLOW rows provide network and endpoint viewpoints.

The decisive issue is likelihood, not logical possibility. One proxy implementation might intentionally coordinate both legs, and one application might use a 600 ms timer. However, microsecond-equal completion across 29 of 32 separately captured TCP pairs, combined with repeated exact 600 ms browser-resource sequencing, is substantially more probable under deterministic synthesis than under ordinary production traffic. The many realistic lower-level details prevent an 81–100 rating, but they do not neutralize those repeated scheduler fingerprints.

## Synthetic Indicator Summary

| Indicator | Category | Weight | Concrete scope |
|---|---|---:|---|
| Proxy ingress and egress TCP legs end at the same recorded microsecond | `distribution_texture` | High | 29 of 32 matched cleartext proxy transactions |
| Multi-request HTTP sessions repeatedly advance by exactly 600 ms | `distribution_texture` | High | 27 of 59 intervals within 10 µs; one six-request run has five exact steps |
| Referenced FUID absent from sensor-local file analysis | `contract_gap` | Low–medium | 5 of 1,958 inspected references |
| SMTP STARTTLS accepted without a same-UID SSL row | `contract_gap` | Low | 1 of 31 SMTP rows marked TLS |
| Stable offsets between sensor clocks | `weak_signal` | Discounted | Dataset-wide but operationally plausible |
| Impossible network or protocol relationship | `hard_contradiction` | None found | No material instance |
| Source-native field or serialization defect | `schema_or_format` | None found | No material instance |
| Implausible environment solely from coverage or sanitized names | `environment_or_collection_plausibility` | None scored | Coverage absence and domains were not used as synthetic evidence |

## Realism Score by Category

| Category | Score | Rationale |
|---|---:|---|
| Field format accuracy | 9/10 | Zeek states, histories, packet/byte fields, UIDs, protocol fields, TLS, and file metadata are source-native and coherent. |
| Temporal patterns | 5/10 | Broad session durations and realistic cache/lease timing are offset by strong 600 ms and exact proxy-close signatures. |
| Cross-source correlation | 9/10 | Sensor-local joins, tuple continuity, certificate chains, proxy transformations, and endpoint delays are strong; a few FUID/STARTTLS gaps remain. |
| Behavioral realism | 8/10 | Scanning, proxy failures, inbound noise, lateral protocols, and destination diversity are convincing. |
| Environmental consistency | 8/10 | Segment roles and traffic direction are coherent, with no material impossible placement found. |

## Recommendations

- Decouple client-facing and origin-facing proxy TCP lifecycle completion. Preserve causal ordering, but independently model response drain, FIN/ACK timing, retransmission, keep-alive policy, and sensor timestamp jitter on each leg.
- Replace fixed 600 ms HTTP transaction spacing with dependency-aware browser scheduling: parallel fetch limits, parser discovery, object-size-dependent completion, RTT/server latency, cache hits, and connection reuse should all influence request times.
- Enforce sensor-local referential integrity for every emitted FUID, or explicitly model the collection/export loss that removes a `files.json` row and make that loss consistent with connection/file-analysis metadata.
- Model STARTTLS as separate acceptance, handshake, and encrypted-session stages so an absent SSL row is attributable to a visible abort/failure state rather than an unexplained companion gap.
- Retain the current connection-state, capture-loss, DNS TTL, TLS-chain, proxy-failure, and cross-sensor viewpoint behavior; these are the strongest authenticity features in the sample.
