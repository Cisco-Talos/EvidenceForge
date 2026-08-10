# Network Forensics Reviewer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 77  
**Synthetic-Confidence Score:** 65

## Executive Summary

The network evidence is unusually strong in tuple integrity, lifecycle accounting, protocol fan-out, and independent-sensor timing, and much of it would survive normal analyst scrutiny. I nevertheless judge it synthetic because the DHCP renewal schedules exhibit a persistent host-seeded timer fingerprint, and one externally originated SMTP/OCSP sequence creates an implausible publication and client-ownership relationship for an internal OCSP responder.

## Evidence For Synthetic

- `[distribution_texture]` DHCP renewals have almost invariant, host-specific periods rather than renewal timing naturally derived from the advertised lease. In `zeek-core/dhcp.json`, `WS-OHADDAD-01` has 13 renewals at a mean interval of 1,787.549 seconds with only 0.503-second standard deviation; `WS-LNGUYEN-01` has 11 at 1,940.636 ± 0.457 seconds; `WS-MCHEN-01` has 11 at 1,969.695 ± 0.582 seconds; and `WS-PPATEL-01` has 12 at 1,692.739 ± 0.763 seconds. All advertise a 3,600-second lease. The differing per-host offsets combined with subsecond repeatability are characteristic of deterministic host-scoped jitter.
- `[environment_or_collection_plausibility]` At `2024-03-18 13:49:54.993246 UTC`, `zeek-core/conn.json` records external `173.194.182.221:62282` delivering SMTP directly to `10.10.2.25:25`. At `13:49:58.046864`, the same external address initiates HTTP to internal `10.10.1.10:80`, requesting `Host: ocsp.meridianhcs.local` with a Firefox user agent (`zeek-core/http.json`, UID `CoVoM2LcC2S4mtqSE2Q`). The ASA confirms an inbound connection with identical untranslated private inside address: `outside:173.194.182.221/55978 ... to inside:10.10.1.10/80 (10.10.1.10/80)`. This resembles an OCSP companion attributed to the remote SMTP peer without a credible public OCSP publication/NAT path.
- `[distribution_texture]` Core DNS is strongly dominated by mechanically recurring infrastructure lookup texture: 553 of 2,210 DNS rows query `DC-01.meridianhcs.local`. One client, `10.10.1.35`, performs 36 A lookups at a mean interval of 611.060 seconds with CV 0.031. This is plausible as periodic software behavior, but in combination with the DHCP fingerprint it suggests deterministic scheduling pools rather than independently evolving resolver/client state.
- `[weak_signal]` The DMZ source `185.70.41.45` creates 437 inbound connections in roughly 50 minutes, including 436 to TCP/443; 383 produce TLS rows, all using TLS 1.3, one cipher, and one SNI (`ehr-portal.meridianhcs.com`). This can represent a real automated client or workload, but its narrowly parameterized texture adds some generator-like regularity.

## Evidence For Real

- Protocol-to-connection integrity is excellent. Every DNS, HTTP, SSL, SMTP, and file UID examined resolves to a connection on its sensor; there were zero tuple mismatches and zero protocol timestamps outside their owning connection intervals.
- Packet accounting obeys network invariants across all 11,784 Zeek connection rows: neither sensor has an instance where IP bytes are less than payload bytes plus minimum IPv4 headers, an `SF` connection without responder packets, or an `S0` connection with responder packets.
- ASA lifecycle texture is credible rather than perfectly closed at the capture boundary: 4,206 TCP build messages have 4,203 teardowns, while all 803 UDP builds have teardowns. There are also 1,064 matched dynamic translation builds and teardowns and 163 policy denies.
- Cross-source byte semantics are source-native. For UID `CnchkJ7HwIg2db6iz1Q` at `12:00:05.841123`, Zeek records 801/18,412 payload bytes and 1,005/19,356 IP bytes. The proxy splits the same transaction into 294+507 client bytes and 178+18,234 server bytes, while the ASA teardown reports 20,361 bytes—the Zeek IP-byte total.
- Multi-sensor timing is plausible rather than identical. The DNS flow `10.10.3.10:45724 -> 10.10.2.10:53` appears at `12:10:28.872284` on core and `12:10:28.915296` on DMZ with different UIDs; Snort observes it at `12:10:28.870185`/`12:10:28.864648`. This is credible sensor-placement and observation latency.
- TLS certificate linkage is internally coherent: all 550 `cert_chain_fuids` across the two sensors resolve, no x509 records are orphaned, and no observed certificate is future-dated or expired.
- Network distributions have meaningful long tails: core includes nine Zeek connection states and DMZ includes nine, with varied reset, rejection, partial, and zero-response behavior; file telemetry includes missing bytes, varied analyzers, multiple MIME families, and repeated files maintaining stable hashes.

## Detailed Analysis

### Quantitative probes

- Source volumes: 6,230 core and 5,554 DMZ Zeek connections; 2,210/784 DNS; 1,058/1,226 HTTP; 114/1,732 SSL; 330/598 files; 67 SMTP; 69 DHCP; 12,376 ASA records; 75 core and 114 perimeter Snort alerts.
- Time span: approximately `2024-03-18 12:00:05` through `17:59:57 UTC`.
- UID tests: zero missing connection UIDs for 2,994 DNS rows, 2,284 HTTP rows, 1,846 SSL rows, 67 SMTP rows, and 928 file rows; zero connection-UID duplicates within either sensor.
- Temporal tests: zero DNS/HTTP/SSL/SMTP events preceding their connection start or exceeding connection end; zero tuple mismatches.
- State/accounting tests: zero failures of minimum IP-byte accounting; zero impossible `SF`, `S0`, or `REJ` responder-state combinations tested.
- Certificate tests: 86 core and 464 DMZ x509 rows; all referenced, none outside validity.
- Firewall tests: message distribution includes 4,206 `%ASA-6-302013` TCP builds, 4,203 `%ASA-6-302014` teardowns, 803 UDP build/teardown pairs, 1,064 NAT build/teardown pairs, 35 ICMP build/teardown pairs, and 163 denies.

### DHCP timing

The DHCP rows are structurally sound: each references a UDP/68→67 `SF` connection, preserves hostname/MAC/IP identity, and carries REQUEST/ACK semantics. The defect is statistical. Every host receives its own nearly fixed renewal interval, but those intervals differ materially despite identical lease duration. That is more consistent with a stable seeded period plus tiny jitter than with lease ACKs independently scheduling the next T1.

### OCSP and SMTP ownership

The SMTP/file chain itself is realistic, including stable content hashes as messages traverse relays. The questionable edge occurs when an external SMTP peer is then modeled as an OCSP client of the organization's private responder. If the responder is intended to be Internet-published, the firewall should show a credible public mapped address and the HTTP host/AIA should be externally usable. If it is internal-only, the remote peer must not originate the request.

### Sensor and firewall correlation

Cross-source timing, bytes, NAT, and protocol decomposition are the strongest features. The core/DMZ observations use independent UIDs and slight latency offsets, Snort timing falls near packet observation rather than slavishly matching Zeek timestamps, and ASA totals use wire bytes rather than application payload bytes.

### Traffic texture

Minute-level connection rates are variable: core averages 17.31 rows/minute with standard deviation 8.91; DMZ contains substantial zero-response scan traffic and nine connection states. The inbound scan population has 219 source addresses and varied port families. These characteristics argue against a simplistic generator, although a few scheduled families remain overly deterministic.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Impact |
|---|---|---:|---|
| `distribution_texture` | Zeek DHCP | 69 rows, eight clients | Host-specific renewal periods repeat with subsecond variance despite common lease durations; strongest generator fingerprint. |
| `environment_or_collection_plausibility` | SMTP, Zeek HTTP/files/OCSP, ASA | One externally originated sequence | Remote SMTP peer accesses internal OCSP host through an untranslated RFC1918 publication path. |
| `distribution_texture` | Zeek DNS | 553 DC A queries; especially one 36-query series | Very stable recurring infrastructure lookup cadence reinforces seeded scheduling concerns. |
| `weak_signal` | Zeek DMZ TLS | 437 connections from one source | Narrow cipher/SNI/client texture is possible automation, but unusually parameterized. |

## Realism Score by Category

- **Field format accuracy:** 9/10 — Zeek, ASA, Snort, proxy, TLS, OCSP, and file fields are source-native and internally valid.
- **Temporal patterns:** 6/10 — sensor latency is excellent, but DHCP and some DNS schedules are too host-deterministic.
- **Cross-source correlation:** 9/10 — UIDs, tuples, byte scopes, NAT, protocol logs, and certificates correlate without impossible ordering.
- **Behavioral realism:** 7/10 — broad protocol and failure-state texture is strong; a few automated families are too narrowly parameterized.
- **Environmental consistency:** 6/10 — topology is mostly coherent, but the external-to-private OCSP sequence needs a credible publication model.

## Recommendations

- If synthetic, derive DHCP renewal time from the most recent ACK/T1 semantics and introduce realistic timer rescheduling, delay, missed renewals, rebinding, and occasional client sleep/reconnect behavior; avoid one permanent seeded period per host.
- Make OCSP ownership and routing explicit. Remote SMTP peers should query a publicly reachable AIA responder through a valid mapped address, while internal endpoints may use `ocsp.meridianhcs.local`. Do not reuse the remote mail peer as an internal OCSP client without visible VPN or publication evidence.
- Add resolver cache/state behavior so repeated DC lookups vary by TTL expiry, process lifecycle, negative caching, and resolver restarts rather than stable per-client cadence.
- Broaden long-running automated TLS-client texture where appropriate: connection reuse, HTTP/2 multiplexing, cipher/version variation across client upgrades, and realistic failure/retry phases would reduce narrow source fingerprints.
