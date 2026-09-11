# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Real  
**Verdict Confidence:** 74  
**Synthetic-Confidence Score:** 34

## Executive Summary

The corpus is mostly production-like: connection states, packet accounting, DNS caching, TLS behavior, sensor clock skew, and firewall/IDS correlation are unusually coherent at a protocol level. The strongest contrary evidence is an unexplained firewall-policy discontinuity during an internal scan, supplemented by overly uniform dual-stack DNS timing and a few weaker collection/distribution artifacts.

## Evidence For Synthetic

- `[contract_gap]` The firewall repeatedly denies `10.10.3.10 → 10.10.2.30:443`—79 times across the window—but permits the same route during the internal scan. Examples:

  - `12:00:08`: ASA denies `10.10.3.10/35200 → 10.10.2.30/443`.
  - `13:40:39`: ASA builds connection `1684232` for `10.10.3.10/35352 → 10.10.2.30/443`.
  - Zeek records that connection as `SF`, service `ssl`, duration `0.636729` seconds, with 172/500 payload bytes.
  - `13:44:53`: ASA resumes denying the same source, destination, and port.

  During the scan minute, approximately 1,270 TCP probes and 253 ICMP probes are accepted by the ASA, with no concurrent deny messages. A temporary ACL change could explain this, but no policy-transition telemetry exists in the provided firewall stream.

- `[distribution_texture]` Dual-stack DNS behavior is nearly universal and one-directional. In `zeek-core/dns.json`, 271 of 272 AAAA queries have an A query for the same client and name within five seconds; every pair has A first, by 40–829 ms, with a median gap of approximately 380 ms. Mixed Windows/Linux application traffic normally produces more variation: simultaneous requests, AAAA-first clients, cache-only queries, and unpaired lookups.

- `[environment_or_collection_plausibility]` Zeek identifies substantial higher-level protocol activity without corresponding protocol logs: 46 core `ssh` connections, 299 database-sensor `mysql` connections, and 18 core `rdp` connections, but no SSH, MySQL, or RDP log stream is present. Selective export could fully explain this, so it is a weak indicator rather than a contradiction.

- `[distribution_texture]` Dynamic response sizes in `web_access.log` vary more than expected for apparently stable pages:

  - `/about`: nine HTTP 200 responses, nine sizes, approximately 20.5–65.7 KB.
  - `/products`: five responses, five sizes, approximately 6.6–70.1 KB.
  - `/login`: five responses, five sizes, approximately 18.8–73.8 KB.

  Personalization and compression can explain some variation, but the one-size-per-request pattern resembles independent value generation.

## Evidence For Real

- TCP and UDP state semantics are strong. Across 19,833 Zeek connection records, I found no negative counters, payload exceeding IP-byte accounting, bytes attributed to zero packets, or `S0` connections containing response traffic. TCP histories align with states such as `S`, `Sr`, `ShADaR`, `ShADadr`, and complete FIN sequences.

- Connection-state diversity is credible. Core traffic includes 8,716 `SF`, 1,951 `S0`, 150 `RSTO`, 98 `RSTR`, 27 `REJ`, and smaller `S1/S2/S3/OTH` populations. Durations have long tails rather than fixed templates: core median `0.043415` seconds, 90th percentile `4.605792`, and maximum `13,315.907602`.

- DNS cache behavior is source-native and convincing. Among 26 cache-eligible repeated non-authoritative answers from the same resolver, name, type, and answer set, 25 decrement their TTL within one second of the value predicted from elapsed time. The remaining pair differs by about 27 seconds.

- DNS content has credible diversity: core records include 2,114 A, 272 AAAA, 250 TXT, 127 PTR, 98 SRV, plus NS/MX/SOA traffic. Responses include 220 NXDOMAINs, 15 SERVFAILs, and four REFUSED results, including realistic `wpad`, `isatap`, stale-host, and reverse-lookup failures.

- Cross-sensor clock behavior looks organic. I matched 4,184 core/DMZ observations of the same five-tuples. They have identical connection states and services but independent Zeek UIDs, a median DMZ-minus-core offset of approximately `-114.172 ms`, gradual drift, and occasional packet/byte differences consistent with distinct capture points.

- Firewall lifecycle accounting is strong. The ASA contains 6,417 TCP build and 6,415 teardown messages; only two builds lack teardown, both plausibly crossing the window edge. All 986 UDP builds have teardowns, no teardown precedes its build, and connection IDs increase consecutively from `1681558` to `1688960`.

- Of 7,403 ASA TCP/UDP builds, 7,401 match a Zeek five-tuple within two seconds. All 5,195 matched records with a finite Zeek duration agree with the ASA’s whole-second duration to within one second.

- TLS semantics are internally sound. The DMZ sensor has 1,531 TLS 1.3 and 689 TLS 1.2 sessions with version-compatible cipher suites. I found no certificate used outside its validity period, SNI/SAN mismatch, version/cipher contradiction, or TLS event after connection closure.

- Certificate identity is stable rather than regenerated per session. For example, 91 observed certificate-bearing connections to `ehr-portal.meridianhcs.com` use one fingerprint, as do 33 for `registry.npmjs.org` and 29 for `api.snapcraft.io`. Missing chains are concentrated in TLS 1.3 or resumed sessions, where passive certificate visibility is naturally limited.

- All 185 Snort alerts match visible Zeek connections. Relative clock offsets are bounded and sensor-specific: approximately 215–325 ms for core and 215–316 ms for perimeter alerts.

- Traffic timing is bursty. Dominant connection families have interarrival coefficients of variation generally above 1, with nearly every millisecond-rounded interval unique. The major `13:40` spike is technically consistent with an observed `nmap -sT -p 22,80,443,445,3306 10.10.2.0/24` scan: roughly 254 targets, five TCP ports, and ICMP discovery.

- DHCP renewal behavior is plausible: 47 transactions across six clients, heterogeneous 3,600/7,200/14,400-second leases, renewal jitter, and one apparent missed renewal rather than mechanically complete sequences.

## Detailed Analysis

### Connection and transport behavior

The three Zeek sensors contain 11,012 core, 461 database, and 8,360 DMZ connection records over an approximately six-hour window. Core protocol volume is 5,858 TCP, 4,743 UDP, and 411 ICMP; DMZ volume is 7,012 TCP, 1,027 UDP, and 321 ICMP.

State/history and byte/packet invariants passed all quantitative checks. One-way UDP syslog and unanswered TCP probes use `S0`; successful UDP exchanges use `SF`; rejected TCP connections use `Sr`; reset and partial-close records show appropriate histories. IP overhead is never below protocol minima.

Traffic is not uniformly distributed. Core minute counts have a mean of 30.6 and standard deviation of 80.5, largely because of the scan burst. Common flows also show substantial timing variability: proxy DNS has interarrival CV 1.54, workstation-to-proxy connections approximately 1.9–4.1, and application-to-database traffic 1.93.

### Internal scan and firewall behavior

At `13:40`, `10.10.3.10` generates approximately 1,524 probes covering 254 internal addresses, five explicit TCP ports, and ICMP. Zeek, ASA, endpoint FLOW, and Snort evidence agree on the tuples and timing.

The unresolved problem is policy behavior. The ASA normally denies several identical DMZ-to-inside routes, particularly `10.10.3.10 → 10.10.2.30:443` and `:8080`. During the scan it builds connections to routes that are denied immediately before and after. The accepted `13:40:39` TLS connection completes with FINs and 1,148 IP bytes, so it is not merely a misleading SYN-state artifact. This remains possible if a temporary rule or dynamic pinhole existed, but the supplied traffic-only ASA collection cannot substantiate that explanation.

### DNS

Core DNS has realistic qtype, rcode, RTT, and TTL diversity. RTTs range from `40 µs` to `2.277271 s`, with 2,382 unique values among 2,878 records. Successful external answers demonstrate proper recursive-cache TTL decrementing; authoritative internal responses correctly return full fixed TTLs.

A/AAAA pairing is the main statistical concern. The near-total pairing and invariant A-before-AAAA direction span unrelated hosts and names. The responses themselves remain plausible: internal names often return NOERROR/NODATA for AAAA, while public-service names return IPv6 answers.

### HTTP, proxy, and web traffic

Core HTTP contains 1,589 transactions, including 1,428 CONNECT requests; DMZ contains 1,818 transactions. CONNECT authority fields are well-formed, all HTTP timestamps follow connection establishment, and no HTTP event occurs after its Zeek connection closes.

All 1,343 successful core CONNECT requests have an outbound DMZ TLS session with the requested SNI within ten seconds; greedy one-to-one matching resolves 1,341. Failure statuses generally lack outbound TLS, as expected. Proxy logs parse cleanly and contain believable 407 authentication challenges, 403 denials, gateway errors, tunnels, forwarding, and SSL inspection.

The public web log includes 710 valid combined-format entries. The Nikto-like activity consists of 344 requests with 127 paths and a credible mix of GET, HEAD, OPTIONS, and POST methods. Static content-hash assets are largely stable, although page-response byte sizes are excessively variable.

### TLS, certificates, and OCSP

TLS versions and ciphers are compatible throughout. Full TLS 1.2 handshakes generally include certificate chains; resumed and TLS 1.3 sessions generally do not. Leaf fingerprints are stable by SNI, certificate validity windows contain each handshake, and SANs match observed names.

All OCSP records satisfy `thisUpdate ≤ ts ≤ nextUpdate`. All 82 OCSP IDs reference a visible files record, and 80 of 82 serials also appear in the local X.509 stream; the two unmatched serials are consistent with partial certificate visibility.

### Cross-source correlation

Every Zeek DNS, HTTP, TLS, SMTP, SMB mapping, and SMB file record references a connection UID present on the same sensor, and none precedes its connection. File-analysis records likewise have no missing connection references.

This integrity was not treated as evidence of synthesis merely because it is complete. What supports realism is the source-native behavior around it: independent sensor UIDs, stable but drifting clock offsets, small capture-point packet differences, integer-second ASA rounding, and different passive visibility for TLS 1.2 versus TLS 1.3.

## Synthetic Indicator Summary

| Priority | Category | Source family | Scope | Effect on score |
|---|---|---|---|---|
| P1 | `contract_gap` | ASA, Zeek | Concentrated scan interval | Identical routes switch from repeated ACL denial to bulk acceptance and back without visible policy-transition evidence. |
| P2 | `distribution_texture` | DNS | Dataset-wide AAAA behavior | 271/272 core AAAA queries are paired, always after A, within a narrow sub-second pattern. |
| P3 | `environment_or_collection_plausibility` | Zeek | Several protocols | `conn.service` identifies SSH, MySQL, and RDP while their normal analyzer streams are absent. Selective collection is a plausible explanation. |
| P4 | `distribution_texture` | Web access | Repeated page responses | Stable-looking pages receive nearly unique and widely varying response sizes. Dynamic rendering or compression may explain part of this. |

No P0 hard contradiction or generator identity leak was found.

## Realism Score by Category

- **Field format accuracy:** 9/10 — Zeek, ASA, Snort, proxy, TLS, DNS, and web fields are well-formed and protocol-compatible.
- **Temporal patterns:** 8/10 — Bursty traffic, long-tailed durations, clock skew, and cache aging are strong; A/AAAA sequencing is too uniform.
- **Cross-source correlation:** 8/10 — Correlation is technically convincing, but the firewall-policy discontinuity remains unresolved.
- **Behavioral realism:** 8/10 — Browsing, proxying, scanning, TLS, DHCP, and service traffic have credible volume and timing.
- **Environmental consistency:** 7/10 — Sensor placement is coherent, but temporary firewall permissiveness and selective protocol-log coverage need explanation.

## Recommendations

1. **P1 — Make firewall policy authoritative.** If this were synthetic, the internal scan should either receive ASA denies consistent with the standing ACL or be preceded by an explicit temporary rule/pinhole change and followed by restoration. Zeek visibility and connection outcomes should follow that decision.

2. **P2 — Diversify resolver dual-stack behavior.** Include near-simultaneous A/AAAA requests, AAAA-first clients, single-family cached lookups, dropped/unobserved companions, and host/OS-specific timing rather than pairing virtually every AAAA query after A.

3. **P3 — Align protocol classification with exported Zeek streams.** For identified SSH, MySQL, and RDP sessions, emit plausible analyzer logs when those analyzers are represented as enabled, or model a consistent selective-export policy across protocol families.

4. **P4 — Preserve resource-size identity.** Derive web response size from resource/version and content encoding, allowing bounded changes for personalization, range requests, and compression instead of independently varying each successful page response.

