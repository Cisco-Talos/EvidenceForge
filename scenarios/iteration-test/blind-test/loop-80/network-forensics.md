# Loop 80 Network Forensics Report

## Verdict

- **Verdict:** Inconclusive, with a moderate synthetic lean
- **Verdict confidence:** 0.69
- **Synthetic-confidence score:** 54/100 (higher means more synthetic)

## Executive summary

The six-hour network slice is technically coherent across its main sources. Zeek DNS, HTTP, TLS, SMB, SMTP, and DHCP records all refer to connection UIDs present in the corresponding sensor's `conn.json`, with no tuple mismatches in those protocol companions. Endpoint FLOW tuples, IDS alert tuples, proxy CONNECTs, and representative ASA NAT/connection records also line up closely with network observations. TCP state, packet, byte, TLS certificate-chain, and service patterns look plausible overall.

There are no hard network contradictions. The main realism concern is a large, sharply concentrated traffic burst: the core and DMZ sensors each record about 1,300 connections in the same minute, including a broad ICMP sweep from a DMZ address into the inside range. That behavior is internally consistent and could be a real scan, but its scale is unusual beside the background traffic. A single proxy CONNECT lacks a matching Zeek HTTP record; its source is the DMZ address that also hosts the proxy-facing service, so this is a limited visibility gap rather than proof of bad data. The evidence supports plausible network telemetry, but does not decisively distinguish a real six-hour capture from carefully generated logs.

## Categorized evidence

### hard_contradiction

- None found in the inspected network and correlated records.
- In each Zeek sensor, all inspected DNS, HTTP, SSL, SMB mapping/file, SMTP, and DHCP UIDs exist in that sensor's connection log. Their four-tuple fields match the connection exactly.
- All 134 parsed Snort alerts (61 core and 73 perimeter) have a matching TCP/UDP connection tuple in at least one Zeek sensor. The IDS and Zeek timestamps are near one another for sampled alert records.
- Sampled Zeek connection, protocol, and endpoint FLOW records have consistent endpoint ordering and source/destination ports. TCP successful sessions generally have nonzero activity; failed inbound probes are represented as incomplete connections.

### contract_gap

- One of 2,290 proxy CONNECT entries could not be paired to a Zeek CONNECT row by source address and host: `10.10.3.10` to `data.mixpanel.app`. The other 2,289 matched Zeek HTTP entries within three seconds. This lone unmatched row may reflect proxy-local traffic or sensor coverage; it is a narrow gap.
- The ASA file has 7,948 TCP connection-build and 7,946 teardown messages, plus 2,611 dynamic TCP translation build and teardown messages each. The small build/teardown difference is compatible with connections still open at the capture boundary. No material NAT reversal or impossible tuple was observed in sampled records.

### distribution_texture

- Zeek covers approximately 13:00–19:00 UTC on 2026-11-02. Counts are substantial but varied: 12,416 core connections, 9,954 DMZ connections, and 467 database-sensor connections. The core and DMZ minute-level counts have high variance because of a single major burst rather than a flat event rate.
- At about 14:40 UTC, the core and DMZ sensors each record roughly 1,300 connections in the same minute. The dominant component is a sweep from `10.10.3.10` toward addresses in `10.10.2.0/24`, including many ICMP probes. This is coherent scan-shaped activity, but notably concentrated compared with surrounding minutes.
- Protocol and state diversity is otherwise credible. Core connection states include `SF`, `S0`, reset, reject, and partial states; DMZ contains a larger share of `S0`, consistent with its inbound exposure. No negative durations or negative byte/packet counters were found.
- Exact repeated five-tuples are uncommon in the three Zeek connection sets, and no group repeatedly reuses one source port across a destination/service during the slice.

### schema_or_format

- No malformed JSON or obvious invalid Zeek field relationships were found in the inspected connection and protocol records.
- TLS records reference certificate FUIDs present in `x509.json`; certificate leaf/issuer relationships and SHA-1 references also match sampled file records. TLSv1.2 and TLSv1.3, multiple ciphers, resumed/non-resumed sessions, and established/unestablished observations are present.
- SMB file records reference existing connection UIDs and include plausible client/server orientation and file-transfer byte fields in sampled cases.

### environment_or_collection_plausibility

- Sensor roles are broadly plausible: the core sensor sees internal authentication, DNS, SMB, proxy, mail, and service traffic; the DMZ sensor sees outbound TLS and inbound scan/probe activity; the database sensor concentrates on application-to-database flows.
- The perimeter firewall shows coherent dynamic translation and connection lifecycle pairs. For example, the DMZ proxy-side host `10.10.3.20` is translated to `203.14.220.1` for outbound HTTPS, with an ASA teardown corresponding to the same public destination. This also agrees with Zeek's outbound TLS observation.
- The DMZ-to-inside ICMP sweep is unusual for an externally facing service host, though it could represent a scan or diagnostic activity. Its existence is not itself a synthetic contradiction; the alert/connection evidence makes the behavior observable and coherent.

### weak_signal

- Exact endpoint-to-Zeek tuple overlap is exceptionally high: 26,782 of 27,012 endpoint FLOW records with complete tuples have an exact Zeek connection tuple, and all those matches are within 3.21 seconds (median absolute timestamp difference about 0.34 seconds). This is strong correlation, but cross-source alignment alone is not treated as a synthetic clue; it is compatible with shared event collection and generation.
- The six-hour boundaries are clean, but this is expected for a bounded slice and is not evidence of a defect.
- The traffic concentration around the 14:40 scan is the main texture clue. A real network scan can cause such a burst, so it provides only modest evidence toward synthetic generation without additional contradictions.

## Detailed analysis

### Zeek and protocol companions

| Sensor | `conn.json` | DNS | HTTP | SSL | SMB mapping | SMB files | Other inspected companions |
|---|---:|---:|---:|---:|---:|---:|---|
| `zeek-core` | 12,416 | 3,132 | 2,435 | 378 | 168 | 300 | 79 SMTP, 60 DHCP |
| `zeek-db` | 467 | 39 | 20 | 34 | — | — | 41 files, including certificate transfers |
| `zeek-dmz` | 9,954 | 1,123 | 2,693 | 2,994 | — | — | 1,783 files |

Every inspected protocol record that carries a connection UID resolves to a connection in its sensor's own `conn.json`; the four-tuple agrees in all checked cases. DNS query and response sizes are varied, and query types include A, PTR, and SRV. HTTP contains normal proxy CONNECT traffic and non-CONNECT web requests. TLS includes plausible external certificate chains and internal enterprise-issued certificates. SMB records link file activity to mapped shares and connection identities.

The core sensor has 9,937 `SF` records, 1,710 `S0`, 430 `OTH`, and smaller counts of reset, reject, and partial states. The DMZ has 7,038 `SF` and 2,337 `S0` records. That larger incomplete-connection share is plausible for an exposed segment with inbound probing. No negative duration or negative traffic counters were present. Zeek's null duration on incomplete connections is not treated as an error.

### Cross-source tuple and lifecycle checks

- Endpoint telemetry contains 27,012 FLOW rows with complete five-tuples. Of these, 26,782 have an exact matching Zeek connection tuple; the closest such connection is within 3.21 seconds, with a median difference of approximately 0.34 seconds.
- Proxy data contains 2,290 CONNECT entries. Source address and destination hostname match 2,289 Zeek HTTP CONNECT entries within three seconds. The sole unmatched CONNECT uses source `10.10.3.10` and host `data.mixpanel.app`.
- All 134 parsed Snort TCP/UDP alert tuples appear in Zeek connection data. The alerts cover DNS lookups, scan attempts, and peer-to-peer traffic, with alert endpoints consistent with sensor observations.
- The ASA perimeter log has 24,333 lines. Build/teardown and NAT lifecycle pairs are numerous and balanced. A sampled outbound HTTPS transaction has an ASA dynamic translation and public-side connection, while Zeek records the DMZ-side TLS destination and a matching server certificate.

### Activity texture and plausibility

The background is not uniform. Per-minute core counts average about 34.5 with high standard deviation, and DMZ counts average about 27.7 with similarly high variation. The peak occurs in both sensors around 14:40 UTC at roughly 1,300 connections in one minute. A DMZ host probes a broad set of inside addresses, making the spike scan-shaped rather than a generic increase in ordinary web or DNS traffic. This is a suspicious but coherent event family; it could be an intentional scan, a diagnostic job, or generated red-herring activity.

The `zeek-db` sensor has far lower volume and is dominated by application-to-MySQL traffic, fitting its apparent role. The proxy logs include varied authenticated users, browser and command-line user agents, domains, tunnel byte counts, and durations. TLS and web activity is therefore not limited to one repeated request shape.

## Realism scores

Scores use 1 (poor) to 5 (strong).

| Dimension | Score | Reason |
|---|---:|---|
| Protocol and connection-state plausibility | 4.5 | Diverse states, normal failed probes, plausible traffic counters, and protocol variety. |
| Cross-source network coherence | 4.8 | Near-complete endpoint tuple agreement; protocol UIDs resolve; IDS and proxy tuples align. |
| Timing and lifecycle behavior | 4.3 | Zeek, proxy, IDS, and firewall timing generally agrees; small capture-boundary residue is expected. |
| Environmental traffic plausibility | 3.8 | Sensor roles and database/proxy activity fit; large DMZ-to-inside scan is unusual but coherent. |
| Distribution texture | 3.4 | Background variation is credible, but the shared one-minute scan burst dominates the count distribution. |
| Schema and format quality | 4.8 | No material malformed rows or UID/tuple inconsistencies observed. |

## Recommendations

1. Preserve the scan as a coherent, bounded traffic family if it is intentional; its strong connection/alert alignment is useful for investigation.
2. If the `data.mixpanel.app` proxy request is expected to represent an ordinary client transaction, verify whether the proxy itself should be excluded from or included in the Zeek sensor path. The available data supports only a one-record collection gap.
3. No network-layer repair is indicated by this slice. A broader authenticity determination would need independent evidence beyond network consistency, particularly because the principal anomaly is plausible operational behavior.
