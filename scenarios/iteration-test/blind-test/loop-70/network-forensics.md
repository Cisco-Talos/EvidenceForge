# Network Forensics Analyst — Authenticity Assessment

## Verdict

- **Assessment:** Real
- **Verdict Confidence:** 62/100
- **Synthetic-Confidence Score:** 24/100

## Executive Summary

The network telemetry is mostly production-like. The Zeek data covers distinct internal, database, and DMZ observation paths, with protocol mixes and outcomes that fit the visible topology. Zeek DNS, HTTP, and SSL records resolve to connection UIDs in their respective sensor datasets, and the DNS reply timestamps align with the corresponding UDP connection timing. The core and DMZ sensors observe overlapping traffic with small capture/timing differences, while the database sensor is strongly concentrated on the database host and MySQL service.

I found no strong network-level contradiction. The large concentration of HTTP `CONNECT` requests through an internal HTTP service, the high count of SF sessions, and the relatively small TLS sample in the core sensor are explainable by proxying and sensor placement. Several data choices look curated or sanitized, but the domains, hostnames, and addresses are not reliable indicators of synthetic origin under the study rules.

## Evidence For Synthetic

- **[weak_signal]** The core and DMZ HTTP tables contain very similar request volumes and method/status distributions (2,211 vs. 2,445 HTTP records; CONNECT dominates both), and their TLS views share the same dominant enterprise endpoints. This is consistent with overlapping observation points, but such tightly aligned samples could also reflect a constructed multi-sensor dataset. See `zeek-core/http.json`, `zeek-dmz/http.json`, `zeek-core/ssl.json`, and `zeek-dmz/ssl.json`.
- **[weak_signal]** HTTP telemetry is unusually dominated by CONNECT requests: 2,016/2,211 in core and 2,070/2,445 in DMZ. The majority return 200, with a smaller but credible tail of 403/407, 5xx, and redirects. This can arise from an explicit proxy path, and the Zeek tuples mostly identify an internal HTTP service on port 8080; it is a concentration, not a protocol contradiction. See the `method`, `uri`, `host`, and `status_code` fields in the two `http.json` files.
- **[weak_signal]** The core sensor has 12,190 connections but only 405 SSL records, while DMZ has 9,320 connections and 2,687 SSL records. This may be a real visibility difference between an internal/core path and a perimeter/DMZ path, but it leaves the exact core TLS collection path uncertain. See `zeek-core/conn.json`, `zeek-core/ssl.json`, `zeek-dmz/conn.json`, and `zeek-dmz/ssl.json`.

## Evidence For Real

- **[contract_gap] No significant gap found.** Every DNS, HTTP, and SSL record in each sensor's respective tables has a matching connection UID in that same sensor's `conn.json`: core DNS 3,164/3,164, HTTP 2,211/2,211, SSL 405/405; database DNS 47/47, HTTP 25/25, SSL 23/23; DMZ DNS 1,012/1,012, HTTP 2,445/2,445, SSL 2,687/2,687. No protocol record has a timestamp earlier than its matching connection's start timestamp. These are coherent source-local joins, not merely broad coverage.
- **[distribution_texture] Connection states include a plausible mix of success and failure.** Core records include 9,740 SF, 1,691 S0, 423 OTH, plus RSTO/RSTR/REJ and a small number of S1–S3 states. DMZ has 6,379 SF and 2,402 S0 plus OTH, resets, and rejects. Database traffic is mostly completed MySQL sessions (276 `mysql`/TCP/3306 records), but also has resets, incomplete connections, ICMP, DNS, and ancillary services. See `conn_state`, `proto`, `service`, and port fields in each `conn.json`.
- **[distribution_texture] DNS reflects both routine resolution and occasional failures.** Core has 2,924 NOERROR, 218 NXDOMAIN, 18 SERVFAIL, and 4 REFUSED answers across 3,164 entries; DMZ has 877 NOERROR, 132 NXDOMAIN, and 3 SERVFAIL across 1,012. Query types include A/AAAA/PTR plus SRV/TXT and a small number of mail/name-service queries. This mix is more credible than a success-only or single-query-type stream. See `rcode_name`, `qtype_name`, `query`, and `answers` in `dns.json`.
- **[contract_gap] DNS transaction details agree with the connection rows.** For example, core UID `Ck4z60395vTlz6KZrI` appears in both `zeek-core/conn.json` and `zeek-core/dns.json`: UDP from `10.10.1.31:62028` to `10.10.2.10:53`, with matching timestamp `1793624404.209087`, DNS success, 0.000995-second RTT, and an SF connection with one request and one response packet. This is internally consistent with a DNS exchange.
- **[environment_or_collection_plausibility] Sensor views show role-specific traffic.** `zeek-db/conn.json` is dominated by `10.10.3.10` to `10.10.4.10:3306` MySQL (276 rows), fitting the DB sensor's apparent focus; `zeek-dmz/conn.json` includes inbound traffic from external `185.70.41.45` to `10.10.3.10:443` and a broad mix of HTTPS, HTTP, DNS, and application paths. `zeek-core/conn.json` includes AD-like DNS, Kerberos, LDAP, SMB, HTTP proxy, and syslog traffic among internal addresses. These differing mixes are plausible for the filenames and address roles visible in the records.
- **[cross-source_correlation] Connection timing and payload fields are coordinated across observation points.** The DB-visible MySQL example UID `CMzR9ePcJty6tXwV72` in `zeek-db/conn.json` records a TCP/3306 session from `10.10.3.10:48660` to `10.10.4.10`, lasting 1.246437 seconds with 3,159/5,365 bytes and 6/7 packets. The corresponding DMZ MySQL observation has the same tuple, ports, byte and packet counts, and nearly identical duration (1.246277 seconds), while the start timestamps differ by about 0.17 seconds. That is plausible for separate sensor vantage points and capture timing.
- **[schema_or_format] Zeek records use recognizable source-native fields and distributions.** The connection tables contain UIDs, tuple fields, protocol/service, state, history, packet/byte counters, and local endpoint flags; protocol logs use matching UIDs and expected protocol-specific fields. The presence of null service/SNI values, TLS 1.2 and 1.3, incomplete handshakes, and a varied HTTP status mix is normal in these telemetry families.
- **[distribution_texture] Sensor timestamps cover a bounded, continuous six-hour observation window.** The Zeek connection timestamps span approximately 13:00–19:00 UTC on 2026-11-02 for all three sensors. Different row counts and slightly different bounds are compatible with separate sensor visibility and event/capture timing. No implausible inter-protocol timestamp reversal was found in the bounded window.

## Detailed Analysis

### Sensor roles and traffic shape

- **Core:** `zeek-core/conn.json` contains 12,190 rows over six hours. TCP (6,703), UDP (5,100), and ICMP (387) are all represented. The service mix is led by DNS (3,174), Kerberos (2,419), HTTP (2,159), LDAP (1,085), SMB (458), TLS/SSL, syslog, SMTP, DHCP, SSH, and RDP. The dominance of internal infrastructure services supports an internal monitoring vantage point.
- **Database:** `zeek-db/conn.json` contains 458 rows over the same window, 276 of which are recognized MySQL sessions between `10.10.3.10` and `10.10.4.10` on TCP/3306. Other visible flows include DNS, syslog, HTTP, TLS, Kerberos, ICMP, and a few administrative/service ports. The narrow distribution is plausible for a sensor or filter focused on a database segment.
- **DMZ:** `zeek-dmz/conn.json` contains 9,320 rows. TCP is predominant (7,949), with UDP (1,077) and ICMP (294). It includes high volumes of TLS/HTTPS, HTTP, and DNS plus MySQL traffic and inbound external connections. The DMZ SSL table has 2,687 rows, including both TLS 1.2 and TLS 1.3; the core SSL table has 405 rows, and the DB SSL table 23. Different TLS visibility is plausible given the sensors' likely placement.

### TCP/UDP states and lifecycle

The state distributions include completed sessions and a meaningful tail of unanswered starts, resets, rejects, and partial states. There are no signs that every session is forced into a successful close. Zeek omits `duration` on incomplete connection records in the core and DMZ data (1,972 and 2,683 rows respectively); this is consistent with incomplete/one-sided observations rather than a malformed table. UDP includes both SF exchanges and one-sided observations. The visible evidence does not imply that all endpoint activity should have a matching network close, so I do not treat those absences as collection failures.

### DNS, HTTP, and TLS joins

All protocol-specific UIDs checked are present in their local sensor's connection table. DNS rows start at the same timestamp as their UDP connection row in the examples checked, and their tuples agree. HTTP and SSL rows are not earlier than their corresponding connection start. DNS responses include positive answers, NXDOMAIN and occasional resolver failures. HTTP includes ordinary success responses, cache/redirect responses, proxy auth/denial statuses, and server errors. SSL contains both TLS versions, missing SNI on some connections, and a handful of unestablished sessions. Those omissions and failures are plausible in passive network collection.

### Network security observations

The Snort files contain perimeter and core alerts for inbound probes, suspicious DNS, outbound policy events, and P2P signatures. For example, `snort-perimeter/snort_alert.log` records a scan attempt from `185.70.41.45` to `10.10.3.10:443` at 13:31:40 and other external probes; `snort-core/snort_alert.log` includes internal DNS queries to suspicious TLDs and P2P signatures. The tuples and timestamps look compatible with the broader network picture. The Cisco ASA log contains built and torn-down connections, translation events, and byte/duration fields. Some messages describe traffic using interface labels such as `dmz` and `inside`; these are native firewall interface/ACL labels and are not enough to infer a direction contradiction. I did not perform a complete alert-to-flow reconciliation, so these records are supporting context rather than proof of exact packet-level matching.

### Limits and weak signals

All evaluated records are bounded to six hours. Without a longer baseline or sensor configuration, the ratio of HTTP CONNECT, the core/DMZ overlap, and low core TLS volume cannot establish collection defects. The traffic set may have been selected for this window, but selection and compactness alone are not evidence of synthetic generation. Hostnames, domains, and addresses appear internally coherent; possible sanitization is not scored as synthetic evidence.

## Synthetic Indicator Summary

| Category | Indicator | Weight |
|---|---|---|
| `weak_signal` | Similar HTTP/TLS distributions across core and DMZ could reflect deliberate multi-sensor curation, though distinct sensor views and timing differences are also plausible. | Low |
| `weak_signal` | CONNECT traffic dominates the HTTP tables; plausible for an explicit proxy on port 8080, but highly concentrated. | Low |
| `weak_signal` | Core TLS visibility is relatively sparse beside its connection volume; likely a sensor-path distinction, but configuration is unavailable. | Low |
| `hard_contradiction` | None identified. | — |
| `contract_gap` | None identified in the checked Zeek DNS, HTTP, and SSL UID/timestamp joins. | — |

## Realism Score by Category

- **Field format:** 9/10 — recognizable Zeek JSON fields and plausible nulls/omissions; the incomplete connections lack duration as expected.
- **Temporal patterns:** 8/10 — bounded six-hour windows, coherent protocol start times and slightly offset sensor observations; deeper long-term periodicity cannot be judged from this sample.
- **Cross-source correlation:** 9/10 — local Zeek protocol UIDs join completely to conn records; overlapping DB/DMZ MySQL observations align in tuple, counters, and duration.
- **Behavioral realism:** 8/10 — mixed DNS outcomes, varied states, proxy statuses, TLS versions, and internal service traffic; HTTP CONNECT concentration is notable but supportable.
- **Environmental consistency:** 8/10 — core, DB, and DMZ roles are reflected in differing traffic mixes; unknown network diagrams and sensor configuration limit certainty.

## Recommendations

1. Preserve the per-sensor separation when reviewing this dataset; `zeek-core`, `zeek-db`, and `zeek-dmz` have materially different visibility and traffic profiles.
2. If stronger provenance confidence is needed, compare the repeated core/DMZ HTTP transactions and DB MySQL sessions against raw packet/capture metadata or documented sensor placement, focusing on expected tuple and timestamp offsets.
3. Validate the core SSL coverage and internal port-8080 proxy path against sensor configuration before treating their relative volume as anomalous.
4. Keep the current conclusion provisional: the network logs support a **Real** assessment, but a six-hour excerpt cannot establish production provenance on its own.
