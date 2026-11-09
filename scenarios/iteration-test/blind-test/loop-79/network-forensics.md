# Blind Network Forensics Assessment — Loop 79

## Verdict

**Verdict: Inconclusive**  
**Verdict Confidence: 0.78**  
**Synthetic-Confidence Score: 24/100** (higher means more synthetic)

## Executive Summary

The six-hour network slice is internally consistent across three Zeek sensors, perimeter firewall, proxy, IDS, and endpoint flow records. Zeek protocol records consistently reference extant connection UIDs and matching tuples; their event times fall inside the parent connection interval. Endpoint flow tuples, proxy CONNECT requests, and firewall-built connections align at high rates and generally at subsecond time deltas. DNS, TLS, SMB, mail, database, proxy, web-server, and directory-service traffic are plausible for the represented roles. Connection states include completed, failed, reset, and partial traffic, with no negative counters or impossible zero-duration completed TCP/UDP sessions in the inspected data.

I found no hard network contradiction that supports calling this slice synthetic. The cross-source consistency is strong, but agreement alone is not proof of real collection: the available network evidence cannot distinguish authentic telemetry from careful deterministic synthesis. The verdict is therefore inconclusive with low synthetic confidence. Remaining mismatches are few and largely explainable by ICMP tuple representation, sensor scope, NAT, or collection boundaries; one proxy CONNECT did not have a matching Zeek HTTP record under the tested key.

## Evidence by Category

### hard_contradiction

- **None observed.** No protocol companion referenced a missing Zeek connection UID. For Zeek `dns`, `http`, `ssl`, `smtp`, `smb_files`, and `smb_mapping`, every record with a connection UID resolved to a connection in the same sensor, with exact endpoint tuple agreement.
- Companion records were temporally compatible with their parent connection: all checked DNS, HTTP, TLS, SMTP, SMB file, and SMB mapping timestamps were within the connection interval (allowing 10 ms before start and 2 seconds after close for timestamp precision/recording behavior).
- Zeek connection rows contained no negative byte or packet counters. Among TCP/UDP rows marked `SF`, none had a zero duration.

### contract_gap

- **Firewall-to-Zeek:** Of 4,048 parsed ASA `Built inbound TCP/UDP connection` messages, 4,045 (99.9%) had an exact protocol/source tuple/destination tuple match in Zeek within 3 seconds. Three inbound web-server tuples did not have a corresponding Zeek tuple in the available sensors. Because these are isolated and firewall NAT/capture scope can differ, this is a collection-visibility gap rather than a contradiction.
- **Proxy-to-Zeek HTTP:** 2,289 of 2,290 parsed proxy CONNECT rows (99.96%) matched a Zeek CONNECT request on client IP, destination host, normalized user agent, and within 10 seconds. One `10.10.3.10` → `data.mixpanel.app` request from `Wget/1.21.3` had no matching Zeek HTTP row under that key. The tuple likely represents a server-side fetch or a vantage-point/coverage difference; it merits spot-checking but does not establish impossible ordering.
- **Endpoint flows:** 26,782 of 27,608 endpoint `FLOW` observations (97.0%) matched a Zeek TCP/UDP tuple within 20 seconds. The unmatched examples were predominantly ICMP, where endpoint records omit ports while Zeek represents ICMP type/code in port-shaped fields. The 20-second window is intentionally permissive; the median nearest matching timestamp was 0.339 seconds.
- **IDS-to-Zeek:** In the core IDS file, 61 of 63 alerts matched a corresponding Zeek tuple and time window. The two unmatched alerts were external ICMP pings to `10.10.2.25`, consistent with differences in ICMP tuple encoding or sensor visibility. The perimeter IDS had more ICMP unmatched cases; its alert records show inbound ping/scan activity, and alert-to-connection matching is less direct where the IDS logs omit port identifiers.

### distribution_texture

- Connection states are varied rather than uniformly successful. Core Zeek recorded `SF` 9,937, `S0` 1,710, `OTH` 430, plus resets/rejects and smaller state groups. DMZ Zeek recorded `SF` 7,038, `S0` 2,337, `OTH` 310, plus resets/rejects. DB Zeek was smaller and predominantly completed traffic (345 `SF` of 467 connections).
- Time distribution varies across the six hourly buckets. Core TCP counts were 906, 2,188, 937, 984, 939, and 912 for hours 13–18 UTC. DMZ TCP counts were 1,492, 2,481, 1,051, 1,232, 1,166, and 1,052. The 14:00 bucket is busier, but there is no identical fixed cadence across sensors.
- Cross-sensor duplicates reflect shared observation of the same tuples. Of 5,134 core/DMZ exact tuple matches within 3 seconds, connection state agreed in all cases; bytes agreed in over 99.8%, while durations and packet counts varied more often. That pattern is compatible with separate sensor vantage points and timing/packet visibility differences.
- DMZ `S0` traffic includes 787 external-origin TCP attempts, while internal service and proxy traffic also appears. This is plausible perimeter scan/no-response texture and has corresponding firewall/IDS activity; I did not treat failed attempts as missing completed sessions.

### schema_or_format

- Zeek JSONL records parse as JSON and use expected sensor-specific fields. Core has Zeek SMB and SMTP companions; DMZ has HTTP/TLS/DNS activity; DB sensor has a smaller, role-focused connection and TLS/DNS set.
- Connection-level ICMP uses Zeek’s numeric endpoint port fields (for example, ICMP type/code) while endpoint EDR FLOW omits source/destination ports. This accounts for many apparent unmatched endpoint tuples and is a representational difference, not an invalid record.
- No malformed or structurally impossible network record was observed in the inspected samples and aggregate checks.

### environment_or_collection_plausibility

- Traffic is role-appropriate: core connections are concentrated on the proxy at `10.10.3.20:8080`, domain controllers on LDAP/Kerberos/SMB ports, and internal services; DMZ observations include public web ingress to `10.10.3.10:80/443`, proxy traffic, and database traffic to `10.10.4.10:3306`; the DB sensor is dominated by MySQL and related internal monitoring traffic.
- The proxy access log’s CONNECT host and user-agent fields strongly agree with Zeek HTTP CONNECT observations. Perimeter ASA build records almost entirely have matching Zeek tuple records. These are realistic multi-source relationships, but their high alignment alone is not a synthetic clue.
- The slice runs from approximately 13:00 to 19:00 UTC on the observed day. I did not penalize absent initiators before the window or connection endings after it.

### weak_signal

- Some joins are exceptionally clean: all inspected Zeek protocol companions had valid same-sensor parent UIDs and tuples, and firewall/proxy joins were near complete. A well-instrumented real collection can produce this; it modestly raises uncertainty because the dataset alone does not establish independent collection provenance.
- One proxy request and a small number of IDS/firewall joins remain unresolved. The discrepancies are isolated and consistent with different observation points, NAT, and ICMP representation; no broader repeated failure pattern emerged.
- Sanitized or fictional-looking names/domains were not considered evidence.

## Detailed Analysis

### Zeek connection and protocol integrity

Inspected `zeek-core`, `zeek-dmz`, and `zeek-db` connection files contain 12,416, 9,954, and 467 rows, respectively. TCP, UDP, and ICMP all occur. TCP state variety includes successful sessions, SYN-only attempts, resets, rejects, and partial/other observations. The time span of each main sensor is approximately 13:00–18:59 UTC. DB Zeek begins later and records a much smaller volume, consistent with a more specialized sensor.

UID joins were exact for every inspected protocol companion: core DNS (3,132), HTTP (2,435), TLS (378), SMTP (79), SMB file records (300), and SMB mappings (168); DMZ DNS (1,123), HTTP (2,693), and TLS (2,994); DB DNS (39), HTTP (20), and TLS (34). Each joined record’s four-tuple matched its connection. Companion timestamps fell inside the corresponding connection lifetime under the tolerance described above. TLS records used plausible TLS 1.2 cipher names and established-state fields; certificates were linked by file IDs.

### Cross-sensor observations

Core and DMZ shared 5,134 exact TCP/UDP/ICMP tuples with record timestamps within 3 seconds. Their state agreed for all matched records. This overlap is consistent with traffic crossing multiple monitored zones. Byte counts were usually identical, while packet totals and durations differed more often, which is plausible for distinct capture locations and close timing.

The proxy log contains 2,290 parsed CONNECT rows. After treating `-` as a missing user-agent value, 2,289 matched Zeek CONNECT rows by client, host, and agent within 10 seconds; matched timestamps differed by less than one second. The one unresolved `data.mixpanel.app` request is a narrow gap, not a recurring discrepancy.

The ASA log contains 4,048 parsed inbound TCP/UDP connection-build records. Exact tuple and protocol matches in Zeek occurred for 4,045 within 3 seconds. The remaining three involve inbound web-server traffic and may be attributable to NAT or sensor coverage. Firewall and IDS records also show refused/failed or scan-related activity, which fits the Zeek `S0`, reset, and reject mix rather than contradicting it.

Endpoint EDR FLOW records provide 27,608 observations. 26,782 joined a Zeek TCP/UDP connection tuple within 20 seconds; the median nearest timestamp gap was 0.339 seconds. The dominant unmatched subset is ICMP, for which EDR omits port fields and Zeek encodes ICMP details in endpoint port fields. The count and tuple-level agreement support cross-source consistency, but do not independently prove collection authenticity.

### Volume and service plausibility

Core traffic is concentrated on the internal proxy (`10.10.3.20:8080`), directory service endpoints (`10.10.2.10/.11:389` and `:88`), and common internal services. DMZ traffic includes inbound web traffic to `10.10.3.10`, proxy traffic, and traffic to the database service `10.10.4.10:3306`. The DB sensor is dominated by port 3306. DNS, TLS, HTTP, SMB, SMTP, DHCP, and ICMP all appear in contexts consistent with the sensor roles. The hourly volumes are nonuniform but stable enough for an enterprise workday; a busier 14:00 hour is visible on core and DMZ.

## Realism Scores

Scale: 0 = implausible, 10 = strongly realistic in the inspected dimension.

| Dimension | Score | Basis |
|---|---:|---|
| Protocol and state behavior | 8.5/10 | Broad state mix, plausible TCP/UDP/ICMP use, no impossible completed zero-duration TCP/UDP rows found. |
| Byte, packet, and duration behavior | 8/10 | Nonnegative counters; cross-sensor packet/duration variation; no broad metric contradictions found. |
| Cross-source tuple and timing alignment | 9/10 | High endpoint, proxy, firewall, and Zeek alignment; parent UID and tuple integrity was complete for checked protocol logs. |
| Role and service plausibility | 8.5/10 | Proxy, directory, database, web, mail, SMB and sensor-specific volumes fit the represented environment. |
| Natural distribution texture | 7.5/10 | Varying hourly volumes and states; the comparatively clean joins are a mild provenance uncertainty. |
| Overall network realism | 8.3/10 | Strong network coherence; authenticity cannot be determined from this slice alone. |

## Recommendations

1. Preserve the current cross-source tuple and lifecycle consistency; it is the strongest quality signal in this slice.
2. If the source data is available to the assessment owner, spot-check the single proxy `data.mixpanel.app` CONNECT and the three ASA inbound web tuples absent from Zeek. Confirm whether routing, NAT, or sensor coverage explains them.
3. Keep ICMP joins protocol-aware by comparing source/destination IP and timestamp when the endpoint source omits Zeek’s ICMP type/code fields.
4. No network-specific repair is indicated by the inspected evidence. To resolve the real-versus-synthetic question, require independent collection provenance or compare against a known contemporaneous capture; this dataset slice alone does not support a confident binary classification.
