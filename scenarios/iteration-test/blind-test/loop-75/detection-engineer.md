# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 97  
**Synthetic-Confidence Score:** 66

## Executive Summary

The collection is broad and internally well joined: it contains endpoint, host, perimeter, and Zeek telemetry over a shared six-hour period, and most endpoint flow tuples can be found in Zeek. Native-looking Windows XML, RFC 5424 syslog, Zeek JSON, and access-log records provide useful detection context. These strengths make the logs operationally useful.

A hard process-identity contradiction in both Mac endpoint streams drives the synthetic verdict. Each Mac records a process with PID other than 1 executing `/sbin/launchd`, with PID 1 itself named as its parent and executable. On macOS, `launchd` is the system's PID 1 service manager; these records describe another launchd instance. Repetition on both modeled Macs makes an isolated collection or parsing error less likely. The remainder of the evidence is mostly realistic, so the synthetic score is in the “likely synthetic” range rather than the highest band.

## Evidence For Synthetic

- **hard_contradiction — duplicated macOS launch daemon identity.** `MAC-MROSS-01` records `PROCESS/CREATE` at 2026-11-02 13:07:49.043 UTC with PID `42177`, PPID `1`, `image_path=/sbin/launchd`, and `parent_image_path=/sbin/launchd` (`ecar.json`). `MAC-MROSS-02` repeats the same impossible identity at 13:08:37.004 UTC with PID `18668`. The corresponding endpoint-security records also describe these PIDs as `/sbin/launchd`. A second launchd process is not a plausible child of PID 1; this is a process identity error, not simply incomplete coverage.

## Evidence For Real

- The formats have useful source-specific structure. Windows event records contain provider, channel, event ID, record ID, and precise UTC `SystemTime`; Sysmon and Security use distinct IDs and payload fields. Zeek rows use standard `ts`/`uid`/five-tuple fields, while Linux syslog uses RFC 5424 framing and the web/proxy logs use access-log fields.
- Correlation is strong. Across the endpoint `FLOW/CONNECT` records, 26,193 of 26,970 tuples (97.1%) match a Zeek connection tuple in either direction when addresses, ports, and protocol are compared. Every Zeek DNS, HTTP, and SSL UID examined resolves to a connection record in its sensor directory.
- Windows endpoint and host-network views are mutually useful. For example, `WS-AJOHNSON-01` has Sysmon network-connection events and Security 5156 filtering events with concrete process/application, addresses, ports, and protocol values. These provide detection pivots beyond the normalized endpoint stream.
- Event times occupy a coherent 2026-11-02 UTC window, approximately 13:00–19:00, across host and network data. Zeek timestamps are fractional epoch seconds, Windows records retain sub-second UTC precision, and endpoint records use millisecond epoch values. The records do not show a broad clock-offset problem.
- The traffic includes useful benign and suspicious mixtures: internal DNS and service traffic, user application flows, rejected or incomplete perimeter connections, and unusual DNS/HTTP destinations. This makes the data usable for hunting rather than merely a sequence of alert-like events.

## Detailed Analysis

### Visible collection scope

The visible scope includes Windows endpoint telemetry (Sysmon and Security XML), normalized endpoint events, macOS Endpoint Security and unified-log exports, Linux syslog and shell histories, web and proxy access records, perimeter firewall and Snort alerts, and three Zeek sensor directories. Most records cover roughly six hours on November 2, 2026. This is enough breadth to test host-to-network detections. I treated lifecycle counts at the edges of this collection window as potentially truncated and did not treat unmatched process starts or terminations alone as evidence of fabrication.

### Schema, IDs, and values

The source formats are generally plausible and parseable. Windows Event XML uses stable provider names and event IDs; Zeek uses distinct per-connection UIDs and companion logs; eCAR-style endpoint events use UUIDs for event and object identity and typed `object`/`action` pairs. The event IDs and record IDs are not obviously reused within the examined endpoint streams. Address, port, process, account, and protocol fields are populated at useful rates. Some normalized action labels are product-specific, so their names alone are not evidence of native source fidelity.

### Timestamps and distribution

Windows, endpoint, Zeek, syslog, and web records all fall into a compatible time window, with no glaring unit or timezone conversion error. Connection records show both completed and incomplete states rather than only successful sessions. The one clear identity defect is independent of timestamp ordering: the Mac launchd records have impossible executable/PID combinations.

### Cross-source correlation and detection usefulness

The flow-to-Zeek tuple match rate is high, and Zeek's DNS, HTTP, and SSL companions link back to connection UIDs. Windows Security 5156 rows provide application and network tuple detail; Sysmon process/network evidence adds host context. The logs support pivots across process, account, destination, and time. This strong correlation is evidence in favor of realistic construction and raises the quality of the dataset for detection exercises, but it does not repair the contradictory Mac process identity.

### Environmental consistency

Hostnames and IPs are generally used consistently across sensor views, and the mix of Windows, Linux, and macOS sources is represented with platform-appropriate record formats. The Mac process path contradiction is a localized but repeated platform-semantic failure. No conclusion relies on domain naming, on the absence of selected Sysmon event types, on perfect cross-source coverage, or on narrative completeness.

## Synthetic Indicator Summary

| Indicator | Category | Evidence | Weight |
|---|---|---|---|
| PID 42177 and PID 18668 are each reported as `/sbin/launchd` children of PID 1 on separate Macs | hard_contradiction | Mac `ecar.json` and Endpoint Security records | High |

## Realism Score by Category

| Category | Score (1–10) | Rationale |
|---|---:|---|
| Field format accuracy | 8 | Native schemas and field types are mostly coherent; normalized endpoint action labels are product-specific. |
| Temporal patterns | 8 | Source timestamps align across the common collection window with useful sub-second precision. |
| Cross-source correlation | 9 | Strong endpoint-to-Zeek tuple matching and complete Zeek companion UID references. |
| Behavioral realism | 6 | Useful benign/suspicious mix, offset by the impossible Mac launchd identities. |
| Environmental consistency | 6 | Host and sensor addressing is coherent overall; the repeated macOS executable/PID mismatch is material. |

## Recommendations

- Correct the Mac process identity source so PID 1 is the only process rendered as `/sbin/launchd`; model the services it spawns with their actual executable paths and parent-child identities.
- Add a platform-aware validation rule that flags macOS records where a non-PID-1 process is attributed to `/sbin/launchd`, and cross-check the eCAR process identity against the native Endpoint Security process token before release.
- Retain the existing endpoint/network tuple and Zeek UID consistency checks; they materially improve detection pivots and are strong parts of this dataset.
