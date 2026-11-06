# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 62
**Synthetic-Confidence Score:** 24

## Executive Summary

The examined Windows, eCAR, Zeek and macOS records have coherent source-specific schemas and plausible field values, with useful process and network correlations across formats. I found no hard contradiction, event-shape defect or impossible visible ordering in the records checked; this review supports a mostly production-like score but cannot establish provenance from the logs alone.

## Evidence For Synthetic

- No high-impact synthetic indicator was demonstrated in the parsed records. In particular, the close Windows process matches and overlapping Zeek observations are compatible with the collection model and are not treated as synthetic clues by themselves.
- [weak_signal] The macOS samples use a narrow set of Endpoint Security event types (9, 11, 15), while the accompanying Unified Log files have only a few rows. The source-family counts alone do not establish an unrealistic collection profile, so this contributes little to the score.

## Evidence For Real

- Windows Security fields and values are plausible for their event types. DC-01 Event 4624 at `2026-11-02T13:04:32.1299541Z` is a type-3 Kerberos machine-account logon for `FILE-SRV-01$`, with a mapped IPv6 source `::ffff:10.10.2.20`; Event 4634 at `13:04:57.9621093Z` closes the same `TargetLogonId` (`0x537d322`). DC-02 has the same shape for a separate machine account, with a matching 4624/4634 pair for `MAIL-FIN-01$` and logon ID `0xcb611fd`.
- Process creation is correlated across Windows Security, Sysmon and eCAR. On WS-MCHEN-01, Security 4688 at `13:01:13.0225089Z` records PowerShell PID `0x1c24`, parent `explorer.exe`; Sysmon Event 1 at `13:01:12.9234823Z` records decimal PID `7204` (the same PID) and image/command line; eCAR also has a process-create for PID 7204 with the same image and parent. On WS-PPATEL-01, a Chrome 4688 at `13:09:04.6775197Z` matches Sysmon Event 1 at `13:09:04.4546644Z`, with the same URL-bearing command line.
- Windows Sysmon Event 3 network rows use plausible client/server semantics. For DC-01, `dns.exe` with `Initiated=false` receives a request from `10.10.1.31` to local `10.10.2.10:53`; for WS-MCHEN-01, `ssh.exe` connects from `10.10.1.31:60624` to `10.10.4.10:22` after its process creation.
- Zeek records have recognizable source-native JSON fields and valid UIDs linking protocol rows to connection rows. The inspected Zeek-core sample has normal conn counters/state fields, a DNS A/NOERROR answer, HTTP CONNECT fields and TLS version/cipher/SNI fields. The same SSH 5-tuple appears in the separate `zeek-db` and `zeek-core` sensor exports with matching packet and byte counters and near-simultaneous timestamps, which is consistent with two observation points rather than duplicate rows in one log.
- The macOS Endpoint Security exports consistently declare schema version 1 and message version 11. Their fork/exec/exit payloads carry audit-token PID and PID-version values, and their timestamps are ordered. On MAC-MROSS-01, launchd’s fork at `13:07:43.411700Z` is followed by exec notifications at `13:07:43.420283Z` and `13:07:43.439181Z`, then a fork at `13:07:43.449316Z` as Terminal is launched.
- The macOS Unified Log entries include timestamp, mach timestamp, boot UUID, writer and sender paths, subsystem/category where present, and message fields. The AppleSystemPolicy message about MeetingAssist is evidence of a policy observation; it does not on its own prove a denied execution or a resulting child process.

## Detailed Analysis

### Windows Event Log and Sysmon

I parsed Windows Security and Sysmon XML from multiple hosts, including DC-01, DC-02, WS-MCHEN-01 and WS-PPATEL-01. The XML event envelope includes EventID and TimeCreated, while Security EventData uses event-specific named fields. Checked IDs include 4624, 4634, 4688, 4689, 5156, and Sysmon 1, 3, 5, 7, 10, 11, 13 and 22. Process and logon IDs use expected hexadecimal forms in Security and decimal PID values in Sysmon; SIDs, GUIDs, Windows paths, mapped IPv6 addresses and command lines are well formed in the reviewed examples.

DC-01’s type-3 machine-account logon and logoff pair share the target account, logon type and ID. Its type-5 service logons use local placeholder addresses and service processes. DC-02’s conhost creation is parented by csrss, while a later `svchost.exe` creation is parented by services.exe. These relationships and the 4688/Sysmon Event 1 timing are plausible in the visible records. The Sysmon Event 3 examples on the domain controller correctly show inbound DNS and Kerberos service activity from client addresses.

### eCAR and network telemetry

The parsed eCAR JSON uses integer millisecond timestamps, UUID-shaped IDs and object/action-specific properties. On WS-MCHEN-01, eCAR process-create for PID 7204 agrees with the PowerShell process in Windows Security and Sysmon. Its FLOW records include source and destination IPs/ports, protocol and direction. Zeek JSON uses floating-point epoch seconds, per-flow UIDs and source-native field names; DNS, HTTP and TLS records show expected record shapes.

A specific SSH connection from `10.10.1.31:60624` to `10.10.4.10:22` is observed in both `zeek-db/conn.json` and `zeek-core/conn.json`: the two entries have different UIDs and timestamps about 55 ms apart but identical byte/packet counters and history. Because these are separate sensor exports, this is compatible with overlapping visibility. It does not indicate a duplicate within one Zeek log or an impossible connection lifecycle.

### macOS Endpoint Security and Unified Log

MAC-MROSS-01 contains 136 Endpoint Security rows and MAC-MROSS-02 contains 167; all reviewed rows declare message version 11 and have populated event payloads. Event types 9, 11 and 15 appear with monotonic timestamps and unique, increasing global sequence values. Fork/exec process identity transitions preserve PID-version detail; the event payload keys correspond to the event type in the examples reviewed.

The Unified Log exports have only two or three rows each, so they provide limited context for evaluating the larger ES exports. Their rows nevertheless have source-native writer/sender and time fields. At `2026-11-02 15:42:17.453397+0000`, AppleSystemPolicy logs that it “would not allow” a MeetingAssist process. I do not infer from this message alone that an authorization denial completed or that a child or effect followed.

### Detection ingestion implications

The inspected data should be processable by source-aware SIEM parsers. The parsers must retain the distinction between Windows UTC SystemTime, Zeek epoch seconds, eCAR epoch milliseconds, and macOS ISO time plus mach timestamp. The sample values and cross-source ordering are coherent after applying those source-specific conversions; I did not observe a field type or timestamp precision defect that would systematically break detections.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected the score |
|---|---|---|---|
| `weak_signal` | macOS Unified Log and Endpoint Security | Two Mac hosts | Unified Log has few rows beside the ES exports. This is only a small uncertainty because the observed counts do not prove a collection inconsistency. |

## Realism Score by Category

- **Field format accuracy:** 8 — Checked Security, Sysmon, eCAR, Zeek and macOS records use coherent source-specific field structures and value formats.
- **Temporal patterns:** 8 — Process creation correlations and visible network/process ordering are plausible at subsecond-to-second precision.
- **Cross-source correlation:** 9 — The checked Windows process records and network tuples align; this level of alignment is compatible with the stated study collection assumptions.
- **Behavioral realism:** 7 — Service, user, authentication and network examples are plausible; this was a detection-ingestion review rather than a full behavior hunt.
- **Environmental consistency:** 7 — The mixed Windows, Linux/network and macOS records use platform-appropriate formats; the few Unified Log entries limit macOS-only comparison.

## Recommendations

- If this were synthetic, retain the source-specific timestamp precision and parser distinctions described above; the inspected values are internally coherent and do not suggest a concrete correction.
- If both macOS sources are intended to support paired detection validation, include enough Unified Log context to compare selected ES lifecycle observations. The current row counts do not independently lower authenticity, but provide limited material for that comparison.
