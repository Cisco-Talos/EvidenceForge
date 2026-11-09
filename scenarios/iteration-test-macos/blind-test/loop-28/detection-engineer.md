# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 78
**Synthetic-Confidence Score:** 27

## Executive Summary

The inspected records are mostly production-like and suitable for ordinary SIEM parsing and correlation. I found no defensible hard contradiction in the bounded checks: source-native event shapes, observed process lifecycles, and representative network/protocol relationships are coherent. These results support realism, but do not distinguish genuine collection from carefully constructed synthetic telemetry with sufficient confidence to assert provenance.

## Evidence For Synthetic

- No independently supported synthetic indicator was established in this bounded review. The checks below found no impossible visible ordering, identity collision, malformed sampled event shape, or violated network byte budget. This is an absence of positive evidence, not proof that the data is real.

## Evidence For Real

- Windows Security events use differentiated source-native shapes. `WS-MCHEN-01.meridianhcs.local/windows_event_security.xml:527` is a version-2 4688 with creator fields, target-token fields, `ParentProcessName`, and `MandatoryLabel`; line 3112 is a version-2 4624 with service logon semantics, while line 11280 is a failure-keyword 4625 with `Status=0xc000006d` and `SubStatus=0xc000006a`.
- Visible session identity is preserved: the same file has a Type 3 4624 at line 10608, `2026-11-02T15:24:47.3724954Z`, and 4634 at line 10739, `15:25:05.7566851Z`, for `marcus.chen`, `TargetLogonId=0x6d542b0`.
- Process identity and source latency are plausible: Sysmon record 525189, Security record 948745, and eCAR line 19 describe PID 7260 / `svchost.exe` within approximately 138 ms, without requiring identical source timestamps.
- In `zeek-core`, 2,979 DNS, 1,990 HTTP, 294 SSL, 196 SMB-file, and 560 file-analysis rows all reference existing connections in the checked files; protocol/file timestamps pass a bounded connection-interval check, and no individual file's `seen_bytes` exceeds its referenced directional connection payload budget.
- macOS ES records distinguish fork, exec actor, and exec target instead of treating every executable transition as a new PID. `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson:1-3` preserve PID 42169 through launchd → xpcproxy → Terminal while updating `pidversion` and executable identity.

## Detailed Analysis

### Scope and reproducibility

I examined only the supplied data directory. This was a representative schema and relationship review, not an exhaustive forensic reconstruction or full vendor-schema certification. XML was parsed with Python's standard `xml.etree.ElementTree`, and JSON/NDJSON with `json.loads`; line numbers below are physical, one-based lines. XML record IDs provide an additional stable selector.

The detailed Windows inspection covered the first occurrence of each of ten event types on WS-MCHEN-01, plus three domain authentication types and the log-clear event on DC-01. Additional representative records included three native ES lifecycle rows, Unified Log messages, Linux syslog/eCAR process rows, and Zeek connection, DNS, HTTP, TLS and SMB/file observations. Aggregate relationship checks were limited to the explicitly named files and hosts.

### Representative Windows event shapes

| File shorthand | Line / record | Event | Checked observations |
|---|---|---:|---|
| WS-MCHEN Security | 254 / 948726 | 4634 | Target identity, logon ID, Type 2; an opening record outside the window is neutral. |
| WS-MCHEN Security | 527 / 948745 | 4688 v2 | Hex process identifiers, creator/target distinction, parent path, elevation token and integrity SID. |
| WS-MCHEN Security | 3112 / 948849 | 4624 v2 | Type 5, NETWORK SERVICE SID `S-1-5-20`, `Advapi`, local services caller, absent remote address. |
| WS-MCHEN Security | 11205 / 949202 | 4648 | Separate subject and explicit target identity, caller process and server fields. |
| WS-MCHEN Security | 11280 / 949204 | 4625 | Audit-failure keywords, password-failure substatus, Type 2/User32 and local address placeholders. |
| WS-MCHEN Sysmon | 3 / 525176 | 10 | Source/target process identities, access mask `0x1000`, thread ID and call trace. |
| WS-MCHEN Sysmon | 38 / 525177 | 5 | Process GUID/PID/image/user and millisecond `UtcTime`. |
| WS-MCHEN Sysmon | 66 / 525178 | 3 | UDP, IPv4 flags, source/destination tuple, initiated direction. |
| WS-MCHEN Sysmon | 373 / 525189 | 1 | Process and parent GUIDs, hashes, logon ID, command line, executable metadata. |
| WS-MCHEN Sysmon | 418 / 525190 | 13 | `SetValue`, HKU target, user attribution and binary-value rendering. |
| DC-01 Security | 167 / 28245280 | 4776 | Native NTLM package string, workstation, account and status. |
| DC-01 Security | 930 / 28245366 | 4769 | Service account/SID, encryption type, IPv4-mapped client address, port and logon GUID. |
| DC-01 Security | 2437 / 28245437 | 4768 | krbtgt service, preauthentication type, ticket options, account SID and certificate placeholders. |
| DC-01 Security | 257716 / 1 | 1102 | Eventlog provider and namespaced `UserData/LogFileCleared`, with record-ID reset to 1. |

File shorthand expands to the corresponding host's `windows_event_security.xml` or `windows_event_sysmon.xml`. These rows have appropriate distinctions between Security and Sysmon provider/channel metadata. I did not infer that the older Kerberos event versions were impossible without an OS/update inventory.

For PID 7260 specifically, Sysmon line 373 records `UtcTime=2026-11-02 13:07:20.918`, its envelope is `13:07:20.9196390Z`, Security line 527 is `13:07:20.9970862Z`, and `WS-MCHEN-01.meridianhcs.local/ecar.json:19` has `timestamp_ms=1793624841056`. This is a coherent multi-source representation with small collection/rendering differences.

I checked all observed Sysmon rows in the selected WS-MCHEN-01 and DC-01 files against their visible Event 5 termination identities. No dependent event carrying the same checked process GUID occurred after its visible termination. This does not establish complete process capture or require pre-window parents to appear.

### Network parsing and accounting

`zeek-core/conn.json` contains 11,660 distinct checked UIDs. Its state distribution includes 9,530 SF, 1,836 S0, 131 RSTO, 86 RSTR, 21 OTH, 20 REJ, and smaller S1/S2/S3 populations. That variety is compatible with mixed transport outcomes; neither diversity nor complete joins establishes provenance.

For the five protocol/file files listed above, I joined `uid` or `conn_uids` to `conn.json`. I flagged rows outside `[conn.ts - 0.01, conn.ts + duration + 1.0]`; none failed. The one-second allowance makes this a gross-ordering check rather than a claim about exact protocol timestamp semantics. I also compared every file row's `seen_bytes` with the summed `orig_bytes` or `resp_bytes` of its referenced connections, selected by `is_orig`; none exceeded that permissive individual-file budget. I did not test summed multi-file payload consumption.

A concrete sample is `zeek-core/files.json:1`, FUID `FHWi70ysEiFCvVUtLq`, a 5,359,834-byte SMB download. `zeek-core/smb_files.json:1-2` show FILE_OPEN followed by FILE_READ for UID `CHobQaXTd62NpmDvAm`, the same filename and FUID. The download directions and identities agree.

### Linux, normalized endpoint, and macOS observations

`APP-INT-01.meridianhcs.local/syslog.log:1` is an RFC5424-shaped CRON message for sysstat PID 2931365. Its eCAR lines 1-3 describe the shell parent, `debian-sa1` child PID 2931366, and child termination, preserving process UUID parentage and root-to-sysstat principal distinction. The source timestamps differ plausibly rather than being byte-identical.

Across eCAR files for APP-INT-01, DB-PROD-01, WS-MCHEN-01, and MAC-MROSS-01, no process UUID with both visible create and terminate records terminated before creation. No checked `actorID` was used more than two seconds after its visible termination. The grace threshold avoids overstating millisecond collection-order effects; these are limited checks of observed identities only.

The two macOS ES files contain 159 and 151 rows respectively. I checked actor and exec-target `(pid,pidversion)` identities for contradictory executable paths and found none. The initial three MAC-MROSS-01 rows use message `version=11`, `action_type=1`, fork/exec event-specific objects, audit-token identities, signing metadata and file stat information. I did not independently certify every version-11 field against a live SDK, so unfamiliar details were not scored as defects.

`MAC-MROSS-01.meridianhcs.local/macos_unified_log.ndjson:2` attributes an AppleSystemPolicy message to kernel PID 0 with a kernel-extension sender, while line 3 is an sshd-session public-key acceptance message with a user-space writer. The policy wording alone does not prove denied execution, and I did not use it to infer an impossible child or file effect. ES notification results were not treated as authorization denials.

## Synthetic Indicator Summary

| Category | Affected source family | Checked scope | Effect on score |
|---|---|---|---|
| No established indicator | Windows, Zeek, Linux/eCAR, macOS | Representative schemas and bounded identity/accounting checks described above | Supports the mostly-realistic band; provides no affirmative provenance evidence. |

No category-qualified defect met the evidence threshold. Collection completeness, sanitized domains, selected event families, and easy-to-follow activity were not scored.

## Realism Score by Category

- **Field format accuracy:** 9 — Sampled event-specific schemas and value representations are coherent; full SDK/version certification was outside scope.
- **Temporal patterns:** 8 — Visible identities pass bounded ordering checks and source timestamps vary plausibly; long-duration behavioral statistics were not assessed.
- **Cross-source correlation:** 9 — Checked process/session identities and network references agree without discovered byte-budget violations.
- **Behavioral realism:** 8 — Inspected service, cron, authentication and desktop process chains are plausible; a bounded sample cannot establish their population realism.
- **Environmental consistency:** 8 — No demonstrated OS/path or host-identity contradiction in the inspected records; host inventories and actual collection settings are unavailable.

## Recommendations

- No defect-driven modification is justified by this review. If this were synthetic, preserve the observed source-specific identity, timestamp and lifecycle distinctions.
- Before claiming full SIEM compatibility, validate the supplied macOS message-version-11 export contract and Windows event versions against the intended collector/parser versions. This addresses the explicit certification limit above, rather than an alleged defect in the logs.
