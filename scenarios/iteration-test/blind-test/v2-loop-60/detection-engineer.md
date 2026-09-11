# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 95  
**Synthetic-Confidence Score:** 86

## Executive Summary

The corpus is exceptionally well formed: schemas, timestamps, event relationships, identifiers, and source-native formatting are largely convincing. However, Windows Security metadata contains a dataset-wide execution-thread fingerprint repeated identically across ten hosts, reinforced by uniform NT device-volume mappings across four Windows build families. Those patterns are sufficiently improbable in independent production systems to support a high-confidence synthetic verdict.

## Evidence For Synthetic

- `[distribution_texture]` All 11,605 Windows Security Event 5156 records use exactly 38 `System/Execution/@ThreadID` values: every multiple of four from `52` through `200`. Every one of the ten Windows hosts contains the entire identical set, despite host volumes ranging from 385 to 4,288 records.

- `[distribution_texture]` Other authentication/audit families use a second fixed thread pool. All 802 Event 4624, 383 Event 4634, 419 Event 4672, 749 Event 4768, 2,072 Event 4769, 56 Event 4776, 102 Event 5140, and 57 Event 5145 records draw exclusively from `{100,104,…,500}`. Conversely, 23 of 24 Event 4625 failures fall outside that pool, reaching ThreadID `9916`. This event-family boundary looks generated rather than like organic thread scheduling within the same per-host LSA process.

- `[distribution_texture]` Of 11,605 Event 5156 records, 11,183 contain NT device paths and every one uses `\device\harddiskvolume1`. The corpus contains Microsoft binary versions from four distinct Windows build families—`17763`, `19041`, `20348`, and `22621`—across servers, domain controllers, and workstations, making identical volume numbering throughout unlikely.

- `[environment_or_collection_plausibility]` All 49 domain-controller Event 5140 records for SYSVOL/NETLOGON use simplified local paths: 27 map SYSVOL to `\??\C:\Windows\SYSVOL`, and 22 map NETLOGON to `\??\C:\Windows\SYSVOL\scripts`. Typical AD shares include the `sysvol` subtree and, for NETLOGON, the domain-specific scripts path.

- `[contract_gap]` Three of 1,881 Zeek FUID references have no matching `files.json` entry:

  - `zeek-core/http.json`, `ts=1710776829.666369`, FUID `FLEcSIMuqYpc4eduGR`
  - `zeek-core/smb_files.json`, `ts=1710781766.84038`, FUID `FQYdmIvDpRskFMvCD2`
  - `zeek-dmz/http.json`, `ts=1710784485.796611`, FUID `FzA0m4BcX0G6KgEYDq3`

  This is weak evidence because an independent files-log policy or collection loss could explain it.

## Evidence For Real

- All 18,232 Security XML events and 11,542 Sysmon XML events parsed successfully. Their provider, version, task, level, opcode, keyword, and channel combinations were internally consistent for all 28 Security and nine Sysmon Event IDs examined.

- No malformed SIDs, GUIDs, IP addresses, ports, or Sysmon hash fields were found. All 970 Sysmon Event 1 `ProcessGuid` values encoded a process-start second consistent with their timestamps to within one second.

- Of 976 Security Event 4688 process creations, 969 matched Sysmon Event 1 within two seconds by host, PID, and image. Every matched pair agreed on command line, parent PID, parent image, and LogonID. Likewise, 819 Security 4689 events matched Sysmon Event 5 terminations.

- Across 7,421 shared Security 5156/Sysmon Event 3 network tuples, source, destination, ports, protocol, and inbound/outbound semantics agreed. All 7,435 Sysmon Event 3 records placed the host’s local IP on the correct side according to `Initiated`.

- No visible process or session dependency was found before a later visible creation using the same identifier. Visible 4624/4634 and eCAR create/terminate lifecycles contained no causal inversions.

- All 10,274 Zeek protocol UID references resolved to `conn.json`; none preceded its connection start or occurred more than one second after a known connection close. All 1,074 TLS certificate FUID references resolved in both `files.json` and `x509.json`.

- The DC-01 log-clear sequence is particularly convincing:

  - Sysmon Event 1 records `cmd.exe /c wevtutil cl Security` at `2024-03-18T17:42:28.8681205Z`.
  - Its child `wevtutil.exe` appears at `17:42:29.0286745Z`.
  - Security Event 1102 appears at `17:42:33.1802494Z` with correct `LogFileCleared` UserData and `EventRecordID=1`.
  - Subsequent Security telemetry resumes at record ID 2 while Sysmon’s independent record sequence continues.

- All 19,376 ASA records passed a source-format probe, including exact PRI-to-ASA-severity agreement. TCP build/teardown counts were 6,417/6,415, consistent with two connections remaining open at the bounded window edge; UDP and ICMP pairs were complete at 986/986 and 318/318.

- All 185 Snort, 2,524 proxy, and 710 web-access records matched their expected line formats.

## Detailed Analysis

### Corpus and parser behavior

The authorized directory contains 105 files: 20 Windows XML files, 48 JSON files, 16 text logs, and 21 bash histories. Core structured volume was 96,015 records: 18,232 Security, 11,542 Sysmon, 32,991 eCAR, and 33,250 Zeek records. The visible interval is approximately `2024-03-18 12:00–17:59 UTC`.

All JSON and XML parsed without error. Security event field sets were stable per Event ID and matched the expected generations of commonly used schemas, including 4624 v2, 4688 v2, 5156 v1, Sysmon Event 1 v5, Event 3 v5, Event 8 v2, and Event 10 v3.

### Windows metadata fingerprint

The strongest discriminator is not an ordinary field error but the execution-thread population.

For example:

- DC-01 Event 5156 at `2024-03-18T12:00:04.6458115Z` uses execution PID/TID `4/200`.
- WS-AJOHNSON-01 Event 5156 at `12:05:35.6068190Z` uses `4/92`.
- FILE-SRV-01 Event 5156 at `12:01:43.7343606Z` uses `4/180`.

Individually these are valid-looking values. Across the corpus, however, every host exhaustively reuses the identical 38-value range `52–200` in increments of four. The separate `100–500` pool governing multiple LSA-backed event families—and its sharp divergence from the 4625 failure population—is a stronger fingerprint than merely observing that Windows IDs are four-byte aligned.

### Windows field and event semantics

SIDs, GUIDs, LUIDs, process IDs, WFP protocol numbers, and insertion strings were syntactically valid. Logon IDs were monotonically increasing by host, and no visible 4634 preceded its matching 4624. Type 3 sessions generally had short lifetimes, while Type 2/10 sessions were longer or crossed the collection boundary.

The primary field-level weakness is uniform WFP application mapping. All 11,183 device paths use `HarddiskVolume1`, including Windows 10, Windows 11, Server 2019, and Server 2022-era binaries. The source-native lowercase device-path form is correct, but the lack of host-specific volume identity is not production-like.

The SYSVOL and NETLOGON paths are syntactically valid NT paths but operationally simplified. Because this is repeated on both domain controllers rather than appearing once as a custom share, it contributes modestly to the synthetic assessment.

### Correlation and detection utility

The data would ingest well into a SIEM. Security 4688 and Sysmon Event 1 agree at a field-by-field level, and the approximately 99% match rate preserves realistic collection gaps. Sysmon process lifecycle and eCAR object identifiers contain no visible create-after-use inversions.

Network detections would also pivot effectively. Security 5156 and Sysmon Event 3 share coherent tuples and direction semantics, while Zeek UID/FUID relationships are nearly complete. I did not count this completeness as synthetic evidence; only the three unresolved FUIDs were treated as a minor contract issue.

### Limitations

The review was restricted to the provided six-hour data directory. No scenario, ground truth, manifest, source code, prior report, or adjacent path was inspected.

The bounded window can hide process, session, and connection initiators, so missing pre-window creations were not penalized. No PCAP, Windows host configuration, Zeek logging policy, or collector/export configuration was available; consequently, the missing FUIDs and unusual share paths remain plausible configuration artifacts rather than hard contradictions.

## Synthetic Indicator Summary

| Priority | Category | Source family | Scope | Effect on score |
|---|---|---|---|---|
| P1 | `distribution_texture` | Windows Security system metadata | Dataset-wide: 11,605 Event 5156 records on ten hosts | Identical exhaustive TID pools across independent hosts are the strongest generator fingerprint. |
| P1 | `distribution_texture` | Windows Security WFP fields | Dataset-wide: 11,183 device paths | Uniform `HarddiskVolume1` across ten heterogeneous Windows hosts removes host-specific system identity. |
| P2 | `environment_or_collection_plausibility` | Windows Security 5140 | Repeated: 49 records on both DCs | SYSVOL/NETLOGON local paths appear simplified rather than deployment-native. |
| P3 | `contract_gap` | Zeek HTTP/SMB/files | Three of 1,881 FUID references | Minor referential gaps; independently filtered `files.log` could explain them. |

No P0 hard contradiction or impossible visible ordering was identified.

## Realism Score by Category

- **Field format accuracy:** 7/10 — Schemas and primitive values are strong, but execution TID populations and uniform device-volume paths are conspicuous.
- **Temporal patterns:** 9/10 — Source-specific precision, lifecycle timing, and the log-clear sequence are convincing; no visible causal inversion was found.
- **Cross-source correlation:** 9/10 — Process, network, UID, and certificate relationships are highly coherent, with only three weak FUID gaps.
- **Behavioral realism:** 8/10 — Process, authentication, firewall, and protocol activity is varied and operationally usable.
- **Environmental consistency:** 6/10 — Cross-host identity is weakened by globally reused thread pools, volume mappings, and simplified AD share roots.

## Recommendations

If this were synthetic, the highest-priority improvements would be:

1. **P1 — Generate `System/Execution` PID/TID metadata from persistent host-specific process and thread lifecycles.** Avoid global finite pools and prevent event-type-specific metadata regimes such as successful logons using `100–500` while failed logons use unrelated high TIDs.

2. **P1 — Assign NT device-volume mappings per host image.** Preserve one mapping consistently within a host, but vary it across independent installations and build families.

3. **P2 — Model deployment-native SYSVOL and NETLOGON roots.** Include the DFSR/FRS-appropriate `sysvol` subtree and domain-specific scripts directory, while allowing explicit custom share configurations.

4. **P3 — Either preserve Zeek FUID referential integrity or make collection filtering explicit and source-coherent.** If a referenced file record is intentionally dropped, apply a believable files-log policy rather than leaving isolated unexplained references.

