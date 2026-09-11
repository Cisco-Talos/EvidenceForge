# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 72  
**Synthetic-Confidence Score:** 58

## Executive Summary

Most of the dataset is unusually strong: its Windows, Sysmon, eCAR, Zeek, firewall, proxy, and Linux records are parser-safe, source-native, and temporally coherent. However, one scheduled-task sequence on DC-01 contains a specific Windows schema-era mismatch and an unexplained execution gap. Those defects outweigh the otherwise production-like telemetry and lead me to a moderately confident synthetic verdict.

## Evidence For Synthetic

- `[schema_or_format]` At `2024-03-18T16:20:38.8611048Z`, `DC-01.meridianhcs.local/windows_event_security.xml` records Event 4698 as `Version=0`, with only the legacy fields through `TaskContent`. The same host’s Sysmon records identify Windows build `10.0.20348.1` and servicing stack `10.0.20348.2322`. On that OS generation, Event 4698 should use the newer schema version and include client-process/RPC fields such as `ClientProcessId`, `ParentProcessId`, and `RpcCallClientLocality`.

- `[contract_gap]` The same Event 4698 registers enabled task `\Microsoft\Windows\Maintenance\DeviceSync` with `StartBoundary=2024-03-18T16:20:38Z` and hourly repetition `PT1H`. No corresponding `DeviceSyncSvc.exe` process appears around either the initial boundary or `17:20:38` in the otherwise dense Security 4688 and Sysmon Event 1 streams. The only execution is at `16:30:29.0612660Z`, parented by `services.exe`, indicating service execution rather than Task Scheduler execution.

- `[weak_signal]` All 419 visible Type 5 Event 4624 records across ten Windows hosts populate `WorkstationName` with the local short hostname. The values are legal, but the fleet-wide absence of blank or `-` behavior is more normalized than many production Security channels. I assigned this little weight because a consistent local logon path could explain it.

## Evidence For Real

- All 31,026 examined Windows events were valid XML. Event metadata and fields were accurate across Security Events 1102, 4624, 4625, 4634, 4648, 4672, 4688, 4689, 4697, 4720, 4768, 4769, 4771, 4779, and 5156, plus Sysmon Events 1, 3, 5, 7, 8, 10, 11, 13, and 22.

- Windows provider GUIDs, channels, versions, task numbers, keyword masks, SIDs, GUIDs, hexadecimal logon IDs, token-elevation values, integrity labels, WFP direction tokens, protocols, and layer identifiers were generally source-correct.

- Security 4688 and Sysmon Event 1 process records closely agree on PID, parent PID, image, command line, user, and lifecycle. The small timestamp offsets vary naturally rather than collapsing to identical values.

- Zeek protocol records consistently join to `conn.json` through valid UIDs. DNS answers and TTL arrays align; HTTP transaction depth is ordered; TLS versions and ciphers are compatible; certificate chains resolve to `files.json`; and reused certificate fingerprints retain identical certificate content.

- ASA connection accounting is excellent. Of 7,713 builds, 7,711 have correctly ordered, tuple-compatible teardowns; the remaining two are open at the end of the observation window. Durations differ from second-resolution wall-clock deltas by at most one second.

- The dataset contains realistic timing imperfections. For example, DC-01’s eCAR Kerberos flow at `12:00:04.642` matches Zeek UID `CshWTFnZWxZWi01FXn` at `12:00:04.459823`, a plausible 182 ms host/sensor offset rather than artificial timestamp equality.

- Network diversity is credible: the DMZ sensor contains 301 distinct external initiators and 527 distinct external destinations, including both concentrated scanner traffic and a broader low-frequency tail.

## Detailed Analysis

### Windows schema and field validation

The Windows files contain 19,007 Security events and 12,019 Sysmon events. Every XML document parsed successfully, and the sampled events used their expected source-native field names and data types.

Event 4624 uses the version 2 field set, including `ImpersonationLevel`, `RestrictedAdminMode`, `VirtualAccount`, and `ElevatedToken`. Logon types are contextually credible: Type 2 and 7 records are local, Type 3 and 10 records carry remote addresses, Type 5 records originate from `services.exe`, and Type 9 records use `seclogo` semantics. Event 4625 records use plausible combinations such as status `0xc000006d`, substatus `0xc000006a`, and failure reason `%%2313`.

Security 4688 records use the version 2 schema, including `MandatoryLabel`, `TargetUserSid`, and `ParentProcessName`. Sysmon correctly preserves its event-specific GUID capitalization distinction: Event 10 uses `SourceProcessGUID`, while Event 8 uses `SourceProcessGuid`.

The material exception is DC-01 Event 4698. The host’s build evidence is internally consistent with Server 2022-era binaries, but the scheduled-task event uses the legacy Event 4698 version and omits the newer provenance fields. This is precisely the kind of mismatch that can break field-extraction and detection logic keyed to modern 4698 schemas.

### Authentication and session lifecycles

Visible logon lifecycles are causally ordered. I found no logoff preceding the corresponding visible logon ID and no process activity using a process GUID before its visible Sysmon Event 1 creation.

RDP sessions show realistic persistence. One DC-01 session logs on at `13:59:10.981` from `::ffff:10.10.1.31:61562`, disconnects through Event 4779 at `14:37:42.161`, and logs off at `15:00:44.658` with the same logon ID and client tuple. Lock/unlock Events 4800 and 4801 are similarly ordered.

Kerberos volumes and sequences are credible: 813 Event 4768 TGT requests, 2,148 Event 4769 service tickets, and six Event 4771 failures coexist with successful network logons. Service names, client addresses, ticket encryption fields, and failure codes were plausible in the sampled records.

### Process, service, and account correlation

A PsExec sequence on DC-01 is especially convincing:

- Sysmon Event 11 creates `C:\Windows\PSEXESVC.exe` at `15:59:45.489`.
- Security Event 4697 installs service `PSEXESVC` at `15:59:45.795`.
- Sysmon Event 1 starts the service binary at `15:59:58.982`; Security 4688 follows at `15:59:59.168`.
- Child `cmd.exe /c whoami && hostname` appears at `16:00:00.633` in Sysmon and `16:00:01.153` in Security.
- Sysmon Event 5 and Security 4689 terminate the service process at `16:00:12.926` and `16:00:13.031`.

The account-management chain is also ordered: the `net user` process appears at `16:14:39.371`, Event 4720 creates `svc_dirsync` at `16:14:42.700`, Event 4724 follows at `16:14:43.718`, and Event 4728 adds the account to Domain Admins at `16:14:47.668`.

At `17:42:26.1855251Z`, DC-01 records Event 1102 using the correct `Microsoft-Windows-Eventlog` provider, `LogFileCleared` structure, SYSTEM identity, and reset `EventRecordID=1`; subsequent Security records restart at low IDs. That behavior is highly source-authentic for a forwarded event stream.

### Zeek, firewall, and endpoint-network correlation

Across the three Zeek sensors, I examined 20,723 connection records plus DNS, HTTP, TLS, X.509, OCSP, files, SMTP, SMB, DHCP, and PE records. Protocol UIDs resolve to parent connections, timestamps remain inside the associated connection intervals, and I found no cross-sensor UID collision.

Certificate modeling is detailed: 1,280 X.509 observations reduce to 189 fingerprints, with 63 reused certificates. Reused fingerprints have identical serials, subjects, issuers, validity periods, key properties, and SANs. SNI values align with leaf-certificate SANs in the sampled TLS chains.

Firewall accounting correlates down to source-native byte semantics. ASA connection 1681560 is built at `12:00:16` for `10.10.2.25:32902 → 10.10.3.20:514` and torn down at `12:00:56` with `bytes 10024`. The corresponding Zeek connection starts at `12:00:16.733311`, lasts `40.190636` seconds, and reports `orig_ip_bytes=9564` plus `resp_ip_bytes=460`, exactly 10,024 bytes.

### Linux, proxy, and behavioral texture

Linux syslog records have credible RFC 5424 structure, PRI values, facilities, service names, PIDs, PAM/session transitions, cron activity, package activity, systemd messages, and Samba operations. SMB authentication and file-operation sequences align with eCAR effective-user fields rather than incorrectly assigning the network user as the persistent `smbd` process owner.

The 295 shell-history commands contain 218 unique commands, with very little repeated bigram structure. Proxy CONNECT records use plausible Apache-style timestamps, status 200, byte fields, tunnel byte accounting, and user-agent/null handling. Web 304 responses correctly use `-` for response size.

The external traffic distribution also has a convincing long tail rather than a tiny fixed address pool. Scanner-heavy sources coexist with hundreds of low-frequency external peers.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---:|---|
| `schema_or_format` | Windows Security 4698 | One DC-01 event | High-impact modern-OS/legacy-event-schema mismatch |
| `contract_gap` | Windows Security and Sysmon process lifecycle | One enabled hourly scheduled task | Expected task execution is absent; the only related process is service-parented at a different time |
| `weak_signal` | Windows Security 4624 | 419 Type 5 records across ten hosts | Fleet-wide `WorkstationName` normalization slightly reduces production texture but is not contradictory |

## Realism Score by Category

- **Field format accuracy:** 8 — Nearly all source-native schemas are excellent, but the DC-01 Event 4698 version is inconsistent with the visible OS generation.
- **Temporal patterns:** 8 — Timing jitter, session durations, clock offsets, and connection lifecycles are strong; the scheduled-task timing remains unexplained.
- **Cross-source correlation:** 9 — Windows/Sysmon/eCAR and Zeek/ASA relationships survive detailed identifier, tuple, byte, and timestamp checks.
- **Behavioral realism:** 9 — Human activity, service traffic, scanner behavior, command diversity, and lifecycle durations have credible variation.
- **Environmental consistency:** 8 — Host roles and software placement are generally coherent, with the scheduled task’s non-execution being the main exception.

## Recommendations

- If this were synthetic, derive Windows event versions and field sets from the modeled OS build. Server 2022-era Event 4698 records should use the modern schema and include client-process and RPC provenance fields.

- Ensure enabled scheduled tasks produce process evidence at their declared trigger boundaries. If a task is suppressed, disabled, deleted, missed, or fails to launch, emit the corresponding source-visible state change or failure evidence.

- Preserve source-native `WorkstationName` behavior for service logons instead of always inserting the local hostname; use blanks or `-` when that is what the modeled authentication package and OS would emit.
