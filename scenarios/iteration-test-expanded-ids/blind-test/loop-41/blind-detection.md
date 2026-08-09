# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 88
**Synthetic-Confidence Score:** 68

## Executive Summary

The Windows, Zeek, firewall, and authentication records are structurally strong and correlate unusually well, but the Sysmon file and registry telemetry contains repeated process-to-artifact ownership errors that a production detection stack would expose immediately. In particular, Windows Error Reporting, Defender history, and Component Based Servicing artifacts are attributed across many hosts to unrelated processes in a templated pattern, which outweighs the otherwise convincing schemas and timing.

## Evidence For Synthetic

- `[contract_gap]` Sysmon Event 11 repeatedly attributes source-specific artifacts to unrelated processes. Of 99 Event 11 records, 37 create `C:\ProgramData\Microsoft\Windows\WER\ReportQueue\...\Report.wer` and 31 create Defender `Scans\History\Service\DetectionHistory\...` files. Examples include:

  - `WS-PPATEL-01`, `2024-03-18T13:49:18.5037961Z`: `SearchProtocolHost.exe` creates `...\WER\ReportQueue\82815\Report.wer`.
  - `WS-PPATEL-01`, `2024-03-18T14:23:16.2866890Z`: `svchost.exe`, running as `NETWORK SERVICE`, creates Defender `DetectionHistory\20342`.
  - `WS-PPATEL-01`, `2024-03-18T15:51:21.5775991Z`: `msiexec.exe` creates Defender `DetectionHistory\68272`.
  - `DC-01`, `2024-03-18T13:17:07.7861809Z`: `userinit.exe` creates Defender `DetectionHistory\88401`.
  - `WS-DRAMIREZ-01`, `2024-03-18T13:30:28.2720597Z`: `lsass.exe` creates Defender `DetectionHistory\41506`.
  - `WS-PPATEL-01`, `2024-03-18T17:55:14.8779761Z`: `csrss.exe` creates `...\WER\ReportQueue\89213\Report.wer`.

  These are not merely missing companion records: the visible Event 11 actor, PID, ProcessGuid, image, user, and target path assert the wrong ownership relationship.

- `[distribution_texture]` Sysmon Event 13 contains a dataset-wide servicing pattern: 275 of 569 registry events set `DWORD (0x00000070)` on distinct Component Based Servicing package `CurrentState` values. The pattern appears on every Windows host, including 116 records on `DC-01`, 43 on `FILE-SRV-01`, and 38 on `MAIL-FIN-01`, spread across the full six-hour window rather than concentrated into coherent servicing episodes.

- `[contract_gap]` Those 275 CBS writes are distributed among `services.exe`, `svchost.exe`, and `msiexec.exe`, including 35 `services.exe`, 35 `msiexec.exe`, and 46 `svchost.exe` records on `DC-01` alone. Native CBS state changes should be owned by a coherent Windows servicing chain such as TrustedInstaller/TiWorker and related update components; rotating unrelated generic service processes through hundreds of package keys is a strong actor-generation fingerprint.

- `[contract_gap]` Some user registry side effects are similarly attached to implausible foreground actors. On `WS-PPATEL-01`, `powershell.exe` is created at `2024-03-18T12:06:03.5979639Z`; at `12:06:03.5991852Z` it writes Office `ShownFirstRunOptin`, and at `12:06:03.5994470Z` it writes an Explorer `OpenSavePidlMRU\docx` value. A bare interactive PowerShell process producing Office and shell MRU side effects within roughly 1–2 ms is semantically implausible.

- `[schema_or_format]` eCAR top-level numeric fields and their duplicated property fields use inconsistent JSON types. For example, the first `DC-01` eCAR process-open record has top-level `"pid":2460` and `"ppid":2332`, but properties contain `"src_pid":"2460"`, `"source_pid":"2460"`, and `"target_pid":"2332"`. Ports, ICMP values, session IDs, and logon types are likewise consistently stringified inside `properties`. This is ingestible, but generic detection content must cast fields depending on which representation it uses.

- `[environment_or_collection_plausibility]` All 674 Sysmon Event 3 records have `Initiated=true`, even though Security 5156 and eCAR show substantial inbound endpoint traffic, including 4,332 inbound 5156 records on `DC-01`. An explicit Sysmon filter could explain this, so I assigned it little score weight, but the intended collection profile is not visible in the records.

## Evidence For Real

- Windows System metadata is highly accurate. All 13,873 Security records use event-appropriate provider, version, level, task, opcode, and keyword values. The sole 1102 record correctly switches to `Microsoft-Windows-Eventlog`, uses `Level=4`, `Task=104`, `Keywords=0x4020000000000000`, places its fields under `UserData/LogFileCleared`, and resets `EventRecordID` to 1.

- Security EventData shapes are credible across 23 event IDs. Examples include full version-2 fields for 4624 and 4688, proper version-1 fields for 5156, appropriate 4768/4769 Kerberos fields, and correctly structured 4697, 4698, 4720, 4728, and 4738 records.

- Logon field semantics are convincing. The 1,121 successful 4624 events use plausible combinations: Type 5 with `Advapi/Negotiate`, Type 3 with Kerberos or NTLM, and Types 2/7/10 with `User32`. Local Types 2 and 7 use `IpAddress=-`; all Type 10 records carry remote addresses.

- Lifecycle ordering is strong. Of 784 Security 4634 records, 778 have a visible matching 4624 LogonID and none precedes its visible login. No 4689 termination precedes a visible 4688 creation for the same host/PID, and no PID is visibly recreated before its previous process terminates.

- Sysmon schemas are accurate across Events 1, 3, 5, 7, 8, 10, 11, 13, and 22. Field capitalization is correct, including `SourceProcessGUID`/`TargetProcessGUID` for Event 10 and `SourceProcessGuid`/`TargetProcessGuid` for Event 8.

- Sysmon ProcessGuid morphology is production-like: GUID prefixes are stable per host and later components vary with process identity and time, rather than appearing as generic RFC UUIDv4 values.

- Security 4688 and Sysmon Event 1 correlate very well without impossible timing. Across the nine Windows hosts, nearly every sampled process matched by host, PID, image, and command line. Typical provider timestamp differences were within roughly ±20 ms; for example, `WS-PPATEL-01` PowerShell PID 6252 appears in Sysmon at `12:06:03.5979639Z` and Security 4688 at `12:06:03.6069104Z`.

- Windows Filtering Platform semantics are correct. All 8,178 Event 5156 records use local-host addresses consistently: `%%14593` records have the host as source, and `%%14592` records have it as destination. No direction/local-address contradiction was found. Applications use native device paths such as `\device\harddiskvolume1\windows\system32\lsass.exe`.

- EventRecordID gaps are host-specific and plausible rather than globally uniform. Adjacent-record rates range from 35.8% to 75.6% in Security and 31.2% to 90.9% in Sysmon, with different gap tails per host.

- Zeek JSON schemas and references are strong. Every one of 2,343 core and 860 DMZ DNS UIDs, 1,123 core and 1,334 DMZ HTTP UIDs, 114 core and 1,907 DMZ SSL UIDs, and all file `conn_uids` resolves to a corresponding `conn.json` row.

- All checked DNS, HTTP, SSL, SMTP, and file observations fall within the corresponding Zeek connection interval. Zeek tuples, services, packet accounting, connection states, certificate FUIDs, and X.509 field types are internally coherent.

- eCAR lifecycle integrity is strong. There are 878 visible successful login/logout pairs with no reversed lifecycle and no mismatches across shared `logon_id`, source IP, source port, session ID, or session type.

- Firewall and network telemetry agree on concrete tuples. For example, the ASA build at `Mar 18 12:00:40` for `195.157.166.202:54897 -> 10.10.3.10:80` corresponds to the DMZ Zeek connection and web access record for the same client request.

## Detailed Analysis

### Windows Security

I parsed all 13,873 records. The dominant event families are 5156 (8,178), 4769 (1,186), 4624 (1,121), 4688 (890), 4634 (784), 4689 (617), and 4768 (549), supplemented by authentication failures, explicit credential use, account administration, service installation, scheduled-task creation, and audit clearing.

Provider metadata and EventData shapes are highly convincing. Event 4625 uses failure keyword `0x8010000000000000`, while successful audit records use `0x8020000000000000`. Its status combinations are credible: 27 bad-password events use `Status=0xc000006d`, `SubStatus=0xc000006a`, `FailureReason=%%2313`; seven disabled-account cases use `SubStatus=0xc0000072`, `FailureReason=%%2307`.

Kerberos fields are also well formed. Event 4768 consistently requests `krbtgt`, uses encryption types `0x12`, `0x11`, or `0x17`, and carries IPv4-mapped IPv6 client addresses. Event 4769 uses service names ending in `$`, appropriate ticket options, and the same address convention. Event 4771 uses `Status=0x18` and `PreAuthType=2`, consistent with bad preauthentication.

The 1102 record at `2024-03-18T17:41:39.4536147Z` is especially convincing: it uses the Eventlog provider, a `UserData` payload, SYSTEM subject fields, and `EventRecordID=1`; following Security records then continue from the reset channel sequence.

### Sysmon

I parsed 4,368 events: 887 Event 1, 763 Event 22, 674 Event 3, 634 Event 5, 569 Event 13, 530 Event 10, 206 Event 7, 99 Event 11, and six Event 8 records. Versions and System metadata are appropriate for each type.

Process lifecycle and correlation are excellent. Sysmon Event 1 fields include native-looking ProcessGuid values, PIDs, hashes, parent metadata, LogonIDs, integrity levels, and current directories. Event 5 termination records do not precede visible Event 1 creation records. Event 10 access masks and call traces have plausible formatting, including `0x1000`, `0x1400`, and `0x1010` with module-plus-offset stacks.

The authenticity break is not XML shape; it is semantic ownership. Event 11 claims that unrelated system processes directly create WER and Defender-owned artifacts. This consumes 68 of only 99 file-create events, so it is not an isolated oddity. Event 13 has the same problem at greater volume: almost half of all registry modifications are CBS `CurrentState=0x70` writes assigned to a rotating trio of generic processes across every Windows host.

These records would materially distort detection engineering. Rules for suspicious access to Defender history, WER staging, or CBS tampering would fire on large amounts of fabricated benign noise, and ProcessGuid/PID pivots would reinforce the wrong process as the owner.

### eCAR

The 26,296 line-delimited JSON records are structurally consistent by object/action family: 16,579 flows, 2,674 module loads, 1,753 process creates, 1,422 terminations, 2,164 user-session records, 725 registry modifications, 530 process opens, 441 file operations, six remote-thread events, and two service creations.

UUIDs are valid, lifecycle identity is stable, process termination ordering is sound, and login/logout correlation is excellent. The main schema concern is type consistency: top-level PID/TID/PPID fields are integers, while semantically equivalent values in `properties` are strings. This would not prevent ingestion, but detection rules need field-specific normalization.

The eCAR registry/file projection also preserves the same implausible actors visible in Sysmon. Cross-source agreement therefore does not cure the defect; it makes the erroneous process ownership more authoritative to analysts.

### Zeek, Firewall, IDS, and Web/Proxy

Both Zeek sensors use credible JSON shapes. All checked protocol UIDs resolve to connection rows, and all protocol/file timestamps remain within the visible connection interval. DNS query types, rcodes, TTL arrays, SSL certificate chains, X.509 fields, HTTP status/body semantics, and file analyzer fields are properly typed.

The core and DMZ views use different UIDs, as independent sensors should, while preserving logical tuples. ASA build/teardown messages have plausible message IDs and native syntax. Snort alerts use standard fast-alert structure with SID, revision, classification, priority, protocol, and tuple.

Proxy and web logs are parser-friendly combined-style records. Proxy records add a quoted key/value extension for tunnel and byte accounting. The custom extension should be documented for production parser use, but it is internally understandable and not a meaningful synthetic clue.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---:|---|
| `contract_gap` | Sysmon Event 11 / eCAR file events | Repeated: 68 of 99 Event 11 records | High — source-specific WER and Defender files have visibly implausible process owners |
| `distribution_texture` | Sysmon Event 13 / eCAR registry events | Dataset-wide: 275 of 569 Event 13 records on all nine Windows hosts | High — repeated CBS state value and package-key construction form a generator-like family |
| `contract_gap` | Sysmon Event 13 | Dataset-wide | High — servicing writes rotate among `services.exe`, `svchost.exe`, and `msiexec.exe` rather than a coherent servicing chain |
| `contract_gap` | User registry effects | Repeated but lower volume | Medium — foreground tools acquire Office/shell side effects within implausibly short startup intervals |
| `schema_or_format` | eCAR | Dataset-wide | Low — duplicated semantic fields use inconsistent JSON types |
| `environment_or_collection_plausibility` | Sysmon Event 3 | Dataset-wide | Low — outbound-only Event 3 coverage is plausibly an intentional filter |

## Realism Score by Category

- **Field format accuracy:** 9 — Windows, Sysmon, Zeek, ASA, Snort, and web fields are exceptionally well structured; eCAR type duplication is the main weakness.
- **Temporal patterns:** 9 — native precision, provider timing offsets, lifecycle ordering, and Zeek connection intervals are convincing.
- **Cross-source correlation:** 9 — process, session, tuple, UID, certificate, and firewall correlations are strong, with no visible reverse causality found.
- **Behavioral realism:** 5 — repeated non-native ownership of WER, Defender, CBS, Office, and shell artifacts is a major endpoint-semantic defect.
- **Environmental consistency:** 7 — host-specific record rates and roles are plausible, but synchronized servicing-like artifact generation across every Windows host is weak.

## Recommendations

- If this were synthetic, build WER and Defender file events from source-native owners. WER queue records should be tied to a credible crash/reporting chain such as the affected process and `WerFault.exe`; Defender history should be owned by `MsMpEng.exe`, `MpCmdRun.exe`, or another explicitly modeled Defender component. Preserve the corrected PID, ProcessGuid, user, and eCAR actor across every projection.

- Model CBS registry activity as a coherent servicing episode. Use TrustedInstaller/TiWorker and appropriate update-service ancestry, OS-build-consistent package identities, clustered transaction timing, and a smaller set of package state transitions instead of distributing `CurrentState=0x70` writes continuously across unrelated processes.

- Attach Office MRU, first-run, Explorer, Defender, and shell-state effects to the application or subsystem that owns them. Do not assign these effects to an arbitrary live process merely because it has the right user or integrity level.

- Normalize eCAR numeric semantics. Keep PID/TID/PPID and port fields numeric wherever the schema permits, or publish an explicit normalized schema so detection content does not alternate between integer top-level fields and string properties.

- If outbound-only Sysmon Event 3 is intentional, preserve and document that collection profile. Otherwise include a small, role-appropriate inbound sample rather than presenting only `Initiated=true` records while other endpoint sources visibly collect inbound traffic.
