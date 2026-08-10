# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Real
**Verdict Confidence:** 84
**Synthetic-Confidence Score:** 25

## Executive Summary

The dataset behaves like a well-instrumented production environment: the Windows Security and Sysmon schemas are source-native, record sequencing is coherent, and sampled process, session, DNS, and network correlations survive detailed field-level checks. I found two low-impact regularities—the invariant network fields on explicit-credential events and a handful of unmatched session closes—but neither rises to a contradiction, so the balance of evidence favors real telemetry.

## Evidence For Synthetic

- `[distribution_texture]` All 31 sampled Security 4648 records have `IpPort=0`, even when `IpAddress` is populated with the source host's non-loopback address; all also use zero `LogonGuid`/`TargetLogonGuid`. Those values are individually legal, but the dataset-wide invariance across different callers (`runas.exe`, PowerShell, Veeam, osquery, Wazuh, and taskhostw) is unusually uniform.
- `[contract_gap]` Seven of 731 Security 4634 records have no visible 4624 with the same host and `TargetLogonId`: five Type 10 and two Type 2 sessions. Examples include `FILE-SRV-01` logon ID `0xf580ed2` closing at `2024-03-18T12:31:25.7592894Z` and `WS-DRAMIREZ-01` ID `0x972cd99` closing at `2024-03-18T17:32:23.1347958Z`. This is under 1% and is explainable by pre-window sessions or collection loss, so it carries little weight.
- `[weak_signal]` The visible eCAR process lifecycle is asymmetric (1,647 creates and 1,387 terminations, with 352 create object IDs lacking a visible terminate). Much of this is expected from long-lived processes and right-censoring at the end of the six-hour window; there were no negative lifetimes among matched pairs.

## Evidence For Real

- Windows event metadata is highly source-accurate across many IDs: Security 4624 is Version 2/Task 12544, 4688 is Version 2/Task 13312, 5156 is Version 1/Task 12810, and Sysmon 1/3/5 use Versions 5/5/3 with their correct task numbers and Operational channel.
- The DC Security audit clear is modeled particularly convincingly. `wevtutil cl Security` is created at `17:41:52.5808719Z` as PID `0x16f4`; Event 1102 follows at `17:41:53.4217549Z` using the Eventlog provider and native `UserData/LogFileCleared` shape, with `EventRecordID=1`; later records continue at IDs 4, 5, and 7. This explains the only apparent record-ID reset.
- Process telemetry cross-checks cleanly. There are 869 Security 4688 process keys and 861 Sysmon Event 1 keys; every Sysmon key has a Security counterpart, sampled paths agree exactly, and the eight Security-only creates are consistent with a small collection/filtering gap. Hashes remain stable for a given image on a given host.
- The explicit `runas.exe` activity on `WS-MCHEN-01` is internally coherent: Security 4688 at `14:49:43.9324942Z` contains valid `/netonly /user:marcus.chen "cmd.exe /c dir \\DC-01\ADMIN$"` operands, 4648 follows at `14:49:44.5317366Z` with the same PID `0x22a4`, and 4689 closes it at `14:49:51.3685682Z`. eCAR independently identifies PID 8868/object ID `6a487254-...` and terminates the same object about 7.4 seconds after creation.
- Security/Sysmon timestamp representation is convincingly source-specific: Windows `SystemTime` carries seven fractional digits, Sysmon `UtcTime` carries milliseconds, and companion image-load records occur within sub-millisecond offsets after process creation rather than sharing one flattened timestamp.
- Zeek JSON uses expected typed fields and shared UIDs. For example UID `CzeEYCiGpA7PNbMnqsM` ties a UDP/53 `conn.json` record at `1710763220.300682` to the corresponding PTR response in `dns.json`, with matching tuple and RTT/duration `0.000837`.
- Source volume and variety are plausible for the visible estate: 1,044 successful logons span Types 3, 5, 10, 2, and 7; Kerberos 4768/4769, NTLM 4776, WFP 5156, Sysmon DNS/network/process/module telemetry, Linux RFC5424 syslog, eCAR, proxy, firewall, IDS, and Zeek are all represented without a schema collision.

## Detailed Analysis

### Windows Security schema and sequencing

I parsed all Windows XML files and counted 18,396 Security events across 22 event IDs. Every inspected ID had one internally consistent field shape and the expected provider/channel metadata. Event record IDs were strictly increasing within every file except the DC Security log, where the reset is causally explained by the correctly shaped Event 1102 audit-clear record. Timestamps remain monotonic across that reset.

Logon coverage includes 718 Type 3, 297 Type 5, 14 Type 10, eight Type 2, and seven Type 7 successes. Of 731 distinct 4634 closes, 724 have a visible same-host 4624 with the same logon ID. The seven exceptions are sparse and include sessions whose start could precede the data window. Conversely, unmatched Type 5 logins are expected because service sessions frequently persist beyond the window.

The 31 Event 4648 records have correct field names and hex process IDs, and the sampled PIDs resolve to visible caller processes. The invariant `IpPort=0` plus zero GUIDs is the main residual texture concern, especially because the caller population is diverse. It is not an impossible value and therefore does not justify a synthetic verdict.

### Sysmon and eCAR process correlation

The Sysmon set contains Events 1, 3, 5, 7, 8, 10, 11, 13, and 22. Process creation fields include plausible `ProcessGuid`, hashes, parent GUID/PID/image, integrity level, logon GUID/ID, terminal session, and user. All 861 Sysmon Event 1 host/PID keys correspond to Security 4688 keys, with exact image agreement in spot checks; only eight of 869 Security creates lack Sysmon Event 1.

Per-host hash consistency is strong. Repeated instances of `powershell.exe`, `cmd.exe`, `svchost.exe`, `taskhostw.exe`, `explorer.exe`, and other binaries retain one hash tuple per host. Cross-host variants cluster rather than changing per execution, which is compatible with different Windows build/patch levels.

The eCAR corpus contains unique event IDs throughout (23,618 of 23,618) and no terminate-before-create ordering among matched process object IDs. Actor IDs, object IDs, PIDs, image paths, logon IDs, and source-process properties provide usable detection pivots. The create/terminate count difference is concentrated enough to merit a lifecycle audit, but window censoring and durable processes are plausible explanations.

### Network and source-family interoperability

Zeek records use native JSON types for ports, timestamps, counts, booleans, arrays, and protocol fields. Connection UIDs join protocol rows correctly in sampled DNS, HTTP, and file-transfer records. Security 5156 records use decimal `ProcessID`, native `%%14592`/`%%14593` direction tokens, device-form application paths, and protocol numbers, while eCAR renders the corresponding endpoint-centric direction and tuple. This is the sort of source-specific difference a real SIEM pipeline must preserve.

Linux syslog is RFC5424-shaped with facility/severity priority, ISO-8601 UTC timestamps, host, app name, proc ID, and realistic PAM/sudo/cron/systemd message families. The timestamps and PIDs are not flattened to the Windows or network-source conventions.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Impact |
|---|---|---:|---|
| `distribution_texture` | Windows Security 4648 | 31/31 records | Legal but unusually invariant port/GUID fields across varied callers; low-to-moderate weight |
| `contract_gap` | Windows Security sessions | 7/731 4634 records | Sparse unmatched closes; plausibly pre-window or collection loss; low weight |
| `weak_signal` | eCAR process lifecycle | 352/1,647 creates lack visible termination | Mostly compatible with durable processes/right censoring; very low weight without process-age stratification |

## Realism Score by Category

- **Field format accuracy:** 10 — Security, Sysmon, Zeek, eCAR, and RFC5424 records use source-native fields, types, metadata, and timestamp formats.
- **Temporal patterns:** 9 — Audit-clear reset and process/session sequences are causal; only sparse unmatched closes remain.
- **Cross-source correlation:** 9 — Security 4688, Sysmon 1, and eCAR processes correlate strongly without collapsing source-specific timing.
- **Behavioral realism:** 9 — Caller commands, process lifetimes, logon mix, service activity, and protocol evidence are operationally credible.
- **Environmental consistency:** 9 — Host roles, authentication protocols, source volumes, and collection families form a coherent enterprise estate.

## Recommendations

- If this were synthetic, diversify Event 4648 network-field outcomes according to the caller and authentication path: preserve `0`/zero-GUID cases where source-native, but include the other native missing/loopback/populated variants only where the underlying Windows path would actually produce them.
- Audit Security session observation as a lifecycle group. If a 4624 is intentionally omitted, omit or explicitly account for its paired 4634 unless the session began before the dataset window; retain a small, explainable collection-loss rate rather than forcing perfect coverage.
- Classify unmatched eCAR process creates by start time and executable role. Ensure short-lived command processes that finish well before the window end receive a coherent create/terminate observation decision, while long-lived services and right-censored processes remain legitimately open.
