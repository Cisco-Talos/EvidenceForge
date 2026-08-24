# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 98
**Synthetic-Confidence Score:** 94

## Executive Summary

The dataset is impressively detailed and largely SIEM-usable, with strong Zeek UID integrity, coherent process identities, realistic Windows metadata, and several convincing multi-source sequences. However, repeated impossible Sysmon timestamps across seven Windows hosts, together with path-specific empty Windows Security fields and visible lifecycle inversions, are strong generator fingerprints that outweigh the otherwise high realism.

## Evidence For Synthetic

- `[hard_contradiction]` Across the nine Sysmon files, 115 of 1,418 Event 1/5 records have `UtcTime` later than their enclosing `System/TimeCreated`; 105 are later by more than one second, 77 by more than one minute, and 61 by more than ten minutes. The defect occurs on seven hosts.
- `[hard_contradiction]` On `WS-AJOHNSON-01`, Sysmon Event 1 for PID 5572, `mstsc.exe`, has `TimeCreated=2024-03-18T14:42:38.4289327Z` but `UtcTime=2024-03-18 15:55:17.726`. Event 5 for the same ProcessGuid occurs at `15:12:51.0435386Z` yet repeats that same still-future `UtcTime`; eCAR independently places creation at `14:42:38.546Z` and termination at `15:12:50.985Z`.
- `[distribution_texture]` Unrelated Sysmon processes repeatedly share identical millisecond `UtcTime` anchors. Seven WS-MCHEN Event 1/5 records share `2024-03-18 17:01:14.451`, while six WS-AJOHNSON records share `2024-03-18 14:00:33.984`.
- `[schema_or_format]` Ten FILE-SRV-01 Security 4624 Type 3 records render empty `SubjectUserSid`, `SubjectUserName`, `SubjectLogonId`, `LogonGuid`, `LogonProcessName`, and `LmPackageName` elements. Successful native events should carry valid values or native placeholders such as `S-1-0-0`, `0x0`, a zero GUID, or `-`, not empty required fields.
- `[hard_contradiction]` Those same FILE-SRV-01 4624 records set `WorkstationName=FILE-SRV-01` even when the remote source is `10.10.1.34`, `10.10.1.31`, or `10.10.1.35`; matching SMB records identify FILE-SRV-01 as the responder. The workstation field therefore describes the target rather than the initiating workstation.
- `[schema_or_format]` All four visible successful RDP Type 10 Security 4624 records have an empty `TargetUserSid` and `LogonGuid`, despite identifying a domain user and successful logon session.
- `[contract_gap]` Twelve RDP bootstrap Security 4688 records have empty `ParentProcessName` values. For example, DC-01 records `userinit.exe` at `14:42:47.3773834Z` with parent PID `0x1234`, then `explorer.exe` at `14:42:47.7112180Z` with parent PID `0x123c`, but omits both known parent image names. Four associated `winlogon.exe` records also have empty subject SID, username, and logon ID.
- `[hard_contradiction]` In WS-AJOHNSON eCAR, PowerShell PID 6496 terminates at `17:19:40.246Z`, followed by five MODULE/LOAD records for the same process UUID between `.256Z` and `.293Z`. These include `kernel32.dll`, `kernelbase.dll`, `ucrtbase.dll`, `advapi32.dll`, and `rpcrt4.dll`.

## Evidence For Real

- All reviewed XML and JSON records parsed successfully. Windows Provider GUIDs, channels, versions, tasks, levels, opcodes, and keywords were generally source-accurate across 10,549 Security events and 3,572 Sysmon events.
- Windows EventRecordIDs increase organically with variable gaps. DC-01 correctly resets its Security record number to 1 at Event 1102 and continues upward afterward; Event 1102 also uses the Eventlog provider and native `UserData/LogFileCleared` structure.
- Sysmon uses the expected per-event field names and casing, including the unusual `SourceProcessGUID`/`TargetProcessGUID` spelling in Event 10. ProcessGuid references that could be checked agreed on PID and image, and no visible Event 5 preceded its matching Event 1 by `TimeCreated`.
- Hash bundles remain stable for the same image and file version, both within and across hosts. No identical full hash bundle was assigned to unrelated binaries in the sampled Event 1 and Event 7 records.
- Zeek child-record integrity is strong. Every reviewed core DNS, HTTP, SSL, SMTP, SMB mapping, and SMB file UID resolved to a `conn.json` record with the same tuple; the same held for DMZ DNS, HTTP, and SSL records. All 52 core and 845 DMZ certificate-chain FUID references resolved to `x509.json`.
- A representative RDP sequence is convincing: Zeek UID `C1wStVgtVC6YEsvW6rZ` opens `10.10.1.99:51767 -> 10.10.1.35:3389` at `15:00:24.009425Z`; Security 4624 authenticates the same source port at `15:00:28.4554515Z`; Security 4779 disconnects it at `15:53:16.4643910Z`, approximately one second before the Zeek transport closes.
- The PsExec evidence is operationally useful and internally coherent: Sysmon Event 11 creates `C:\Windows\PSEXESVC.exe` at `15:59:41.2855966Z`, Security 4697 registers `PSEXESVC` at `15:59:41.5922704Z`, Sysmon Event 1 starts it under `services.exe` at `15:59:42.9751565Z`, and its child `cmd.exe /c whoami && hostname` follows at `15:59:43.7107773Z`.
- RFC 5424 syslog records have plausible PRI/version framing, UTC precision, host/application identities, process IDs, and service-specific messages. Proxy and web records likewise use ingestible, internally consistent formats.

## Detailed Analysis

### Windows and Sysmon schema fidelity

The dominant Windows event templates are accurate. Security 4624 uses Version 2 and the expected 27 fields; 4688 uses Version 2 with command line, parent image, mandatory label, and target-token fields. Sysmon Event IDs 1, 3, 5, 7, 8, 10, 11, 13, and 22 use consistent field sets and plausible schema versions.

The strongest defect is internal to Sysmon timestamps. `UtcTime` is the source-native occurrence time and should precede the event provider’s `TimeCreated` by a small publishing delay. Instead, substantial subsets point minutes or hours into the future. The largest sampled offset is WS-MCHEN PID 7724 `mmc.exe`: Event 5 has `TimeCreated=14:55:09.5039903Z` but `UtcTime=17:01:14.451`, an offset of 7,564.947 seconds. These are not bounded-window omissions or ordinary collection delays; a record cannot be published before its own claimed occurrence.

### Windows authentication and process semantics

Normal logon lifecycle ordering is generally good: matched 4624/4634 identifiers do not show visible logoff-before-logon inversions, and privileged 4672 records align with visible sessions or built-in service logon IDs.

Two specialized paths lose native identity semantics. FILE-SRV-01 SMB logons emit empty subject and authentication fields and report the server itself as `WorkstationName`. The RDP path emits successful 4624 records without the authenticated user SID, then creates `winlogon.exe`, `userinit.exe`, and `explorer.exe` with empty subject or parent-image fields. Queries depending on `TargetUserSid`, `SubjectUserSid`, `LogonProcessName`, or `ParentProcessName` would therefore miss otherwise obvious activity.

### Correlation and lifecycle integrity

Security, Sysmon, eCAR, and Zeek often agree exceptionally well on PIDs, paths, users, tuples, and timing. The RDP and PsExec samples demonstrate useful detection pivots rather than merely matching identifiers.

The eCAR PID 6496 sequence is an exception. Its process object is explicitly terminated and then reused as the actor for five subsequent module loads. Because all records are in the same source family and reference the same UUID, this is a visible lifecycle contradiction rather than a missing pre-window initiator.

### Zeek and SIEM usability

Zeek JSON field names and JSON types are broadly credible: ports and counters are integers, timestamps and intervals are numeric, boolean flags remain booleans, and vectors such as `answers`, `TTLs`, `conn_uids`, and `cert_chain_fuids` are arrays. Child timestamps remain within their connection intervals in the reviewed correlations, and failed/S0 connections omit duration while retaining plausible packet histories.

The logs are highly usable for DNS, HTTP, TLS, SMB, authentication, process, and service detections. Their principal reliability risk is not parsing but semantic time and identity corruption in the affected Windows records.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected the synthetic-confidence score |
|---|---|---|---|
| `hard_contradiction` | Sysmon Event 1/5 | 115 records across 7 of 9 Windows hosts; 105 exceed one second | Source occurrence times are later than the events that contain them, sometimes by more than two hours. |
| `distribution_texture` | Sysmon Event 1/5 | Repeated clusters on multiple user endpoints | Unrelated processes reuse identical future millisecond time anchors, resembling shared generator state. |
| `schema_or_format` | Security 4624, SMB path | 10 FILE-SRV-01 logons | Required subject and authentication values are rendered as empty XML elements. |
| `hard_contradiction` | Security 4624, SMB path | All 10 sampled file-share logons | `WorkstationName` identifies the responding file server rather than the remote source workstation. |
| `schema_or_format` | Security 4624/4688, RDP path | Four sessions and twelve bootstrap processes | Successful logons omit target SIDs; child processes omit known subject or parent identity. |
| `hard_contradiction` | eCAR process/module lifecycle | One process, five dependent events | Module loads occur after termination for the same process UUID. |

## Realism Score by Category

- **Field format accuracy:** 6/10 — Most schemas are accurate, but empty required Security fields materially break native-event fidelity.
- **Temporal patterns:** 3/10 — Repeated future Sysmon occurrence times and one post-termination module sequence are decisive contradictions.
- **Cross-source correlation:** 8/10 — Zeek UIDs, RDP sessions, process identities, hashes, and service activity correlate strongly outside the identified defects.
- **Behavioral realism:** 8/10 — Process trees, authentication types, service installation, network activity, and ordinary host behavior are operationally plausible.
- **Environmental consistency:** 8/10 — Host roles, addressing, software, and source-family volumes are generally coherent; the SMB workstation attribution is the notable exception.

## Recommendations

If this were synthetic, the following would improve it:

- Derive each Sysmon record’s `UtcTime` from that record’s actual canonical occurrence. Enforce `UtcTime <= System/TimeCreated`, require Event 1 time to represent creation and Event 5 time to represent termination, and reject repeated time anchors across unrelated processes.
- Add native-template validation that rejects empty required Windows fields. Render documented values or source-native placeholders such as `S-1-0-0`, `0x0`, a zero GUID, or `-`.
- Populate SMB 4624 subject/authentication fields from the actual logon contract, and derive `WorkstationName` from the initiating client rather than the receiving server.
- Preserve the authenticated `TargetUserSid` and full process lineage through RDP session bootstrap so `winlogon.exe`, `userinit.exe`, and `explorer.exe` carry valid subjects and parent image names.
- Order eCAR module evidence before the matching process termination, or delay termination until all dependent records for that process UUID have been emitted.
- Add final rendered-output invariants for native timestamp ordering, required-field non-emptiness, process-dependent events within create/terminate bounds, and source-versus-target workstation semantics.
