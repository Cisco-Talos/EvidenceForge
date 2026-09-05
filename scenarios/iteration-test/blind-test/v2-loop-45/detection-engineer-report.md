# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 91
**Synthetic-Confidence Score:** 78

## Executive Summary

The collection is unusually strong in parseability, Event ID metadata, timestamp formatting, and cross-source correlation, but two repeated Windows-native defects are difficult to reconcile with production telemetry. Most decisively, 158 successful Type 3 logons use the destination computer as `WorkstationName` while leaving multiple normally populated or placeholder-valued fields empty, and the visible RDP process chains assign `winlogon.exe` to System PID 4 while withholding parent images even when the parent processes are present in the same logs.

## Evidence For Synthetic

- `[hard_contradiction]` Across 158 Security Event ID 4624 Type 3 records, `WorkstationName` is the receiving computer rather than the source represented by `IpAddress`. For example, `DC-02.meridianhcs.local/windows_event_security.xml` at `2024-03-18T12:17:36.2452037Z` records source `::ffff:10.10.1.36` but `WorkstationName=DC-02`; `FILE-SRV-01.meridianhcs.local/windows_event_security.xml` at `2024-03-18T12:01:43.5380897Z` similarly uses `WorkstationName=FILE-SRV-01` for source `::ffff:10.10.1.34`. The pattern repeats on DC-01, DC-02, and FILE-SRV-01 across many users and source addresses, making it a systematic source/destination ownership error rather than an isolated hostname-resolution failure.
- `[schema_or_format]` The same 158 Event ID 4624 records render empty strings for `SubjectUserSid`, `SubjectUserName`, `SubjectLogonId`, `LogonGuid`, `LogonProcessName`, and `LmPackageName`. A raw Windows event normally renders explicit source-native values or placeholders such as `S-1-0-0`, `-`, `0x0`, and the zero GUID; successful network logons also identify a trusted logon process such as Kerberos or NtLmSsp. These records instead combine `AuthenticationPackageName=Negotiate`, a real source address and port, and `ProcessName=C:\Windows\System32\lsass.exe` with six blank fields.
- `[hard_contradiction]` Three visible RDP session bootstraps contain impossible Windows ancestry. In `WS-AJOHNSON-01.meridianhcs.local/windows_event_sysmon.xml`, Event ID 1 at `2024-03-18T14:59:41.8663288Z` gives `winlogon.exe` PID 6292 a parent PID of 4 and `ParentImage=-`; subsequent visible Event ID 1 records give `userinit.exe` PID 6312 parent PID 6292 and `explorer.exe` PID 6316 parent PID 6312, but still set both parent images to `-`. Windows session initialization is rooted through `smss.exe`, not System PID 4, and Sysmon should resolve the image for the two parents that are themselves recorded moments earlier.
- `[contract_gap]` The same RDP defect appears in Security 4688. On WS-AJOHNSON-01 at `2024-03-18T14:59:41.9163185Z`, `winlogon.exe` has creator PID `0x4` with an empty `ParentProcessName`; at `14:59:42.1057181Z`, `userinit.exe` names parent PID `0x1894` but leaves `ParentProcessName` empty; and at `14:59:42.5142736Z`, `explorer.exe` names parent PID `0x18a8` but again leaves the parent path empty. Equivalent chains occur on DC-01 at `14:30:33Z` and WS-AJOHNSON-01 at `15:19:51Z`.
- `[schema_or_format]` The corresponding successful Type 10 logons have blank `TargetUserSid` and blank `LogonGuid` despite resolved domain usernames and domains. Examples are DC-01 at `2024-03-18T14:30:33.6445953Z` for `MERIDIANHCS\marcus.chen`, and WS-AJOHNSON-01 at `2024-03-18T14:59:41.9589236Z` and `15:19:51.1048236Z` for `MERIDIANHCS\aisha.johnson`. The users' complete domain SIDs appear elsewhere in the same source family, so these are not unresolved identities at the collection level.
- `[distribution_texture]` Every one of the 869 Sysmon Event ID 3 records has `Initiated=true`, and all 869 use `DestinationHostname=-`, including records from domain controllers and servers that also contain abundant inbound Security 5156 activity. A uniform outbound-only Sysmon filter is possible, so this is not independently dispositive, but the all-or-nothing field texture across ten Windows systems adds mild synthetic weight.

## Evidence For Real

- All 18,106 Security events and 4,845 Sysmon events parsed as XML, and every inspected Event ID had a stable, source-appropriate field set. Metadata was generally accurate: Security 4688 used version 2/task 13312, 5156 used version 1/task 12810, and Sysmon Event IDs 1, 3, 5, 7, 8, 10, 11, 13, and 22 used plausible versions, tasks, channels, providers, and keywords.
- The Security log-clear event is especially convincing. DC-01 Event ID 1102 at `2024-03-18T17:42:17.6718975Z` uses provider `Microsoft-Windows-Eventlog`, the Eventlog-specific `UserData/LogFileCleared` schema, record ID 1, and is followed by a realistic record-ID restart; the other Security logs remain monotonically increasing.
- Process correlation is strong without visible causal inversions. Of 963 Sysmon process-create events, all but seven had matching Security 4688 records by host, PID, image, and sub-second time, and matched records agreed on command line, parent PID, and parent image except for the explicitly identified blank-parent chains. No Sysmon dependent event referenced a matching visible process creation that occurred later.
- Session lifecycles are mostly coherent. Type 3 Security 4624/4634 pairs reuse the same Logon ID, user, and logon type, with unmatched starts or ends explainable by the six-hour collection boundary. The repeated Type 7 unlocks sharing an existing interactive Logon ID and eventual Type 2 logoff are source-native behavior rather than contradictions.
- Zeek JSON is structurally credible. Protocol records in all three sensors reference existing `conn.json` UIDs; checked DNS, HTTP, SSL, SMTP, SMB mapping, and SMB file records match the connection four-tuple; protocol timestamps fall within plausible connection intervals; and every `files.json` `conn_uids` reference resolves.
- Field values show useful enterprise variation: Kerberos encryption types include AES256, AES128, and RC4; failed logons contain coherent status/substatus combinations; Sysmon hashes use correctly sized MD5, SHA1, SHA256, and IMPHASH values; and DNS results include successful A/SRV answers as well as `9002` and `9003` failures.
- Cross-source timestamp differences are realistically nonzero. Matching Sysmon Event ID 1 records precede Security 4688 by roughly 35–642 ms rather than sharing identical timestamps, while Sysmon `SystemTime` trails its millisecond `UtcTime` by small variable delays.

## Detailed Analysis

### Source inventory and parseability

The visible window is approximately six hours, from `2024-03-18T12:00:00Z` through `17:59:56Z`. I inspected ten Windows Security XML files, ten Sysmon XML files, twenty eCAR JSON streams, three Zeek sensor families, Cisco ASA, Snort, proxy, web access, Linux syslog, and shell-history data. JSON-line files parsed cleanly in the sampled and aggregate checks, Windows XML documents parsed cleanly, eCAR record IDs were unique, and timestamps and GUID/hash syntax were consistently machine-readable.

The Security source contains 28 Event IDs. High-volume IDs include 5156 (11,230), 4769 (2,015), 4688 (971), 4624 (874), 4689 (820), 4768 (776), 4634 (439), and 4672 (426), plus lower-volume share access, NTLM validation, object access, explicit credential use, account management, service creation, scheduled task creation, RDP disconnect, and log-clear records. Sysmon contains Event IDs 1, 3, 5, 7, 8, 10, 11, 13, and 22 with stable field order and source-appropriate types.

### Windows Event ID and field semantics

Most Windows schemas are well formed. Event 4624 version 2 contains the expected 27 fields; 4625 carries coherent `0xc000006d` status values with `0xc000006a` bad-password or `0xc0000072` disabled-account substatus; 4768 and 4769 use appropriate Kerberos field families; and 4688 includes command line, target subject fields, parent path, and mandatory label. Event 1102 correctly changes provider and payload namespace rather than being forced into a Security-Auditing `EventData` shape.

The main exception is a repeated Type 3/Negotiate subtype. Exactly 158 of 874 Event 4624 records have empty `SubjectUserSid`, `SubjectUserName`, `SubjectLogonId`, `LogonGuid`, `LogonProcessName`, and `LmPackageName`. Those same records set `WorkstationName` to the target host: 53 occur on DC-01, 28 on DC-02, and 77 on FILE-SRV-01. Representative raw values include target user `sophia.martinez`, target SID `S-1-5-21-1524654518-2022274387-1755902678-1008`, target Logon ID `0xcb75e4d`, source `::ffff:10.10.1.36:54574`, destination-side process `lsass.exe`, but `WorkstationName=DC-02`. This combination would mislead detections and enrichment that interpret WorkstationName as the originating workstation, and the repeated empty-string placeholders are unlike the explicit placeholders elsewhere in the same files.

The three visible Type 10 RDP logons form a second defective family. Each has a resolved domain account but blank `TargetUserSid` and `LogonGuid`. The accompanying process chain is visible in both Sysmon and Security: winlogon, userinit, then explorer. The PIDs correlate across sources and timestamps are coherent, but `winlogon.exe` is attributed to PID 4 rather than `smss.exe`, while each child has an unresolved parent image despite a visible parent PID and process-create record. This is not merely missing pre-window context: userinit and explorer's exact parents are created inside the visible window immediately before them.

### Process and endpoint correlation

Security 4688 and Sysmon Event ID 1 correlation is otherwise excellent. Host-by-host matching found 956 of 963 Sysmon process starts represented by a Security 4688 record within one second, with all 963 Sysmon events accounted for and only seven additional Security-only starts. Matching command lines and parent PIDs were consistent. Process termination also showed no visible future-create inversions: when a matching create existed for a Security 4689 or Sysmon Event 5 identifier, it preceded termination.

Sysmon GUIDs have correct brace/dash formatting, and all configured hashes have valid hexadecimal lengths. The same image is stable within a given host/build context, while common binaries vary across several hosts in a way consistent with differing Windows builds or patch levels. Event 22 DNS fields show plausible status and result forms, Event 7 signature fields distinguish valid from unavailable signatures, and Event 13 registry details use source-appropriate strings such as `DWORD (0x00000001)` and `Binary Data`.

### Authentication and session correlation

Logon and logoff correlation is largely realistic. Type 3 sessions overwhelmingly have matching 4634 records with the same Logon ID, user, and logon type. Long-lived Type 5 service sessions remain open at the end of the bounded window, while a small number of pre-window sessions terminate without a visible start. Type 7 unlock records appropriately reuse an interactive session's Logon ID, so a later Type 2 logoff for that ID is not a contradiction.

Kerberos records use plausible ticket options and encryption types, and the one Event 4771 failure at `2024-03-18T14:59:41.1933225Z` correctly combines status `0x18` with pre-auth type 2. Event 4648 records contain syntactically valid SIDs, process IDs, target accounts, server names, and zero GUID placeholders. The rare account-management and persistence events also use credible Event IDs and field families.

### Network and cross-source utility

The Zeek family is highly usable for detections. Every checked DNS, HTTP, SSL, SMTP, SMB file, and SMB mapping UID resolves to a `conn.json` row in the same sensor, and the origin/responder tuple agrees. `files.json` connection references also resolve. Cisco ASA built/teardown IDs, NAT translations, Snort tuples, proxy requests, and Zeek activity expose practical pivot keys rather than isolated alerts.

The eCAR corpus contains 33,912 valid JSON records with unique top-level IDs and a coherent vocabulary including PROCESS/CREATE, PROCESS/TERMINATE, PROCESS/OPEN, FLOW/CONNECT, USER_SESSION/LOGIN and LOGOUT, MODULE/LOAD, FILE operations, REGISTRY/MODIFY, THREAD/REMOTE_CREATE, and SERVICE/CREATE. Property variants generally reflect event semantics rather than arbitrary schema drift. The Windows RDP parentage defect carries into eCAR/Sysmon/Security semantics, but the broader endpoint-to-network correlation remains operationally useful.

### Distribution and detection behavior

Timing has useful entropy: Windows record IDs have realistic gaps, process-source delays vary, and protocol events are not stamped identically to their parent connections. Counts vary materially by host and role. The main lower-confidence distribution concern is Sysmon Event ID 3: all 869 records are `Initiated=true`, `SourceIsIpv6=false`, `DestinationIsIpv6=false`, and `DestinationHostname=-`. This could result from a deliberate outbound-only policy with reverse lookup disabled, so I treat it as supporting texture rather than a contradiction.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `hard_contradiction` | Security 4624 Type 3 | 158 records across DC-01, DC-02, and FILE-SRV-01 | High: destination host is repeatedly written into a field that represents the originating workstation, directly corrupting detection semantics. |
| `schema_or_format` | Security 4624 Type 3 | The same 158 records | High: six identity/authentication fields use empty strings where Windows-native values or placeholders are expected. |
| `hard_contradiction` | Sysmon 1 / Security 4688 RDP chains | Three session bootstraps on two hosts | High: `winlogon.exe` is parented to System PID 4, and visible userinit/explorer parents remain unresolved. |
| `schema_or_format` | Security 4624 Type 10 | Three successful RDP logons | Medium: resolved domain users have blank target SIDs and blank Logon GUIDs. |
| `distribution_texture` | Sysmon 3 | 869 records across ten hosts | Low: the collection is uniformly outbound-only and never resolves a destination hostname; plausible policy choices prevent treating this as decisive. |

## Realism Score by Category

- **Field format accuracy:** 6/10 — Most schemas and primitive formats are excellent, but repeated blank 4624 fields and blank RDP identity/parent fields are source-native defects.
- **Temporal patterns:** 9/10 — Timestamps, source delays, lifecycle ordering, and record-ID behavior are varied and largely credible.
- **Cross-source correlation:** 8/10 — PID, command-line, UID, tuple, and lifecycle matching is strong, reduced by the RDP parent-image contract failure.
- **Behavioral realism:** 7/10 — The activity is operationally plausible, but System-parented winlogon chains are not valid Windows behavior.
- **Environmental consistency:** 7/10 — Host roles, source volumes, and protocol mix are plausible; repeated destination-as-workstation semantics and uniform outbound-only Sysmon network telemetry reduce realism.

## Recommendations

- If this were synthetic, populate Event 4624 network-logon subject and authentication fields using Windows-native values or placeholders. In particular, emit `S-1-0-0`, `-`, `0x0`, and the zero GUID where the source lacks a principal, and choose a valid `LogonProcessName` consistent with the negotiated authentication package.
- If this were synthetic, derive Type 3 `WorkstationName` from the originating endpoint when known, not the receiving computer. When Windows would not resolve a source NetBIOS name, use `-`; never substitute the destination hostname.
- If this were synthetic, model RDP session process ancestry through `smss.exe -> winlogon.exe -> userinit.exe -> explorer.exe`. Carry each visible parent's image into both Sysmon `ParentImage` and Security 4688 `ParentProcessName`, and ensure the Sysmon/Security/eCAR views share the same parent identity.
- If this were synthetic, populate successful Type 10 `TargetUserSid` from the resolved account and render a source-native zero or actual `LogonGuid` rather than an empty string.
- If this were synthetic, add limited inbound `Initiated=false` Sysmon Event ID 3 coverage or document a consistently expressed outbound-only filtering policy in the record population; when DNS enrichment is enabled for a process, allow a realistic minority of `DestinationHostname` values rather than forcing `-` for every record.
