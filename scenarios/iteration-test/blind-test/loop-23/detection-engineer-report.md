# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 78
**Synthetic-Confidence Score:** 62

## Executive Summary

The dataset is largely credible and should exercise ordinary SIEM parsing and correlation well, but native macOS fork timestamps contain repeated, microsecond-identical phase patterns across separate commands on both Macs. This localized distribution artifact supports a synthetic verdict, while the absence of demonstrated lifecycle contradictions and the strong Windows/network field consistency keep the score near the lower end of “likely synthetic.”

## Evidence For Synthetic

- [distribution_texture] `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson`, lines 35, 38, 41 and 44, records four distinct fork events at `2026-11-02T13:48:41.198588000Z`, `13:49:08.198588000Z`, `13:49:43.198588000Z` and `13:50:02.198588000Z`. Different children, PIDs 29678, 29725, 29784 and 29816, all inherit precisely the same fractional microsecond, at intervals of exactly 27, 35 and 19 seconds. Their subsequent exec observations have different fractional times. This resembles integer offsets applied to one activity anchor, rather than independently observed kernel fork times.
- [distribution_texture] The pattern recurs in another command group on that Mac, lines 53, 56 and 59: `14:37:50.487145000Z`, `14:38:28.487145000Z`, `14:38:57.487145000Z`. It also occurs independently on `MAC-MROSS-02.meridianhcs.local/macos_endpoint_security.ndjson`, lines 86, 89 and 92: `15:30:55.965208000Z`, `15:31:17.965208000Z`, `15:31:58.965208000Z`. Across 102 fork records, ten records belong to these three repeated-fraction groups. Repetition across both hosts makes an isolated timestamp coincidence less persuasive. These are multiple examples of one timing defect, not three independent defect families.

## Evidence For Real

- All 20 Windows XML files parsed successfully: 18,076 Security events and 11,747 Sysmon events. All 80,066 records in the supplied JSON/NDJSON files also parsed. Windows Security, Sysmon, Zeek, eCAR, native ES and Unified Log use distinguishable source shapes and precision.
- I checked all 990 visible Sysmon process creations against visible parent creation/termination records by ProcessGuid. None had a demonstrated parent-created-later, parent-terminated-earlier, or parent-PID mismatch. All 794 visible Sysmon create/terminate pairs had non-integer lifetimes, countering a claim of widespread integer-duration construction.
- Across all three Zeek directories, protocol rows with an available connection UID agreed on both endpoint addresses and ports and fell within the connection interval, allowing one millisecond for numeric precision. No negative duration or payload-byte count exceeding IP-byte count was found. The only missing connection reference was one SMB mapping; that alone is compatible with collection loss or filtering.
- Zeek connection histories include varied termination, retransmission and loss texture. All 1,372 records containing `G` or `g` also had positive `missed_bytes`; this is a meaningful semantic consistency check, not merely reference completeness.
- `DC-02` has a coherent NTLM Type 3 example: 4624 at `13:04:44.0171612Z`, LogonID `0xcb5c02d`, source `::ffff:10.10.1.34:51922`, followed by SYSVOL access using that LogonID and source tuple and a 4634 at `13:04:47.0513596Z`.
- The Security log-clear record is rendered as the Eventlog provider’s 1102 with namespaced `UserData/LogFileCleared`, rather than being forced into a generic Security-Auditing EventData shape. On `DC-01`, `18:42:21.9831196Z` has EventRecordID 1; later records continue from the reset sequence.
- Native macOS fork/exec/exit records preserve actor/target distinctions, PID continuity across exec, incremented PID versions and stable shell thread identity. They do not misuse native ES as network FLOW telemetry. I found no visible native fork-before-dependent or exit-before-later-actor contradiction in either Mac file.

## Detailed Analysis

### Scope and method

I examined only the supplied data directory. The observed slice is approximately November 2, 2026, 13:00–19:00 UTC. Counts are logical records, not XML line counts. I parsed all structured files, examined representative records from more than 20 event types/shapes, and ran targeted relationship checks across the full relevant populations.

No conclusion uses filesystem timestamps, domain resolvability, attack linearity, source completeness, or absent Sysmon event types. Missing pre-window processes and sessions were not treated as failures. External schema documentation was outside this study’s data-only scope; therefore the checks below distinguish recognizable field semantics from a claim of exhaustive vendor-version certification.

### Native macOS timing: principal synthetic indicator

The first MAC-MROSS-01 cluster contains curl download, bash script execution, `ls`, and `id` children. The relevant exec records are:

| ES line | Exec time, UTC | Executable / argument detail |
|---|---|---|
| 36 | 13:48:41.201976000 | `/opt/homebrew/opt/curl/bin/curl -fsS -o /Users/maya.ross/Downloads/connector-check.sh ...` |
| 39 | 13:49:08.207155000 | `/bin/bash .../connector-check.sh --check-config` |
| 42 | 13:49:43.205524000 | `/bin/ls -l .../connector-check.sh` |
| 45 | 13:50:02.207561000 | `/usr/bin/id` |

The four fork times retain `.198588000`, while their exec delays vary. Consequently this is not simply a source exporting all timestamps at whole-second precision. The identical fractional times also appear in `mach_time`: 24953308766112, 24953956766112, 24954796766112 and 24955252766112. Differences are exactly the corresponding whole-second intervals at 24 million ticks per second.

The second MAC-MROSS-01 group comprises the script’s `--check-network` run, `cat /etc/resolv.conf` and `cat /etc/hosts`. MAC-MROSS-02’s group comprises `dscl`, `find` and `du`, with distinct children 13190, 13236 and 13310. Their exec delays again vary normally. The issue is the repeated subsecond timing of the observed fork occurrences, not the content or narrative neatness of those commands.

Ordinary command automation can schedule actions at integer-second intervals, and a transformed export might preserve a scheduling phase. Those alternatives prevent treating the finding as physically impossible. However, multiple independent observed forks repeating an exact microsecond phase in three groups on two hosts is an appreciable distribution tell. This is the principal reason for the synthetic verdict.

The native ES exports declare message `version: 11` and wrapper `schema_version: 1`. The observed types are 9/exec, 11/fork and 15/exit, all notification actions. I did not infer an authorization denial from their result fields or require file notifications that the visible subscription does not establish. Unified Log rows are separate exports with process/sender image fields, subsystem/category, boot UUID and their own timestamp representation. Sparse Unified Log coverage was not scored as a defect.

### Windows schema and event semantics

The following examples illustrate actual record verification. Times are UTC on November 2, 2026; host names abbreviate their supplied directory names.

| Host / event | Time or record | Fields checked and result |
|---|---|---|
| DC-02 / 5156 | 13:00:04.6195699 | Decimal ProcessID 5272, device-form dns.exe application path, protocol 17, inbound Direction `%%14592`, responder port 53: coherent WFP shape. |
| DC-02 / 4776 | 13:00:08.9498956 | `PackageName=MICROSOFT_AUTHENTICATION_PACKAGE_V1_0`, machine account `WS-DRAMIREZ-01$`, `Status=0x0`: coherent credential validation. |
| DC-02 / 4769 | 13:00:27.0756073 | `TargetUserName=DC-01$`, `ServiceName=DC-02$`, domain SID, IPv4-mapped IPv6 client and hex encryption type `0x11`: consistent TGS fields. |
| DC-02 / 4689 | 13:01:05.1409742 | Hex ProcessId `0x1710`, spoolsv.exe, `Status=0x0`, SYSTEM subject: expected termination field family. |
| DC-02 / 4688 v2 | 13:01:05.9719627 | WmiPrvSE.exe new PID `0x1a94`, parent PID `0x13fc`, ParentProcessName, MandatoryLabel, separate creator/target fields: expected v2 shape. |
| DC-02 / 4624 v2 | 13:04:44.0171612 | Type 3, NTLM/NtLmSsp, NTLM V2 and 128-bit key, client source tuple, target LogonID `0xcb5c02d`: consistent authentication mechanism. |
| DC-02 / 5140 v1 | 13:04:44.0918410 | Same LogonID/source tuple as preceding 4624; SYSVOL and local SYSVOL path: coherent share access. |
| DC-02 / 4634 | 13:04:47.0513596 | Target LogonID `0xcb5c02d`, Type 3 and same user as 4624: coherent paired close. |
| DC-02 / 4672 | 13:06:22.9288926 | SYSTEM `0x3e7` with native multiline privilege list: correctly structured special privileges. |
| DC-02 / 4768 | 13:22:14.0689810 | `krbtgt`, service RID 502, `PreAuthType=2`, `Status=0x0`, cert fields present but empty: coherent password-based TGT example. |
| DC-02 / 4771 | 16:00:29.4533223 | `Status=0x18`, preauth type 2, client `::ffff:10.10.1.99`, failure keywords `0x8010000000000000`: appropriate failure semantics. |
| DC-02 / 4625 | 16:26:32.7785952 | NTLM Type 3, status `0xc000006d`, substatus `0xc0000072`, failure keywords: coherent disabled-account failure. |
| FILE-SRV-01 / 5145 | 13:00:05.9658109 | Share-relative name, access mask/list, client tuple, subject LogonID: shape supports share-access rules. |
| FILE-SRV-01 / 4656 | 13:00:05.9709815 | Handle `0xb013d0ff`, transaction GUID, ProcessId `0x4`, object path and requested access: coherent open request. |
| FILE-SRV-01 / 4663 | 13:00:06.1459007 | Same handle/object/subject; access mask `0x2`: actual write access follows request. |
| FILE-SRV-01 / 4658 | 13:00:09.7044244 | Same handle and subject: close follows access. |
| WS-PPATEL-01 / 4800, 4801 | 18:08:51 / 18:51:43 | Same LogonID `0xd9f40cf` and SessionId 2: lock/unlock pairing is plausible. |
| DC-01 / 4698 | 17:19:51.1022232 | TaskContent contains task XML, principal, command, TimeTrigger and PT1H repetition: appropriate structured task payload. |
| DC-01 / 1102 | 18:42:21.9831196 | Eventlog provider, Level 4, Task 104, namespaced UserData and record reset: source-specific log-clear form. |
| DC-02 / Sysmon 1 | 13:01:05.871 UtcTime | WmiPrvSE.exe PID 6804, parent 5116, hash algorithms, integrity level and GUIDs: process fields and parent match the Security observation. |
| DC-02 / Sysmon 5 | 13:01:05.030 UtcTime | PID 5904, spoolsv.exe and stable ProcessGuid: termination agrees with Security 4689. |
| DC-02 / Sysmon 10 | 13:03:35.692 UtcTime | Source/target GUIDs, SourceThreadId, GrantedAccess `0x1010`, CallTrace and users: recognizable ProcessAccess shape. |
| DC-02 / Sysmon 8 | 13:03:35.857 UtcTime | Same source/target processes, new thread 6536, address/module/function: coherent remote-thread observation. |

Security’s seven-digit UTC representation and Sysmon’s millisecond `UtcTime` are distinct. Sampled Sysmon ProcessGuids encode the appropriate process creation second; for example DC-01’s `{83eb9c06-89b0-6ae8-aa02-0000049e1d00}` corresponds to `13:01:36`, agreeing with `UtcTime=13:01:36.889`.

A naive LogonID check initially encounters earlier activity followed by a Type 7 unlock using the same identifier, or repeated SYSTEM service logons using `0x3e7`. Those are not proof that the session began late. I excluded them rather than counting false ordering failures. I found no activity after a visible 4634 for its matched non-system LogonID in the tested set.

### Network, normalized endpoint and Linux ingestion

Zeek comprises 23,312 conn rows, 4,360 DNS rows, 5,493 HTTP rows, 3,806 SSL rows and associated file/certificate/SMB/SMTP/DHCP records. The conn population includes successful, reset, refused, incomplete and unidirectional traffic. DNS includes A, AAAA, PTR, SRV, TXT, MX, NS and SOA with multiple response codes; answer and TTL array lengths agreed in the checked population. TLS 1.3 uses its corresponding ciphers and abbreviated visible handshake history; TLS 1.2 has full/resumed variants. I found no cipher/version contradiction in those distributions.

For example `zeek-db/conn.json` UID `CejGkF1Vxdvx1XEH8` starts at `1793624609.669453`, with client `10.10.4.10:42023` to proxy `10.10.3.20:8080`. Its HTTP record at `1793624609.745278` is a CONNECT to `security.ubuntu.com:443` receiving 407 and a 753-byte HTML body, with `resp_fuids` referencing the HTTP file record. This is consistent proxy-control-message evidence, not an invented direct HTTPS request.

One `zeek-core/smb_mapping.json` row, line 89, at `1793640924.870598` references UID `CiasUTGUEwayOvoB44`, client `10.10.1.22:57720` to `10.10.2.20:445`, with no supplied conn row. I do not score this as a synthetic indicator: a single absent companion can result from observation or export differences, and no concrete contradictory conn tuple was present. It is an ingestion/reference limitation to retain when testing joins.

The 38,311 eCAR rows include process creation, termination, open/modify, sessions, flows, modules, files, registry and service actions. Full-population identity checks found no visible process actor activity before its visible creation or after its visible termination. This is a check of the identifiers in this normalized export, not certification of every possible eCAR consumer contract.

Linux syslog uses RFC5424-like headers with application, PID and message fields. For example DB-PROD-01 has sudo command logging at `13:05:40.527012Z`, followed by appropriate PAM session events in the source population, while SSH connection/auth/session records use their daemon identities. Recognizable variations include rsyslog queue diagnostics, journald usage, multipathd, irqbalance, dbus activation and polkit messages. I did not require all possible service families or apply Windows or native Mac endpoint expectations to these hosts.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | Native macOS Endpoint Security fork timestamps | Three groups; ten of 102 forks; both Mac hosts | Strongest and only materially scored indicator: distinct observed forks preserve identical microsecond phases over integer-second command gaps, while exec timing varies. Supports a likely-synthetic score, but is not a hard impossibility. |

No hard contradiction or generator identity leak was demonstrated. The lone absent SMB conn reference was not used to inflate the score. Strong correlation was counted as realistic behavior, never as a synthetic tell by itself.

## Realism Score by Category

- **Field format accuracy:** 9 — Structured records parse and sampled native fields are convincing; this is not exhaustive vendor-version certification.
- **Temporal patterns:** 6 — Broad causal order is sound, but repeated precise fork phases on both Macs are a concrete timing artifact.
- **Cross-source correlation:** 9 — Endpoint identities and network protocol tuples agree in tested relationships; one SMB connection reference is unavailable.
- **Behavioral realism:** 9 — Process ancestry, auth mechanisms, proxy failures and varied connection outcomes are operationally plausible.
- **Environmental consistency:** 9 — Windows, Linux and native macOS representations remain distinct and broadly consistent with their visible roles and collection boundaries.

## Recommendations

- If this were synthetic, generate or observe each native fork occurrence with its own plausible subsecond timing rather than reusing an activity anchor’s fractional component for integer-second command offsets. Preserve the existing fork-before-exec ordering, actor thread identity and wall-clock/mach-clock relationship.
- If this were synthetic, add a distribution check for repeated microsecond phases among different child processes over multi-second command groups, especially when following exec times already show variable latency. Test the three cited groups directly without prohibiting ordinary millisecond rounding or genuinely shared-event timestamps.
- If this were synthetic, retain the demonstrated Windows field shapes, source-specific log-clear payload, GUID continuity and network byte/history consistency while repairing the localized timing texture. They are already substantial realism strengths.
