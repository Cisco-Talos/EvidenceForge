# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 78
**Synthetic-Confidence Score:** 28

## Executive Summary

The inspected records are mostly production-like and would support ordinary SIEM parsing and correlation. I found no demonstrated impossible ordering or source-native contradiction in the bounded checks; the principal reservation is a small, repetitive macOS command vocabulary, which is also compatible with administrative or diagnostic activity and cannot establish provenance.

## Evidence For Synthetic

- [weak_signal] Repeated macOS version discovery is conspicuous in the small visible execution sample: `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson` contains five `/usr/bin/sw_vers` executions among 58 exec notifications, and the corresponding `MAC-MROSS-02` file contains six among 59. Examples are host 01 lines 12, 30, 64, 114 and 133, and host 02 lines 12, 33, 65, 92, 96 and 125. Bare invocation and `-productVersion` recur over several hours. A bounded command pool could produce this texture, but legitimate repeated diagnostics could too; this carries little weight.
- No high-impact synthetic indicator was verified. In particular, the source counts and selected collection scope do not independently justify an absence-based finding.

## Evidence For Real

- Windows Security and Sysmon have credible distinct source metadata and representations: Security 4688 version 2 uses hexadecimal process identifiers and token/mandatory-label fields, while Sysmon 1 version 5 uses decimal PID, ProcessGuid, hashes, parent identity and millisecond UtcTime. On `WS-AJOHNSON-01`, Security record 129949 and Sysmon record 30297 identify the same `taskhostw.exe` process, PID 5204 / `0x1454`, with source-native timestamp differences.
- A visible session pair on `WS-AJOHNSON-01` preserves user, logon type and LogonID: Security records 130339 and 130342 describe `aisha.johnson`, type 3, `0x267372a`, from `15:09:53.9137773Z` to `15:10:45.0863285Z` on 2026-11-02. DC-01 records 28245643 and 28245662 similarly pair `MAIL-FIN-01$`, type 3, `0x5386f6a`.
- Zeek SMB evidence preserves transport direction and byte feasibility. `zeek-core/conn.json` line 8, UID `CHobQaXTd62NpmDvAm`, is `10.10.1.21:37130` to `10.10.2.21:445`, with 5,361,807 responder payload bytes. `files.json` line 1 reports a 5,359,834-byte responder-to-originator file with the same connection UID, which fits inside that transport.
- macOS native notifications distinguish fork actor, exec actor and exec target. On MAC-MROSS-01, ES lines 1–3 retain PID 42169 while pidversion advances 10 → 11 → 12 through launchd-forked child, xpcproxy exec, and Terminal exec. This is substantially more plausible than assigning a new process identity indiscriminately to every executable image.
- DC-01's Security 1102 is rendered with the Windows Eventlog provider and `UserData/LogFileCleared` in its own namespace, rather than the Security-Auditing provider and generic EventData. Its EventRecordID is 1. This is a meaningful source-native distinction.

## Detailed Analysis

### Scope and method

I inspected only the supplied data directory. This was a bounded review: detailed representative records across Security 4624, 4625, 4634, 4648, 4672, 4688, 4768, 4769, 5140, 5156, 4697, 4698 and 1102; Sysmon 1, 3, 5, 7, 8, 10, 11, 13 and 22; macOS fork/exec/exit notifications and Unified Log examples; Linux syslog/eCAR examples; and representative Zeek protocol/file records. Reading a type is not equivalent to validating every optional field or every OS release's schema. I did not consult external documentation or infer authenticity from file modification times, domain resolution, or project metadata.

For targeted structural checks I parsed both macOS ES files (152 and 151 records), the WS-AJOHNSON-01 Sysmon file, Security session events on WS-AJOHNSON-01 and DC-01, and the zeek-core connection index. Protocol cross-checks were limited to the first 200 records per family: DNS 200, SSL 200, HTTP 200, SMB mappings 106 and SMB files 183. File-byte checks were limited to the first 200 files records. These limits should not be read as exhaustive validation of the collection.

### Windows source shape and identity

The representative Security 4624 record 130012 on WS-AJOHNSON-01 is a type 5 LOCAL SERVICE logon with SID `S-1-5-19`, LogonID `0x3e5`, `Advapi`, `Negotiate`, services.exe caller and absent network address/port. The following 4672 record 130013 preserves that account and LogonID. The first sampled failed interactive logon, record 130170 at `14:18:19.8218782Z`, has type 2, User32, winlogon.exe and no remote IP: the failure status/substatus are `0xc000006d` / `0xc000006a`. These fields are mutually coherent.

DC-01 Kerberos examples distinguish TGT and service ticket evidence: record 28245437 is 4768 for `DC-02$`, service `krbtgt`, PreAuthType 2; record 28245366 is 4769 for `FILE-LNX-01$`, service `DC-01$`. Both use IPv4-mapped client addresses, successful status and AES encryption code `0x12`. I do not require a fresh visible TGT before every service ticket because cached/pre-window tickets are possible.

The WS-AJOHNSON-01 process pair is reproducible at Security XML line 56 (record 129949), Sysmon XML line 44 (record 30297), and Sysmon XML line 89 (record 30298). Sysmon creation UtcTime is `13:06:37.575` and termination UtcTime is `13:06:53.073`; both use ProcessGuid `{fd907e59-8add-6ae8-0702-000094a4144b}`, PID 5204 and taskhostw.exe. The Security creation timestamp is `13:06:37.6251808Z`; this small inter-source difference is plausible.

The targeted Sysmon check found no event carrying a ProcessGuid after its visible termination in this host file. Grouping Security 4624/4634 records by TargetLogonId on the two checked hosts found no account changes within an ID or visible logoff-before-later-logon conflict. Repeated type 7 unlock entries on the existing interactive session were not treated as duplicate fresh sessions. Missing pre-window creation and post-window closure were neutral.

The scheduled task record 28257120 on DC-01 contains escaped Task Scheduler XML, task URI `\Microsoft\Windows\Maintenance\DeviceSync`, service-account principal and an hourly TimeTrigger. The 1102 event at `18:42:31.1287936Z` has the Eventlog provider, Level 4, Task 104 and namespaced LogFileCleared payload (EventRecordID 1, XML line 260264). These details would matter to parsers that distinguish EventData and UserData.

### Zeek protocol and accounting checks

In the bounded protocol samples, every tested UID existed in conn.json, and all four endpoint fields agreed with its connection. No sampled protocol timestamp preceded transport open by more than 10 ms or exceeded the recorded connection interval by more than 100 ms. Those tolerances allow small source-rendering differences; they do not prove all records are correctly ordered.

The SMB example begins at epoch `1793624460.195223`, mapping at `1793624460.294981`, file open at `1793624460.515653`, and files observation at `1793624460.716762`; the connection duration is 1.549823 seconds. Transport, mapping and file direction fit together. None of the first 200 files records exceeded the available payload bytes of their referenced conn records in the selected direction. This is a useful contradiction test, though it does not validate packet captures or every accounting field.

The first DNS example uses numeric qtype 1 / name A, successful response, answers and corresponding TTL array. The first DHCP record uses an array of UIDs and a REQUEST/ACK pair, rather than the per-connection UID scalar used by other Zeek families. JSON decoding succeeded in the checked samples.

### macOS semantics and limitations

Both ES files declare message version 11 and expose audit tokens, executable file metadata, actor/target distinction, signing metadata and event-specific fork/exec/exit payloads. Checking `(pid, pidversion)` found no observed actor after its own exit and no executable path change within the same checked identity. This is a bounded identity-consistency result, not certification against every field in the version 11 SDK.

MAC-MROSS-01's three Unified Log records use a logEvent shape, UTC offsets, process/sender paths and UUIDs. Line 2 attributes an AppleSystemPolicy message to the kernel/extension writer; it says policy *would not allow* MeetingAssist. I do not infer an actual denied execution, child process, or successful effect from that wording alone. Line 3 attributes an accepted SSH public key message to sshd-session at `16:02:23.591596+0000`, with source `10.10.1.42:52550`.

The only scored reservation is the repeated `sw_vers` texture. For example MAC-MROSS-01 invokes it at `13:08:08.585566Z`, `13:30:38.081934Z`, `15:16:00.015447Z`, `16:42:25.147167Z` and `17:39:08.414427Z`. The intervals vary; there is no demonstrated fixed cadence. Both machines belong to the same named user, which further weakens their independence as evidence of templating. I found no hard contradiction in these records.

### Linux and peripheral parsing

Representative APP-INT-01 syslog uses RFC5424-style records with host, application and process identifiers. The initial CRON message references PID 2931365 and sysstat's debian-sa1 task; eCAR begins with corresponding shell process creation and its debian-sa1 child, followed by child termination. Windows-like hexadecimal logon identifiers in normalized Linux eCAR are not by themselves native Linux schema defects.

Sample ASA lines distinguish inbound TCP connections and mapped DMZ addresses, Snort fast alerts include GID:SID:revision and protocol tuples, and proxy CONNECT lines explicitly distinguish control-message bytes from tunnel bytes. I did not validate every vendor signature or configuration-specific access-log extension.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| weak_signal | macOS Endpoint Security exec | Eleven sw_vers executions among 117 exec observations on two machines for the same user | Small reservation about repeated command vocabulary; compatible with genuine diagnostics, insufficient for a synthetic verdict |

No hard_contradiction, contract_gap, or demonstrated schema_or_format defect was established by the bounded checks. The score reflects mostly realistic inspected telemetry with limited provenance certainty; it is not my confidence that the dataset is synthetic.

## Realism Score by Category

- **Field format accuracy:** 9 — Representative XML/JSON/syslog records have credible source-specific shapes, identifiers and metadata; optional/version-specific fields were not exhaustively certified.
- **Temporal patterns:** 9 — Checked process/session and protocol lifecycles have plausible ordering and varied timestamps.
- **Cross-source correlation:** 9 — Bounded UID/tuple and process/session checks agreed; file bytes fit transport capacity.
- **Behavioral realism:** 8 — Mixed service, user, authentication and network activity is plausible; repeated macOS version checks leave a weak vocabulary concern.
- **Environmental consistency:** 9 — Checked Windows, Linux and macOS evidence respects the visible platform and native-versus-normalized source distinctions.

## Recommendations

- If this were synthetic, review the concentration of `sw_vers` executions in the two macOS ES files against the intended user/admin workflow. Retain repetitions if they represent a specific diagnostic practice; otherwise broaden the underlying legitimate activities rather than changing timestamps merely to disguise repetition.
- Preserve the observed source-specific identity and byte-accounting relationships. The bounded review found no concrete defect that warrants changing collection coverage, adding arbitrary missing event families, or altering lifecycle timing.
