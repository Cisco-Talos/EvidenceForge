# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 80
**Synthetic-Confidence Score:** 38

## Executive Summary

The telemetry is mostly convincing at the parser and correlation layers: native Windows field layouts, scoped process identities, macOS exec transitions, and Zeek connection/protocol relationships survive extensive checks. One macOS executable-metadata chronology is suspicious, but it is localized and potentially explainable by metadata preservation or alteration; I did not establish a dataset-wide generator fingerprint or an impossible visible activity sequence.

## Evidence For Synthetic

- [contract_gap] In `MAC-MROSS-02.meridianhcs.local/macos_endpoint_security.ndjson`, line 1, at `2026-11-02T13:12:07.845472000Z`, the parent process is `/sbin/launchd`, PID 1, pidversion 1, with `start_time=2026-10-06T13:00:00.000000Z`. Its executable has `st_birthtimespec=2026-10-29T09:40:49.455382268Z`, `st_ctimespec` equal to that later value, device 692 and inode 2509863. Thus the file presented as the running launchd executable has a creation time approximately 23 days after that process began. The same PID 1 metadata appears in 11 top-level actor records. This warrants investigation for independently assembled process and file histories. I treat it as a moderate, qualified signal, since birthtime is metadata and alteration/restoration can undermine a literal creation-time interpretation; it is not a demonstrated execution-order impossibility.
- [weak_signal] `zeek-core/smb_mapping.json`, line 93, has UID `C4bqaKVpaYQLPkuTrz` at epoch `1793640924.871449`, with tuple `10.10.1.22:59392 -> 10.10.2.20:445` and share `\\FILE-SRV-01\ClinicalExports`, but no corresponding UID occurs in the supplied connection logs. This is a specific reference-integrity exception inside the connection-log time range, rather than a general complaint about source coverage. An export omission or independently filtered stream could explain it; I did not increase the score for this missing companion by itself.

## Evidence For Real

- All supplied Windows XML files parsed successfully. Across event types, provider identity, channel, task, audit-success/failure keywords, numeric/hexadecimal PID conventions, token/integrity fields and event-specific data layouts were generally credible. Native paths contain single separators; JSON escaping does not leak into the XML values.
- Sysmon process identities remain coherent across creation, use and termination. The automatic visible-window checks found no use before the matching visible creation or use after the matching visible termination for the checked `ProcessGuid`, source GUID and target GUID fields.
- All 37,414 eCAR records parsed as JSON. Checking matching process-object identities and actor identities found no visible termination before creation, actor use before creation, or actor use after termination.
- Zeek contributes 23,141 connection records across three sensors, with no duplicate connection UID within any sensor. For protocol rows with a supplied matching connection, the originator/responder tuples agree and timestamps remain within the transport interval to the tolerance described below.
- The 307 macOS ES records preserve distinct fork, exec and exit observations. In particular, a forked launchd image becomes xpcproxy through an exec transition, with the same PID, a changed pidversion, and the retained original process start time. This is much more source-aware than a flat list of normalized process creations.
- Successful NTLM network logons and their visible logoffs match by host and LogonID. For example, DC-02 has a Type 3 NTLM logon for `diego.ramirez`, ID `0xcb5c02d`, at `13:04:44.0171612Z`, and Type 3 logoff at `13:04:47.0513596Z`; the same source tuple appears in the related share access.
- The data contains realistic variations: failed local authentication, Kerberos preauthentication failures, lock/unlock and reconnect/disconnect records, short and long processes, full and resumed TLS handshakes, TLS attempts that do not establish, proxy authentication responses, and source-specific timestamp precision. These observations support plausibility without making completeness itself evidence either way.

## Detailed Analysis

### Scope and method

I examined only files under the supplied data directory, and read no scenario, ground truth, implementation, evaluation, or earlier assessment. I parsed every Windows XML event, every eCAR row, the Zeek JSON streams and both macOS ES streams; I also inspected representative Unified Log, RFC 5424 syslog, HTTP access, proxy, ASA and IDS records. Checks use record contents rather than filesystem timestamps. Domains were treated as potentially sanitized.

The visible network slice covers approximately six hours on November 2, 2026. Sources include 37,414 eCAR rows, 23,141 Zeek connections, 4,385 DNS rows, 5,547 HTTP rows, 3,668 TLS rows, 2,550 files rows, 1,308 X.509 rows and 307 macOS ES rows. These are counts, not evidence that production must have any particular source volume.

### Event-specific field review

The following examples span more than twenty record types. Times are UTC on November 2 unless stated otherwise. File paths are relative to the supplied data directory.

| Source and event | Concrete fields checked | Finding |
|---|---|---|
| DC-02 Security 4624, 13:04:44.0171612 | Version 2; Type 3; NtLmSsp/NTLM; NTLM V2; key length 128; mapped IPv4 source; hex LogonID | Coherent network NTLM shape. |
| DC-02 Security 4634, 13:04:47.0513596 | Target SID/name/domain, Type 3, `0xcb5c02d` | Matches the visible successful network logon. |
| WS-PPATEL-01 Security 4625, 17:11:56.5878667 | Failure keywords `0x8010000000000000`; status `0xc000006d`; substatus `0xc000006a`; User32; Type 2; no remote IP | Plausible local bad-password record. |
| WS-PPATEL-01 Security 4648, 16:06:00.1349337 | Subject session; alternate `priya.patel-admin`; target DC-01; mmc PID | Event fields support explicit-credential detection. |
| FILE-SRV-01 Security 4656, 13:00:05.9709815 | File object, handle `0xb013d0ff`, mask `0x12019f`, PID `0x4` | Credible audited file handle request. |
| FILE-SRV-01 Security 4663, 13:00:06.1459007 | Same handle/object/session; `AccessMask=0x2`, `AccessList=%%4417` | Consistent write access. |
| FILE-SRV-01 Security 4658, 13:00:09.7044244 | Same handle, owning PID and session | Visible handle close follows access. |
| DC-02 Security 4672, 13:06:22.9288926 | SYSTEM SID/session; newline-separated privilege names | Structurally plausible special-privileges event. |
| DC-02 Security 4688, 13:01:05.9719627 | Version 2; hex new/creator PIDs; WmiPrvSE child; svchost parent; mandatory label | Suitable process-creation shape. |
| DC-02 Security 4689, 13:01:05.1409742 | Exit status `0x0`; terminated PID and spoolsv image | Correct termination field family. |
| DC-02 Security 4697, 17:25:33.2643166 | Service name, executable, type `0x10`, start type 3, LocalSystem | Credible service-installation schema. |
| DC-01 Security 4698, 17:19:47.7438924 | XML TaskContent, task namespace, executable action, trigger, principal | Task data is structurally detailed and internally consistent. |
| DC-01 Security 4720/4724/4738/4728 | Same `svc_dirsync` SID ending 2188; creation at 17:15:05, password reset at :06, change at :08, group addition at :13 | Account/group identity chain is consistent; account flags use the event's native SAM representation. |
| DC-02 Security 4768, 13:22:14.0689810 | krbtgt service, SID ending 502, encryption `0x12`, preauth 2, client IP | Plausible TGT request shape. |
| DC-02 Security 4769, 13:00:27.0756073 | Requester DC-01$, service DC-02$, options `0x40810000`, encryption `0x11` | Machine-account service-ticket shape is plausible. |
| DC-02 Security 4771, 16:00:29.4769631 | Failure `0x18`, preauth 2, krbtgt, client mapped IPv4 | Consistent Kerberos preauthentication failure. |
| DC-02 Security 4776, 13:00:08.9498956 | MICROSOFT_AUTHENTICATION_PACKAGE_V1_0; workstation; machine account; status 0 | Correct NTLM credential-validation field family. |
| DC-02 Security 5140, 13:04:44.0918410 | Same user/session/source port as 4624; SYSVOL; local share path | Correlates to the network logon without tuple drift. |
| DC-02 Security 5156, 13:00:04.6195699 | Decimal PID 5272; NT device path; inbound direction token; UDP 17; DNS port | Native WFP representation is plausible. |
| DC-02 Sysmon 1, 13:01:05.8754957 | Decimal PID 6804 = Security `0x1a94`; WmiPrvSE; parent PID 5116 = `0x13fc`; hashes | Cross-source process identity agrees. |
| DC-02 Sysmon 10/8, 13:03:35 | Source and target process GUID/PID/image; access mask; call trace; new thread start module/function | Access and remote-thread events use their respective field spellings and shapes. |
| DC-02 Sysmon 22, 13:00:48.9197436 | SRV query; status 0; `0 100 88` results | DNS evidence is not forced into address-only results. |
| DC-01 Security 1102, 18:42:20.0702537 | Eventlog provider; level 4; task 104; UserData/LogFileCleared namespace; EventRecordID 1 | Correctly uses UserData rather than ordinary Security EventData. |
| Zeek core DNS/conn UID `CmN2OeyFuu5qT4yxIk` | Same tuple and `ts`; DNS RTT 0.000678 equals UDP duration; 58/86 payload bytes versus 86/114 IP bytes | DNS/transport accounting is coherent. |
| Zeek core DHCP, 13:00:31.176521 | `uids` array; REQUEST/ACK; client/server/assigned addresses; numeric lease time | Transaction shape supports renewals rather than imposing a full discover sequence. |
| macOS ES fork/exec on MAC-MROSS-02, 13:12:07 | PID 88252; pidversion 6461355 to 6461356; launchd to xpcproxy; retained start_time | Credible exec identity transition, subject to the separate PID 1 file-history issue. |

### Correlation and lifecycle checks

For Sysmon I keyed process checks by host and ProcessGuid, rather than by PID alone. For eCAR I keyed by host and objectID/actorID. I found no reversed visible creation/termination relationship in those checks. This does not prove all operating-system lifecycles are captured: pre-window processes and post-window exits remain legitimate.

For Windows sessions, an initial naive join to the last 4624 per LogonID produced false alarms because Type 7 unlocks reuse an existing session identity and well-known SYSTEM/service IDs recur. Excluding those as session initiators and checking against the initial ordinary successful logon removed the apparent pre-logon violations. I do not score those false positives.

For Zeek I verified tuple equality on matching protocol UIDs, and checked for protocol timestamps more than 100 ms before connection start or more than one second after `ts + duration`. No matching protocol rows exceeded those bounds. The one unmatched SMB mapping is explicitly qualified above; its absence does not establish impossible ordering or a collection-profile contradiction.

Hash lengths were also checked programmatically: all 1,036 populated Windows SHA1, MD5 and SHA256 hash groups had their expected lengths, as did all 1,023 populated IMPHASH values. Zeek checks likewise found no wrong lengths among 1,511 MD5, 1,569 SHA1, 1,511 SHA256 and 1,308 certificate fingerprints. No conclusion about actual binary authenticity follows from a valid hash length alone.

### macOS interpretation

The records declare ES message version 11 and include audit-token pidversion, actor/target separation, native file stat data and event-specific payloads. Per-event-type sequence numbers advance independently while global sequence numbers advance across event types. Comparing all recursively embedded process identities found no executable/path/hash/inode conflict for a fixed host/PID/pidversion among 216 distinct process identities, and no conflicting size/mode for the 67 encountered device/inode identities.

The very small Unified Log extract is not evidence of synthetic origin by itself. On MAC-MROSS-01 it includes an ASP policy message at `15:42:09.009673+0000`; I do not infer execution denial or downstream effects solely from that message. ES notifications are not treated as authorization decisions, and native ES rows are not required to contain normalized EDR FLOW fields.

The launchd file birthtime on MAC-MROSS-02 remains the strongest concern. Unlike a missing pre-window initiator, both the process start timestamp and the contradictory-looking file metadata are visible in the same record. However, it is still weaker than a visible fork occurring after a dependent exec, since metadata preservation or deliberate timestamp changes remain possible.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| contract_gap | Native macOS ES process/file metadata | MAC-MROSS-02 PID 1; 11 actor observations | Moderate qualified concern: executable birthtime is about 23 days later than the running process start. Insufficient alone for a firm synthetic verdict. |
| weak_signal | Zeek SMB reference integrity | One mapping UID among 23,141 connection rows | Documented diagnostic exception; no independent score increase, because filtering/export loss can explain it. |

No established hard contradiction, malformed hash population, generator identity leak, or widespread lifecycle inversion was found. The score is below 41 because the inspected data is mostly production-like, with a localized chronology concern rather than multiple strong synthetic defects.

## Realism Score by Category

- **Field format accuracy:** 9 — Windows, Zeek and ES structures parse and expose credible event-specific fields; actual OS manifests and binary content were not independently available.
- **Temporal patterns:** 8 — Visible process and protocol ordering survives checks; the launchd executable birthtime weakens historical consistency.
- **Cross-source correlation:** 9 — Process, session and protocol joins are strong, with one qualified orphan SMB UID.
- **Behavioral realism:** 8 — Varied authentication, administrative, service and network activity; no scored narrative-design assumptions.
- **Environmental consistency:** 8 — Platform-specific paths and identities generally agree; one host's PID 1 process/file history merits verification.

## Recommendations

- If this were synthetic, derive PID 1 process start and executable file-history metadata from a compatible host/boot history. For the MAC-MROSS-02 example, either represent a preexisting launchd executable or provide log-visible context explaining later preserved/altered birth metadata; do not independently randomize those histories.
- If this were synthetic, verify whether the SMB mapping UID `C4bqaKVpaYQLPkuTrz` is intentionally retained without its transport record. Preserve the collection/filtering explanation where available, or retain the matching connection if the intended export is complete for that UID. This is a diagnostic improvement, not a requirement to collect every source.
- Preserve the existing distinctions between local and remote authentication, native ES fork/exec/exit events, UserData-based 1102 records, and transport/protocol identities; these directly support parser behavior and reduce misleading correlation findings.
