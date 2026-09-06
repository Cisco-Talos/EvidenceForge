# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 86
**Synthetic-Confidence Score:** 68

## Executive Summary

The dataset is structurally strong and unusually useful for detection testing, with well-formed source records, credible metadata, and internally coherent process and network identifiers. I nevertheless assess it as synthetic because two repeated Windows logon families contain concrete source-native defects: 151 successful Type 3 logons have partially empty authentication/subject fields and target-owned workstation names, while four Type 10 logons have empty target SIDs that become populated on the matching logoff.

## Evidence For Synthetic

- [hard_contradiction] Four successful Security 4624 Type 10 records have an empty `TargetUserSid`, but the later 4634 for the same host and `TargetLogonId` supplies a concrete SID. Examples include DC-01 at `2024-03-18T17:09:56.8851662Z`, logon ID `0x55df795`, followed by 4634 at `17:59:47.6443615Z` with SID `S-1-5-21-1524654518-2022274387-1755902678-1003`, and FILE-SRV-01 at `17:06:19.5077017Z`, ID `0xf88fcda`, followed by 4634 at `17:59:42.7458552Z` with SID ending `-1007`. The same defect occurs twice on WS-AJOHNSON-01 (`0x26d9655` and `0x2701ac7`).
- [schema_or_format] There are 151 successful 4624 Type 3/Negotiate records whose `SubjectUserSid`, `SubjectUserName`, `SubjectLogonId`, `LogonGuid`, `LogonProcessName`, and `LmPackageName` are empty XML values rather than source-native identities or unavailable-value markers. The defect repeats 47 times on DC-01, 28 on DC-02, and 76 on FILE-SRV-01.
- [hard_contradiction] Those same 151 Type 3 records repeatedly assign `WorkstationName` to the receiving computer rather than the visible source. At `2024-03-18T12:06:14.2779266Z`, DC-01 records source `::ffff:10.10.2.27` but `WorkstationName=DC-01`; at `12:04:06.0678842Z`, FILE-SRV-01 records source `::ffff:10.10.2.11` but `WorkstationName=FILE-SRV-01`. Other records identify those source addresses as MAIL-FIN-01 and DC-02, respectively.
- [contract_gap] The four affected RDP sessions also produce 12 visible `winlogon.exe` → `userinit.exe` → `explorer.exe` process-create chains with missing parent-image identity in both endpoint sources. Security 4688 leaves `ParentProcessName` empty, while the matching Sysmon Event 1 uses `ParentImage=-` even though each parent PID is visible in the immediately preceding create event. On WS-AJOHNSON-01 at `15:00:29.5013547Z` through `15:00:30.0711575Z`, for example, PIDs 5976, 5980, and 5984 form a coherent chain but every Sysmon parent image is `-`.

## Evidence For Real

- All inspected Windows XML files parsed successfully. Security and Sysmon envelopes use credible provider GUIDs, channels, event versions, tasks, levels, opcodes, keyword masks, timestamp precision, and field ordering across the sampled event IDs.
- Sysmon event timestamps behave naturally: across 4,816 inspected records with `UtcTime`, provider `TimeCreated` follows the payload time by roughly 0.156–83.147 ms, with no negative delay. The distribution varies by event family rather than using one fixed offset.
- Sysmon process identity is internally strong. Across all ten Windows hosts, no visible dependent event referenced a `ProcessGuid` before its visible Event 1 create, no dependent event appeared after the matching Event 5 termination, and no GUID-to-PID/image mismatch was found.
- Security 4688, Sysmon Event 1, and eCAR `PROCESS/CREATE` records agree on PID, image, command line, and principal for the correlated records sampled. A small number of one-source omissions are consistent with the stated collection missingness and were not scored.
- Zeek correlation is source-native and consistent. Every inspected UID in `dns.json`, `http.json`, `ssl.json`, `files.json`, `ocsp.json`, `smtp.json`, `smb_mapping.json`, and `smb_files.json` resolved to a `conn.json` record in the same sensor, with no tuple mismatch or protocol event outside the visible connection interval.
- The network schemas show credible variety: Zeek Core contains TCP, UDP, and ICMP; nine connection states; realistic DNS A/AAAA/PTR/SRV/TXT mixtures and failure rcodes; and valid TLS-version/cipher pairings. No impossible response bytes on `S0`/`REJ`, payload-without-packets, or IP-byte-underflow condition was found.
- The Security log-clear sequence on DC-01 is convincing: Event 1102 at `2024-03-18T17:41:59.2606262Z` uses the Eventlog provider's `UserData/LogFileCleared` structure, resets `EventRecordID` to 1, and subsequent records advance from the reset rather than continuing the prior sequence.

## Detailed Analysis

**Windows Security schema and event semantics.** I parsed every Security XML record and grouped System metadata and EventData field sets by Event ID. The common records—4624 v2, 4625 v0, 4634 v0, 4648 v0, 4656/4663 v1, 4688 v2, 4689 v0, 4768/4769 v0, 5140 v0, 5145 v0, and 5156 v1—have stable field order and plausible System metadata. Failure examples also use coherent values: workstation interactive failures pair `Status=0xc000006d`, `SubStatus=0xc000006a`, and `FailureReason=%%2313`, while disabled-account failures pair `SubStatus=0xc0000072` with `%%2307`.

The successful Type 3/Negotiate family is the major exception. A DC-01 record at `2024-03-18T12:06:14.2779266Z` contains `TargetUserName=aisha.johnson`, `TargetLogonId=0x5380860`, source `::ffff:10.10.2.27:56290`, and process `C:\Windows\System32\lsass.exe`, but renders six identity/authentication values as empty tags. It simultaneously uses `SubjectDomainName=MERIDIANHCS` and `WorkstationName=DC-01`, creating a partially populated subject and assigning the target hostname to a remote-source field. This is not an isolated damaged record: the exact pattern recurs 151 times across three receiving hosts.

The RDP family has a smaller but harder identity contradiction. The DC-01 Type 10 logon for Marcus Chen records an empty `TargetUserSid` at `17:09:56.8851662Z`; its same-LUID 4634 later records the expected domain SID. Equivalent SID changes occur on FILE-SRV-01 and in two WS-AJOHNSON-01 sessions. A successful logon can legitimately have an unavailable `LogonGuid`, but an empty XML value is itself non-native compared with a zero GUID or `-`, and the same session's changing target SID cannot be attributed to window truncation or source delay.

**Windows process and Sysmon correlation.** I sampled and programmatically checked Event IDs 1, 3, 5, 7, 8, 10, 11, 13, and 22. Field names, decimal PIDs, braced GUIDs, hash formats, image paths, and timestamp formats are SIEM-friendly. All 4,816 payload timestamps preceded their provider timestamps, and visible GUID lifecycles had no impossible ordering or identity reuse. Cross-source process creates also align closely: for example, WS-AJOHNSON-01 PID 5192 is `SearchProtocolHost.exe` in Security 4688, Sysmon Event 1, and eCAR, with matching command line and SYSTEM ownership.

The RDP child-process records lose parent image information despite retaining correct parent PIDs. At DC-01, Sysmon creates PID 5652 `winlogon.exe`, then PID 5656 `userinit.exe` with parent PID 5652, then PID 5660 `explorer.exe` with parent PID 5656, but every `ParentImage` is `-`; corresponding Security 4688 records leave `ParentProcessName` empty. The same three-row pattern occurs on FILE-SRV-01 and twice on WS-AJOHNSON-01. This would weaken parent-image-based Sigma/Splunk detections even though PID correlation remains possible.

**Zeek and eCAR ingest behavior.** I parsed all JSON lines and validated UIDs, connection tuples, and timing against each sensor's `conn.json`. Core had 10,960 connections, DMZ 7,847, and DB 434; protocol children remained within their visible connection intervals with zero missing UIDs or tuple disagreements. TCP state/payload checks found no `S0`/`REJ` response payload, no payload without packets, and no IP-byte total below payload bytes. TLS 1.3 records use only TLS 1.3 cipher names, while TLS 1.2 records use appropriate ECDHE suites.

The eCAR streams are valid JSON and expose stable object/action vocabulary such as `PROCESS/CREATE`, `PROCESS/TERMINATE`, `FLOW/CONNECT`, `USER_SESSION/LOGIN`, and file actions. Grouping by `objectID` found no visible terminate-before-create, logout-before-login, or duplicate lifecycle for an object. Apparent missing creators at the beginning of the slice and unclosed objects at the end were treated as permitted boundary state, not authenticity defects.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Score impact |
|---|---|---|---|
| `hard_contradiction` | Windows Security 4624/4634 RDP sessions | Four sessions on three hosts | The same logon ID changes from an empty target SID at login to a concrete SID at logoff. |
| `schema_or_format` | Windows Security 4624 Type 3 | 151 records on DC-01, DC-02, and FILE-SRV-01 | Required or conventionally represented identity/authentication values are emitted as empty XML tags in a repeated family template. |
| `hard_contradiction` | Windows Security 4624 Type 3 | Same 151 records | `WorkstationName` repeatedly names the receiver despite a different visible source IP/host. |
| `contract_gap` | Security 4688 and Sysmon Event 1 | Twelve process creates in four RDP chains | Both endpoint projections omit parent image while preserving a visible, resolvable parent PID chain. |

## Realism Score by Category

- **Field format accuracy:** 6/10 — Most schemas and values are strong, but repeated empty 4624 values and absent RDP parent images are material detection-ingest defects.
- **Temporal patterns:** 9/10 — Source timestamps, provider delays, process lifecycles, and Zeek protocol timing show no repeated impossible ordering.
- **Cross-source correlation:** 8/10 — Process, flow, and UID pivots work well; the RDP identity and parent-image projection gaps prevent a higher score.
- **Behavioral realism:** 8/10 — Authentication, process, protocol, failure, and background-event mixtures are varied and technically plausible outside the defective families.
- **Environmental consistency:** 8/10 — Hostnames, IP roles, paths, identities, and services are generally coherent, including mixed Windows/Linux and internal/external traffic.

## Recommendations

- If this were synthetic, populate successful 4624 Type 3 subject and authentication fields using native unavailable markers only where Windows truly would not provide a value. Derive `WorkstationName` from the initiating endpoint when available; otherwise emit the native unavailable marker rather than the receiver hostname.
- If this were synthetic, make the target SID immutable across each logon lifecycle. A successful Type 10 4624 and its matching 4634 should render the same domain SID, and unavailable GUID values should use the source-native zero GUID or `-` representation rather than empty XML.
- If this were synthetic, carry the already visible parent process image into both Security 4688 `ParentProcessName` and Sysmon Event 1 `ParentImage` for RDP-created `userinit.exe` and `explorer.exe`. Preserve `-` only when the parent genuinely cannot be resolved.
