# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 92
**Synthetic-Confidence Score:** 75

## Executive Summary

The collection is highly parseable and much of its Windows, Sysmon, eCAR, and Zeek correlation is convincing, but several source-native defects are difficult to reconcile with production telemetry. The strongest indicators are an impossible visible Security 4688 parent/child ordering on FILE-SRV-01 and repeated empty identity/process fields concentrated in network and remote-interactive logon paths.

## Evidence For Synthetic

- [hard_contradiction] In `FILE-SRV-01.meridianhcs.local/windows_event_security.xml`, EventRecordID 273631 at `2024-03-18T17:06:19.6927294Z` creates `userinit.exe` as PID `0x17e8` with creator PID `0x17e4`, but EventRecordID 273632 does not create that parent `winlogon.exe` PID `0x17e4` until `2024-03-18T17:06:19.9159049Z`, 223 ms later. This is a visible same-channel inversion for the exact parent PID; the corresponding Sysmon events show the physically possible order (`winlogon.exe` PID 6116 at `17:06:19.3817720Z`, then `userinit.exe` PID 6120 at `17:06:19.5798457Z`).
- [schema_or_format] Of 872 Event 4624 records, 151 network logons have truly empty `SubjectUserSid`, `SubjectUserName`, `SubjectLogonId`, and `LogonProcessName` values rather than source-native sentinel/identity values. Examples include DC-01 at `2024-03-18T12:06:14.2779266Z` (`aisha.johnson`, Logon ID `0x5380860`) and FILE-SRV-01 at `2024-03-18T14:00:06.9352241Z` (`marcus.chen`, Logon ID `0xf71ba07`); the same 151 records also have an empty `LogonGuid` and `LmPackageName`.
- [contract_gap] The remote-interactive Windows process chains repeatedly lose parent image identity in rendered endpoint sources. Twelve Security 4688 records across DC-01, FILE-SRV-01, and WS-AJOHNSON-01 have empty `ParentProcessName`; for eight child records, Sysmon supplies the exact parent GUID and PID but renders `ParentImage` and `ParentCommandLine` as `-` even though that parent has a visible Event 1. For example, FILE-SRV-01 Sysmon EventRecordID 1644945 creates `userinit.exe` PID 6120 from GUID `{1b54004d-748b-65f8-5002-00002ac79ff7}`/PID 6116 but reports `ParentImage=-`; EventRecordID 1644944 visibly identifies that GUID and PID as `C:\Windows\System32\winlogon.exe`.
- [schema_or_format] Four successful type-10 Event 4624 records have an empty `TargetUserSid` and `LogonGuid`, despite naming known domain users. These occur on DC-01 at `17:09:56.8851662Z`, FILE-SRV-01 at `17:06:19.5077017Z`, and WS-AJOHNSON-01 at `15:00:29.5947752Z` and `15:20:34.8148036Z`. The associated four 4688 `winlogon.exe` records also have empty `SubjectUserSid`, `SubjectUserName`, and `SubjectLogonId`, producing a repeated remote-session rendering fingerprint.
- [distribution_texture] The empty-field defects are not isolated corruption: the exact same all-empty 4624 subject/logon-process shape recurs 151 times across DC-01, DC-02, and FILE-SRV-01, while the same remote-interactive three-process field-loss pattern recurs in four sessions. That family-level repetition is much more suggestive of templated generation than sporadic collection damage.

## Evidence For Real

- All reviewed JSON and XML sources parsed successfully. Windows provider names, channels, versions, tasks, levels, opcodes, keyword masks, timestamp precision, and the normal field sets for the represented Event IDs were generally plausible.
- The process telemetry correlates unusually well in substantive ways: 926 of 930 Security 4688 events had Sysmon Event 1 counterparts, with all 926 Sysmon creates represented and no image mismatches. The observed source-time offsets were bounded at roughly 35–650 ms.
- Visible Sysmon process lifecycles were coherent outside the parent-image defect: no dependent event preceded a visible creation for the same ProcessGuid, no termination preceded its visible creation, and no overlapping visible PID reuse was found.
- Binary identity was internally stable. Across 121 distinct `(Image, FileVersion, OriginalFileName)` groupings in Sysmon Event 1, repeated instances retained identical SHA1, MD5, SHA256, and IMPHASH values; SID-to-account mappings were also stable.
- Windows logon/logoff correlation showed no visible 4634-before-4624 inversion for the same Logon ID. The Security channel's EventRecordID reset at Event 1102 on DC-01 was source-native: Event 1102 used the Eventlog provider, `UserData/LogFileCleared`, and record ID 1.
- Zeek companion integrity was strong without obvious schema breakage: every reviewed DNS, HTTP, and SSL UID resolved to a `conn.json` UID on the same sensor, and none of those protocol records visibly preceded its connection start. Connection states and protocol fields were varied rather than single-valued.
- eCAR records were valid line-delimited JSON, used stable object/action shapes, and preserved useful PID, principal, process UUID, flow tuple, and lifecycle correlations. In the affected remote-session chains, eCAR retained the parent source image even where Security/Sysmon rendering lost it.

## Detailed Analysis

### Windows Security schema and Event ID fidelity

The Security files contained 17,302 events across ten Windows hosts. The dominant types were 5156 (11,579), 4769 (2,094), 4688 (930), 4624 (872), 4768 (800), 4689 (773), 4634 (447), and 4672 (430), with lower-volume 4625, 4648, object-access, share-access, account-management, service-install, scheduled-task, session lock/unlock, and log-clear events.

The normal schemas were credible. Event 4624 used Version 2/Task 12544 and included the extended fields expected from that version; 4688 used Version 2/Task 13312; 5156 used Version 1/Task 12810. Logon types included interactive 2, network 3, service 5, unlock 7, new credentials 9, and remote interactive 10 with generally plausible authentication packages and IP conventions. Failure status/substatus combinations such as `0xc000006d/0xc000006a` and Kerberos `0x18` were credible.

The rendering failures are therefore conspicuous. Empty XML data values are used where Windows normally emits an account/sentinel representation, and the defects cluster by activity family rather than random record damage. The type-3 empty-subject block affects 151 records, while the type-10 path loses target SID and later creator/parent fields in four sessions.

### Process creation, parentage, and cross-source correlation

Security 4688 and Sysmon Event 1 correlated strongly by host, PID, image, and time. All 926 Sysmon process creates matched a Security create within two seconds and had the same image; ProcessGuids were syntactically valid. Hashes used consistent `SHA1,MD5,SHA256,IMPHASH` formatting and remained stable for identical visible binary identities.

The FILE-SRV-01 inversion is nevertheless decisive. The Security record itself claims `userinit.exe` PID `0x17e8` was created by PID `0x17e4`, and then creates PID `0x17e4` as `winlogon.exe` in the next record 223 ms later. This is not a missing pre-window parent or post-window termination. It is an impossible visible order involving the exact linked PID inside one source channel, while Sysmon and eCAR both retain the correct parent-first sequence.

The parent-image omissions form a related contract gap. For the four remote-interactive session chains, Security renders blank parent names for `winlogon.exe`, `userinit.exe`, and `explorer.exe`. Sysmon knows the exact parent ProcessGuid/PID for the child stages yet renders their image and command line as `-`; its own immediately preceding Event 1 identifies those parents. This would weaken parent-based Sigma/Splunk detections and is not explained by the six-hour boundary.

### Timestamp and lifecycle behavior

Windows `SystemTime` values had seven fractional digits; Sysmon `UtcTime` used millisecond precision and was close to provider time. EventRecordIDs were monotonic per file except for the expected DC-01 Security reset at log clearing. No visible Sysmon dependent event or termination preceded creation for the same ProcessGuid, no overlapping PID reuse was observed, and paired Windows logon IDs did not show visible logoff-before-logon inversions.

The single FILE-SRV-01 Security inversion is therefore not part of broad random disorder. It occurs within an otherwise highly ordered set and conflicts with the correct ordering in the other endpoint sources.

### Zeek and eCAR processing behavior

The Zeek JSON records used plausible conn, DNS, HTTP, SSL, X.509, file, SMB, DHCP, SMTP, OCSP, and PE field shapes. Across all three sensors, DNS/HTTP/SSL records had matching connection UIDs and timestamps at or after connection start. TLS versions and cipher suites were plausible, HTTP transaction depths varied, DNS included multiple query/rcode classes, and connection-state distributions included SF, S0, RSTO, RSTR, REJ, OTH, S1, S2, and S3.

The eCAR corpus used parseable JSON and coherent object/action combinations (`PROCESS CREATE/TERMINATE/OPEN`, `FLOW CONNECT`, `USER_SESSION LOGIN/LOGOUT`, and supporting FILE/MODULE/REGISTRY/THREAD/SERVICE records). The correctly populated eCAR parent fields in the remote-interactive chains make the Windows output omissions look like a source-rendering contract defect rather than genuinely unavailable collection data.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `hard_contradiction` | Windows Security 4688 | One exact FILE-SRV-01 process chain | Same-channel child creation visibly precedes creation of its linked parent PID. |
| `schema_or_format` | Windows Security 4624 | 151 repeated type-3 logons on three servers | Core subject, logon-process, and GUID fields are empty rather than source-native values/sentinels. |
| `contract_gap` | Security 4688, Sysmon 1, eCAR PROCESS | Four remote-interactive sessions on three hosts | Endpoint renderers lose parent image identity despite exact visible parent GUID/PID and eCAR ownership. |
| `schema_or_format` | Security 4624/4688 | Four type-10 sessions | Successful logons lose target SID/GUID and their `winlogon.exe` creates lose creator identity. |
| `distribution_texture` | Windows remote/network logon families | Repeated/family-level | Identical missing-field shapes recur by event path rather than as sporadic source loss. |

## Realism Score by Category

- **Field format accuracy:** 6/10 — Most field sets and encodings are strong, but repeated truly empty identity and parent fields are not source-native.
- **Temporal patterns:** 7/10 — Precision and most lifecycle ordering are credible, but the FILE-SRV-01 4688 parent/child inversion is a hard defect.
- **Cross-source correlation:** 8/10 — PID, image, hash, GUID, Logon ID, and Zeek UID correlation is excellent aside from the remote-session parent rendering gap.
- **Behavioral realism:** 8/10 — Process, authentication, service, DNS, TLS, and network behaviors are varied and operationally plausible.
- **Environmental consistency:** 8/10 — Host identities, SIDs, binary hashes, network addresses, and source mixes are broadly consistent.

## Recommendations

- If this were synthetic, enforce parent-before-child ordering independently for every rendered source after source-specific delay is applied. Add a source-local invariant test using the exact creator PID/ProcessGuid relationship, especially for `winlogon.exe -> userinit.exe -> explorer.exe` remote-session chains.
- Render Windows unavailable values with the values Windows actually emits (`S-1-0-0`, `-`, `0x0`, or the all-zero GUID as appropriate) rather than empty XML text. Cover type-3 server logons and type-10 remote-interactive logons with schema fixtures.
- Preserve known parent identity through Security 4688 and Sysmon Event 1 rendering. When a parent GUID/PID is visible and resolves to a process, populate `ParentProcessName`/`ParentImage`/`ParentCommandLine` from that same canonical process identity.
- Require successful domain logons to carry the known target SID, and require synthetic `winlogon.exe` process creates to carry a valid creator subject. Add detection-oriented validation that rejects empty required identity fields before output is accepted.
