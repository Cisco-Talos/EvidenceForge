# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 83
**Synthetic-Confidence Score:** 64

## Executive Summary

The supplied logs are broadly usable by a detection stack: XML/JSON parsing, common Windows event shapes, process identities, and the tested Zeek joins are convincing. My synthetic verdict rests primarily on a narrowly scoped but concrete inconsistency inside an account-change audit record, with a repeated nonstandard Defender executable placement as supporting evidence; it does not rest on attack completeness, source completeness, or thin macOS coverage.

## Evidence For Synthetic

- [hard_contradiction] `DC-01.meridianhcs.local/windows_event_security.xml:188859`, Event 4738, record 28256928, at `2026-11-02T17:15:15.7635027Z`, reports `OldUacValue=0x15` and `NewUacValue=0x10` (lines 188903–188904), but its entire `UserAccountControl` change list is one token, `%%2081` (188905–188906). The numeric SAM flags clear **two** independently meaningful bits, `0x1` (account disabled) and `0x4` (password not required). The native event's change-description field should enumerate those changes. This is a source-local semantic inconsistency that can cause rules using the description field to disagree with rules decoding the numeric delta. The numeric values are SAM flags, not LDAP `userAccountControl` values; that distinction is incorporated in this finding. [Microsoft's 4738 specification](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4738) describes a separate description for each change, and its example clearing the same password-not-required bit includes `%%2050`, which is absent here. [MS-SAMR defines the two flags](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/b10cfda1-f24f-441b-8f43-80cb93e786ec).
- [environment_or_collection_plausibility] Nine distinct Windows hosts execute `C:\Windows\System32\MpCmdRun.exe -SignatureUpdate`. Examples are `DC-01.../windows_event_sysmon.xml:825` at `13:02:57.886` (PID 3704), `FILE-SRV-01.../windows_event_sysmon.xml:618` at `13:10:28.460` (PID 4904), and `WS-AJOHNSON-01.../windows_event_sysmon.xml:4769` at `14:39:07.640` (PID 5340), all on November 2. This is inconsistent with the documented normal installation locations in Program Files or the versioned ProgramData Defender platform directory. Copying the tool to System32 is possible, so this is supporting environmental evidence, not an impossible execution. Its recurrence on nine hosts makes a shared path-assumption error plausible. [Microsoft documents the standard locations](https://learn.microsoft.com/en-us/defender-endpoint/command-line-arguments-microsoft-defender-antivirus).

## Evidence For Real

- Windows source records use coherent native conventions: Security events have Level 0 and appropriate success/failure keyword masks, hexadecimal process/logon IDs, the Security-Auditing provider identity, and event-specific field names. Sysmon records use a separate provider/channel, decimal PIDs, process GUIDs, millisecond `UtcTime`, and finer `SystemTime` precision.
- A visible successful network logon closes with the same identity: DC-01 Security Event 4624 at `13:07:15.9751026Z`, record 28245503 (`windows_event_security.xml:2866`), is `MAIL-FIN-01$`, type 3, `TargetLogonId=0x5382af7`; Event 4634 at `13:07:19.0025931Z`, record 28245507 (line 3001), uses the same logon ID, account, SID, and type.
- Full scans of the supplied Sysmon files found no event bearing a `ProcessGuid` after that GUID's visible Event 5 termination, no duplicate visible Event 1 creation for the same GUID, and no tested same-GUID event timestamp preceding its visible Event 1. These checks are evidence of usable lifecycle relationships, not proof of authenticity.
- The common process-creation fields matched between Security 4688 and Sysmon 1 on each host for matched PIDs: image, parent image, and command line. Matching coverage itself is neutral, but no contradiction emerged from this test.
- Zeek has diverse transport outcomes, including resets, rejects, incomplete attempts, midstream observations, packet gaps, UDP traffic, and ICMP. For example, the 12,382 core connection records include TCP SF 4,894; TCP S0 1,465; TCP RSTO 171; TCP RSTR 106; UDP SF 4,971; and ICMP OTH 398. This is more plausible than uniformly successful transport.
- macOS ES rows distinguish the pre-exec actor from the exec target and increment PID version across exec without pretending it is a fork. For MAC-MROSS-01, lines 1–3 show PID 42154 progress from launchd's forked image (pidversion 10), to xpcproxy (11), to Terminal (12), with the target principal/audit session changing at the application transition.
- Linux log records carry plausible RFC 5424 envelopes and source-specific message vocabulary, including PAM/session messages, sudo denials, systemd-logind, cron, resolver downgrade messages, and UFW blocks. Their presence and variability support realism, although they cannot independently establish origin.

## Detailed Analysis

### Input provenance and method

I read the neutral reviewer briefing and files under `/private/tmp/log-study-vn4mfwps/data` only, and used system `python3` with `/private/tmp` as the explicit working directory. I did not access repository code, authored scenarios, previous assessments, sibling reports, or project pages. Inherited generic operating instructions were not treated as evidence of origin. External verification used official Apple, Microsoft, and Zeek documentation with actual domain-restricted searches/direct official links.

I parsed all 20 Windows XML files: 19,411 Security records and 12,058 Sysmon records. I also parsed all 37,394 eCAR records and the three Zeek connection sets (22,509 total rows), with their supplied HTTP, DNS, SSL, SMTP, and SMB companions. Both native macOS ES files contain 299 total records (119 and 180); I inspected their process identities, lifecycle ordering, and same-inode executable metadata. I sampled Linux syslog and shell-history files as an additional platform/collection check. I did not attempt an exhaustive vendor manifest validation of every field in every event version.

Citations below are relative to the supplied data root. XML line numbers identify the opening Event unless a field line is given; JSON/NDJSON line numbers identify individual records.

### Windows schema and event spot checks

The following checks cover more than twenty event types and include actual field-level examination rather than only event counts:

| File / line | Record examined | Result |
|---|---|---|
| `DC-01.../windows_event_security.xml:3` | 5156, `13:00:07.5257163Z` | Version 1; decimal `ProcessID=2420`; device path to dns.exe; inbound UDP/53 tuple; resource-coded Direction and LayerName. No demonstrated format defect. |
| Same file, 167 | 4769, `13:00:54.3867357Z` | Computer-account requester, DC service account, AES type `0x12`, IPv4-mapped source address, hexadecimal options/status. Plausible version-0 ticket schema. |
| Same file, 368 | 4768, `13:01:28.2103308Z` | krbtgt service and RID 502; PreAuthType 2; mapped IPv4 address; empty certificate fields for password preauthentication. Plausible. |
| Same file, 1023 | 4688, `13:02:58.1951694Z` | Version 2, `NewProcessId=0xe78` (3704), parent `0x91c` (2332), SYSTEM subject, integrity SID, and target-account placeholders. Schema plausible; executable placement discussed separately. |
| Same file, 1107 | 4689, `13:03:10.9108534Z` | Matching process PID `0xe78`, image, and SYSTEM context; positive lifetime. |
| Same file, 2866 / 3001 | 4624 / 4634 | Matching network logon identity `0x5382af7`, type 3; positive lifetime of about 3.03 seconds. |
| Same file, 3483 | 4776 | `MICROSOFT_AUTHENTICATION_PACKAGE_V1_0`, workstation and username fields, status `0x0`; native NTLM credential-validation shape. |
| Same file, 12952 | 4779 | `AccountName`, `AccountDomain`, exact field name `LogonID`, `RDP-Tcp#5`, and ClientAddress present; Task 12551 matches the [documented event](https://learn.microsoft.com/ja-jp/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4779). |
| Same file, 13935 | 4672 | NETWORK SERVICE SID `S-1-5-20`, logon `0x3e4`, multiline privilege list. Plausible service-token audit. |
| Same file, 19445 | 5140 | NETLOGON share, SYSVOL scripts local path, network source and logon subject present. Plausible. |
| Same file, 21007 | 4648 | Explicit credentials distinguish SYSTEM caller from `svc_backup` target credentials; Veeam process identity and server name provided. |
| Same file, 178472 | 4697 | PSEXESVC, service type `0x10`, demand start `3`, LocalSystem service account; native service-install fields. |
| Same file, 188680 | 4720 | `svc_dirsync`, SID ending 9975, primary group 513, Old/New SAM flags `0x0 -> 0x15`; structure matches a new-account audit. |
| Same file, 188823 | 4724 | Same target SID/account; distinct successful password-reset audit. |
| Same file, 188859 | 4738 | Numeric delta and one-token change list disagree; principal synthetic finding. |
| Same file, 188984 | 4728 | Member DN/SID versus Domain Admins group SID ending 512 are distinguished correctly. |
| Same file, 192482 | 4698 | Embedded TaskContent decodes as XML with task namespace, trigger, principal, settings, and executable action. |
| `DC-02.../windows_event_security.xml:123501` | 4771 | Failure keyword mask `0x8010000000000000`, status `0x18`, PreAuthType 2, source endpoint; failure semantics coherent. |
| `FILE-SRV-01.../windows_event_security.xml:97/146/199/240` | 5145 / 4656 / 4663 / 4658 | Same subject/logon, file path and handle `0x8a164b99`; request, access, then handle close. `4663 AccessMask=0x2` and `%%4417` agree as write-data. |
| `MAIL-FIN-01.../windows_event_security.xml:9599` | 4625 | Disabled-account SubStatus `0xc0000072`, failure audit mask, NTLM network logon, IPv4-mapped address. |
| `WS-AJOHNSON-01.../windows_event_security.xml:24918/26199` | 4800 / 4801 | Same account, logon ID `0x25f0cdc`, and SessionId 2; unlock follows lock. |

The ellipsis in the table abbreviates `.meridianhcs.local`, not an unspecified host.

Sysmon spot checks on DC-01 included Events 3 (line 3), 22 (603), 1 (825), 5 (910), 10 (2592), 7 (12991), 8 (69435), 11 (110953), and 13 (114620). The sources distinguish `SourceProcessGUID`/`TargetProcessGUID` in ProcessAccess from other event-specific spellings and carry appropriate network, DNS, file, and registry fields. The 1/5 pair for GUID `{83eb9c06-8a01-6ae8-3302-00109ba9a3f2}` has creation `13:02:57.886`, termination `13:03:10.683`, PID 3704, and the same image.

Hash-format checks found 1,114 each of Sysmon SHA1/MD5/SHA256 values, all at their required 40/32/64 hexadecimal lengths, and 1,105 IMPHASH values at 32 characters. No field-width defect was found. File hashes remained stable per image path within each host in the examined Event 1/7 data. Version/resource metadata is populated for most binaries: 921 of 1,001 Event 1 records have at least one of FileVersion/Description/Product/Company/OriginalFileName beyond `-`. I therefore do not claim a blanket missing-metadata fingerprint.

### Why the account-change inconsistency matters

The important record is a single native Windows audit event, so observation gaps or collection-window boundaries cannot explain its own fields disagreeing. With SAM flags:

`0x15 = 0x10 | 0x4 | 0x1`

`0x10 = USER_NORMAL_ACCOUNT`

The transition removes both disabled-account and password-not-required flags. The event instead gives only `%%2081`. I do not need to infer any earlier unseen account state: OldUacValue and NewUacValue explicitly supply both sides. The [official 4738 definition](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4738) and [SAMR flag table](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/b10cfda1-f24f-441b-8f43-80cb93e786ec) establish the mismatch. This finding has substantially more weight than the Defender path anomaly.

### Network schema and correlation

I joined protocol records to conn records within each sensor, retaining sensor-local UID identity. All 4,713 HTTP, 4,196 DNS, 3,041 SSL and 79 SMTP records have matching conn UIDs and matching four-tuples. None of those records precedes its connection start by more than 1 ms or exceeds connection end by more than a 200 ms allowance in this check. HTTP request/response body lengths do not exceed their corresponding transport payload byte counts.

For example, core `conn.json:1` and `dns.json:1` share UID `C811ndvH4HplPDAtP9L`, timestamp `1793624402.512987`, and `10.10.1.31:57900 -> 10.10.2.11:53/udp`. Its SRV query, answer names, and TTL arrays are structured appropriately. Core `http.json:1` uses UID `C4XPc6ui6FdF9H8H3Z` found at `conn.json:3`; CONNECT host/URI, status 200, and zero HTTP body lengths are plausible for a tunnel rather than a claim that the complete encrypted exchange had no payload.

Core SMB has two records (lines 153–154) for UID `Cr7mRCkac27kS4mWeXo` without a supplied conn row. I do **not** score that absence: the connection could close beyond the slice, and the briefing explicitly makes window-edge absence neutral. Likewise, low-level byte counts smaller than sequence-derived payload plus all nominal headers occur only with nonzero missed bytes in the checks; the [Zeek specification](https://docs.zeek.org/en/current/scripts/base/protocols/conn/main.zeek.html) explains that TCP payload counts derive from sequence numbers, whereas IP bytes reflect observed packets. Treating that as an impossible accounting error would be incorrect.

All checked Zeek hash fields had correct widths: 1,451 MD5, 1,493 SHA1, 1,451 SHA256, and 1,303 certificate fingerprints. TLS certificates use separate key and signature algorithm fields, so an EC leaf with an RSA issuer signature is not itself contradictory.

### macOS and Linux interpretation

MAC-MROSS-01 and MAC-MROSS-02 contain native-style ES notifications for fork/exec/exit, with declared message version 11, and a separate sparse Unified Log export. They are not interchangeable with the normalized eCAR FLOW rows. I found no reuse of an exited `(pid,pidversion)` actor, no actor start time after its own message time, and no conflicting path/size/cdhash values for one `(st_dev,st_ino)` executable identity in these ES files.

The ES process and exec-target layout broadly accords with [Apple's es_process_t](https://developer.apple.com/documentation/endpointsecurity/es_process_t?language=objc) and [es_event_exec_t](https://developer.apple.com/documentation/endpointsecurity/es_event_exec_t?language=o_9) descriptions. I do not claim complete v11 serializer conformance from these checks, and do not score unfamiliar export extensions as defects. In particular, the `action_type=1` notifications are observations, not independent proof that an authorization policy denied execution. MAC-MROSS-01 Unified Log line 2 says the policy **would not allow** MeetingAssist; I do not convert that text alone into a proven denial and then allege impossible later execution.

APP-INT-01 syslog lines 3–6 show one SSH daemon PID 2931388 receiving a connection from `10.10.1.35:65202`, accepting public-key authentication, opening PAM session, then logind session 376068. Lines 8–9 close an older, different daemon PID/session; that is compatible with a pre-window login and was not scored as an orphan. WEB-EXT-01 line 3 records a sudo command denial; I found no matching eCAR execution/child under that denied sudo PID in the explicit search, so I do not allege a denial/effect contradiction.

All eCAR records parsed as JSON and their top-level `id` values parsed as UUIDs. The mix includes FLOW/CONNECT 27,630; PROCESS/CREATE 2,294; PROCESS/TERMINATE 2,108; USER_SESSION/LOGIN 985; and USER_SESSION/LOGOUT 530. Those different counts are not automatically lifecycle defects because of collection boundaries and source scope. eCAR object identifiers also carry object-specific semantics; they should not all be required to be UUIDs merely because the record `id` is one.

### Calibration and limits

The data passes many meaningful consistency checks. One narrowly localized account-audit defect plus a repeated path anomaly supports a likely-synthetic assessment, but does not justify a claim of dataset-wide broken telemetry or an 81–100 score. Sanitization or an intervening custom exporter could conceivably alter the change-description field, and environment-specific packaging could explain System32 placement. These alternatives lower verdict confidence from certainty. Neither normal benign command repetition nor complete source joins was used as a negative indicator.

## Synthetic Indicator Summary

| Category | Source family | Scope | Effect on synthetic-confidence score |
|---|---|---|---|
| hard_contradiction | Windows Security 4738 | One visible account-change record, DC-01 record 28256928 | Primary driver: numeric flags describe two cleared states but the native change list contains one unrelated/incomplete token; rules can disagree on the same event. |
| environment_or_collection_plausibility | Windows process telemetry, Security 4688 and Sysmon 1 | System32 MpCmdRun placement on nine Windows hosts | Supporting, limited weight: repeated nonstandard executable placement suggests an environment model assumption; custom deployment remains possible. |

## Realism Score by Category

- **Field format accuracy:** 8 — Common event schemas, PID formats, hashes, JSON/XML, and native timestamps are convincing; 4738 semantic field consistency fails in one significant case.
- **Temporal patterns:** 9 — Tested visible lifecycles and protocol intervals are coherent, with varied transport outcomes and plausible source-specific timing.
- **Cross-source correlation:** 9 — Tested process and network joins agree; no broad correlation failure was demonstrated.
- **Behavioral realism:** 8 — Plausible platform-specific processes, authentication and background activity; repeated nonstandard Defender executable placement lowers confidence.
- **Environmental consistency:** 8 — Mostly coherent mixed-platform estate, with the System32 Defender utility pattern as the clearest environmental concern.

## Recommendations

- If this were synthetic, derive all 4738 change-description tokens from the actual old/new **SAM** flag delta, ensuring the same record accurately describes each changed flag. For the visible `0x15 -> 0x10` transition, include both account-enable and password-required changes, using the correct native message resources; validate descriptions against numeric fields rather than only checking that fields exist.
- If this were synthetic, place MpCmdRun in a documented Defender installation directory matching the host's platform version and update the canonical process identity consistently across 4688, Sysmon, and normalized endpoint records. If System32 placement is intentional, the environmental evidence should reflect the custom deployed executable rather than treating that location as a default Microsoft installation.
- Preserve the positive properties already demonstrated: source-specific ID and timestamp formats, scoped process identities, honest packet-loss accounting, distinction between native ES and normalized EDR, and window-aware lifecycle interpretation. No recommendation to add arbitrary missing source families follows from this review.
