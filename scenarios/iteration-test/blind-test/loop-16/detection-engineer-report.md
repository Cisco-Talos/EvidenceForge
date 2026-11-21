# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 79
**Synthetic-Confidence Score:** 44

## Executive Summary

The supplied telemetry has strong parser compatibility, plausible source-native fields, and substantial identity and lifecycle consistency across Windows, Linux, macOS, endpoint, and network records. The main concern is a systematic authentication-evidence gap: 114 of 121 successful domain-account NTLM logons have no matching successful 4776 anywhere in the supplied Windows logs, despite visible collection of that event family on both domain controllers. This raises a bounded concern about synthetic construction, but unknown filtering or collection scope prevents treating it as a demonstrated impossibility or issuing a confident synthetic verdict.

## Evidence For Synthetic

- [contract_gap] **Successful domain-account NTLM logons frequently lack visible credential validation.** Across the ten Security XML files, 121 events have `EventID=4624`, `AuthenticationPackageName=NTLM`, and a domain-account `TargetUserSid` beginning `S-1-5-21-`. Only seven have a successful 4776 with matching account and source workstation anywhere in the supplied logs; all seven also occur within 60 seconds. The other 114 are concentrated on FILE-SRV-01 (52), DC-02 (34), and DC-01 (28). For example, DC-02 `windows_event_security.xml`, record 25377533 at `2026-11-02T13:04:44.0168727Z`, authenticates `MERIDIANHCS\diego.ramirez` from `WS-DRAMIREZ-01` / `::ffff:10.10.1.34` using `NtLmSsp`, `NTLM V2`, LogonType 3, and TargetLogonId `0xcb5c02d`; neither DC has a successful 4776 for that user/workstation pair anywhere in the slice. The concern is mechanism-specific companion coverage within an event family that is collected, not the absence of a desirable additional source. An account-aware export filter, another authenticating DC outside the supplied set, or selective collection could explain it, so this finding receives moderate weight rather than hard-contradiction weight.
- [weak_signal] **The NTLM companion gap coincides with a field-population partition.** Of those 121 successful domain-account NTLM logons, all 108 with a nonzero `LogonGuid` lack a matching successful 4776; the seven matched cases all have a zero GUID, and six additional zero-GUID cases lack validation. For comparison, WS-DRAMIREZ-01 record 235885 at `13:13:10.5499153Z` has a zero GUID and is preceded by DC-02 record 25377768 at `13:13:10.4730897Z`, validating `diego.ramirez` from `WS-EBROOKS-01`. This partition suggests two differently constructed authentication paths, but it could also reflect different real applications or export policies. I do not assert that nonzero NTLM logon GUIDs are inherently impossible, and I do not count this as an independent major defect.

## Evidence For Real

- The 20 Windows XML files parse successfully, containing 17,454 Security and 11,378 Sysmon events. Source-specific provider/channel differences and fields survive export rather than being flattened into one generic event schema.
- DC-02 records 25377533, 25377534, and 25377537 form a plausible logon/share-access/logoff sequence at `13:04:44.0168727Z`, `13:04:44.0918417Z`, and `13:04:48.2582990Z`, sharing user SID and LogonId `0xcb5c02d`. Across the supplied Security files, 373 logoffs have visible matching logons with consistent account SID, account name, and logon type, and none of those matched closures precedes its logon.
- Sysmon process identities are coherent: no observed ProcessGuid maps to conflicting PID/image pairs, including source/target process-reference fields. Referenced Sysmon activity does not precede a visible creation or follow a visible termination for the same host and GUID in the checks performed.
- Hash fields have valid widths throughout the parsed Sysmon records: 991 SHA1 values of 40 hexadecimal characters, 991 MD5 values of 32, 991 SHA256 values of 64, and 980 IMPHASH values of 32. The observed MD5-to-SHA256 and SHA1-to-SHA256 mappings do not show conflicting hash tuples.
- In 47 Linux SSH `Accepted` records checked against the receiving host's normalized endpoint telemetry, the matching inbound TCP/22 FLOW observation occurs before acceptance. For example, DB-PROD-01 receives the flow from `10.10.1.31:51676` at endpoint timestamp `1793627116308` ms, before syslog acceptance at `13:45:25.194983Z`.
- Zeek records contain realistic successful, rejected, reset, unanswered, partial, and ICMP connection states. The checked protocol rows preserve connection tuples, and packet/IP-byte totals satisfy basic payload-plus-IP-header lower bounds.
- macOS ES records distinguish fork, exec, and exit and carry version 11 messages, audit-token PID versions, parent/responsible tokens, signing identity, file metadata, and source-local sequence numbers. The supplied native records are not misrepresented as normalized network FLOW events.

## Detailed Analysis

### Scope and method

I examined only the supplied data directory. I parsed the Windows XML, JSON/NDJSON endpoint and network records, and representative text sources, using identifier-based joins and source-native field checks rather than filesystem metadata or names as authenticity clues. The visible telemetry covers approximately `2026-11-02 13:00–19:00 UTC`; this is a time slice, so missing pre-window initiators and post-window finalizers were not treated as defects.

The endpoint JSON files contain 36,902 records across 23 hosts. The three Zeek sensors contain 22,567 connection records: core 12,166, DMZ 9,962, and DB 439. Their DNS counts are 3,190, 1,158, and 33, respectively; HTTP counts are 2,459, 2,760, and 14; TLS counts are 442, 3,043, and 22. These differences are compatible with different sensor placements and are not themselves synthetic indicators.

### Windows schema and source-native event checks

The table gives specific checked records spanning more than twenty event types. Host names below omit the common `.meridianhcs.local` suffix; Security and Sysmon refer to `windows_event_security.xml` and `windows_event_sysmon.xml` in the corresponding host directory. Times are UTC on November 2, 2026.

| Source / event | Host; record; timestamp | Field-level check and result |
|---|---|---|
| Security 4624 v2 | DC-02; 25377533; 13:04:44.0168727 | Named subject/target SID and LogonId fields, Type 3, NTLM fields, mapped IPv4 address and source port are structurally plausible. Companion-validation concern discussed separately. |
| Security 4634 v0 | DC-02; 25377537; 13:04:48.2582990 | Same target SID, username, Type 3, and LogonId `0xcb5c02d` as the visible logon. |
| Security 4688 v2 | DC-02; 25377512; 13:03:10.2133839 | `NewProcessId=0x1afc` equals decimal 6908; creator `ProcessId=0x13fc` equals 5116. Includes parent image, token-elevation and mandatory-label fields. |
| Security 4689 v0 | DC-02; 25377476; 13:01:12.8988389 | Hex PID `0x1710` equals 5904; image is `spoolsv.exe`; exit `Status=0x0`. |
| Security 4768 v0 | DC-02; 25378398; 13:36:25.3804591 | Machine principal `MAC-MROSS-02$`, service `krbtgt`, domain SID ending 502, AES type `0x12`, preauth type 2, and empty certificate fields are compatible with password-derived Kerberos preauthentication. |
| Security 4769 v0 | DC-02; 25377526; 13:04:12.0433563 | Machine-account client and service-account target `DC-02$`; AES type `0x12`, status zero, mapped client address. I do not require a fresh TGT for every TGS. |
| Security 4776 v0 | DC-02; 25377547; 13:05:04.0060995 | `PackageName=MICROSOFT_AUTHENTICATION_PACKAGE_V1_0`, machine target `WS-EBROOKS-01$`, workstation and status fields have expected shapes. |
| Security 5140 v1 | DC-02; 25377534; 13:04:44.0918417 | `ShareName=\\*\SYSVOL`, native local-path prefix, source tuple, access fields, and subject LogonId agree with the visible network logon. |
| Security 5145 v0 | FILE-SRV-01; 271775; 13:00:05.9658107 | Share `\\*\ClinicalExports`, relative target `Servers\archive-final.bak`, access mask `0x12019f`, and subject identity are populated. |
| Security 4656 v1 | FILE-SRV-01; 271776; 13:00:05.9844267 | Handle `0xec6f2c02`, object path and access mask follow the share check; PID 4 / System is plausible for server-side file access. |
| Security 4663 v1 | FILE-SRV-01; 271777; 13:00:06.1459007 | Same handle, subject and file, with write-data mask `0x2`. |
| Security 4658 v0 | FILE-SRV-01; 271778; 13:00:09.7044242 | Same handle closes after the visible access. |
| Security 4697 v0 | DC-02; 25384372; 17:25:33.2643168 | Service name/image, `ServiceType=0x10`, demand start `3`, and `LocalSystem` account are source-appropriate. Suspicious service content is not an authenticity defect. |
| Security 4698 v0 | DC-01; 28256897; 17:19:49.0220124 | Task content is escaped XML with the task-scheduler namespace, SYSTEM principal, PT1H repetition and an executable action. |
| Security 4720 v0 | DC-01; 28256693; 17:15:05.8598692 | Account-creation fields include target SID, SAM name, UAC changes and account attributes. |
| Security 4728 v0 | DC-01; 28256709; 17:15:11.1750917 | Member SID matches the newly created account; target `Domain Admins` SID ends 512. |
| Security 1102 v0 | DC-01; 1; 18:42:25.0109549 | Correctly changes provider to Microsoft-Windows-Eventlog and uses namespaced `UserData/LogFileCleared`; record-ID reset is explicable here. |
| Sysmon 1 v5 | DC-02; 1368550; 13:03:10.0556657 | PID 6908 / parent 5116 and `dllhost.exe` agree with Security 4688; ProcessGuid, parent GUID, hashes, user and integrity fields are retained. |
| Sysmon 3 v5 | DC-02; 1368530; 13:00:02.6083531 | Inbound DNS to `10.10.2.11:53`, `Initiated=false`, protocol `udp`, destination process `dns.exe`; identity/tuple fields are plausible. |
| Sysmon 5 v3 | DC-02; 1368538; 13:01:12.7897932 | PID 5904 / `spoolsv.exe` matches the Security termination, with a modest source timestamp difference. |
| Sysmon 7 v3 | WS-PPATEL-01; 739852; 14:49:12.4623713 | OUTLOOK loads OLMAPI32.DLL; signed/signature/status and loaded-file hashes are present. |
| Sysmon 8 v2 | DC-02; 1371286; 16:25:57.7031809 | Source/target process GUIDs, images, users, new thread ID and hex start address are present. |
| Sysmon 10 v3 | DC-02; 1368548; 13:02:43.8573018 | Retains source-native `SourceProcessGUID` / `TargetProcessGUID` capitalization, thread ID, access mask and call-trace fields. |
| Sysmon 11 v2 | WS-PPATEL-01; 739780; 14:12:14.8659408 | Process identity, target path and separate creation timestamp fields are present. |
| Sysmon 13 v2 | DC-02; 1368557; 13:03:48.6922536 | `EventType=SetValue`, registry target and `Details=DWORD (0x00000000)` are appropriate field shapes. |
| Sysmon 22 v5 | DC-02; 1368531; 13:00:48.6988320 | SRV query `_kerberos._tcp.meridianhcs.local` has zero status and SRV-shaped query results; I do not require only A-record answers. |

The Security success/failure keyword distinction is preserved in sampled 4624/4625/4771 records. Security 5156 uses decimal process/protocol fields and native device paths, whereas 4688 represents process IDs in hex; a SIEM should not assume one PID encoding across those events. Sysmon informational level/channel and millisecond `UtcTime` coexist with seven-fractional-digit XML `SystemTime` values. Differences between Security and Sysmon timestamps were not treated as impossible ordering merely because source publication order differs.

### Authentication evidence gap and its limitations

The 68 observed 4776 events comprise 58 successful machine-account validations, seven successful human-account validations, and three human-account failures with `Status=0xc000006a`. Thus this is not a simple absence of the Credential Validation family. The 114 unmatched successful domain-account NTLM logons have no matching successful account/workstation pair even when the entire visible slice is searched, not just a short timing window.

Another example is FILE-SRV-01 record 273885 at `18:42:14.0126701Z`: `maya.ross`, workstation `MAC-MROSS-02`, address `::ffff:10.10.1.42`, port 55490, NTLM V2, LogonId `0xf8d79e9`. This is a domain account authenticated using NTLM, for which DC credential-validation evidence is normally expected when successful credential-validation auditing is collected. The distribution matters to an MSSP detector that joins NTLM successes to authoritative validation records: the supplied slice supports that join for a small subset of users and sources while omitting it systematically for the large file/DC subset.

Nevertheless, these are exported logs with no supplied filter policy or authoritative inventory of every authenticating DC. I cannot prove that every qualifying native event was retained. I therefore classify this as a conditional contract gap and retain an inconclusive verdict. The nonzero/zero GUID partition strengthens the concern modestly, but the two observations are related and are not counted twice as separate major defects.

I excluded false lifecycle findings caused by SYSTEM's reusable well-known LogonId `0x3e7` and Type 7 workstation unlocks. Earlier process activity under an existing session is not invalid merely because a later unlock or service-logon record repeats its identifier.

### Network parsing and reference integrity

All checked DNS, HTTP, SMTP, TLS and SMB protocol rows with visible connection counterparts preserve the matching UID's four-tuple. Within those matched records, protocol timestamps do not precede connection open beyond a 1 ms tolerance or follow its recorded interval by more than the 0.5-second screening tolerance. No TCP SF record had fewer than two packets in either direction in the implemented sanity check; all connection records passed the basic condition that IP bytes cover payload plus at least 20 bytes per packet.

One `zeek-core/smb_mapping.json` row, line 88, has UID `CX1d8Nt5AvbnppMKWt`, timestamp `1793640924.870342`, and tuple `10.10.1.22:49554 → 10.10.2.20:445`, without a supplied conn counterpart. This is not scored: Zeek connection logging and protocol logging can fall on different sides of a collection boundary for a long-lived connection, and the slice does not establish its termination time.

The network sources also preserve protocol distinctions. The first core SMTP row has STARTTLS state, empty message-envelope arrays and no fabricated message content. CONNECT HTTP rows represent tunnel setup with zero body lengths, while the proxy text records explicitly separate control-message and tunnel accounting. These properties matter to parsers and byte-based detections and are more credible than collapsing encrypted payload into plaintext HTTP bodies.

### Linux and macOS semantics

Linux syslog uses parseable RFC5424-shaped records, including priority, version, timestamp, hostname, application and PID fields. DB-PROD-01's SSH public-key fingerprints remain stable for a user across repeated sessions, while source ports change. Sudo records retain invoking users and separate root PAM sessions; network acceptance was checked against inbound transport as described above.

DHCP has useful internal timing detail. On WS-LNGUYEN-01, `syslog.log` lines 3–5 show REQUEST/ACK/bound at `13:01:19`, with renewal in 1886 seconds. The next visible REQUEST is `13:32:45.995180Z`, approximately that interval later. Zeek's supplied lease for `10.10.1.21` is 3600 seconds, making this renewal timing reasonable. Other clients have 7200- or 14400-second leases rather than a single identical lease across all hosts.

The two native macOS ES files contain 333 events: 106 fork, 123 exec and 104 exit. Every visible exec PID has a visible fork in the export; additional execs per process are compatible with exec replacing a process image. `(pid,pidversion)` identities do not map to conflicting image paths in these records; executable inode/size/cdhash/signing tuples are stable per path on each host. Event-specific sequence numbers advance separately for types 9, 11 and 15, while global sequence numbers interleave them. I observed no exec-to-exit temporal inversion for the same PID version.

For example, MAC-MROSS-02 ES lines 1–2 show launchd forking PID 88252 at `13:12:07.845472000Z`, then the child execing xpcproxy at `13:12:07.861432000Z`; actor PID version 12 and target PID version 13 are distinguished. Native ES notifications were evaluated as observations, not authorization denials or confirmations of unrelated effects. The five Unified Log records are too sparse to establish general OS logging coverage; that sparsity is not scored. Their writer image, sender image, subsystem/category and timestamp fields are evaluated separately from normalized endpoint telemetry.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on synthetic-confidence score |
|---|---|---|---|
| contract_gap | Windows Security NTLM 4624 / DC 4776 | 114 unmatched domain-account successes of 121; concentrated on two DCs and FILE-SRV-01 | Main upward influence: mechanism-specific companion coverage is inconsistent with the successful validation collection visible elsewhere. Weight limited by unknown filtering and DC coverage. |
| weak_signal | Windows Security authentication field population | 108 nonzero-GUID NTLM successes all lack matching validation; seven matched successes have zero GUID | Small additional concern about differing construction paths; related to the first finding and not independently decisive. |

No hard contradiction, demonstrated generator identity leak, or proven source-native schema impossibility was established by this review. Unmatched boundary-state records, selected Sysmon coverage, domain sanitization, suspicious-activity narrative shape, and mere completeness of cross-source matching did not affect the score.

## Realism Score by Category

- **Field format accuracy:** 9 — XML/JSON parse successfully, checked event-specific fields are credible, and hash widths and source-specific PID encodings are consistent.
- **Temporal patterns:** 9 — Checked process, session, handle and SSH ordering is plausible; DHCP renewal intervals agree with visible client messages.
- **Cross-source correlation:** 7 — Strong process, session and network joins, reduced by the systematic conditional NTLM validation gap.
- **Behavioral realism:** 8 — Service, interactive, remote administration and protocol activity have plausible visible distinctions; no narrative-shape penalty is applied.
- **Environmental consistency:** 8 — Platform-specific endpoint records and sensor volumes are coherent, with uncertainty about authentication collection/filtering across domain controllers.

## Recommendations

- If this were synthetic, ensure successful domain-account NTLM network logons and their authoritative credential-validation events follow a consistent authentication/collection policy. The concrete target is the 114 unmatched 4624 successes identified above, rather than adding unrelated event families.
- If omissions are intentional, make account/source filtering or authenticating-DC scope explicit in the collection description and apply it consistently. Preserve the legitimate pre-logon validation ordering shown by DC-02 record 25377768 and WS-DRAMIREZ-01 record 235885.
- If this were synthetic, review why nonzero versus zero LogonGuid population partitions the NTLM cases with and without visible validation. Derive field population from the actual authentication mechanism and source/export behavior; do not randomize GUIDs merely to increase variation.
