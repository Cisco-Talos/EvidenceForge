# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 80
**Synthetic-Confidence Score:** 34

## Executive Summary

The supplied telemetry is mostly production-like from a detection ingestion and correlation perspective: it parses, preserves meaningful source-specific differences, and survives several broad identity, interval, and lifecycle checks. I found one bounded normalized-session closure gap on a Mac, but no demonstrated impossible process ordering, malformed native identity, or transport/application contradiction sufficient to establish synthetic origin. The low synthetic-confidence score describes the observed realism; the higher verdict confidence describes my confidence that this evidence does not support a decisive origin determination.

## Evidence For Synthetic

- [contract_gap] A visible SSH session closes in the native process and network evidence but has no corresponding normalized session closure. `MAC-MROSS-02.meridianhcs.local/ecar.json:94` records successful `USER_SESSION/LOGIN`, object ID `39502e16-8050-4eaa-99a0-25f8d5ed2185`, `logon_id=0x138a1ed4`, source `10.10.1.41:49252`. The same file's lines 103–107 bind the shell process PID 30066 to that logon ID; lines 121–123 terminate that shell and both session-side sshd processes at approximately 14:35:00 UTC. `macos_endpoint_security.ndjson:71–73` independently observes their exits at 14:34:59.389845, .693690, and .997535. `zeek-core/conn.json:2497`, UID `CMz1bnvhInTRzegoAhZ`, observes the same tuple to `10.10.1.42:22`, with `ts=1793629477.445446` and `duration=621.618998`, ending at 14:34:59.064444. There is no `USER_SESSION/LOGOUT` for this object or logon ID anywhere in the 464-row target eCAR file, which continues until 18:57:08.132. This is an in-window normalization/lifecycle gap, not a missing post-window closure. Its authenticity weight is limited: selective collection, normalization loss, or dropped observations can also produce it in real telemetry. The peer Mac's eCAR does record its inbound SSH logout (`MAC-MROSS-01.../ecar.json:379`), so the normalized source is capable of representing this phase.

## Evidence For Real

- Source-specific Windows representations are plausible rather than simply copied field for field: DC-02 Sysmon Event 1 record 1368617 uses decimal `ProcessId=7132`, whereas Security Event 4688 record 25377656 uses hexadecimal `NewProcessId=0x1bdc`; image, command line, parent, and identity agree. Their observation timestamps differ by approximately 194 ms, with Sysmon retaining a separate millisecond `UtcTime`.
- A real SMB-style lifecycle is present in `FILE-SRV-01.../windows_event_security.xml`: Type 3 NTLM logon record 271773 at 13:00:05.2927380, share/object access records 271775–271778, and logoff record 271779 at 13:00:11.5896983 consistently use `Target/SubjectLogonId=0xf62b74b`, user `marcus.chen`, and source `10.10.1.31:57013` where applicable. The matching Zeek mapping uses that same tuple and the `ClinicalExports` share.
- Windows audit failure flags and failure status values differ appropriately from success records. DC-02 record 25382687 is Event 4625 with `Keywords=0x8010000000000000`, `Status=0xc000006d`, and account-disabled `SubStatus=0xc0000072`; ordinary successes use `0x8020000000000000`. The 1102 clear event has its distinct provider/UserData representation and resets the Security record sequence.
- The three Zeek sensor exports contain several connection outcomes, not merely successful completed sessions. For example, `zeek-db/conn.json:1` records `RSTO`, zero responder payload, and directional packet accounting; its second row records `RSTR` and nonzero `missed_bytes`. These are plausible native distinctions, and no application handshake success was found attached to a clearly failed SYN-only/rejected transport in the checks performed.
- Native Mac ES records distinguish the pre-exec actor from the post-exec target, preserve PID across exec, and change PID version. `MAC-MROSS-02.../macos_endpoint_security.ndjson:1–3` follows launchd fork → xpcproxy exec → iTerm exec. This is not the simplistic one-new-PID-per-program representation that often breaks detections on Unix systems.
- Linux records include coherent sudo/PAM phases and different facilities/severities: `MAIL-EDGE-01.../syslog.log:2–4` uses one sudo PID 1985795 for the command, PAM open, and PAM close, with PRI 85 for the command and 86 for PAM messages. Postfix rows 15–19 preserve queue ID `94CB7CDEF` through smtpd, cleanup, qmgr, and successful delivery.

## Detailed Analysis

### Input provenance and boundaries

Actual evidence reads were restricted to the 117 files inside the supplied data directory. I read the supplied neutral detection prompt as instructions. I did not read repository files, TODO.md, scenario files, previous reports, or other reviewers' analyses. Generic project operating instructions were inherited in the agent environment; that is an environment limitation, but I did not use them or harness metadata as evidence of the dataset's origin.

All file paths below are relative to the supplied data directory. XML citations identify physical lines and/or native EventRecordID; JSON/NDJSON citations use physical line numbers. Findings concern the visible time slice, chiefly 2026-11-02 13:00–19:00 UTC. I did not penalize pre-window processes lacking a create row or surviving processes lacking a later termination, selected-out Sysmon event families, sparse Unified Log coverage, sanitized names/addresses, or the compactness/completeness of suspicious activity.

### Parsing and audit coverage

I parsed all 74,633 JSON/NDJSON records and all 30,815 XML Event elements with standard JSON and XML parsers. No parser failures were encountered. XML line counts are much larger than event counts because each record is multiline; they should not be confused with source volume.

Windows Security contains 12,518 Event 5156 rows, 2,004 Event 4769 rows, 898 Event 4688 rows, 820 Event 4624 rows, 780 Event 4689 rows, 771 Event 4768 rows, and 398 Event 4634 rows, among other types. Sysmon contains 7,940 Event 3 rows, 1,170 Event 22 rows, 895 Event 1 rows, 783 Event 5 rows, 731 Event 10 rows, and smaller populations of other collected types. Different source counts are not themselves defects: selection, host visibility, and observation differences are permitted.

The Mac ES population is 283 records across the two hosts. MAC-MROSS-02 has 49 fork, 60 exec, and 48 exit notifications; MAC-MROSS-01 has 40 fork, 47 exec, and 39 exit notifications. These counts are compatible with exec preserving process identity and with processes extending outside the observation window.

### Twenty representative native/normalized checks

The following checks inspect actual fields rather than inferring authenticity from file names. They are schema/semantic spot checks, not a claim to have validated every field against a current vendor manifest.

| Evidence location | Fields/relationship inspected | Result |
|---|---|---|
| `DC-02.../windows_event_security.xml:3`, RID 25377457, 5156 | Decimal `ProcessID=5272`, native device application path, UDP `Protocol=17`, `SourcePort=51161`, destination 53, inbound direction token | Plausible filtering-platform event; agrees with the Sysmon tuple |
| Same file `:126`, RID 25377464, 4689 | `ProcessId=0x1a7c`, `Status=0x0`, SYSTEM subject | Plausible process-termination shape |
| Same file `:360`, RID 25377478, 4624 | Version 2; Type 5; LOCAL SERVICE SID `S-1-5-19`; LUID `0x3e5`; no remote IP | Appropriate service/local semantics rather than invented remote endpoint |
| Same file `:415`, RID 25377479, 4672 | Subject and LUID align with the immediately preceding service logon | Plausible privilege attribution |
| Same file `:4730`, RID 25377656, 4688 | Version 2; hex child/parent IDs; TargetLogonId null sentinel; mandatory label | Plausible creation record, numerically consistent with Sysmon |
| Same file `:129904`, RID 25382687, 4625 | Failure keywords, primary/substatus, Type 3, mapped IPv4 source | Plausible account-disabled network failure |
| Same file `:181670`, RID 25384834, 4697 | Service name, executable, Type `0x10`, StartType `3`, `LocalSystem` account | Coherent service-install field values |
| `DC-02.../windows_event_sysmon.xml:3`, RID 1368530, 3 | `Initiated=false`; remote source; local DNS destination; UDP | Host-side responder interpretation is coherent |
| Same file `:83`, RID 1368534, 10 | Source/target GUIDs and IDs, access mask `0x1010`, pipe-separated call trace | Plausible ProcessAccess shape |
| Same file `:158`, RID 1368536, 5 | Process GUID, decimal PID, image, user, millisecond UtcTime | Plausible termination format; no unsupported requirement for a pre-window create |
| Same file `:249`, RID 1368539, 22 | SRV-style `_kerberos._tcp` query; successful status; priority/weight/port/target results | Source-native DNS field content is coherent |
| Same file `:2490`, RID 1368617, 1 | GUID, parent GUID/PID, hashes, command line, SYSTEM LUID, session 0 | Plausible SYSTEM COM-surrogate creation |
| `FILE-SRV-01.../windows_event_security.xml:97`, RID 271775, 5145 | Share/local path, relative target, subject LUID, mapped source IP/port, access mask/list | Internally consistent share access |
| Same file `:146`, RID 271776, 4656 | Handle `0x1b169349`, full target path, `ProcessId=0x4`, System | Handle request agrees with the access scope |
| Same file `:199`, RID 271777, 4663 | Same handle/path/LUID; `AccessMask=0x2` and `%%4417` | Coherent WriteData observation |
| Same file `:240`, RID 271778, 4658 | Same handle and LUID at later time | Visible handle closes in the correct order |
| `DC-01.../windows_event_security.xml:270291`, RID 1, 1102 | Eventlog provider, Level 4, clear-specific keywords, namespaced UserData | Correctly distinct event shape; not forced into the Security-Auditing template |
| `MAC-MROSS-02.../macos_endpoint_security.ndjson:2` | Version 11; NOTIFY exec actor PID 19023/version 10 versus target PID 19023/version 11; xpcproxy args | Exec is represented as image replacement, not a child creation |
| `MAC-MROSS-02.../macos_unified_log.ndjson:2` | Info message; sshd-session writer; empty subsystem/category; accepted-auth text and matching source tuple | Plausible Unified Log projection; not confused with an authorization decision |
| `zeek-db/conn.json:1–2` and `dns.json:1` | Native dotted tuple fields, typed counters/booleans, states/history, DNS flags/answers/TTL | Parsable, source-appropriate structures and directional accounting |

### Identity and lifecycle checks

For every Windows Sysmon file, I built dictionaries keyed by ProcessGuid for visible Event 1 and Event 5 observations. I compared events' ordinary, source, target, and parent GUID references against visible creation and termination times. I found no referenced visible process used before its Event 1 or after its Event 5. I also found no same-GUID disagreement in PID and image across these references. This is a bounded result: it does not assert that every process must have a visible create row.

For example, DC-02 GUID `{d55311aa-8af8-6ae8-4c02-00001f4dc1b2}` is PID 7132, `dllhost.exe`, in Event 1 RID 1368617 at 13:07:04.5861676 and Event 5 RID 1368763 at 13:15:29.8487302. The lifetime is positive and its image/PID remain consistent.

Across Windows Security, I compared ordinary process-creation logon ownership to visible 4624 and 4634 observations, excluding the persistent well-known SYSTEM/LOCAL SERVICE/NETWORK SERVICE LUIDs from naive before-login checks. No tested 4688 effective logon ownership preceded its visible logon, and none of the tested SubjectLogonId references occurred after its visible logoff. I did not treat the overall imbalance of logons/logoffs as an authenticity indicator, since service sessions and window boundaries matter.

For all eCAR files, I similarly compared visible PROCESS CREATE/TERMINATE identities and actor references with a 100 ms tolerance for the bounded checks. No tested actor reference occurred outside its visible lifetime beyond that tolerance. This did not require static images on Mac processes: exec legitimately changes the image of one process. The session normalization gap described above is separate from a process lifetime contradiction.

### Network and application checks

For each of `zeek-db`, `zeek-core`, and `zeek-dmz`, I indexed conn rows by sensor-local UID and checked every DNS, HTTP, SSL, and SMTP row against its conn row. All 4,313 DNS, 4,610 HTTP, 3,142 SSL, and 79 SMTP rows matched their connection's four-tuple; no UID was missing. Their timestamps fell inside the conn interval with a 100 ms tolerance. I found no `ssl.established=true` attached to S0, REJ, SH, or SHR states.

HTTP request/response body sizes did not exceed corresponding directional conn payload bytes. File `seen_bytes` did not exceed the indicated direction's payload for its referenced connections, and file connection UIDs resolved. Basic conn accounting also passed the conservative check that observed IP bytes cover reported payload plus at least 20 bytes per packet. These results demonstrate usability for joins and byte-based analytics; completeness of matching is not a synthetic clue and was not scored as one.

Connection-state diversity is substantial: zeek-core has 10,053 SF, 1,897 S0, 150 RSTO, 116 RSTR, and smaller OTH/REJ/S1/S2/S3 populations. Zeek-dmz has 6,516 SF and 2,606 S0, among other states. I did not infer an unrealistic failure ratio solely from these counts because the visible sensor scope includes traffic that can generate failures.

### Mac and collection interpretation

The ES records declare message version 11. I inspected their notification semantics, actor/target split, audit-token UID/PID/PID-version identity, executable metadata, args, and exit shape. I did not claim full vendor schema conformance without an OS/build declaration and matching manifest. Native process and file metadata were not interpreted as network FLOW telemetry, and `action.result.auth=0` on a notification was not treated as evidence of an authorization denial.

The Unified Log exports contain only six rows total. That is insufficient to infer an entire system's logging behavior and is neutral under the stated collection assumptions. The normalized eCAR format carries additional job-control, privilege, audit-session, and exec modifications that need not have separate rows in the selected ES notification subset.

The SSH closure gap is reproducible by filtering the full MAC-MROSS-02 eCAR file for object ID `39502e16-8050-4eaa-99a0-25f8d5ed2185`, or for `object=USER_SESSION` and `properties.logon_id=0x138a1ed4`. Only the LOGIN appears. Filtering the same file for that logon ID and PROCESS TERMINATE finds the three in-window session-process terminations. The plausible real-data alternative is a collection/normalization omission, so this finding warrants investigation rather than an assertion of impossible native behavior.

### Distribution and uncertainty

Repeated operational commands are present. For example, the sysstat `debian-sa1 1 1` command and its shell wrapper each occur exactly twelve times on ten Linux hosts. This is compatible with a common periodic deployment over a six-hour slice; I did not score it as an artificial count merely because it is regular. Repeated troubleshooting commands on the two Macs also belong to the same named user, so their shared vocabulary is not independent evidence of a generator.

The result is a modest synthetic-confidence score: the normalized session omission is concrete, but it is limited and explainable in production. Neither the successful broad checks nor the suspicious activity's organization can establish real origin. I found no hard contradiction to justify the upper rubric bands.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| contract_gap | Normalized eCAR USER_SESSION, checked against native Mac ES and Zeek | One completed inbound SSH session on MAC-MROSS-02, LUID `0x138a1ed4` | Modest upward weight: full in-window process/transport closure without normalized logout; real collection/normalization loss remains plausible |

No proven hard_contradiction, schema_or_format defect, or independent distribution_texture defect was included in the score.

## Realism Score by Category

- **Field format accuracy:** 9 — All parsed records are ingestible, and the native spot checks preserve plausible event-specific names, values, numeric forms, and provider differences; full vendor-manifest conformance was not established.
- **Temporal patterns:** 9 — Tested visible process identities and protocol intervals have coherent ordering, with source-specific precision and latency rather than forced timestamp equality.
- **Cross-source correlation:** 8 — Broad network and Windows identity checks pass; the Mac normalized SSH session closure gap lowers this category.
- **Behavioral realism:** 8 — Operational command, service, authentication, and network behavior is plausible within the visible slice; behavior outside the collected sources cannot be assessed.
- **Environmental consistency:** 9 — Observed platform-specific paths, service identities, host-side connection direction, and role-related activity are consistent in the inspected evidence.

## Recommendations

- If this were synthetic, preserve the eCAR session's final LOGOUT when the same collected source records that session's shell and sshd process terminations, or make an intentional normalization/observation omission consistent and explicit in the collection assumptions. Verify MAC-MROSS-02 LUID `0x138a1ed4` against the already present end-of-session evidence; do not add unrelated sources merely to increase coverage.
