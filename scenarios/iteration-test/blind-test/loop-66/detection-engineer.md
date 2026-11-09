# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 72
**Synthetic-Confidence Score:** 42

## Executive Summary

The telemetry is largely suitable for ingestion and correlation in a real detection stack: the Windows schemas, process identities, session relationships, and Zeek reference relationships withstand substantial mechanical checking. A small set of questionable registry-writer assignments and one unusually long native macOS utility execution suggest constructed behavior, but neither establishes an impossible event or a sufficiently strong case for a definitive synthetic verdict.

## Evidence For Synthetic

- [environment_or_collection_plausibility] Several successful Sysmon registry writes associate a minimally privileged service identity with unusually sensitive, unrelated machine configuration. In `DC-02.meridianhcs.local/windows_event_sysmon.xml:5253`, Event 13, record 1368699, `UtcTime=2026-11-02 13:15:25.282`, attributes setting `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell` to `explorer.exe` to PID 5132, `svchost.exe`, `User=NT AUTHORITY\NETWORK SERVICE`. `WS-PPATEL-01.meridianhcs.local/windows_event_sysmon.xml:5578` and `FILE-SRV-01.meridianhcs.local/windows_event_sysmon.xml:7213` similarly assign enabling the Sysmon channel to NETWORK SERVICE PIDs 5064 and 3372. These assignments merit scrutiny as a recurring actor-selection issue; unusual ACLs or a legitimate privileged service arrangement could explain them, so they are not hard contradictions.
- [weak_signal] Native macOS telemetry records an unexpectedly long execution of bare `/usr/bin/id`: `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson:82` executes PID 64542 at `2026-11-02T16:03:56.829615000Z`; line 83 records its successful exit at `16:05:23.587114000Z`, 86.757499 seconds later. This is far longer than the other visible bare `id` executions on that host. Directory-service delays, scheduling, or blocked output remain possible, so this has low weight.
- [weak_signal] The two Mac shell histories repeatedly use the same short administrative vocabulary, including the identical absolute-path `find /Users/maya.ross/Documents -maxdepth 2 -type f -name '*.pdf'` command (`MAC-MROSS-01.../zsh_history/maya.ross.zsh_history:10,18` and `MAC-MROSS-02.../zsh_history/maya.ross.zsh_history:7,18`). This is a limited behavioral-texture concern, substantially weakened by the same named user owning both histories and by the broader application/process activity in native ES records.

## Evidence For Real

- All 20 Windows XML files parse, covering 18,438 Security and 11,604 Sysmon events. All 75,476 records in the supplied `.json` and `.ndjson` files parse as JSON. Native and normalized source distinctions are preserved rather than conflated.
- Sysmon process identity and lifecycle checks found no PID/image disagreement for a GUID with a visible create, no dependent event preceding that GUID's visible create, no dependent event following its visible termination, and no visible parent creation after its child. Pre-window processes were retained as neutral unknowns.
- Windows network session evidence is internally useful. On DC-02, Security XML line 1498 records NTLM Type 3 logon `0xcb5c02d` for `diego.ramirez` from `::ffff:10.10.1.34:58763` at `13:04:44.0172028Z`; line 1635 logs off the same SID, user, LUID and LogonType at `13:04:51.6401162Z`.
- Across 22,270 Zeek connections, protocol rows carrying a scalar `uid` matched a connection in the same sensor's file, retained the connection tuple, and fell within the visible connection interval to a 1 ms comparison tolerance. Matching is evidence of functionality, not itself proof of real origin.
- Zeek includes genuine-looking transport imperfections: resets, incomplete handshakes, one-sided UDP exchanges, retransmissions and content gaps. Every connection with `G` or `g` in its history has nonzero `missed_bytes` (39 at zeek-db, 555 at zeek-core, 631 at zeek-dmz).
- macOS ES records distinguish fork, exec and exit, preserve PID across exec while changing PID version, carry parent/responsible audit tokens, and distinguish GUI launch paths from SSH process trees. Those are meaningful native semantics, not merely Windows-style process rows with Mac paths.
- Linux logs include service-specific programs, syslog priorities, SSH public-key fingerprints, PAM sessions, sudo messages and application failures. For example, `WEB-EXT-01.meridianhcs.local/syslog.log:169` has a public-key acceptance at `13:34:10.641433Z`, while line 301 contains an Apache `proxy_fcgi:error` with its own client address and worker PID.

## Detailed Analysis

### Examination scope and method

I read the supplied neutral briefing and files under `/private/tmp/log-study-uerqg1nx/data` only. Read-only parsing used system Python from the neutral study directory. I did not access project code, scenarios, prior assessments, or repository documentation; schema lookups used official Microsoft, Apple and Zeek documentation.

The visible data spans approximately six hours on November 2, 2026 and contains Windows, Linux, native macOS, normalized eCAR, network-sensor, proxy, firewall and IDS sources. I parsed all Windows events and all JSON records, then checked identity and timing relationships across the full relevant files. Missing starts and ends outside this slice were not treated as defects. No claim of full vendor-schema certification is intended: XML/JSON parsing proves syntax, while the following sampling and relationship checks address semantics.

### Twenty representative record checks

Paths below are relative to the supplied data directory. `DC02/Security` means `DC-02.meridianhcs.local/windows_event_security.xml`; `DC02/Sysmon` means that host's `windows_event_sysmon.xml`. Line numbers identify the opening XML event or the individual JSON row.

| # | Record | Fields and result |
|---|---|---|
| 1 | DC02/Security:3, Event 5156 | Version 1; decimal `ProcessID=5272`; device-form application path; inbound `Direction=%%14592`; UDP `Protocol=17`; receive layer 44. The field capitalization and value forms match the documented event example. |
| 2 | DC02/Security:126, Event 4689 | Hex process ID `0x193c`, `Status=0x0`, SYSTEM subject and a process image; termination data has the expected event shape. Its initiating process need not be inside this slice. |
| 3 | DC02/Security:1022, Event 4624 | Version 2 with extended logon fields; Type 5 SYSTEM service logon uses LUID `0x3e7`, `Advapi`, and no remote IP/port. These are coherent local service semantics. |
| 4 | DC02/Security:1077, Event 4672 | SYSTEM special privileges follow the service logon with the same subject LUID; privilege names are actual Windows privilege identifiers. |
| 5 | DC02/Security:1121, Event 4688 | Version 2; `NewProcessId=0x1c30` is decimal 7216, matching the WmiPrvSE Sysmon create; parent ID `0x13fc` is 5116. Target-subject placeholders and mandatory integrity SID are present. |
| 6 | DC02/Security:1246, Event 4769 | Version 0; machine requester `WS-AJOHNSON-01$`, service account `DC-02$`, service SID, ticket options, encryption type `0x12`, client address and status are provided. A TGS preceding a later visible TGT is not inherently impossible because an earlier TGT can predate collection. |
| 7 | DC02/Security:1498, Event 4624 | Type 3 NTLM, `NtLmSsp`, NTLM V2, mapped IPv4 client address and nonzero source port agree with remote network authentication. |
| 8 | DC02/Security:1635, Event 4634 | The LUID, SID, user and Type 3 match sample 7; time ordering is correct. |
| 9 | DC02/Security:1832, Event 4768 | `ServiceName=krbtgt`, domain krbtgt RID 502, `PreAuthType=2`, AES ticket type and empty certificate fields fit password/key-based Kerberos preauthentication. |
| 10 | DC02/Security:25823, Event 4776 | `MICROSOFT_AUTHENTICATION_PACKAGE_V1_0`, target account, workstation and status are present; this is the credential-validation schema rather than a fabricated 4624 field set. |
| 11 | DC02/Security:111157, Event 4625 | Audit-failure keyword `0x8010000000000000`, status `0xc000006d`, disabled-account substatus `0xc0000072`, Type 3 and NTLM are syntactically and semantically compatible. |
| 12 | `FILE-SRV-01.../windows_event_security.xml:698`, Event 5145 | Source tuple, share/local path, relative filename and `AccessMask=0x120089` are supplied. Following 4656/4658 records at lines 743/792 share handle `0xe8c12c20`; request precedes handle close. |
| 13 | DC02/Sysmon:710, Event 1 | PID 7216, parent 5116, process/parent GUIDs, hashes, logon information, image metadata and `ParentUser` have expected field names and types. |
| 14 | DC02/Sysmon:755, Event 10 | Uses native `SourceProcessGUID`/`TargetProcessGUID` capitalization, decimal PIDs, hexadecimal access mask and a module-offset call trace. Source and target identities pass the available GUID checks. |
| 15 | DC02/Sysmon:83, Event 5 | Termination has `UtcTime`, GUID, PID, image and user, rather than incorrectly copying the entire create-event schema. |
| 16 | `zeek-core/conn.json:1` | UDP DNS has `history=Dd`, one packet each way, and IP byte counts exactly 28 bytes above payload counts (41/69 and 57/85); positive duration and `SF` are compatible with a completed UDP exchange. |
| 17 | `zeek-core/dns.json:1` | Same UID/tuple as sample 16; numeric and named query type/class agree, A answer is IPv4, and answer/TTL arrays correspond. |
| 18 | `zeek-core/http.json:1` | HTTP CONNECT uses authority-form URI `api.snapcraft.io:443`, status 200 and zero response body, a reasonable proxy-tunnel control transaction. |
| 19 | `MAC-MROSS-01.../macos_endpoint_security.ndjson:1` | Notification fork (`event_type=11`, `action_type=1`) names launchd as actor and the new PID 42171 as child. Child initially retains launchd's executable, as expected before exec. |
| 20 | Same ES file:2 | Exec notification (`event_type=9`) keeps PID 42171, transitions PID version 10 to 11, and changes the target executable to xpcproxy with arguments. It is not misread as another process creation or an authorization denial. |

The WFP comparison used Microsoft's [5156 event example](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5156). The observed Zeek fields/history meanings are consistent with the [connection record definition](https://docs.zeek.org/en/current/scripts/base/protocols/conn/main.zeek.html).

### Full-file correlation checks

For Sysmon, I indexed visible creates and terminations by host and GUID and checked the process fields in dependent events, including both participants in process-access and remote-thread events. I also checked visible parent GUID/ID/image agreement and parent lifecycle ordering. These checks found no violations; they do not certify identities for processes whose create is outside the window.

For Windows 4624/4634 pairs with a visible initiating record, I checked target user, SID, domain, LUID and logon type; no paired identity disagreements were found. A preliminary timestamp comparison appeared to put some workstation processes before the first visible 4624 with their LUID, but those 4624s were Type 7 unlocks, not evidence that the original session began then. I excluded those apparent anomalies.

For Zeek I checked the 416 database, 12,146 core and 9,708 DMZ connection rows against protocol rows carrying a scalar UID. I checked tuple equality and whether protocol timestamps fell within the connection's `ts` through `ts+duration`, allowing 1 ms for numeric precision. No mismatches were found. This check does not cover every possible FUID, multi-UID file association or application transaction rule. TCP `SF` packet counts also avoided trivially impossible handshake/close counts, and basic IP-byte/payload accounting was consistent in the checks performed.

### Registry writer plausibility

The most substantial concern is attribution rather than schema. Eleven Event 13 rows identify NETWORK SERVICE as writer across seven distinct machine-level registry targets; some, such as W32Time configuration, may be explained by a correctly permissioned service. The Winlogon shell, common startup directory and Sysmon channel writes are more questionable together.

DC-02 eCAR line 64 associates PID 5132 with `svchost.exe -k netsvcs`; WS-PPATEL-01 eCAR line 11 does the same for PID 5064. Those rows make the service context explicit but do not establish an administrative token or the relevant ACL. Microsoft's [NetworkService account documentation](https://learn.microsoft.com/en-us/windows/win32/services/networkservice-account) describes a locally restricted account. I therefore regard the recurring sensitive-write assignments as a moderate plausibility problem, not proof that Windows could never log them. Inferring default ACLs as known facts about this organization would overstate the evidence.

### macOS semantics and behavioral timing

Both native ES files declare message version 11. The fork/exec/exit event discriminants agree with their payloads, per-type sequence numbers increase, global sequence numbers increase, and separate process audit tokens distinguish actor from exec target. Apple's [message description](https://developer.apple.com/documentation/endpointsecurity/es_message_t) and [sequence-number documentation](https://developer.apple.com/documentation/endpointsecurity/es_message_t/seq_num) support those interpretations. I did not infer an obsolete schema merely because the declared version is newer than older ES examples.

The long `id` execution is corroborated by normalized eCAR lines 323–324: the same object, PID 64542 and `/usr/bin/id` image persist for approximately 86.8 seconds. Because native ES itself records the long interval, it is not simply an eCAR ingestion delay. This remains an outlier, not an impossible lifetime: output or directory-service dependencies can block a short utility.

The Unified Log row `MAC-MROSS-01.../macos_unified_log.ndjson:2` says `ASP: Security policy would not allow process ... MeetingAssist`. I did not treat that diagnostic phrase as proof of an authorization denial or infer later executable activity from it. The native ES and normalized EDR sources have different meanings and need not contain identical record families.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| environment_or_collection_plausibility | Sysmon registry events, corroborating eCAR process context | 11 NETWORK SERVICE writes across seven registry targets; sensitive examples on DC-02, WS-PPATEL-01 and FILE-SRV-01 | Moderate upward pressure: questionable recurring writer/target selection, tempered by unknown service ACLs and token configuration. |
| weak_signal | Native macOS ES and eCAR | One bare `id` lifetime of 86.757499 seconds on MAC-MROSS-01 | Small upward pressure: unusual for this command, but blocking can explain it. |
| weak_signal | macOS shell histories | Repeated short command vocabulary on two hosts owned by the same user | Very small upward pressure; repetition alone is readily explainable. |

No demonstrated hard contradiction or source-schema failure was established. Successful correlation and complete references did not increase the synthetic-confidence score.

## Realism Score by Category

- **Field format accuracy:** 9 — XML/JSON syntax and sampled event-specific native fields are strong; no verified schema defect found.
- **Temporal patterns:** 8 — Lifecycle ordering is sound in the tested identities; the isolated long `id` lifetime is questionable.
- **Cross-source correlation:** 9 — Process identities, paired sessions and tested Zeek protocol references agree, subject to stated coverage limits.
- **Behavioral realism:** 7 — Diverse activity is present, with limited command vocabulary and an unusual utility lifetime remaining concerns.
- **Environmental consistency:** 7 — Host/source roles largely fit; sensitive registry writes under NETWORK SERVICE weaken confidence in service ownership modeling.

## Recommendations

- If this were synthetic, make the process/token chosen for each machine registry write reflect the service responsible for that exact setting. Revisit the cited Winlogon, common-startup and Sysmon-channel writes before broadening generic registry noise. Preserve legitimate restricted-service writes when the actual service ACL warrants them.
- If this were synthetic, derive native short-utility lifetimes from the command's behavior, and introduce long blocking runs only with an intentional cause. Review the 86.8-second bare `id` execution rather than applying generic session/activity durations to every child command.
- If this were synthetic, expand per-user shell vocabulary where justified by observed work, while preserving repeated commands for recurring tasks. The existing same-user repetitions should not be removed merely to manufacture randomness.
