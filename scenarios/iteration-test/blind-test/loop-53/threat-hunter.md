# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Real
**Verdict Confidence:** 62
**Synthetic-Confidence Score:** 28

## Executive Summary

The supplied slice is mostly production-like from a threat-hunting perspective: suspicious remote access, credential access, lateral administration, collection, and outbound transfer can be followed through technically compatible identities, process lifetimes, network tuples, and destination-side evidence. I found a weak command-vocabulary texture on the two Macs, but no demonstrated impossible same-identity ordering or privilege/credential contradiction in the paths examined; this makes Real a modest-confidence choice rather than an origin determination.

## Evidence For Synthetic

- [weak_signal] The two Mac shell histories have a narrow, overlapping diagnostic vocabulary. `MAC-MROSS-01.meridianhcs.local/zsh_history/maya.ross.zsh_history` has 20 entries and 13 distinct complete commands; the corresponding MAC-MROSS-02 file has 18 entries and 11 distinct commands. Both repeatedly use the same fully qualified `sw_vers -productVersion`, `uname -a`, `id`, `ps aux`, `pwd`, `du`, and PDF-finding commands. On MAC-MROSS-01, lines 1–3 have the identical second `1793624869`; MAC-MROSS-02 lines 1–3 similarly share `1793626653`. Repeated diagnostic tasks and second-resolution history can explain this, and both files belong to the same user, so this receives only a small score contribution. It is a limited vocabulary/distribution concern, not an impossible activity sequence or evidence that the suspicious activity is too easy to narrate.

## Evidence For Real

- A sampled incoming RDP pivot is temporally viable. `zeek-core/conn.json:6811` shows `10.10.1.99:43679 → 10.10.1.35:3389`, UID `CFxmuO8Vo3wQC758awW`, opening at epoch `1793635205.317127`, state `SF`, duration `2815.606741`. The destination's `WS-AJOHNSON-01.meridianhcs.local/ecar.json:598` records successful Type 10 authentication at `16:00:10.909Z`, approximately 5.592 seconds after transport open, with the same source port and LUID `0x26d8ea1`.
- Credential-access telemetry has a usable, internally compatible process identity. `WS-AJOHNSON-01.meridianhcs.local/windows_event_sysmon.xml:11741` records PID 5896, `ms-index-service.exe`, the credential-access command line, High integrity, and ProcessGuid `{fd907e59-bdfd-6ae8-8a02-0010f692e726}`. Event 10 at line 11821 accesses the matching LSASS PID 4292, and Event 8 at line 11856 uses the same source and target GUIDs. The Security 4688 event at line 19461 supplies elevated-token/high-integrity fields, so this is not visibly a medium-integrity process inexplicably gaining LSASS access.
- Alternate outbound credentials preserve the local account correctly. The Aisha workstation Security events beginning at lines 26466 and 26508 show 4648 for `runas.exe`, followed by Type 9 with local identity `aisha.johnson`, outbound identity `marcus.chen`, and a new LUID `0x27cb81f`. Later local collection processes retain Aisha as their principal while using that LUID. This is compatible with NewCredentials semantics rather than an account-ownership error.
- The Linux database extraction pivot crosses both endpoint and network evidence. `DB-PROD-01.meridianhcs.local/syslog.log:193–196` contains connection, accepted root password, PAM session open, and logind session creation for source `10.10.2.30:51026`. Database eCAR lines 495–506 then follow the root shell, dump, compression, and SCP process. The receiving APP-INT host logs a separate reverse-direction SSH session for source `10.10.4.10:38233` and creates the target archive at eCAR line 786.
- The Mac-to-Mac SSH path has endpoint rather than merely network evidence: `MAC-MROSS-02.meridianhcs.local/macos_unified_log.ndjson:2` records accepted keyboard-interactive/PAM authentication from `10.10.1.41:56599`; destination eCAR line 161 agrees with that account and tuple. `zeek-core/conn.json:2451` opens TCP/22 approximately 7.982 seconds before the eCAR login.
- The visible source mix contains substantial background activity and different operational roles: 37,051 eCAR records, 19,553 Windows Security records, 12,119 Sysmon records, 22,650 Zeek connection records across three sensors, 23,193 ASA records, 4,191 Linux syslog lines, and 3,550 proxy lines. There are mail, DNS, SMB, HTTP, TLS, OCSP, DHCP, endpoint process, service, and session observations. These are observations of available volume, not a claim that a complete environment must supply every source.

## Detailed Analysis

### Scope and provenance

I read the complete supplied neutral briefing and inspected only files inside `/private/tmp/log-study-_yn9uggi/data` for local evidence. All analysis commands used system `python3` from `/private/tmp`, parsing JSON, XML, and text with the standard library. Logged commands were treated as inert data; none were executed. I did not read repository code, project files, scenarios, TODO/worklogs, other assessments, or neighboring input inventories. Generic inherited project operating context was not used to infer origin.

The endpoint data contains 23 host directories, with Windows Security/Sysmon XML on 10 hosts, Linux-style syslog on 11, and Endpoint Security/Unified Log artifacts on two Macs. The eCAR window is `2026-11-02T13:00:01.077Z` through `18:59:57.834Z`, approximately six hours. Internal address ranges include `10.10.1.*`, `10.10.2.*`, `10.10.3.*`, and `10.10.4.*`. Host names suggest workstations, directory servers, file servers, mail, proxy, web, application, logging, and database roles; these are inferences from the records, not externally supplied topology.

Public reference searches were restricted using the actual `domains: ["learn.microsoft.com"]` tool filter. References consulted were Microsoft's Event 4624 documentation, Sysmon event/configuration documentation, Event 4720 documentation, Task Scheduler schema/trigger documentation, and related official logon-type pages returned by those constrained searches. No task-project public pages or general-web origin searches were accessed. The substantive references used below are linked where relevant. File citations are relative to the supplied data directory; JSON/text line numbers are physical lines, and XML line numbers identify the opening `<Event>`.

### Initial access and credential access

The RDP observation above is preceded by failed credential attempts from `10.10.1.99` in workstation eCAR lines 590, 596, 600, and 617, using multiple account names and failure reason `bad_password`. This supplies legitimate hunt pivots without making the attempts' suspiciousness an authenticity indicator.

The successful RDP session creates a distinct LUID and TerminalSessionId. Discovery processes at workstation eCAR lines 696–721 use the RDP LUID and a visible PowerShell parent; the same host has another interactive session with its own LUID. That distinction matters: concurrent local and remote activity by the same named account does not imply a single impossible process tree.

At `16:44:45.638` Sysmon process creation identifies the renamed executable carrying `privilege::debug` and `sekurlsa::logonpasswords` arguments. The later LSASS ProcessAccess and remote-thread observations are suspicious, but I do not infer that command text alone proves a successful password extraction. The evidence does demonstrate a high-integrity process interacting with the credential-bearing target, consistent with the event meanings in [Microsoft's Sysmon documentation](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events). The initiating process then has a visible termination rather than an obviously inverted lifecycle.

### Windows administration and persistence pivots

On DC-01, eCAR line 3765 and Security XML line 187338 record installation of `PSEXESVC` under the Aisha network identity. eCAR line 3766 then creates `C:\Windows\PSEXESVC.exe` under SYSTEM with `services.exe` as parent, and line 3774 creates its SYSTEM `cmd.exe` child. This transition from network caller to service account is technically plausible; equating the service's SYSTEM identity with the caller's network identity would be an analytical error.

Security XML lines 198489, 198546, 198738, and 198869 preserve the same newly created `svc_dirsync` SID through account creation, password reset, account change, and Domain Admins membership. The RID is distinct from the group RID 512. Creation uses the SAM-account flag representation described by [Microsoft's Event 4720 reference](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4720); it should not be compared directly with the LDAP userAccountControl integer representation as though they were interchangeable.

The DC also records `DeviceSyncSvc` installation and a scheduled task at Security XML lines 202313 and 202350. I inspected the embedded TaskContent, but did not turn uncertain XML ordering details into a proven native-format defect: the consulted Microsoft schema and examples do not provide enough basis here to claim that this captured task could not exist. The Event 1102 record at line 272496 uses the Eventlog provider, UserData/LogFileCleared structure, SYSTEM identity, and EventRecordID 1. Its different body shape is not a missing-EventData error.

The later NewCredentials path on the workstation is especially useful for testing account semantics. At `18:01:28.9384857Z`, Security 4624 retains Aisha locally while naming Marcus for outbound access; eCAR line 1130 describes the same cloned session. Microsoft's [Event 4624 reference](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624) explicitly distinguishes these identities. I found no basis to label this an inconsistent username pivot.

### Collection and outbound transfer

Workstation eCAR lines 1138–1213 show directory creation, queries/copies from the two file servers, compression, and creation of `C:\ProgramData\Microsoft\cache_7f3a.zip`. Line 1296 reads that archive with the same curl process created at line 1289. The proxy lines 3278–3279 identify client `10.10.1.35`, source port 52745, tunnel ID `PT-f74d626f47bff8b1`, CONNECT setup, and inspected POST to `/upload/telemetry/7f3a2b19` at `18:24:39`. The POST's `cs_bytes=18783258` is distinct from CONNECT-control bytes, avoiding an obvious mistake in which tunnel payload is counted as the CONNECT message itself. Zeek-core HTTP line 2045 sees the corresponding client-side CONNECT; I do not require the passive sensor to see decrypted POST contents.

A separate upload is supported by WS-LNGUYEN eCAR lines 354, 358, and 366 and its shell history: a support archive is prepared, then read by a multipart curl request with JSON metadata and a gzip part. `zeek-core/http.json:1378` gives body length 1,573,258 and two origin FUIds/MIME types, while `PROXY-01.../proxy_access.log:2186` records the ticket URL, Lina identity, HTTP 200, and response length 96. The DMZ sensor's HTTP lines 1552–1553 distinguish client-to-proxy and proxy-to-upstream legs. These provide a plausible nonmalicious comparison for the malicious-looking archive transfer; I did not classify every upload as exfiltration merely because curl appears.

For the database path, `zeek-db/conn.json:389` opens the original root SSH transport at `18:14:38.438571Z`; acceptance occurs later in syslog at `18:14:50.634655Z`. The dump process begins after the accepted session and shell, followed by gzip and SCP. SCP uses a second transport in the opposite direction: `zeek-db/conn.json:390`, `10.10.4.10:38233 → 10.10.2.30:22`, duration 36.503624 seconds. The destination's eCAR line 785 records root authentication, line 786 creates `/tmp/.cache/rpt_0318.sql.gz`, and line 788 ends that session. The original interactive SSH session survives this separate transfer. No same-session transport/authentication inversion was demonstrated.

### Lifecycle checks and limits

I parsed all 37,051 eCAR records and compared actor references against visible PROCESS CREATE and TERMINATE records on the same host. There were no actor uses timestamped before the matching visible create or after the matching visible termination. I separately checked process creates against visible same-LUID USER_SESSION LOGOUT records and found none occurring more than one second afterward. For exec-capable processes, I updated current image state on PROCESS MODIFY; I did not mistake the original forked shell image for the final executable.

All 22,650 Zeek connection records were parsed. Within each sensor, I compared repeated TCP four-tuples for overlapping visible intervals and found no overlaps between distinct UIDs. Remote-interactive logins with matching visible TCP/22 or TCP/3389 tuples began after transport open and before transport close; some logins had no corresponding sensor row, which I treated as neutral coverage variation rather than a defect.

These are bounded consistency checks, not proof of physical authenticity. EDR observations and native logs can have different delays, successful login is not equivalent to successful execution of every shell argument, disconnected RDP sessions can survive transport closure, and this window can omit initiators or finalizers. I did not penalize unavailable Sysmon event families, source completeness, sanitized domains, filesystem timestamps, narrative compactness, or the absence of operational mistakes.

### Baseline texture and signal-to-noise

There are 27,794 eCAR FLOW/CONNECT records against 2,150 PROCESS/CREATE records, 1,018 USER_SESSION/LOGIN records, 635 PROCESS/OPEN records, and 13 THREAD/REMOTE_CREATE records. DC and proxy/web workloads are heavier than most endpoints; the two directory servers have 5,890 and 4,873 eCAR records, while DB-PROD has 568. These differences fit the visible infrastructure functions sufficiently that source volume alone does not expose the suspicious path as a tiny isolated island.

Linux command histories include role-related administration, development work, typos, pipes, background tailing, and varying commands. Windows process lifetimes span short helpers and long-lived applications rather than a single fixed duration. On the Macs, however, the histories remain unusually dominated by generic system and Documents-directory checks, with substantial repetition on both machines. This is the only authenticity concern I can responsibly retain from this review, and its same-user/small-sample explanation limits its weight.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Score effect |
|---|---|---|---|
| weak_signal | macOS zsh histories | 38 commands across two hosts belonging to the same account; overlapping small diagnostic vocabulary and three initial commands per host sharing a second | Small upward effect only; compatible with repeated troubleshooting and coarse history timestamps. No hard contradiction demonstrated. |

No hard_contradiction was established. Complete correlations were treated as functional evidence for hunting, not as an authenticity penalty.

## Realism Score by Category

- **Field format accuracy:** 9 — Parsed native and normalized records support useful GUID/LUID/PID/tuple pivots; no demonstrated field impossibility in the paths reviewed.
- **Temporal patterns:** 9 — Tested visible process lifecycles and remote transport/authentication relationships are compatible; histories have a small, explainable burst texture.
- **Cross-source correlation:** 9 — RDP, Windows service execution, alternate credentials, SSH/SCP, multipart upload, and inspected proxy activity provide workable cross-source pivots.
- **Behavioral realism:** 8 — Actions use technically plausible accounts, privileges, tools, and paths; the two Mac histories have a narrow diagnostic vocabulary.
- **Environmental consistency:** 9 — Workload differences, mixed endpoint platforms, and network segments are supported by the visible records; no platform-specific missing-source requirement was imposed.

## Recommendations

- If this were synthetic, improve the Mac shell-history vocabulary identified above by deriving command choice from the actual tasks those endpoints perform, including task-specific arguments and working files where supported by the intended collection. Preserve legitimate repeated troubleshooting; do not add arbitrary mistakes or attack detours as a substitute for realistic task variety.
- Keep the working process, credential, transport, and upload pivots intact. I found no log-supported reason to add more event families or invent missing pre-window/post-window records merely to raise coverage.
