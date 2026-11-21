# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Real
**Verdict Confidence:** 64
**Synthetic-Confidence Score:** 24

## Executive Summary

The records are predominantly production-like from a detection engineering perspective: the sampled source-native schemas are coherent, and systematic process, session, and network checks did not uncover a demonstrated impossible visible lifecycle. Some Linux daemon messages have repetitive texture, but that evidence is weak and could reflect shared hardware or software; it does not outweigh the detailed, plausible source semantics. The verdict is deliberately moderate because a sufficiently careful synthetic dataset could also pass these checks.

## Evidence For Synthetic

- [weak_signal] Repetitive hardware-specific daemon text crosses host roles. The exact message `IRQ 16 affinity hint keeps vector on CPU 0 (ahci)` appears 36 times across `APP-INT-01` (13), `DB-PROD-01` (16), and `PROXY-01` (7); `NUMA node 0: balancing pass complete, 2 IRQs moved` appears 62 times across `DB-PROD-01` (19), `LOG-MON-01` (21), and `WEB-EXT-01` (22). Examples include `APP-INT-01.../syslog.log` at `2026-11-02T13:00:04.070199Z` and `DB-PROD-01.../syslog.log` at `13:01:15.183386Z`. These repeated, specific values could come from a narrow message pool. Shared builds and hardware remain credible explanations, so this receives little weight.
- No substantiated hard contradiction, decisive schema violation, or generator identity leak was found in the checks described below.

## Evidence For Real

- Windows audit events distinguish source-native types rather than forcing every record into one generic shape. In `DC-01.../windows_event_security.xml`, Event 1102 at `2026-11-02T18:42:20.0702537Z` uses the `Microsoft-Windows-Eventlog` provider, Level 4, Task 104, a namespaced `UserData/LogFileCleared` payload, and `EventRecordID=1`. The later 4726 at `18:50:30.3730345Z` has record ID 393 and returns to Security-Auditing/EventData.
- The FILE-SRV-01 file handle lifecycle is credible: 4656 at `13:00:05.9709815Z`, 4663 at `13:00:06.1459007Z`, and 4658 at `13:00:09.7044244Z` share `HandleId=0xb013d0ff`, `SubjectLogonId=0xf62b74b`, and `ProcessId=0x4`. The granted/accessed rights are differentiated.
- Sysmon identities survive joins across event types. Across ten Windows hosts, checks found no visible same-GUID use before creation, use after termination, PID/image change under the same GUID, or child creation outside a visible parent's lifetime.
- Network telemetry contains failed, partial, and gapped observations with internally plausible accounting. For example, `zeek-db/conn.json` UID `C93ifniu5gvSHbzZKsj` has `missed_bytes=356` and a gap indicator in `history=ShADadfFG`; the corresponding sequence-based byte versus observed-IP-byte discrepancy is explainable by the reported gap.
- TLS telemetry distinguishes visibility conditions: no sampled TLS 1.3 connection claims a certificate chain, while TLS 1.2 full handshakes can carry certificate references and resumed sessions generally do not.
- Native Mac records preserve fork/exec distinctions, PID versions, pre-exec actors, target executable identities, and notification semantics. The visible Terminal, iTerm, Chrome helper, and SSH chains are more detailed than simply attaching a process name to a normalized event.

## Detailed Analysis

### Scope and method

I examined only the supplied data directory. All 78,941 JSON/NDJSON records parsed successfully, and the Windows XML files parsed into 29,386 events. I inspected actual representative records across more than twenty event/source shapes and performed additional automated consistency checks. These checks establish practical parsing and join behavior; they are not an exhaustive certification of every platform version's schema.

I treated the input as a collection window, allowed pre-window processes/sessions and post-window survivors, and did not penalize deliberately selected Sysmon coverage. Domain names and addresses were treated as potentially sanitized. No source completeness or high matching rate was treated as evidence of synthesis.

### Windows event schemas and field values

The Security data includes 29 distinct Event IDs. Routine volume is led by 5156 (11,773), 4769 (2,096), 4688 (931), 4624 (809), and 4689 (794). The Sysmon collection contains 11,606 records, including 7,736 network connections, 1,152 DNS queries, 927 process creates, 791 terminations, and 707 process-access records.

Representative checks included:

| Source/event | Visible example and check |
|---|---|
| Security 4688 | DC-01 `13:01:37.2023469Z`: Version 2, `NewProcessId=0xe48`, `ProcessId=0x930`, `ParentProcessName=...svchost.exe`, `MandatoryLabel=S-1-16-16384`; parent and new PID fields are distinct. |
| Security 4689 | DC-01 `13:00:05.3779607Z`: termination carries `ProcessId=0xb64`, `ProcessName=...winlogon.exe`, and `Status=0x0`. The initiating process need not be in-window. |
| Security 4624 | DC-01 `13:10:16.4138675Z`: NETWORK SERVICE SID `S-1-5-20`, Type 5, `Advapi`, local services.exe, and absent remote IP are mutually plausible. |
| Security 4672 | DC-01 `13:10:16.4406977Z`: privileges attach to NETWORK SERVICE's `0x3e4`, following its visible logon. |
| Security 4634 | DC-01 `13:10:49.8084721Z`: machine account `MAIL-FIN-01$`, Type 3, uses a normal hexadecimal target logon identifier. |
| Security 4776 | DC-01 `13:00:05.5841888Z`: package `MICROSOFT_AUTHENTICATION_PACKAGE_V1_0`, workstation `WS-MCHEN-01`, and status `0x0` have credible NTLM validation shape. |
| Security 4768 | DC-01 `13:03:23.7991453Z`: krbtgt service/RID 502, machine principal, PreAuthType 2, IPv4-mapped IPv6 client address, and AES encryption value `0x12`. |
| Security 4769 | DC-01 `13:00:18.3707849Z`: service account `DC-01$`, ticket options, client port, status, encryption type, and logon GUID are separately represented. An earlier TGT is not required inside the slice. |
| Security 5156 | DC-01 `13:00:18.3670663Z`: decimal `ProcessID=2336`, device-form application path, protocol 17, and inbound Kerberos tuple to `10.10.2.10:88`. |
| Security 5140 | DC-01 `14:06:57.1114610Z`: share `\\*\NETLOGON`, local SYSVOL path, remote port, and file access mask have differentiated meanings. |
| Security 4625 | MAIL-FIN-01 `14:43:18.7251932Z`: failure keywords `0x8010000000000000`, Type 4, disabled-account substatus `0xc0000072`, and no remote tuple fit a batch failure. |
| Security 4697 | DC-01 `17:00:12.2938629Z`: `PSEXESVC`, service image, Type `0x10`, demand start `3`, and LocalSystem are represented as service data. |
| Security 4698 | DC-01 `17:19:47.7438924Z`: task content is escaped XML, includes a task namespace, principal, time trigger, repetition interval, and executable action. |
| Security 1102 | DC-01 `18:42:20.0702537Z`: appropriate distinct provider/UserData structure and record-ID reset, as noted above. |
| Sysmon 1/3/5 | DC-01 process create at `13:01:36.8896748Z`, inbound UDP connection at `13:00:18.3883432Z`, and termination at `13:00:05.1350891Z` use event-specific fields and decimal PIDs. |
| Sysmon 8/10 | DC-01 `13:13:02.9121340Z` and `13:01:54.3493599Z` distinguish remote-thread data from access-mask/call-trace data. |
| Sysmon 11/13 | File creation and registry SetValue have different target fields (`TargetFilename` versus `TargetObject`) and their own payloads. |

A SID-to-account scan across the visible Security EventData found no domain SID assigned to multiple distinct account names. This does not authenticate the directory but avoids an easy identity-join defect.

### Process and session lifecycles

The Sysmon checks covered all 927 visible creation records and 791 termination records. For each available matching GUID, I compared event times, PID, image path, and parent creation/termination. No visible ordering or identity violation was found. Normalized eCAR PROCESS records also passed object-ID creation/termination ordering checks.

Security logon/logoff checks found no non-well-known TargetLogonId whose visible 4634 preceded its matching visible 4624. Different create/terminate and login/logout counts were not scored: many records cross collection boundaries, and audit coverage is selective.

### Zeek semantics and correlation

There are 23,141 connection records across the three sensors: 12,230 core, 10,481 DMZ, and 430 DB. For protocol rows carrying `uid`, I compared the same-sensor connection tuple and timestamp against the corresponding conn record. Matched rows showed no tuple mismatch, protocol event more than 10 ms before the connection's start, or protocol event more than one second beyond the connection duration.

One SMB mapping UID, `C4bqaKVpaYQLPkuTrz`, in `zeek-core/smb_mapping.json` line 93 did not have a conn row in this slice. Its time is `1793640924.871449` and tuple is `10.10.1.22:59392 -> 10.10.2.20:445`. A missing companion alone is not a contradiction: a connection log may be written on close, outside the slice, or collected differently. I did not score this as synthetic evidence.

The first core DNS pair, UID `CmN2OeyFuu5qT4yxIk`, consistently uses UDP `10.10.1.31:49610 -> 10.10.2.11:53`, timestamp `1793624403.868779`, and RTT/duration `0.000678`. The DHCP example at `1793624431.176521` uses plural `uids` and `msg_types=[REQUEST, ACK]`, which differs appropriately from ordinary single-UID protocol rows. SMTP STARTTLS rows can have empty envelope/body metadata after TLS establishment; I did not assume encrypted message contents should be visible.

Packet/IP-byte checks initially identified some payload-versus-observed-byte differences, but none exceeded the respective connection's reported `missed_bytes`. Likewise, UDP syslog `S0` records with originator payload and no responder packets are not TCP handshake contradictions. These candidates were rejected rather than counted as defects.

### Mac and Linux source interpretation

The Mac ES exports declare message Version 11 and contain 307 rows: 115 exec notifications (type 9), 97 forks (type 11), and 95 exits (type 15). I treated these as native process notifications, not EDR FLOW records. Checking `(pid, pidversion)` identities found no inconsistent executable/start-time identity or visible post-exit reuse of that exact identity.

For example, MAC-MROSS-01 PID 25527 forks from launchd at `13:07:32.811343000Z`, execs xpcproxy at `13:07:32.820534000Z`, then Terminal at `13:07:32.835499000Z`; PID version advances as the executable changes. MAC-MROSS-02 separately shows iTermServer, login, ShellLauncher, and zsh. These are plausible differences between terminal applications, not a universal fabricated shell ancestry. Executable inode/device and cdhash values remained consistent for repeated observations of each path on each Mac.

MAC-MROSS-01's Unified Log message at `15:42:09.009673+0000` says security policy “would not allow” MeetingAssist. I did not interpret that wording as proof of an enforced denial or use it to claim contradictory child execution. The native Unified Log format, ES notifications, shell history, and normalized eCAR were kept semantically distinct.

Linux RFC5424-style syslog has microsecond UTC timestamps and separates sudo command, PAM session open, and PAM session close. DB-PROD-01's sudo PID 1366977 runs `/usr/sbin/service mysql status` at `13:05:40.527012Z`, opens the root session at `13:05:40.703256Z`, and closes it at `13:05:46.810133Z`. The principal UID and host role fit the operation. The repeated irqbalance strings are the main residual texture concern, with no demonstrated impossibility.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| weak_signal | Linux syslog | 36 identical AHCI affinity messages across three hosts; 62 identical NUMA balancing messages across three hosts | Small upward adjustment for a possible narrow hardware-message pool; shared infrastructure is a plausible explanation. |
| None substantiated | Windows, eCAR, Zeek, Mac ES | Systematic lifecycle and selected schema checks | No hard-contradiction penalty; positive checks support production-like usability but do not prove provenance. |

## Realism Score by Category

- **Field format accuracy:** 9 — XML/JSON parsed; sampled event-specific payloads, provider distinctions, and source-native field representations were credible.
- **Temporal patterns:** 9 — No demonstrated visible process/session inversion; gaps and collection boundaries explain the checked edge cases.
- **Cross-source correlation:** 9 — Matched network tuples and process identifiers were coherent; one unmatched SMB UID is inconclusive within a time slice.
- **Behavioral realism:** 8 — Source-visible process ancestry and privileged-operation lifecycles are plausible; repetitive daemon text leaves a small concern.
- **Environmental consistency:** 8 — Host roles, platform paths, and protocol usage broadly agree; repeated hardware details could reflect shared infrastructure or a limited pool.

## Recommendations

- If this were synthetic, make recurring irqbalance messages depend on each host's actual modeled hardware and daemon state. In particular, preserve shared AHCI/NUMA values only where APP-INT-01, DB-PROD-01, PROXY-01, LOG-MON-01, and WEB-EXT-01 genuinely share those conditions. The visible repetitions alone do not justify adding random message noise.
- Preserve the existing event-specific schemas, stable process identities, native fork/exec distinctions, and collection-window behavior. The checks did not identify a justified need to add more sources, manufacture missing companions, or introduce deliberate correlation errors.
