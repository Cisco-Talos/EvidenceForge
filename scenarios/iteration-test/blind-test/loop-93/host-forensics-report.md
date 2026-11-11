# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 75
**Synthetic-Confidence Score:** 20

## Executive Summary

The inspected endpoint evidence is production-like: exact Windows process and network joins, a Linux SSH session, and a macOS fork/exec transition preserve sensible identities and ordering. This bounded review demonstrated no qualifying synthetic defect, but realistic endpoint contracts do not establish real-world provenance, so the authenticity verdict remains inconclusive.

## Evidence For Synthetic

- No demonstrated synthetic indicator in the bounded sample. I did not score complete joins, clean progression, source selection, sanitized naming, or absent out-of-window lifecycle endpoints as synthetic evidence.
- Unverified details in the macOS export remain a limitation, rather than a `schema_or_format` finding: the inspected Endpoint Security rows declare message `version:11` and export `schema_version:1`, but the supplied rows do not establish an exact macOS release or the exporting product's complete serialization contract.

## Evidence For Real

- `WS-MCHEN-01.meridianhcs.local/windows_event_sysmon.xml`, EventRecordID **525184**, Event 1, records `taskhostw.exe`, PID **7208**, parent **5904** (`svchost.exe`), SYSTEM/`0x3e7`, at native `UtcTime` **2026-11-02 13:02:42.477**. Security EventRecordID **948728**, Event 4688, agrees on image, command, `NewProcessId=0x1c28`, parent `ProcessId=0x1710`, subject and logon; its timestamp is **13:02:42.6189107Z**. The eCAR process object **9469aeb0-f350-4f4c-8c1c-9ffb5b224b62** agrees at **13:02:42.585Z**.
- The same host's DNS flow is consistent across Security 5156, Sysmon 22 and eCAR: PID **5916**, `svchost.exe`, **10.10.1.31:57649 → 10.10.2.11:53/UDP**; Sysmon QueryName is `_ldap._tcp.meridianhcs.local`, with two DC SRV answers. Source timestamps are separated by tens of milliseconds rather than being copied exactly.
- `WEB-EXT-01.meridianhcs.local/syslog.log` has public-key acceptance, PAM open and PAM close for the same **sshd PID 2696510**, user **aisha.johnson**, source **10.10.1.35:61284**. eCAR independently identifies that SSH source tuple and user as a successful session.
- On `MAC-MROSS-01`, the ES fork and subsequent exec for **PID 41136** distinguish a process lifetime from image changes: inherited `/sbin/launchd` becomes `/usr/libexec/xpcproxy`, with `pidversion` **12 → 13**. eCAR preserves one process object and represents exec as MODIFY, with matching prior/current image and version fields.
- Aggregate checks found no eCAR own-object record before its visible PROCESS/CREATE, and no actor use more than one second after its visible PROCESS/TERMINATE, across the supplied host eCAR files. This is supporting consistency, not proof of origin or exhaustive lifecycle validation.

## Detailed Analysis

### Scope and method

I inspected only the assigned data directory and this briefing. The detailed sample comprises **16 actual records**: 6 Windows records for two exact pivots; 4 macOS ES/eCAR fork/exec records; 1 macOS Unified Log record; 1 unrelated Linux kernel record; and 4 Linux SSH syslog/eCAR records. Aggregate-only scans counted source families, grouped hashes, and checked selected process lifetime predicates; they did not substitute for source-native record inspection. No embedded command or URL was executed.

The macOS source timestamps counted in the aggregate scan span approximately **13:00–18:57 UTC on 2026-11-02** across two hosts. All lifecycle conclusions are limited to visible identities within the supplied collection. Unequal creates/terminates are not themselves findings.

### Exact cross-source pivot 1: Windows process creation

Host `WS-MCHEN-01.meridianhcs.local`, PID **7208**, image `C:\Windows\System32\taskhostw.exe`, creation around **13:02:42Z**:

| Source | Exact join evidence | Time |
|---|---|---|
| Sysmon Event 1, record 525184 | ProcessGuid `{7b2a0e3f-89f2-6ae8-5c02-0000d8538e2e}`; PID 7208; PPID 5904; SYSTEM; LogonId 0x3e7 | UtcTime 13:02:42.477; SystemTime 13:02:42.4797906Z |
| Security Event 4688, record 948728 | NewProcessId 0x1c28 = 7208; ProcessId 0x1710 = 5904; same image/command; SubjectLogonId 0x3e7 | 13:02:42.6189107Z |
| eCAR PROCESS/CREATE | objectID 9469aeb0-f350-4f4c-8c1c-9ffb5b224b62; pid 7208; ppid 5904; principal SYSTEM; logon_id 0x3e7 | timestamp_ms 1793624562585 |

The `svchost.exe` parent and system-session ownership are plausible for a task-host launch. The available evidence does not show this exact process terminating early or assigning another image to the same creation.

### Exact cross-source pivot 2: Windows DNS process/tuple

Security 5156 record **948718**, at **13:00:02.6464717Z**, shows PID **5916** and device-path `svchost.exe` on **10.10.1.31:57649 → 10.10.2.11:53**, protocol **17**. eCAR FLOW/CONNECT id **fd296eb2-1914-4882-bdc9-b07448be2e89**, at timestamp_ms **1793624402643**, gives the same exact tuple/PID, outbound UDP, principal LOCAL SERVICE, and `svchost.exe -k LocalService`. Sysmon Event 22 record **525176**, native UtcTime **13:00:02.677**, independently attributes `_ldap._tcp.meridianhcs.local` resolution to that PID/image/user, returning DC-01 and DC-02 on port 389. This is a coherent DNS transaction; the SRV answer's LDAP port is not the DNS transport destination port.

### Linux SSH and system activity

`WEB-EXT-01/syslog.log` line **112**, **13:25:18.805366Z**, records `Accepted publickey for aisha.johnson from 10.10.1.35 port 61284 ssh2: RSA SHA256:Os+Oa+Sjl3hMR9m6VEDWViS4GO/l3yRTIMorDToGMbs`, emitted by **sshd 2696510**. Line **113**, **13:25:18.852945Z**, opens `pam_unix(sshd:session)` for UID **2528**; line **291**, **14:18:22.247852Z**, closes that same user/session-bearing sshd PID, about 53 minutes later.

The exact source/user tuple matches eCAR USER_SESSION/LOGIN object **9984fa2b-5c2c-4463-ac36-7dc2b55d9e86**, timestamp_ms **1793625918362**, session_id **213**, logon_id **0x135d10e2**, session_type **ssh**. Its normalized timestamp is approximately 443 ms before syslog acceptance; differing source observation semantics make this insufficient to demonstrate an impossible ordering. I did not infer missing process or transport events from this small session sample.

A separate **13:00:20.665947Z** kernel UFW record on WEB-EXT-01 reports a blocked inbound TCP SYN to port 3389, including interface, TCP flags and packet metadata. It is plausible network background noise on a Linux system, not evidence that an RDP service exists there.

### macOS process semantics

`MAC-MROSS-01/macos_endpoint_security.ndjson` starts with an ES fork notification (`event_type:11`, action_type 1) at **13:00:06.950823000Z**. Launchd PID 1 forks child PID **41136** with process start time **13:00:06.950823Z**, `pidversion:12`, inherited launchd executable identity and root credentials. The paired eCAR CREATE at timestamp_ms **1793624408307** assigns object **85243acd-6fc1-4805-aaa7-5f44bd360f9e**, operation fork, PPID 1 and launchd image.

The ES exec notification (`event_type:9`) at **13:00:06.953308000Z** keeps the pre-exec actor at version 12 and gives the target version **13**, `/usr/libexec/xpcproxy`, args `xpcproxy application.com.google.Chrome.542001333.111636006`, and the same process start time. eCAR MODIFY at timestamp_ms **1793624408308** retains that object and reports execution `:exec:0 → :exec:1`, matching previous/current images and version. This models an exec transition rather than a second unrelated process. ES and normalized eCAR have different observation times; that difference alone is not a defect.

The inspected Unified Log record at **13:03:16.611945+0000** comes from loginwindow PID **40562**, userID **0**, subsystem `com.apple.loginwindow.logging`, category Standard, message `-[Login1 launchWorkspace] | enter`. I did not conflate that diagnostic message with authorization, successful user login, or a process-creation record.

### Aggregate checks and their limits

WS-MCHEN-01 contains **465 Sysmon** rows, including **113 Event 1**, **81 Event 5**, **89 Event 22**, and **89 Event 3**. Its Security source has **654 rows**, including **114 Event 4688**, **81 Event 4689**, **23 Event 4624**, **13 Event 4634**, and lock/unlock events. Differences between counts do not establish defects without exact identities and collection scope.

Across the ten Windows Sysmon files, the aggregate inspected **934 Event 1 rows** grouped by exact image path *within each host*: no group had multiple Hashes values. This supports stable binary identity within this slice, but does not prove binary authenticity or rule out replacement under a different path.

Visible parent-create ordering was checked in three eCAR hosts: **58/58** joinable WS-MCHEN-01 children, **130/130** WEB-EXT-01 children and **36/36** MAC-MROSS-01 children were not earlier than their visible parent CREATE. These are UUID-based joins, not PID-only comparisons. The actor-after-termination check allowed a one-second source-latency tolerance; it did not inspect arbitrary dependent identities or all session semantics.

MAC-MROSS-01 has **141 ES rows** (45 fork, 52 exec, 44 exit), **643 eCAR rows**, and **3 Unified Log rows**; MAC-MROSS-02 has **175 ES rows** (54 fork, 64 exec, 57 exit), **506 eCAR rows**, and **2 Unified Log rows**. These differences are compatible with source selection and window boundaries. I do not score thin Unified Log coverage or eCAR-only FLOW visibility as synthetic without a contradictory collection promise.

This review does not establish per-user behavioral variation, broad application-role placement, macOS native policy/launch-item correctness, or full-day/week timing texture. Those require a different bounded sample or documented collection context, not assumptions about absent sources.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on synthetic-confidence score |
|---|---|---|---|
| None demonstrated | Windows Security/Sysmon/eCAR; Linux syslog/eCAR; macOS ES/Unified/eCAR | 16 detailed records and the stated aggregate predicates | No upward penalty for a demonstrated defect. Score 20 reflects a production-like inspected sample, not certainty about provenance. |

## Realism Score by Category

- **Field format accuracy:** 8 — Inspected Windows fields, Linux syslog and typed macOS process export are coherent; exact macOS exporter/release semantics were not comprehensively verified.
- **Temporal patterns:** 8 — Source offsets, parent ordering and the SSH session duration are plausible; a bounded slice does not establish weekly or human timing texture.
- **Cross-source correlation:** 9 — Exact Windows process/tuple joins and macOS fork/exec ownership agree; this is supporting realism, not a synthetic tell or proof of origin.
- **Behavioral realism:** 7 — Task-host activity, DNS discovery, SSH administration and Mac application bootstrap are plausible; the sample is too small to establish per-user variety.
- **Environmental consistency:** 8 — Inspected Windows, Linux and macOS records retain platform-appropriate semantics, without a demonstrated role or source-coverage contradiction.

## Recommendations

- No data change is justified by a demonstrated defect in this bounded review. If this were synthetic, preserve the exact process/session ownership and native-versus-normalized timestamp distinctions shown here.
- Before making a stronger provenance claim, document the collection scope and macOS exporter/release contract, then choose a separate bounded sample for user behavior and policy/launch lifecycle checks. Thin source coverage alone should not be repaired or penalized.
