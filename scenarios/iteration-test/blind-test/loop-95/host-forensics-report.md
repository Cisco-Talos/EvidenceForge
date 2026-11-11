# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 82
**Synthetic-Confidence Score:** 35

## Executive Summary

The examined endpoint evidence is mostly realistic: exact Windows process identities and a Linux SSH session agree across independent source families, and macOS records distinguish fork from successive executable images. I found no demonstrated impossible lifecycle, denied-execution effect, or native-field contradiction in this bounded review; repeated Windows service command vocabulary is a weak indication of templating, with ordinary administrative activity an equally viable explanation.

## Evidence For Synthetic

- [weak_signal] FILE-SRV-01 Security 4688 command vocabulary is concentrated: 21/97 process creations are `WmiPrvSE.exe -secured -Embedding`, 17/97 `taskhostw.exe`, and 13/97 `taskhostw.exe /Run` (51/97 combined). That concentration could arise from a limited command pool, but it also fits repeated service and management work on a file server. I did not establish an unrealistic rate or timing pattern, so it is a minor uncertainty rather than a demonstrated defect.
- [weak_signal] WS-AJOHNSON-01 also repeats several short commands (`powershell.exe` 8/117, `cmd.exe` 6/117, `taskhostw.exe` 5/117). Bare command lines can be real; the review did not show that these records claimed a richer operation requiring omitted arguments. This observation does not independently support a synthetic verdict.

## Evidence For Real

- WS-AJOHNSON-01 PID 5180 has matching image, command, SYSTEM principal, parent PID 4356, and logon ID `0x3e7` in Sysmon 1, Security 4688, and eCAR PROCESS/CREATE. Source timestamps differ by plausible subsecond amounts rather than contradicting process identity.
- APP-INT-01 SSH PID 2937762 and source tuple `10.10.1.21:38780` produce a plausible connection, accepted-password, PAM-open, PAM-close sequence, with matching normalized eCAR login/logout identity. Authentication follows the connection and close follows successful login.
- MAC-MROSS-01 ES records use message `version:11` and distinct fork/exec observations. PID 41136 retains its start time while exec changes its executable and audit-token pidversion from 12 to 13. Normalized eCAR represents the same lifetime with stable objectID and separate execution IDs.
- Windows logon distributions vary by apparent role: WS-AJOHNSON-01 has type 3/5/7/9/10 counts 14/6/2/1/1, while FILE-SRV-01 has type 3/5/10 counts 65/63/3. Workstation lock/unlock events are present (two each on WS-AJOHNSON-01).
- Linux shell vocabulary varies by host: APP-INT-01 histories contain Docker operational checks, FILE-LNX-01 storage/audit checks, and WS-OHADDAD-01 Python/data/SQL commands. The histories contain respectively 36/34, 17/17, and 16/16 total/distinct commands, rather than one identical command sequence copied to all three hosts.

## Detailed Analysis

### Scope and method

Only the assigned `data` directory was examined. This was a bounded representative review, not an exhaustive lifecycle audit: the core sample comprises Windows process evidence, Linux SSH/auth/background records, and Mac fork/exec/policy observations, supplemented by useful event/command aggregates. I used two exact cross-source pivots below, plus a Mac execution-identity check. Filesystem timestamps, domain resolvability, absence of selected Sysmon event types, completeness of joins, and narrative structure did not influence the score.

The Mac ES windows observed through source aggregates were 2026-11-02 13:00:06.950823–18:54:59.789184 UTC on MAC-MROSS-01 and 13:09:33.569707–18:56:59.856210 UTC on MAC-MROSS-02. I did not infer a host boot or session start from those first observed records. No absent pre-window creator or post-window termination was scored.

### Exact pivot 1: Windows process creation

Files under `WS-AJOHNSON-01.meridianhcs.local/`:

1. `windows_event_sysmon.xml`, EventRecordID 30326: Sysmon Event 1 at `2026-11-02T13:10:01.7957426Z`, embedded UtcTime `13:10:01.794`, ProcessId `5180`, ProcessGuid `{fd907e59-8ba9-6ae8-5f00-00102d8b8bdb}`, image `C:\Windows\System32\taskhostw.exe`, command `taskhostw.exe /Run`, parent PID `4356` / `svchost.exe`, user `NT AUTHORITY\SYSTEM`, LogonId `0x3e7`, session 0, System integrity.
2. `windows_event_security.xml`, EventRecordID 129968: Security 4688 at `13:10:02.1751666Z`, NewProcessId `0x143c` (=5180), creator ProcessId `0x1104` (=4356), same executable/command/parent, subject SYSTEM / `0x3e7`, mandatory label `S-1-16-16384`.
3. `ecar.json`, record ID `5c1723f1-42a0-4cdf-a011-c0ae868771ad`: timestamp_ms `1793625002033` (=13:10:02.033Z), PROCESS/CREATE, PID 5180, PPID 4356, principal SYSTEM, matching command/image and logon ID.

These are an exact PID/image/parent/time join, not a match based merely on a common executable name. Hexadecimal Windows Security PIDs correctly resolve to the decimal Sysmon/eCAR values. The source timestamp spread is approximately 379 ms. I found no identity or ownership conflict in this pivot. No claim is made that all 117 Security and 118 Sysmon process creations were exhaustively matched.

The workstation has 118 Sysmon 1 and 99 Sysmon 5 rows, versus 117 Security 4688 and 97 Security 4689 rows. Those raw count differences alone cannot establish missingness or contradictions in a time slice and were not scored.

### Exact pivot 2: Linux SSH lifecycle

Files under `APP-INT-01.meridianhcs.local/`:

- `syslog.log:58`, `13:34:40.581864Z`: sshd PID 2937762, connection from `10.10.1.21 port 38780` to `10.10.2.30 port 22`.
- `syslog.log:59`, `13:34:47.103568Z`: same PID/tuple, accepted password for lina.nguyen.
- `syslog.log:60`, `13:34:47.243309Z`: same PID, `pam_unix(sshd:session)` opened for lina.nguyen(uid=5302).
- `syslog.log:76`, `14:00:58.148983Z`: same PID/user, PAM session closed.
- `ecar.json`, PROCESS/CREATE ID `074199ad-c129-4e89-a21a-2d397f980e6c`: timestamp_ms `1793626478453` (=13:34:38.453Z), PID 2937762, PPID 36038, root, `/usr/sbin/sshd`, command `sshd: lina.nguyen [priv]`.
- `ecar.json`, USER_SESSION/LOGIN ID `97b5805c-4b58-4803-8cbd-24702c537211`: `13:34:48.126Z`, lina.nguyen, exact source IP/port, session objectID `3451c175-9da0-45cb-ba13-aefd36fb3f7b`, logon ID `0x1518bcf1`, session ID 337, session_type ssh.
- `ecar.json`, USER_SESSION/LOGOUT ID `1c0ef79c-c731-48f9-b94b-6c99419547b6`: `14:00:59.134Z`, same session objectID, user, tuple, logon/session IDs.

The visible session lasts about 26 minutes. Process observation precedes the connection/auth sequence, and normalized login and logout follow native PAM observations by approximately 0.88 and 0.99 seconds. That is compatible with separate observation times. A second lina.nguyen SSH session uses port 47273 and a different objectID; it was not conflated with port 38780.

Background examples also have plausible source-specific content: APP-INT-01 records rsyslog forwarding queue pressure at `13:00:32.218756Z` and systemd-resolved restoring UDP+EDNS0 for DNS server `10.10.2.11` at `13:00:58.761421Z`. These are supporting examples, not proof of a particular operating-system release.

### macOS execution and policy interpretation

`MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson` starts with launchd PID 1 forking PID 41136 at `13:00:06.950823000Z`; the fork child's image is initially `/sbin/launchd`. At `13:00:06.953308000Z`, exec changes that same PID to `/usr/libexec/xpcproxy`, with args `xpcproxy application.com.google.Chrome.542001333.111636006`. The target pidversion is 13 versus 12 before exec; start_time remains `13:00:06.950823Z`.

The corresponding first two `ecar.json` rows use objectID `85243acd-6fc1-4805-aaa7-5f44bd360f9e`, first PROCESS/CREATE (fork), then PROCESS/MODIFY (exec). Execution IDs change from `:exec:0` to `:exec:1`; this is a coherent representation of a process lifetime with a new image, not two competing process creations. eCAR timestamps occur around 1.35 seconds after the ES observations; source delay alone is not impossible ordering.

`macos_unified_log.ndjson` records loginwindow `-[Login1 launchWorkspace] | enter` at `13:03:16.611945+0000`. A later kernel/AppleSystemPolicy message at `15:47:27.953941+0000` says `ASP: Security policy would not allow process: 62993, /Applications/MeetingAssist.app/Contents/MacOS/MeetingAssist`. I did not treat this as evidence that PID 62993 successfully executed. The bounded eCAR lookup returned no PID 62993 activity; no contradicted denial-to-effects transition was demonstrated. A policy message is not interchangeable with a successful ES exec notification.

MAC-MROSS-01 has 141 ES records (45 fork, 52 exec, 44 exit) and MAC-MROSS-02 has 175 (54 fork, 64 exec, 57 exit). Exec can exceed fork because successive exec images share one lifetime, and exits can involve lifetimes that started before collection. These counts therefore do not establish a defect. I did not use unfamiliar native numeric details as an unverified schema finding, nor infer a specific macOS release solely from ES message version.

### Limits

Exact process/hash consistency across every Windows host, all Mac parent/responsible identities, every service session, and complete network FLOW ordering were outside this bounded review. The small sample can establish that the cited joins work; it cannot certify the entire collection. Concentrated service command vocabulary remains explainable without a generator, and thin source coverage is not a scored issue.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| weak_signal | Windows Security 4688 | FILE-SRV-01: 51/97 creations use three WMI/taskhost command strings | Minor templating suspicion; repeated service execution is a credible alternative |
| weak_signal | Windows Security 4688 | WS-AJOHNSON-01: recurring bare PowerShell/cmd/taskhost strings | Minor uncertainty about command-pool breadth; no demonstrated invalid activity |
| No demonstrated hard contradiction | Windows, Linux, macOS endpoint | Bounded records and exact joins described above | Keeps score below the mixed/strong synthetic ranges |

## Realism Score by Category

- **Field format accuracy:** 8 — Examined XML, RFC5424-like syslog, normalized eCAR, and Mac records preserve plausible source distinctions; complete native-schema validation was outside scope.
- **Temporal patterns:** 8 — Sampled SSH and process observations have plausible ordering and source delays; no exhaustive timing-distribution claim.
- **Cross-source correlation:** 9 — Exact Windows and SSH pivots agree in identities, ownership, and lifecycle; this is affirmative realism evidence, not a synthetic clue.
- **Behavioral realism:** 7 — Host-specific shell vocabulary and Windows session mixtures are plausible; repeated service command strings leave a weak templating concern.
- **Environmental consistency:** 8 — Examined platform/role evidence is compatible with a mixed workstation/server environment; no role contradiction established.

## Recommendations

- If this were synthetic, investigate whether FILE-SRV-01's 51/97 WMI/taskhost process concentration reflects the intended service workload. Retain it if supported; expand behavior only where real service semantics require it, rather than adding arbitrary command variety.
- If this were synthetic, preserve the demonstrated exact-identity ownership and source timing behavior for Windows process and Linux SSH events, and the distinction between Mac fork, exec, and policy observations. These examples did not need correction.
- No missing-source expansion or forced lifecycle closure is recommended on the basis of this time slice.
