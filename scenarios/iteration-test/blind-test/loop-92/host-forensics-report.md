# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 80
**Synthetic-Confidence Score:** 32

## Executive Summary

The bounded endpoint review is mostly production-like: the two exact identity pivots preserve Windows process ownership and macOS fork/exec/credential transitions, with plausible differences in observation timestamps. I found no demonstrated impossible lifecycle or source-native contradiction; a small amount of potentially generic administrative command vocabulary is too weak to determine provenance.

## Evidence For Synthetic

- [weak_signal] `APP-INT-01.meridianhcs.local/bash_history/aisha.johnson.bash_history` contains five commands, four querying journal units: `smb-client`, `gunicorn`, `cifs-utils`, and `smbclient`, with `ll` between them. Several unit names resemble client/package vocabulary rather than established service identities. This could reflect loosely tailored command pools, but the logs do not show installed unit inventories or command results, and a real administrator can query nonexistent units while troubleshooting. It has very little weight.
- No `hard_contradiction`, established `contract_gap`, or verified native `schema_or_format` defect was demonstrated in this bounded review. Strong alignment and restricted source coverage are not counted against authenticity.

## Evidence For Real

- The Windows pivot matches PID 5180 (`0x143c`), parent 4356 (`0x1104`), SYSTEM ownership, logon ID `0x3e7`, image `C:\Windows\System32\taskhostw.exe`, and command `taskhostw.exe /Run` across Sysmon Event 1, Security 4688, and eCAR PROCESS/CREATE. Their timestamps differ by fractions of a second rather than conflicting in identity or ownership.
- A second Windows sampled service process, MonitoringHost.exe PID 5208, has `services.exe` parent 4284, SYSTEM credentials, and compatible Security/Sysmon process records. Missing file-version/hash fields are represented as `-`, rather than fabricated metadata being mandatory everywhere.
- The macOS pivot retains one PID 41136 across the launchd fork, xpcproxy exec, and Chrome exec. The image changes advance `pidversion` from 12 to 13 to 14 without inventing another process lifetime. eCAR preserves one object ID and separate execution IDs, and explicitly represents the credential transition.
- An aggregate check of the available Windows Sysmon files counted 934 Event 1 records and 795 Event 5 records. There were zero matched GUID cases with termination before creation, and zero per-host image paths with differing nonempty hash strings among the sampled source family. Unequal creation/termination totals are not a defect in a time slice.
- The macOS file-identity aggregate found 26 executable `(st_dev, st_ino)` identities on MAC-MROSS-01 and 31 on MAC-MROSS-02, with no inconsistent path/hash/size triples for the same identity in the records reviewed by the aggregate.
- Linux background records include application queue pressure, cron work, and accepted SSH authentication rather than only interactive shell activity. APP-INT-01 shell histories contain 36 commands and 34 distinct exact command strings across the four supplied histories, which does not support a strong repetition claim.

## Detailed Analysis

### Scope, methods, and collection boundary

I inspected only the assigned data directory and this analyst briefing. The review used 19 representative record samples (listed below), two exact cross-source identity pivots, and bounded aggregate checks; it was not an exhaustive process-tree, lifecycle, or source-schema audit. Parent directory contents, scenarios, code, evaluations, ground truth, and other reports were not inspected. Commands and URLs appearing in evidence were treated as text.

Selected eCAR extents are approximately November 2, 2026, 13:00–19:00 UTC: WS-AJOHNSON-01 has 1,517 rows; APP-INT-01 975; MAC-MROSS-01 643; MAC-MROSS-02 506. macOS ES extents are 13:00:06.950823–18:54:59.789184 and 13:09:33.569707–18:56:59.856210 respectively. These are observed source extents, not proof of continuous full collection. I did not require pre-window initiators, post-window terminators, absent Sysmon types, a particular audit facility, or comprehensive macOS Unified Log coverage.

### Representative samples and exact pivot 1: Windows process

Host labels in the tables abbreviate directory names by omitting `.meridianhcs.local`; all files are inside the assigned data directory. XML records are identified by source-native record ID where available; JSON line numbers are one-based.

| Sample | Source | Concrete observation |
|---|---|---|
| 1 | WS-AJOHNSON-01/windows_event_sysmon.xml, EventRecordID 30326 | Event 1 at `13:10:01.7957426Z`; embedded UtcTime `13:10:01.794`; PID 5180; ProcessGuid `{fd907e59-8ba9-6ae8-5f00-00102d8b8bdb}`; parent PID 4356, svchost.exe; SYSTEM, session 0. |
| 2 | WS-AJOHNSON-01/windows_event_security.xml, EventRecordID 129968 | Event 4688 at `13:10:02.1751666Z`; NewProcessId `0x143c`, creator `0x1104`, taskhostw.exe `/Run`, SubjectLogonId `0x3e7`, system integrity label. |
| 3 | WS-AJOHNSON-01/ecar.json, line 17 | PROCESS/CREATE at epoch ms `1793625002033` (`13:10:02.033Z`); PID 5180, parent 4356, objectID `c1768f0c-97ca-49d9-8ee4-a5716307f697`, SYSTEM and matching command/image/logon ID. |
| 4 | WS-AJOHNSON-01/ecar.json, line 23 | PROCESS/TERMINATE at epoch ms `1793625250939` (`13:14:10.939Z`), same objectID and PID; visible lifetime is about 249 seconds. |
| 5 | WS-AJOHNSON-01/windows_event_sysmon.xml, EventRecordID 30332 | Event 1 at `13:12:00.0836288Z`; MonitoringHost.exe PID 5208, parent services.exe PID 4284, SYSTEM, logon `0x3e7`, `-Embedding`. |
| 6 | WS-AJOHNSON-01/windows_event_security.xml, EventRecordID 129970 | Event 4688 at `13:12:00.1245411Z`; NewProcessId `0x1458`, creator `0x10bc`, matching MonitoringHost.exe and command. |

The exact pivot is samples 1–4, using host, PID, image, parent PID, and command for the initial cross-source match and eCAR objectID for termination continuity. The Sysmon GUID is not assumed to equal the normalized EDR object UUID. The taskhostw Security timestamp is about 380 ms after Sysmon's event-header timestamp, while eCAR falls between them. These source timestamps do not show an impossible process relationship. The second Windows pair is a representative service-process corroboration within the same host, not a third independent pivot exercise.

### Representative samples and exact pivot 2: macOS fork and exec

All rows below are from MAC-MROSS-01.meridianhcs.local. ES is a version-11 message envelope with schema_version 1 and notification action_type 1. I distinguish the ES process snapshot from the exec target, rather than interpreting the old image as a second process or a denied execution.

| Sample | Source | Concrete observation |
|---|---|---|
| 7 | macos_endpoint_security.ndjson, line 1 | FORK at `13:00:06.950823000Z`: launchd PID 1 produces child PID 41136, pidversion 12, root, executable `/sbin/launchd`, process group/session 1. |
| 8 | macos_endpoint_security.ndjson, line 2 | EXEC at `13:00:06.953308000Z`: same PID, target xpcproxy, pidversion 13, root; arguments identify Chrome application launching. |
| 9 | macos_endpoint_security.ndjson, line 3 | EXEC at `13:00:06.958279000Z`: old xpcproxy snapshot already has real/effective UID 501; Chrome target PID 41136, pidversion 14, auid 501, asid 100001, process group 41136 and POSIX session 1. |
| 10 | macos_endpoint_security.ndjson, line 4 | EXIT at `13:00:29.844683000Z`: Chrome PID 41136, pidversion 14, UID 501, process group 41136. |
| 11 | ecar.json, line 1 | CREATE at `13:00:08.307Z`, operation fork, objectID `85243acd-6fc1-4805-aaa7-5f44bd360f9e`, PID 41136, parent 1, execution suffix `exec:0`, root. |
| 12 | ecar.json, line 2 | MODIFY at `13:00:08.308Z`, operation exec, same objectID, xpcproxy, pid_version 13, execution suffix `exec:1`. |
| 13 | ecar.json, line 3 | MODIFY at `13:00:08.308Z`, operation service_drop, same process, real/effective UID 501, previous UID 0, process_principal maya.ross while source principal is root. |
| 14 | ecar.json, line 4 | MODIFY at `13:00:08.309Z`, operation exec, same objectID, Chrome, pid_version 14, audit_uid 501, audit_session_id 100001, group 41136, execution suffix `exec:2`. |
| 15 | ecar.json, line 7 | TERMINATE at `13:00:31.201Z`, same objectID/PID, Chrome and maya.ross. |
| 16 | macos_unified_log.ndjson, line 1 | `13:03:16.611945+0000`, loginwindow PID 40562, subsystem `com.apple.loginwindow.logging`, category Standard, `-[Login1 launchWorkspace] | enter`. This is a separate background sample, not claimed to identify PID 41136's session. |

The second exact pivot uses host/PID, image sequence, audit identity transitions, and eCAR's retained objectID/execution IDs. The approximately 1.35-second ES-to-eCAR observation offset stays lifecycle-compatible. Both sources preserve the Chrome exit after both exec images. Audit session ID 100001 and POSIX session 1 are distinct fields and are not required to equal one another. The 22.894-second process lifetime is possible and, alone, does not support a distribution or authenticity claim.

Aggregate macOS checks counted 141 ES records on MAC-MROSS-01 (45 forks, 52 execs, 44 exits) and 175 on MAC-MROSS-02. Matching visible fork/exit PIDs yielded 44 and 53 durations, ranging from 0.013796 to 20,814.013538 seconds and 0.003386 to 20,691.927463 seconds. Short diagnostic processes and long sessions coexist. These aggregates are descriptive: PID-only duration pairing was not used to allege exact-identity contradictions, and out-of-window starts or stops were not penalized.

### Linux background and shell texture

| Sample | Source | Concrete observation |
|---|---|---|
| 17 | APP-INT-01/syslog.log | `13:00:32.218756Z`, rsyslogd PID 36008: queue `fwdRule1` has 2028 pending messages and 2 workers. |
| 18 | APP-INT-01/syslog.log | `13:05:00.101478Z`, CRON PID 2932089, sysstat: `command -v debian-sa1 > /dev/null && debian-sa1 1 1`. |
| 19 | APP-INT-01/syslog.log | `13:34:47.103568Z`, sshd PID 2937762: accepted password for lina.nguyen from `10.10.1.21` port 38780, ssh2. |

There are 248 APP-INT-01 syslog lines. These samples support a Linux host with routine monitoring, logging, and remote administration. I did not expand the SSH tuple into another exact source pivot, or conclude that earlier session-close rows were orphaned simply because their logins were outside the visible interval. The five-command aisha history supplies the low-weight vocabulary observation above; no command output establishes whether the units existed or whether the user intended a successful operation.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| weak_signal | Linux bash history | One user's five-command APP-INT-01 history, with four journal-unit queries | Slight upward pressure only: client/package-like unit names could reflect generic administrative vocabulary, but real troubleshooting explains the observation. |
| No established high-impact indicator | Windows Sysmon/Security/eCAR; macOS ES/eCAR | Two exact pivots and bounded aggregates | No demonstrated hard contradiction or contract gap; uncertainty remains because the sampling scope cannot authenticate provenance. |

## Realism Score by Category

- **Field format accuracy:** 9 — Sampled Windows XML and macOS JSON distinguish appropriate source fields and representations; exhaustive native-version schema validation was outside scope.
- **Temporal patterns:** 9 — Visible creation/exec/exit order is coherent, source delays are plausible, and aggregate durations span short commands and long sessions.
- **Cross-source correlation:** 9 — Both exact pivots preserve ownership and identity through process lifetimes and image transitions.
- **Behavioral realism:** 8 — Service and administrative activity is plausible; a small amount of generic-looking Linux unit-query vocabulary remains weakly suspicious.
- **Environmental consistency:** 9 — Windows and Linux process conventions are separated, while macOS audit/session and fork/exec evidence retain their own meanings.

## Recommendations

- If this were synthetic, verify that the APP-INT-01 command vocabulary reflects installed services or intentional troubleshooting. In particular, retain `journalctl -u cifs-utils`, `-u smbclient`, and `-u smb-client` only where the modeled administrator's task reasonably explains those names. The existing evidence does not justify changing them automatically.
- No other corrective recommendation is warranted by the bounded evidence. Expanded collection would improve authentication confidence, but absent sources and collection-window limits are not themselves defects.
