# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Real
**Verdict Confidence:** 60
**Synthetic-Confidence Score:** 25

## Executive Summary

The bounded endpoint sample is predominantly production-like: Windows process identity agrees across three sources, and a macOS SSH session has coherent network-before-authentication ordering and a stable session identity. I found no demonstrated impossible lifecycle, source-native field contradiction, or defensible distribution defect in this sample; the real verdict is tentative because structurally competent synthetic telemetry could also pass these checks.

## Evidence For Synthetic

- No concrete synthetic indicator was demonstrated within the inspected sample. This is a limited negative finding, not evidence that the entire collection is authentic.
- No category score or verdict penalty was assigned to absent source families, unmatched events at collection boundaries, or unverified native-format concerns.

## Evidence For Real

- On `WS-MCHEN-01`, Sysmon Event 1 record `525184`, Security 4688 record `948728`, and eCAR line 10 agree on `taskhostw.exe`, PID `7208` (`0x1c28`), parent `svchost.exe` PID `5904` (`0x1710`), SYSTEM ownership, and LogonID `0x3e7`. The subsecond differences between source observation timestamps are credible.
- On `MAC-MROSS-02`, Unified Log authentication for `maya.ross` from `10.10.1.41:63450` follows the same tuple's Zeek TCP/22 open by approximately eight seconds; eCAR subsequently records LOGIN and LOGOUT with one unchanged session objectID. This is coherent lifecycle evidence rather than independent, unrelated rows.
- Across four selected endpoints, 330 eCAR process identities have both CREATE and TERMINATE observations, with zero negative lifetimes. Unmatched records were not treated as faults because these are windowed collections.
- The Windows sample includes realistic process-parent families and distinct field semantics, including hexadecimal Security PIDs and decimal Sysmon/eCAR PIDs. All 44 image paths among 113 sampled-host Sysmon creation events had one consistent hash set each.
- macOS Endpoint Security fork and exec observations preserve one process lifetime while advancing the exec image and audit-token PID version. Linux and macOS shell history records use different, appropriate history encodings.

## Detailed Analysis

### Scope and sampling

I examined only the assigned data directory and the supplied briefing. I inspected 18 individual logical records: ES 2, Unified Log 2, Windows XML 2, eCAR 5, syslog 4, Zeek 1, and shell histories 2. Aggregate checks were restricted to four selected endpoints and one Windows host's Sysmon records; this was not a full collection audit.

Selected eCAR windows on November 2, 2026 were approximately 13:00–19:00 UTC: `WS-MCHEN-01` 13:00:02.643–18:59:43.734; `APP-INT-01` 13:00:33.694–18:57:12.468; `MAC-MROSS-01` 13:00:08.307–18:55:01.020; `MAC-MROSS-02` 13:00:40.237–18:57:00.738. These are observed source bounds, not asserted organization-wide collection boundaries.

### Exact cross-source pivot 1: Windows process creation

The initial Sysmon Event 1 in `WS-MCHEN-01.meridianhcs.local/windows_event_sysmon.xml` has recordID `525184`, `UtcTime=2026-11-02 13:02:42.477`, header `SystemTime=2026-11-02T13:02:42.4797906Z`, ProcessGuid `{7b2a0e3f-89f2-6ae8-5c02-0000d8538e2e}`, PID `7208`, image `C:\Windows\System32\taskhostw.exe`, parent PID `5904`, parent image `C:\Windows\System32\svchost.exe`, user `NT AUTHORITY\SYSTEM`, LogonId `0x3e7`, and System integrity.

Security 4688 record `948728` at `13:02:42.6189107Z` reports the same image and parent, NewProcessId `0x1c28=7208`, ProcessId `0x1710=5904`, SubjectLogonId `0x3e7`, SubjectUserSid `S-1-5-18`, and MandatoryLabel `S-1-16-16384`. Its unused TargetUser fields are null-user values rather than contradictory ownership.

eCAR line 10 at timestamp_ms `1793624562585` (13:02:42.585Z) is PROCESS/CREATE objectID `9469aeb0-f350-4f4c-8c1c-9ffb5b224b62`, PID `7208`, PPID `5904`, principal `SYSTEM`, command `taskhostw.exe`, and logon_id `0x3e7`. Its source process UUID agrees with actorID `6d80205a-6342-443b-b363-684d29d4d9cb`. Different UUID namespaces across Sysmon and eCAR are not a mismatch.

The host's 465 Sysmon records include 113 creations and 81 terminations. Its 654 Security records include 114 creations, 81 terminations, 23 successful logons, 13 logoffs, six failures, two lock events and one unlock. Those counts alone do not imply missing required companions. Among 113 Sysmon creation rows there are 44 image paths and zero paths with multiple hash sets. Parent/child distributions include `SearchIndexer.exe → SearchProtocolHost.exe` (5), `svchost.exe → taskhostw.exe` (7), and PowerShell → OpenSSH `ssh.exe` (5); no implausible relationship is established by these aggregates.

### Exact cross-source pivot 2: macOS SSH session and network transport

`MAC-MROSS-02.meridianhcs.local/macos_unified_log.ndjson` row 2 at `2026-11-02 14:25:16.479467+0000` is emitted by `/usr/libexec/sshd-session`, PID `30178`, UID `0`, and says `Accepted keyboard-interactive/pam for maya.ross from 10.10.1.41 port 63450 ssh2`.

`zeek-core/conn.json` line 2598, UID `C0iAZFQ8y0tA6AcQ2S`, describes `10.10.1.41:63450 → 10.10.1.42:22`, TCP, service SSH, `SF`, open `14:25:08.357404Z`, duration `590.530608` seconds, and a bidirectional byte/packet exchange. Authentication therefore occurs after transport establishment. Zeek connection rows summarize a flow; their file presentation does not make the row timestamp a late authentication observation.

Mac eCAR line 106 records USER_SESSION/LOGIN at `14:25:17.384Z`, principal `maya.ross`, the exact source tuple, logon_id `0x138a3100`, session_type `ssh`, objectID `54693d52-e2be-43f8-9650-f2786b2e340b`. Line 144 records LOGOUT at `14:35:10.321Z` with the same objectID, principal and tuple. Transport close is approximately `14:34:58.888012Z`; a session-observation logout about 11.4 seconds later is not itself impossible. I did not equate an application logout timestamp with a packet-level close timestamp.

### macOS native process and history evidence

The first two `MAC-MROSS-01` ES records are a fork at `13:00:06.950823Z` and exec at `13:00:06.953308Z`. Launchd PID 1 forks PID `41136`, audit PID version `12`; that child subsequently executes `/usr/libexec/xpcproxy` with target PID `41136`, PID version `13`, and the original start time retained. The exec arguments name a Chrome application service. The changing image and PID version are compatible with exec within one lifetime, rather than evidence of two simultaneous processes. Notification `action_type=1` is not treated as a separate authorization denial. Declared ES message version is 11; I did not claim unsupported version-specific native-schema defects.

The Mac's first zsh entry is `: 1793624889:0;/usr/bin/id`, while APP-INT aisha's first bash entry pairs `#1793641111` with `journalctl -u smb-client --since '1 hour ago' --no-pager | tail -20`. These are credible history representations. A single administrative command cannot establish user-role realism across the environment.

### Linux and windowed lifecycle limits

APP-INT syslog first records an rsyslog queue backlog of 2028 messages at `13:00:32.218756Z`, then a systemd-resolved UDP+EDNS0 recovery notice at `13:00:58.761421Z`. Later sampled login messages open sessions for aisha.johnson UID `2528` at `13:03:12.662934Z` and root UID `0` at `13:06:12.849450Z`. Local login activity on an application host is possible; no source-visible rule establishes it as forbidden or contradictory.

The first APP-INT eCAR records include rsyslogd outbound TCP/514 telemetry and a bash termination near the beginning of the visible window. I did not flag the latter without a visible initiating record. Selected-host matched eCAR process lifetimes were: Windows 74, APP-INT 159, Mac-01 44, Mac-02 53; none terminated before its matching CREATE. This limited test does not establish parent validity for every process, boot/session ancestry, or agreement for all native source observations. No memory artifacts were supplied or examined.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| No demonstrated indicator | Windows Security/Sysmon/eCAR, selected Linux and macOS host evidence, one Zeek pivot | 18 individual records; selected-host aggregates and two exact cross-source pivots | No hard contradiction or scored gap established. Score 25 reflects predominantly plausible observed telemetry with substantial sampling and provenance uncertainty. |

## Realism Score by Category

- **Field format accuracy:** 9 — Sampled Windows IDs, source-specific PID formats, history encodings, and Mac process identity structures are coherent; native semantics were not exhaustively verified.
- **Temporal patterns:** 9 — Sampled process and SSH orderings are plausible; all 330 selected-host paired eCAR process lifetimes are nonnegative.
- **Cross-source correlation:** 9 — Exact Windows process and Mac SSH tuple pivots agree on identities and ordering; this does not validate all records.
- **Behavioral realism:** 8 — Selected service, maintenance, login and administrative activity is plausible, but the sample cannot establish long-term persona or daily routine behavior.
- **Environmental consistency:** 8 — Distinct Windows, Linux and native Mac representations are coherent in the sample; host-role and wider collection assumptions remain incompletely established.

## Recommendations

No concrete repair is justified by the sampled evidence. If this were synthetic, preserve the observed exact process/session identities, platform-specific process transitions, and source-appropriate timing offsets. Any broader claim about host-role behavior, long-tail activity, or native lifecycle completeness should first be tested against additional bounded samples; those areas are limitations here, not demonstrated defects.
