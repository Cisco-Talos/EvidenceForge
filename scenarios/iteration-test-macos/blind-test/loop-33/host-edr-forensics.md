# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 82
**Synthetic-Confidence Score:** 67

## Executive Summary

The endpoint evidence is mostly convincing at the identity, process-tree and correlation levels, but repeated exact-duration macOS activity and fixed Linux background-message quotas suggest synthetic construction. This verdict rests on measurable distribution artifacts, not a demonstrated impossible process lifecycle or on the apparent completeness of the suspicious activity.

## Evidence For Synthetic

- [distribution_texture] Six independent launchd inventory activities across both Macs have **exactly 2.000000 seconds from fork notification to exit notification**, despite distinct timestamps and intervening xpcproxy/exec stages. On `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson`, fork/exit pairs are lines **28/31**, **64/67**, and **121/124**; on `MAC-MROSS-02.meridianhcs.local/macos_endpoint_security.ndjson`, pairs are **36/39**, **100/103**, and **138/141**. All ultimately execute `/usr/bin/sw_vers`, with exit status 0. Exact microsecond equality to a two-second lifetime across every such activity is substantially less plausible than an approximate shared runtime.
- [distribution_texture] Every one of the **11 Linux syslog files contains exactly eight `dbus-daemon` messages**, despite different endpoint/server roles, total volumes ranging from 184 to 1,283 rows, and different temporal spreads. Reproducible examples: `DB-PROD-01.../syslog.log` lines **10, 14, 20, 28, 38, 45, 49, 52**; `APP-INT-01.../syslog.log` lines **6, 17, 26, 27, 32, 40, 59, 64**; `WS-LNGUYEN-01.../syslog.log` lines **17, 56, 62, 64, 150, 155, 240, 260**. The content alternates between a small set of activation/success messages. Shared software can explain common vocabulary; it is less persuasive as an explanation for the identical count on every host.
- [distribution_texture] The Linux background quotas extend beyond D-Bus: all **10 hosts that have anacron rows have exactly five**, and nine Linux hosts have exactly 12 CRON rows (two others have 11 and zero). Anacron's five-row lifecycle is individually legitimate, so it is only supporting evidence; in combination with the fixed D-Bus quota, it produces a repeated bounded-background texture across unrelated machines. Examples include `APP-INT-01.../syslog.log` lines **38–47**, `LOG-MON-01.../syslog.log` lines **48–60**, and `MAIL-EDGE-01.../syslog.log` lines **2–37**.

## Evidence For Real

- Windows process identity and lifecycle relationships hold up well. Across **864 Sysmon Event 1 records**, repeated executable paths retain the same hash strings within each host. Checks of visible GUID-linked starts, terminations, subsequent observations and parent identities found no visible use-after-termination or parent-image/PID contradiction in the tested relationships.
- A concrete three-source example is PID **7248**, `dllhost.exe`, on `WS-MCHEN-01`: Sysmon creation at `2026-11-02 13:01:10.515`, Security 4688 at `13:01:10.6850674Z`, and eCAR creation at `13:01:10.619Z` agree on executable, parent `svchost.exe` PID **5896**, SYSTEM ownership and command line. The Sysmon termination at `13:05:32.497` and Security 4689 at `13:05:32.5244988Z` agree on the same PID and executable. XML record starts are Sysmon lines **31/137** and Security lines **38/122**; eCAR creation is line **3**.
- Linux SSH sessions show credible auth/PAM/logind sequences and user-specific public-key fingerprints. On `DB-PROD-01.../syslog.log`, lines **120–121** record accepted public-key authentication for `marcus.chen` and the subsequent PAM open at `15:22:10.933342Z` / `15:22:11.017810Z`; line **152** closes that session at `16:06:02.590473Z`. Other users and hosts have distinct timings and identities.
- The Macs distinguish process birth from successive image executions. `MAC-MROSS-01.../macos_endpoint_security.ndjson` lines **1–7** show launchd → xpcproxy → Terminal, then login → zsh, with same-PID exec transitions and separate child PIDs. `MAC-MROSS-02` instead has iTerm2, iTermServer and ShellLauncher stages. This is appreciably more realistic than representing every exec as a fresh process.
- macOS eCAR explicitly carries `operation=fork`, `operation=exec`, `execution_id`, previous images, audit/session identifiers and privilege changes. For example, `MAC-MROSS-01.../ecar.json` lines **10–19** preserve PID **42186** through launchd/xpcproxy/Terminal and then create separate login and shell processes. The differing images on CREATE versus subsequent MODIFY rows are therefore explained, not a mismatch.
- Background roles vary meaningfully: DB-PROD has multipath/IRQ activity, WEB-EXT has substantial UFW noise, mail hosts have Postfix/Dovecot, and Linux workstations have desktop/network/power-management services. This argues against treating the entire dataset as one generic endpoint template.

## Detailed Analysis

### Scope and method

I examined only the supplied data directory. I inventoried host-source volumes, parsed every supplied Windows Security and Sysmon XML file, checked process GUID lifetimes and parent identities, checked per-host executable hash stability, tested eCAR actor references against visible process creation/termination, and read specific Linux, shell-history and macOS native records. Absence of events outside the collection window, selected Sysmon event coverage, sanitized names and complete correlations were treated as neutral.

### Windows process and logon evidence

The Windows material has differentiated event families: domain controllers have substantial Kerberos/authentication traffic, the file server has share/object-access records, and workstations have ordinary application and lock/unlock activity. Counts differ by host rather than following one fixed total. For example, DC-01 has 6,981 Security events and WS-MCHEN has 638; this difference is consistent with the visible roles.

The `WS-MCHEN-01` dllhost example above is useful because its hexadecimal and decimal PIDs agree: `0x1c50` is 7248, and `0x1708` is parent PID 5896. SYSTEM SID, logon ID `0x3e7`, integrity and parent service command line agree across the endpoint views. Source timestamps differ by plausible small amounts; I did not interpret those offsets as an error.

Within each host I compared Sysmon process-creation hashes by exact executable path, and found no conflicting hash strings. I also compared visible parent GUIDs against parent images and PIDs, and checked dependent Sysmon/eCAR observations against visible terminal events. Those checks did not reveal an impossible visible lifecycle. Across Security records, the same domain SID did not map to conflicting usernames in the inspected dataset. This is substantive evidence of good internal fidelity, although consistency alone cannot establish production origin.

### Linux services and sessions

The Linux messages have appropriate RFC5424-style envelopes, auth severity/facility patterns, numeric process IDs, and plausible session-open/close relationships. The accepted-key example on DB-PROD is accompanied by logind removal after the PAM close (lines 152–153). Sudo sequences similarly include command, open and close records, such as DB-PROD lines **17–19**, where `lina.nguyen` runs `/usr/bin/apt list --upgradable` and the root sudo session opens and closes over several seconds.

The strongest Linux concern is distributional rather than syntactic. D-Bus emits exactly eight messages on every Linux host, but those eight messages occupy quite different portions of the window. DB-PROD's eight all occur between `13:12:12.096602Z` and `13:29:37.436071Z`; WS-LNGUYEN's extend from `13:21:13.516963Z` to `18:21:47.983815Z`. Thus the count equality is not simply eight observations of a clearly shared periodic timer. Standardized fleet images or selected extraction could explain some commonality, which limits the weight of this indicator. Nevertheless, exact per-host quotas combined with the repeated five-row anacron groups are characteristic of bounded background construction.

### macOS native process semantics and timing

I interpreted ES fork, exec and exit records separately and preserved audit-session versus POSIX-session distinctions. I did not treat an audit-token change across an exec/credential transition as proof of a new process. The Terminal and iTerm process graphs are coherent at this level.

The six inventory activities provide the clearest measurable timing artifact:

| Host | PID | Fork time UTC | Exit time UTC | Fork-to-exit |
|---|---:|---|---|---:|
| MAC-MROSS-01 | 44454 | 13:30:55.503137 | 13:30:57.503137 | 2.000000 s |
| MAC-MROSS-01 | 59593 | 15:15:46.859128 | 15:15:48.859128 | 2.000000 s |
| MAC-MROSS-01 | 73937 | 17:39:13.244911 | 17:39:15.244911 | 2.000000 s |
| MAC-MROSS-02 | 21918 | 13:43:10.118008 | 13:43:12.118008 | 2.000000 s |
| MAC-MROSS-02 | 44095 | 15:46:48.875258 | 15:46:50.875258 | 2.000000 s |
| MAC-MROSS-02 | 56592 | 17:52:20.143237 | 17:52:22.143237 | 2.000000 s |

All dates are 2026-11-02. These are not wall-clock-rounded timestamps: arbitrary fractional parts are preserved exactly in the exit. The command is `/usr/bin/sw_vers`, and the process passes through launchd/xpcproxy before its final image. Other sw_vers invocations in the same files have variable subsecond lifetimes, such as MAC-MROSS-01 lines **11–13** and **103–105**. A fleet inventory agent can explain repeated invocation, but does not naturally explain exact fork-to-exit equality at microsecond resolution for all six instances of one activity family.

I found a policy message at `15:42:04.607857Z` in MAC-MROSS-01 Unified Log line **2**, stating that security policy would not allow MeetingAssist. I did not extrapolate successful execution or claim a denial/child-process contradiction from that message alone. Likewise, I did not score sparse Unified Log coverage or demand absent launch-item/file facilities.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Score impact |
|---|---|---|---|
| distribution_texture | macOS Endpoint Security | Six inventory process lifetimes across two hosts | Highest: all are exactly two seconds from fork to exit despite unrounded timestamps and intermediate exec stages. |
| distribution_texture | Linux syslog / D-Bus | Eleven hosts, eight rows each | Moderate: fixed count across different host roles, volumes and temporal spreads suggests quotas. |
| distribution_texture | Linux syslog / anacron and CRON | Ten five-row anacron groups; nine 12-row CRON totals | Low supporting weight: regular scheduled activity is plausible, but reinforces the repeated background shape. |

No hard contradiction or verified native schema violation is required for this verdict, and none is claimed here.

## Realism Score by Category

- **Field format accuracy:** 9 — XML, normalized endpoint and native macOS fields are detailed and generally coherent in the checks performed.
- **Temporal patterns:** 6 — Source offsets and most lifetimes are credible; the six exact two-second process lifetimes are a substantial artifact.
- **Cross-source correlation:** 9 — Tested process identity, PID, principal and parent relationships align; no impossible visible GUID-linked lifecycle was found.
- **Behavioral realism:** 8 — User/session and service-role variation is present, with plausible native process chains.
- **Environmental consistency:** 7 — Role-specific background activity helps, while identical Linux background quotas weaken organic fleet variation.

## Recommendations

- If this were synthetic, derive inventory-process exits from actual command lifecycle semantics and variable execution/scheduling time; avoid adding an exact fixed duration to every fork timestamp. Preserve the existing separate fork/exec identities.
- If this were synthetic, make D-Bus activations follow service requests, idle exits and host activity rather than emitting an identical count per host. Preserve legitimate fleet-wide configuration similarities while varying observed activity counts naturally.
- If this were synthetic, retain authentic cron/anacron scheduling, but ensure the combined background-family counts arise from those schedules and the collection window rather than fixed per-host quotas. The five-row anacron lifecycle itself does not need arbitrary extra noise.
