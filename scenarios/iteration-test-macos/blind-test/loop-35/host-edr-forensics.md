# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 79
**Synthetic-Confidence Score:** 43

## Executive Summary

The endpoint evidence is substantially production-like: Windows process identities and binary hashes are stable, visible process lifecycles are coherent, and macOS telemetry distinguishes forks, successive executable images, and process termination. A shared, narrow administrative vocabulary across otherwise different Linux hosts raises a moderate texture concern, but I did not establish an impossible endpoint lifecycle or source-native contradiction sufficient to confidently classify the collection as synthetic.

## Evidence For Synthetic

- [distribution_texture] Linux administrative context has a conspicuously small shared vocabulary: all 115 sudo command records across 11 hosts use exactly seven working directories, with counts `/srv/app` 20, `/home/deploy` 19, `/home/ops` 17, `/tmp` 17, `/etc` 16, `/var/log` 14, and `/home/admin` 12. The same context vocabulary occurs on mail servers, a proxy, workstations, and a laptop. For example, `MAIL-EDGE-01.meridianhcs.local/syslog.log:52,55,58,61` changes PWD from `/home/ops` to `/home/deploy` to `/etc` and back to `/home/deploy` over approximately 23 seconds on the same `pts/2`; `PROXY-01.../syslog.log:2,15,31,35` and `WS-LNGUYEN-01.../syslog.log:23,45,89,92` use the same small pool. This resembles independently sampled command/context templates. Standardized administrative practices or shared troubleshooting tooling remain a plausible real-world explanation; it is not an impossibility.
- [weak_signal] Both Mac shell histories heavily reuse the same diagnostic vocabulary under the same user: `id`, `sw_vers`, `uname`, `pwd`, `ls`, `du`, `df`, `ps`, `find`, and `dscl`, interspersed with SSH. In `MAC-MROSS-01.../zsh_history/maya.ross.zsh_history:1-3,9-15,19-22` and `MAC-MROSS-02.../zsh_history/maya.ross.zsh_history:1-9,12-19`, repeated discovery commands dominate. This modestly reinforces the command-pool impression, but one administrator working on two Macs can readily produce it. I give this little independent weight.

## Evidence For Real

- A visible Windows process has compatible evidence across three views: `WS-MCHEN-01.../ecar.json:4` creates SYSTEM `dllhost.exe`, PID 7248, parent PID 5896, at 13:01:10.619; its Sysmon creation has the same PID, image, COM argument, and SYSTEM logon `0x3e7` (`windows_event_sysmon.xml:53` identifies the PID). Security event 4688, record 948724, records `NewProcessId=0x1c50` and creator `ProcessId=0x1708`, matching decimal 7248 and 5896. The eCAR termination is later, at 13:05:32.422 (`ecar.json:9`).
- The Mac native export models executable changes within one process lifetime. `MAC-MROSS-01.../macos_endpoint_security.ndjson:1-3` shows launchd forking PID 42186, followed by `/sbin/launchd` → `/usr/libexec/xpcproxy` → Terminal, with pidversions 10 → 11 → 12 and preserved process start time. Lines 4-10 then show Terminal → login → zsh and a separate fork/exec/exit for `/usr/bin/id`. This avoids treating each executable image as a new unrelated process.
- Linux SSH evidence contains a plausible sequence rather than just an isolated acceptance line. `APP-INT-01.../syslog.log:2-5` records source `10.10.1.35:59357`, public-key acceptance, PAM session open, and logind session 376201. Lines 83-84 close that session roughly an hour later using the same sshd PID 2931384 and the same logind session identifier.
- Windows logon activity varies with apparent endpoint role. DC-01 has 132 Type 3, 129 Type 5, and two Type 10 successful logons; the user workstation WS-MCHEN-01 has six Type 5, two Type 3, one Type 2, one Type 9, and two Type 7. Workstation lock/unlock events and reconnect/disconnect events are represented. These are more plausible than a universal logon mix.
- Checks of all supplied Sysmon process-creation hashes found no within-host case in which the same image path changed its hash. Across the supplied eCAR process identities, I found no visible child creation referencing an already terminated parent, and no later actor use beyond a 200 ms allowance after the actor's visible termination.

## Detailed Analysis

### Scope and method

I examined only the supplied data directory. It contains eCAR telemetry for 23 hosts: 35,078 records, including 2,012 PROCESS/CREATE and 1,890 PROCESS/TERMINATE records. I parsed all 11,651 supplied Sysmon XML events and 18,797 Security XML events, reviewed source-native examples, checked visible identity/lifecycle relationships, and inspected Linux syslog, Mac native JSON exports, and shell histories. Counts describe the supplied collection, not a claim that it contains every event a host generated.

The analysis treats pre-window process/session starts and post-window closures as neutral. Source filtering and collection differences can explain unmatched rows; I did not count absence of an arbitrary event family or unmatched collection coverage as synthetic evidence.

### Windows processes and sessions

The process hierarchy includes service-control children, COM surrogates under svchost, search workers under SearchIndexer, interactive applications under explorer, and console processes associated with csrss. For example, WS-DRAMIREZ-01's Sysmon creation at 13:04:00.317 places Citrix SelfService under explorer PID 6460; 13:10:37.302 places SearchFilterHost under SearchIndexer PID 5868. These are differentiated parent roles rather than a single generic parent.

The MCHEN dllhost example above aligns Security's hexadecimal PID fields, Sysmon's decimal fields, and eCAR's process identity. Its Sysmon `UtcTime=13:01:10.515` precedes Security's `TimeCreated=13:01:10.6850673Z` by approximately 170 ms, which is compatible with distinct observations; I do not require identical timestamps.

Visible repeated logon IDs on workstations were explainable by unlock activity. WS-PPATEL-01 Security records 358957 and 359197 reuse `0xda71218` for a Type 2 logon at 16:43:05.8294609 and Type 7 at 17:27:26.9627353. WS-MCHEN-01 similarly uses `0x6d87737` for Type 2 and a later Type 7. I did not count those as duplicate independent sessions. Reserved service logon IDs also require different interpretation from a newly allocated interactive logon ID.

I checked Sysmon ProcessGuid relationships for creation after a visible parent's exit, parent creation after child creation, and later same-GUID dependent evidence after process termination. No such visible ordering contradiction was found. That finding is bounded to observed identities; it does not establish that every unobserved process was valid.

### Linux administrative behavior

The strongest concern is contextual texture, not an invalid command or impossible security event. Across the 115 sudo command records, routine read-only checks recur: `apt list --upgradable` and `apt-cache policy openssl` appear five times each; several resource, package, socket, and timer queries occur four times. Those commands are ordinary and can reflect shared procedures. The concern is their combination with a seven-directory PWD vocabulary spanning 11 different hosts and rapidly changing directories on a single TTY.

For contrast, system activity has useful specificity. APP-INT's cron sysstat entries are minute-aligned with subsecond scheduling variation (`syslog.log:1,62,82,106`), while WS-LNGUYEN's equivalent cadence is offset to minute 03 (`:5,21,49,72`). Cron periodicity is expected and is not itself evidence of synthesis. SSH acceptance, PAM, logind, sudo opens/closes, and differing account UIDs contribute credible endpoint structure.

I did not allege a PWD contradiction merely because shell history does not display every `cd`: history can be filtered, incomplete, or originate from different shell contexts.

### macOS identity and collection semantics

Both native Endpoint Security exports declare message `version=11`. The visible records distinguish `fork`, `exec`, and `exit`; eCAR additionally represents credential/session changes as PROCESS/MODIFY. I did not interpret every MODIFY as a new process.

Across the native exports, I checked `(pid, pidversion)` against executable path and found no instance where that exact identity silently described different paths. Repeated `(st_dev, st_ino)` executable identities did not describe conflicting paths either. Terminal/login/zsh on MAC-MROSS-01 and iTerm/iTermServer/login on MAC-MROSS-02 are explicitly different chains: the latter is visible at `macos_endpoint_security.ndjson:4-10`.

`MAC-MROSS-01.../macos_unified_log.ndjson:2` contains a kernel AppleSystemPolicy message at 15:42:13.191716 about MeetingAssist. It is a policy message, not proof of a successful exec, and I did not infer a successful child or file effect from it. The sparse Unified Log export is not scored as unrealistic coverage by itself. I also make no claim about unverified release-specific native fields solely because their structure is unfamiliar.

### Weight of evidence and uncertainty

The shared command/context palette is a concrete distribution observation, but it is compatible with a centrally managed environment and one administrator's habits. None of the observed suspicious activity was scored for narrative neatness, completeness, linearity, or lack of retries. The absence of a demonstrated hard contradiction, together with credible identity and lifecycle behavior, keeps the score in the mixed/inconclusive band rather than the likely-synthetic band.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | Linux syslog sudo records | 115 command records across 11 hosts; seven PWD values | Moderate concern about reusable command/context sampling; shared operating procedures could explain it. |
| weak_signal | Mac zsh histories | Two hosts, same user, 41 total history entries | Small reinforcement from narrow repeated diagnostic vocabulary; not an independent contradiction. |

## Realism Score by Category

- **Field format accuracy:** 9 — Parseable source-shaped Windows XML and Mac JSON with consistent observed identity fields; no demonstrated native schema defect.
- **Temporal patterns:** 8 — Visible lifecycle ordering and differing source timestamps are coherent; host administrative activity retains some repetitive texture.
- **Cross-source correlation:** 9 — Sampled Security/Sysmon/eCAR process evidence agrees; broad visible lifecycle checks found no impossible same-identity ordering.
- **Behavioral realism:** 7 — Legitimate maintenance and application roles are credible, but Linux administrative context and Mac diagnostic vocabulary are narrow.
- **Environmental consistency:** 8 — OS-specific process chains and endpoint/server logon mixes are differentiated; shared administrative context remains somewhat generic.

## Recommendations

- If this were synthetic, preserve the existing process identity and lifecycle discipline. Add host- and operator-specific administrative working-directory continuity so commands on one TTY do not repeatedly hop among the same seven generic contexts without an apparent task relationship.
- If this were synthetic, broaden operational command habits according to the actual host role and user workflow, while retaining repeated commands where normal work calls for them. The improvement should address the observed shared context vocabulary, not add arbitrary event types or inflate collection volume.
