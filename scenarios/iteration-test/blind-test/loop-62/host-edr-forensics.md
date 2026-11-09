# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 94
**Synthetic-Confidence Score:** 84

## Executive Summary

Most of the endpoint evidence has credible process ancestry, identity continuity and source-specific timing, including Windows process/logon lifecycles and distinct macOS fork versus exec observations. However, both Mac Endpoint Security exports allocate new native audit-token PID versions backwards in event time, repeatedly and by large margins; this is a concrete kernel-identity contradiction, rather than a judgment about the activity's narrative or collection completeness. That narrowly located but repeated defect drives the score into the rubric's hard-contradiction band.

## Evidence For Synthetic

- [hard_contradiction] Newly allocated macOS process identity versions move backwards. In `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson:76`, an exec target receives `pid=64190,pidversion=89` at `2026-11-02T16:00:08.559082000Z`; line 77 then records a *new fork child* `pid=64367,pidversion=70` at `16:02:01.753084000Z`. These are allocations in the event payload, not observations of two old processes. `mach_time` also increases, from `25142605417968` to `25145322074016`, and `global_seq_num` advances from 75 to 76. Kernel PID-version allocation uses a shared incrementing counter for forks and exec transitions; the native values cannot describe this chronological sequence without an extraordinary counter wrap unsupported by the records.
- [hard_contradiction] The same defect occurs four times on the second Mac. `MAC-MROSS-02.meridianhcs.local/macos_endpoint_security.ndjson:36` gives a new exec target version 44 at `13:42:47.084365000Z`; line 38 gives a new fork child version 39 at `13:47:08.148869000Z`. Additional visible transitions go 85 → 81 (lines 94/96), 93 → 88 (102/105), and 117 → 94 (115/117). The last pair spans nearly seven minutes and also has increasing native `mach_time` and sequence numbers. This is not merely JSON row reordering or ordinary retention of a parent's older identity.
- [distribution_texture] The native identifier population reinforces the allocation problem. Extracting only `event.fork.child.audit_token.pidversion` and `event.exec.target.audit_token.pidversion` yields exactly 93 distinct consecutive values 10–102 on Mac 01 and 126 distinct consecutive values 10–135 on Mac 02, each used once. Allocation values are packed across all visible activity even while the chronological order reverses. I treat this as supporting texture of the same identity defect, not a separate independent reason to inflate the score, and do not penalize the existence of complete matching records.

## Evidence For Real

- Windows process creation records retain matching command, PID and parent identity across source families. On `WS-MCHEN-01.meridianhcs.local`, Sysmon Event 1 beginning at `windows_event_sysmon.xml:335` creates `mstsc.exe /v:MAIL-FIN-01`, PID 7220, parent 7208 (`explorer.exe`), user `MERIDIANHCS\marcus.chen`, LUID `0x6c37b70`. Security 4688 beginning at `windows_event_security.xml:429` reports the same executable/command and hexadecimal PID `0x1c34`, with parent `0x1c28` and the same LUID. The timestamps differ by approximately 225 ms, a credible source-specific offset.
- That RDP client also has consistent termination evidence: Sysmon Event 5 at `windows_event_sysmon.xml:688` and Security 4689 at `windows_event_security.xml:1263` place its exit at `13:21:16.5965379Z` and `13:21:16.5982840Z`, respectively. This is useful lifecycle evidence rather than an isolated creation-only tree.
- The Mac exports distinguish process lifetime from executable image. Mac 01 Endpoint Security lines 1–7 show launchd forking PID 42158, successive exec images `xpcproxy` and Terminal, then separate login and zsh processes; they do not mislabel each exec as an unrelated new process. Mac 02 lines 1–10 have an appropriately different iTerm2 → iTermServer → login → ShellLauncher → zsh chain.
- Linux authentication evidence has source-specific detail. `MAIL-EDGE-01.meridianhcs.local/syslog.log:26–27` reports public-key authentication for aisha.johnson followed by the PAM session opening, using the same sshd PID 1986991; line 128 closes that session. The key fingerprint is retained on later connections by the same user (for example lines 131 and 230), while another user's key differs (line 79).
- Background Linux process trees include concrete service behavior. `APP-INT-01.meridianhcs.local/ecar.json:1–3` shows cron → `/bin/sh -c 'command -v debian-sa1 > /dev/null && debian-sa1 1 1'` → `debian-sa1 1 1`, with matching parent/actor identities and child termination. The corresponding CRON message is visible in `syslog.log:1`.

## Detailed Analysis

### Scope, provenance and method

Inputs actually accessed were the supplied neutral `host-prompt.md` briefing and files under `/private/tmp/log-study-yflye15q/data`, plus primary Apple documentation/source for interpreting native audit-token semantics. No project files, authored scenario, TODO/worklog, earlier assessment or other reviewer report was accessed. Generic inherited operating instructions were present as an environment limitation and were not used as evidence of data origin. Parsing used system `python3` with `/private/tmp` as its explicit working directory.

I inventoried the supplied data files; parsed all 10 Windows Sysmon XML exports, their Windows Security companions, all 24 host eCAR exports and both complete Endpoint Security exports; and read representative Linux syslog/history and Mac Unified Log entries. The Sysmon files contain 972 Event 1 creations, 826 Event 5 terminations, 8,025 Event 3 connections, 1,192 Event 22 DNS events and additional access, registry, module, thread and file observations. Those counts describe the inspected population and are not, by themselves, authenticity indicators. Native macOS observations comprise 135 ES rows on Mac 01 and 182 on Mac 02, each declaring `schema_version=1` and message `version=11`.

### Native macOS audit-token allocation

The decisive distinction is between an already-running process's token appearing later and a *new identity allocation* appearing in a fork child or exec target. An old parent retaining version 16 while a child has version 83 is normal; a newly forked child receiving 70 after a completed exec received 89 is the contradiction here.

The official XNU fork implementation assigns the new child's identity version using `OSIncrementAtomic(&nextpidversion)`; the exec implementation likewise obtains a new value from `nextpidversion` and installs it on the process. See [Apple XNU fork allocation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_fork.c) and [Apple XNU exec identity update](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_exec.c). Apple's [Endpoint Security process documentation](https://developer.apple.com/documentation/endpointsecurity/es_process_t) identifies the audit token as process identity information; this is not an arbitrary application-local ordinal.

The reproducible allocation inversions are:

| Host | Earlier newly allocated identity | Later newly allocated identity | ES file lines |
|---|---|---|---|
| Mac 01 | 16:00:08.559082, PID 64190, exec target version 89 | 16:02:01.753084, PID 64367, fork child version 70 | 76 / 77 |
| Mac 02 | 13:42:47.084365, PID 21882, exec target version 44 | 13:47:08.148869, PID 22291, fork child version 39 | 36 / 38 |
| Mac 02 | 15:47:08.759441, PID 44126, exec target version 85 | 15:57:28.381371, PID 45089, fork child version 81 | 94 / 96 |
| Mac 02 | 16:05:43.435835, PID 45873, exec target version 93 | 16:46:08.479104, PID 49760, fork child version 88 | 102 / 105 |
| Mac 02 | 17:12:27.399142, PID 52334, exec target version 117 | 17:19:16.577170, PID 53019, fork child version 94 | 115 / 117 |

All times are on 2026-11-02 and UTC. `mach_time` increases through every listed pair; `global_seq_num` also increases. The process histories continue under the same long-lived launchd identities. Nothing visible supports a reboot, a native counter overflow or mixed machine attribution explaining these transitions. Native sequence time therefore corroborates wall-clock time instead of offering a clock-adjustment explanation.

A privacy transformation could theoretically replace native identifiers with application-assigned values. No such transformation is declared, and the same data exports expose those values specifically as native `audit_token.pidversion`. If they were deliberately remapped, the finding would instead mean that the export no longer preserves native PID-version semantics. I am not using sanitized names, changed domains or copied filesystem timestamps in this judgment.

The eCAR stream carries the same identity values, which limits an explanation based solely on a corrupted ES serializer: Mac 01 `ecar.json:294` reports PID 64190's exec `previous_pid_version=88,pid_version=89`; its later inbound SSH process chain carries lower versions in both representations. Matching between these sources is positive for correlation, but it cannot repair a shared value that violates its declared native meaning.

### Windows process, session and hash consistency

The inspected Windows records generally make good use of canonical identities: decimal Sysmon PIDs align with hexadecimal Security PIDs, parent GUIDs are stable, user logon IDs carry through relevant creations, and ordinary system/service processes use appropriate service principals. The Marcus Chen RDP client example above is an explicit creation/termination check across two Windows sources.

Across all Windows Sysmon exports, grouping Event 1 records by host, image and reported file version produced 265 groups, with no group containing conflicting `Hashes` strings. This is an internal consistency result; it does not authenticate any binary against an external catalog. I also checked visible Sysmon process GUID relationships for dependent records preceding a visible creation or following a visible termination, and visible child creation preceding its visible parent creation. Those checks found no violations. These results support the realism of the Windows lifecycle layer and constrain the verdict: the demonstrated hard defect is not a dataset-wide claim that every host process tree is broken.

Windows Security checks also found no 4688 creation assigned to a non-reserved LUID after that LUID's visible 4634 session termination. Processes and sessions with pre-window starts or post-window endings were not counted as missing lifecycle evidence. Nor did I infer a collection defect from unequal counts of source-specific events.

### Linux endpoint and shell texture

The Linux subset has plausible service, scheduler, authentication and user-command detail. The mail host's repeated public-key sessions preserve key identity, PAM open/close records are process-linked, and the cron child hierarchy uses a service principal instead of treating every shell command as an interactive user action. The database history includes operational commands such as MySQL status queries and logs; the developer workstation history includes repositories, builds, editors and SSH. These are log-visible role distinctions, although they are not proof of authenticity.

History file ordering alone was not scored: history can be written by multiple concurrent shells, and a literal `exit` followed later by another history entry does not establish that one terminated shell continued executing. Regular CRON timing was likewise treated as plausible scheduler behavior. I did not require boot records, every Sysmon event family or additional endpoint products beyond the visible collection.

### Mac session and policy interpretation

The Mac process chains retain per-exec image changes and distinct local versus remote shells. Mac 01's Unified Log line 2 says `ASP: Security policy would not allow process: 62445, /Applications/MeetingAssist.app/Contents/MacOS/MeetingAssist`; I did not translate that text into successful child execution, or infer command effects that are absent from the visible data. Similarly, creating and later deleting the endpoint-inventory plist was not equated with an immediate service start or stop. Sparse Unified Log coverage was neutral, as required by the collection assumptions.

The Mac 01 interactive SSH `id` process at ES lines 93–94 lasts approximately 87 seconds, considerably longer than other visible `id` executions. Slow account lookup or a delayed process can explain an isolated long runtime, so I did not score that observation as a contradiction. The identity counter finding above does not rely on this weaker timing impression.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on synthetic-confidence score |
|---|---|---|---|
| hard_contradiction | Native macOS Endpoint Security audit tokens | Five backwards new-allocation transitions across both Mac hosts; native sequence and monotonic time agree with wall time | Dominant evidence: violates source-native process-identity allocation rather than merely looking unusual |
| distribution_texture | Native ES PID-version population, corroborated in normalized eCAR values | Complete consecutive ranges 10–102 and 10–135 despite chronological allocation inversions | Supports the same underlying identity defect; not independently double-counted |

## Realism Score by Category

- **Field format accuracy:** 7 — Windows and Linux structures are credible; native Mac identity values violate their field semantics.
- **Temporal patterns:** 6 — Most observed lifecycles are coherent, but five native identity-allocation sequences contradict event time and monotonic time.
- **Cross-source correlation:** 9 — Explicit Windows creation/termination examples align well; the Mac sources agree on values even where those values are wrong.
- **Behavioral realism:** 9 — Distinct application, development, administrative and service activity is visible without needing narrative-based penalties.
- **Environmental consistency:** 9 — Platform-specific process chains and service behavior are generally credible; no source-coverage penalty was applied.

## Recommendations

- If this were synthetic, allocate Mac native PID versions at the actual chronological fork/exec transition using one host-wide monotonic identity counter. Keep an existing process version stable until an exec or other applicable native identity transition; do not assign values by activity-group preparation order.
- If this were synthetic, validate the *newly allocated* `fork.child` and `exec.target` versions against both `time` and `mach_time`, then ensure eCAR projects those corrected values. A later observation of an old parent's token must remain legal, so the check should target allocations rather than every token occurrence.
- If native identifiers were deliberately anonymized, disclose that transformation and preserve ordering semantics, or mark remapped values as normalized identities instead of presenting them as native audit-token PID versions. This would let downstream analysts distinguish export transformation artifacts from impossible endpoint behavior.
