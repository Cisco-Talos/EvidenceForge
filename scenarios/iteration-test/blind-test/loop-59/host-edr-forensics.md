# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 90
**Synthetic-Confidence Score:** 76

## Executive Summary

The host evidence is unusually competent at preserving process, session, and cross-source ownership, but the macOS process identity values and repeated exact timing boundaries suggest constructed telemetry. The strongest concern is the allocation pattern of native-looking Endpoint Security `audit_token.pidversion` values; a second, independent concern is repeated exactly 1 ms shell-command serialization. Neither the completeness of the suspicious activity nor the amount of source coverage affected this assessment.

## Evidence For Synthetic

- [schema_or_format] **Native process identity allocation appears to follow activity groups rather than kernel chronology.** In `MAC-MROSS-02.meridianhcs.local/macos_endpoint_security.ndjson`, line 2 records a new `/bin/sh` image with PID 19775 and target `pidversion=32` at `13:20:29.882486Z`. Line 3 subsequently introduces a new child PID 21356 with `pidversion=10` and `start_time=13:37:11.846603Z`; lines 4–5 give that process versions 11 and 12 through successive execs. Another long separation occurs between line 80 (`15:25:40.511790Z`, new SSH image version 89) and lines 81–83 (`15:46:42.616461Z` onward, newly forked PID 44085 progressing through versions 83–85). These are newly allocated identities, not later observations of old processes. Apple's public XNU implementation allocates fork and exec versions from the same incrementing counter. This recurring low-number block ordering is strongly inconsistent with an ordinary native export, though an undocumented identity-remapping transformation would be an alternative explanation.
- [distribution_texture] **Exactly 1 ms separates prior command exit and next command fork seven times on one Mac.** In that same file, line pairs 18→19, 21→22, 24→25, 85→86, 88→89, 94→95, and 97→98 each differ by precisely `0.001000` seconds. For example, `/usr/bin/sw_vers` exits at `13:37:33.437983Z` and the next command forks at `13:37:33.438983Z`; `/usr/bin/dscl` exits at `15:48:48.136163Z` and the next command forks at `15:48:48.137163Z`. The timestamps retain microsecond precision, making the repeated exact offset conspicuous. Scripted commands can be close together, but do not naturally guarantee the same elapsed time across these different operations and two bursts.
- [weak_signal] **The shell activity has a limited recurring diagnostic vocabulary across two distinct Macs.** Both zsh histories repeatedly cycle through `sw_vers -productVersion`, `id`, `uname -a`, `ps aux`, `df -h`, `du -sh /Users/maya.ross/Documents`, and the identical PDF `find` command. On MAC-MROSS-01, history lines 10, 18 repeat the latter command; on MAC-MROSS-02 it appears at lines 8, 19 and also in the remote-session ES records. Repeated commands are normal, especially for the same user, so this contributes little independently. Its relevance is the repeated command pool together with the exact serialization artifact, not any particular suspicious storyline.

## Evidence For Real

- The Windows process model is substantially coherent. Across all ten supplied Sysmon XML files, I parsed 1,001 Event 1 records. For 271 child records whose parent also has a visible Event 1, the parent's ProcessGUID resolves to matching PID, image and user. I found no contradictory values in those comparisons.
- Sysmon process lifetimes are coherent where both endpoints are visible: among events carrying `ProcessGuid`, my check found no same-GUID record with a System timestamp before its visible Event 1 or after its visible Event 5. This is a bounded check of those fields, not a claim about every possible source or target reference.
- Windows activity includes normal service accounts, SearchIndexer/SearchProtocolHost relationships, interactive shells, network logons, workstation locks/unlocks, and service-specific evidence. For example, `WS-MCHEN-01/windows_event_sysmon.xml` around lines 70–115 describes PID 6792 SearchProtocolHost under PID 6072 SearchIndexer, with SYSTEM identity and system integrity. Security 4688 identifies the same child as hexadecimal `0x1a88` and parent `0x17b8` at `13:00:32.0907713Z`.
- macOS records distinguish fork, exec, and exit rather than treating every exec as a fresh PID. `MAC-MROSS-01/macos_endpoint_security.ndjson` lines 1–7 preserve PID 42154 through launchd→xpcproxy→Terminal images and introduce separate login and shell children. MAC-MROSS-02 lines 6–12 separately model iTermServer, login, ShellLauncher and zsh. The terminal types are not merely renamed copies.
- Linux evidence contains plausible session, privilege and maintenance relationships. `APP-INT-01/syslog.log` lines 3–6 show SSH connection→public-key acceptance→PAM session opening→logind session creation. Lines 12–15 show a sudo command and its PAM open/close messages. Linux EDR also contains cron→shell→sysstat executable relationships and normal systemd user-manager/terminal trees.
- Negative lifecycle findings were not manufactured from the collection boundaries. For example, the first two DB-PROD-01 EDR rows are terminations, and its first syslog row is an SSH session close. Those may close activity that began before collection and are neutral.

## Detailed Analysis

### Input provenance and method

I read the supplied neutral briefing and files under `/private/tmp/log-study-0kwedkcm/data` only. I did not inspect repository files, scenario definitions, prior assessments, other reviewers' outputs, or inventories outside the data directory. Generic inherited operating instructions were available as environment context and were not treated as evidence of the dataset's origin. Parsing used system `python3` from an explicit `/private/tmp` working directory. External verification was limited to official Microsoft documentation and direct Apple upstream source URLs.

I inventoried the supplied host files, parsed all eCAR files, all ten Windows Security/Sysmon XML pairs, and both complete macOS Endpoint Security files (119 and 180 records). I examined actual Linux syslog and EDR entries, macOS histories, and Unified Log entries. Counts and parent/lifecycle checks were automated; interpretation and the examples below came from reading individual records. Network protocol authenticity was outside this endpoint-focused assessment.

### Windows process and session evidence

The Windows records offer convincing detail beyond process names: correlated parent identities, decimal/hexadecimal PID representations, process metadata, logon IDs and integrity levels. Microsoft's [Sysmon documentation](https://learn.microsoft.com/en-au/sysinternals/downloads/sysmon) describes ProcessGUID as a process correlation value and Events 1 and 5 as process creation and termination evidence; that is the role used in my checks.

I found no eCAR actor use more than one second before that actor's visible process creation or more than one second after its visible termination, across the supplied eCAR files. This test uses stable object/actor identities rather than PID alone. In Windows Security records, I also found no 4688 whose `SubjectLogonId` pointed to an already visibly logged-off session according to the checked 4634 records. The checks do not prove complete authenticity, but they remove several common endpoint contradictions.

The logon-type mix varies plausibly by host. WS-MCHEN-01 has 34 visible successful logons: 22 type 3, six type 5, two type 2, two type 7 and two type 9. WS-SMARTINEZ-01 includes three type 7 unlock logons and three each of 4800/4801. The domain controllers carry far more authentication and filtering-platform events than the workstations. I did not score missing Sysmon classes, absent full boot sequences, or a lack of any particular EDR product.

DC-01 has 121 type 5 logons in this slice, with SYSTEM/LOCAL SERVICE/NETWORK SERVICE accounting for 50/37/34. This deserves operational investigation in a real environment, but service restart and audit policy context are unavailable. Reusing the reserved well-known system logon identities is not itself a contradiction, and I did not add this count to the synthetic score.

### macOS native identity and timing

The ES-shaped records declare `schema_version=1` and message `version=11`; they include audit tokens, parent/responsible tokens, start times, executable stat identities, fork children, exec targets and exit status. I distinguished these native-looking records from the normalized eCAR rows and did not apply Linux or Windows event requirements to them.

The PID-version concern is about **allocation**, not the ordinary observation of an old identity after a new one. MAC-MROSS-02's newly forked iTerm process starts seventeen minutes after the shell with version 32, but starts at version 10. The launchd parent consistently retains PID 1, version 1 and start time `2026-10-06T13:00:00Z`. A reboot therefore does not explain the identity reset in the supplied records. Later newly created process groups similarly use lower blocks than groups already observed much earlier.

Apple's upstream [fork implementation](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/kern/kern_fork.c) assigns new process versions by incrementing `nextpidversion` (around line 924). Its [exec implementation](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/kern/kern_exec.c) updates the identity from that counter again (around lines 6630–6638). This supports a kernel-semantic concern, not an assertion that version values must be contiguous in a filtered collection. Small scheduling inversions are possible; missing events can create gaps. Neither normally explains repeated much later newly created groups receiving these much lower values. The exact OS build and any privacy remapping are not documented, so I score this conservatively as a strong source-native identity inconsistency rather than declaring an absolutely impossible kernel event.

The seven exact 1 ms gaps provide a separate temporal tell. They occur after commands with differing runtimes and repeat in bursts roughly two hours apart. A pasted script could explain rapid succession; the deterministic microsecond boundary remains unusual. At logout, lines 170–172 also place cat, shell and login exits at `18:56:58.339699Z`, `.339700Z` and `.339701Z`. A single group of near-simultaneous exits would not be sufficient, so I treat that as supporting texture rather than an independent hard contradiction.

The macOS evidence also contains several things that should **not** be penalized. `MAC-MROSS-01/macos_unified_log.ndjson` line 2 says a policy would not allow the MeetingAssist path. It does not demonstrate that a child actually executed; I did not infer successful effects from the message. Different executable images under one PID are properly represented as exec transitions. A change in group/session fields between fork and exec can reflect legitimate session setup, so I did not score those changes. Sparse Unified Log coverage is neutral without an explicit collection contract.

### Linux behavior and collection limits

Linux sources show realistic-looking maintenance families: sysstat, anacron, resolver fallback, queue forwarding, snap activity, sudo and SSH/PAM/logind sequences. APP-INT-01 EDR lines 1–2 expose a `sysstat` shell under cron and its `/usr/lib/sysstat/debian-sa1` child. WS-LNGUYEN-01 EDR lines 27–30 show a user systemd manager and gnome-terminal-server/shell hierarchy, consistent with desktop rather than server activity.

Many Linux syslog messages are terse and recurrent, but repeated daemon message text is expected in production. I have not treated repetition of a service's own message template, selected-source gaps, early session closes, or long-lived processes surviving collection as authenticity defects. The decisive weaknesses remain localized to native Mac identity allocation and temporal texture, rather than broad claims that every host looks wrong.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| schema_or_format | macOS Endpoint Security | Repeated new-process identity blocks on MAC-MROSS-02, including 32→10 and 89→83 across substantial time gaps | Largest effect: values are inconsistent with ordinary kernel allocation chronology; undocumented remapping remains possible |
| distribution_texture | macOS Endpoint Security | Seven exit-to-next-fork transitions across two bursts | Strong supporting evidence: identical 1 ms gaps despite microsecond timestamp precision |
| weak_signal | macOS shell history and ES | Same user's two Macs | Small effect only: narrow recurring diagnostic vocabulary reinforces the timing texture but is explainable by user habits |

These indicators are not counted as numerous independent defects merely because they appear in multiple records. No generator identity leak or conclusive cross-source lifecycle inversion was established.

## Realism Score by Category

- **Field format accuracy:** 7 — Rich and mostly coherent Windows/Linux/Mac shapes, weakened by native Mac identity allocation semantics.
- **Temporal patterns:** 6 — Variable activity and plausible lifetimes, but repeated exact 1 ms sequencing is conspicuous.
- **Cross-source correlation:** 9 — Checked Windows parents, process lifetimes and normalized actor identities are coherent; no demonstrated inversion.
- **Behavioral realism:** 7 — Credible platform-specific trees and maintenance behavior, with a repetitive Mac diagnostic command pool.
- **Environmental consistency:** 8 — Host roles and desktop/server distinctions are broadly plausible; no unsupported missing-source penalty applied.

## Recommendations

- If this were synthetic, allocate native Mac process versions using a host-wide chronological identity owner, accounting for fork and successive execs. Preserve existing versions in later snapshots instead of allocating independent blocks to activity groups. If the values were intentionally remapped for privacy, document the remapping so consumers do not mistake them for native kernel counters.
- If this were synthetic, replace repeated exact exit-plus-1 ms shell starts with timing grounded in actual scripted versus interactive execution. Maintain causal ordering while varying scheduling and user delay according to the activity.
- If this were synthetic, diversify the recurring Mac diagnostic activity only where the recorded user/task context supports it. Preserve legitimate repeated routines; avoid treating arbitrary command variety as a substitute for correct process and session semantics.
- Retain the coherent parent identities, fork/exec distinction, platform-specific terminal chains, sudo/SSH session phases and window-boundary handling already present.
