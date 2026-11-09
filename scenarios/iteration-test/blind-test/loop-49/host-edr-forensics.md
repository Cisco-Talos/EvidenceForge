# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 93  
**Synthetic-Confidence Score:** 82

## Executive Summary

Most endpoint relationships are credible: Windows process identities correlate across sources, Linux SSH sessions have ordered authentication and session evidence, and macOS records distinguish forks from successive executable images. However, four reversals in newly allocated macOS process audit-token versions conflict with the native kernel allocation semantics; this concrete identity/timing contradiction drives the synthetic verdict, rather than the completeness or narrative of the activity.

## Evidence For Synthetic

- [hard_contradiction] In `MAC-MROSS-02.meridianhcs.local/macos_endpoint_security.ndjson`, successive **new fork children** receive decreasing `audit_token.pidversion` values: line 44 → 47 has 69 → 47; line 80 → 82 has 84 → 72; line 101 → 105 has 95 → 88; and line 117 → 120 has 111 → 97. Their event times, child `start_time` values, and `mach_time` all advance. These are not later observations of older processes. Apple's upstream XNU `forkproc` allocates the child version using a shared atomic increment, so these substantial backward steps are inconsistent with native allocation. See the full comparisons and qualification below.

## Evidence For Real

- Across the ten Windows hosts, 894 of 895 Sysmon Event 1 records have a Security 4688 counterpart with the same host, numeric PID, executable path, and command line. This is useful positive evidence of coherent process construction, not evidence against authenticity because it is complete.
- The visible process lifecycle checks found no Sysmon dependent event more than 0.5 seconds outside a matching visible ProcessGUID lifetime, including parent references. Normalized eCAR actor references likewise did not precede a visible process creation or follow its visible termination by more than 20 milliseconds in the checked records. Pre-window parents and post-window exits were treated neutrally.
- `DB-PROD-01.meridianhcs.local/syslog.log`, lines 44–47, shows source `10.10.1.21:44816`, sshd PID `1048269`, connection at `13:47:50.510924Z`, accepted password at `13:48:06.604116Z`, PAM opening at `13:48:06.723068Z`, and logind session `277109` at `13:48:07.409876Z`. Its later PAM close and session removal are present at `14:38:41.861681Z` and `14:38:42.692384Z`.
- macOS provides meaningful fork/exec separation. On MAC-MROSS-01, ES lines 8–10 show PID `42160` forked with the inherited zsh image, then executing `/usr/bin/id`, then exiting; the creation time remains constant across the exec. eCAR lines 15–16 represent the same process lifetime using CREATE followed by MODIFY with `operation=exec`. Treating the initial inherited zsh image as an erroneous `id` process name would be incorrect.
- User/tool differences are visible. Windows `marcus.chen` has `mstsc.exe /v:...` activity and `runas.exe /netonly`; Linux `lina.nguyen` has git, build, editor, and container commands; Maya's Macs show Terminal versus iTerm-specific launch chains. These distinctions are more plausible than one undifferentiated cross-platform process pool.

## Detailed Analysis

### Input provenance and limits

Actual local inputs were the complete neutral briefing at `/private/tmp/log-study-pdlkpnp9/host-prompt.md` and files under `/private/tmp/log-study-pdlkpnp9/data`. I inventoried the supplied data; parsed all 20 Windows XML files (19,030 Security and 11,785 Sysmon events), all 23 eCAR files (35,805 rows), and both ES files (126 and 157 rows); and examined native macOS Unified Log entries, both zsh histories, and selected Linux syslog records. This was an endpoint review, not an exhaustive network-protocol assessment.

Public reference access used Apple developer documentation, Microsoft Learn, and direct raw URLs in Apple's official XNU repository. Searches used actual domain filters. No repository files, authored scenarios, prior assessments, other reviewers' outputs, or project documentation were accessed. Generic inherited repository/environment instructions were an unavoidable limitation of the reviewing environment and were excluded from origin inference. Filesystem copying times, sanitized domains, and commands as executable instructions were excluded; all commands appearing in logs were treated as inert data.

The macOS export declares ES message `version=11` and wrapper `schema_version=1`. These do not independently identify an exact macOS release. I therefore avoided undocumented release-specific schema claims, and distinguished native ES fields from normalized eCAR fields.

### Native macOS process-identity allocation

The strongest finding uses only newly created children in `event.fork.child`, avoiding a common mistake of comparing old actor/parent tokens observed at different times. In MAC-MROSS-02's ES file:

| ES lines | First fork child | Later fork child | Child pidversion | mach_time, first → later |
|---|---|---|---|---|
| 44 → 47 | `14:22:52.776507Z`, PID 29633 | `14:24:42.387235Z`, PID 30060 | 69 → 47 | 56106546636168 → 56109177293640 |
| 80 → 82 | `15:00:21.710528Z`, PID 38957 | `15:23:41.846670Z`, PID 41771 | 84 → 72 | 56160521052672 → 56194124320080 |
| 101 → 105 | `16:05:46.686677Z`, PID 45878 | `16:25:23.065029Z`, PID 47721 | 95 → 88 | 56254720480248 → 56282953560696 |
| 117 → 120 | `17:12:27.393377Z`, PID 52334 | `17:19:29.440742Z`, PID 53037 | 111 → 97 | 56350737441048 → 56360866577808 |

All times are on 2026-11-02. Each child's `start_time` equals its corresponding fork time. Per-type sequence counters also advance (16→17, 28→29, 35→36, 40→41), as do global counters (43→46, 79→81, 100→104, 116→119). The observed order therefore has several independent representations.

Apple's native implementation declares the shared `nextpidversion` and assigns a new fork child's `p_idversion` using `OSIncrementAtomic(&nextpidversion)`; its process code maps `proc_pidversion` to that identity field. This supports an implementation-based inference that the four backward allocations are incompatible with ordinary native process identity assignment. [Apple XNU fork implementation](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/kern/kern_fork.c), [Apple XNU process identity implementation](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/kern/kern_proc.c).

This is not a counter that restarts for each login or parent. Both launchd and interactive-shell children are allocated from the shared kernel sequence. A wall-clock correction does not explain increasing Mach time; out-of-order export does not explain the children's own creation times; and missing records would create gaps, not reverse allocations. Counter wraparound is not a credible explanation for repeated decreases between these small values within hours.

There is one material alternative: an undocumented sanitization/export stage may have replaced audit-token version values or modified process timestamps. That would explain a defect in an otherwise real input, so the verdict is not certain. The briefing permits privacy sanitization but does not establish that these native identity fields were renumbered. This qualification is why the score is just inside the 81–100 band rather than near 100. MAC-MROSS-01 did not show the same new-fork ordering reversals.

### Windows process and logon evidence

The Windows population includes expected parent relationships such as services.exe→service processes, SearchIndexer.exe→SearchFilterHost.exe, and winlogon.exe→userinit.exe→explorer.exe. Process lifetimes and parent identities were substantially coherent in the checks described above. The sole unmatched exact Sysmon/4688 process key was DC-01 PID `3944`, dllhost.exe at `14:12:02.1940901Z`; one unmatched record does not establish a collection defect.

Logon types are differentiated: domain controllers contain network/service sessions and remote interactive sessions, while workstations also show local interactive and unlock activity. I excluded reserved SYSTEM/service logon IDs and unlock reuse when checking account/session chronology. No ordinary-account 4688/4689/4648 event was more than one second before its earliest matching visible non-unlock 4624 or after its latest matching visible 4634 in that check. These are bounded consistency results, not proof that every account transition is authentic. Microsoft's definition of creator versus target identity was respected. [Microsoft 4688 field documentation](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688).

### Linux and macOS interpretation safeguards

Linux sudo evidence includes the invoking user, root command, PAM open/close, and corresponding eCAR child process. For example, DB-PROD-01 syslog lines 1–3 identify sudo PID `1043495`, invoking `lina.nguyen`, and `/usr/bin/lsblk`; eCAR lines 2–3 distinguish the sudo process from root's lsblk child.

For macOS, a changed executable image did not reset the process lifetime, a responsible token was not treated as a parent token, and a policy log was not treated as proof of a successful child execution. Apple defines `start_time` as fork creation time and describes ES notifications as reports of events that have occurred; these semantics informed the reading. [Apple ES process start time](https://developer.apple.com/documentation/endpointsecurity/es_process_t/start_time), [Apple ES message semantics](https://developer.apple.com/documentation/endpointsecurity/es_message_t).

I did not penalize absent Sysmon event families, short Unified Log exports, lack of additional file-event subscriptions, out-of-window lifecycle endpoints, source matching completeness, or the compactness of suspicious activity. No native launch-item activation or command effect was inferred merely from a path, registration attempt, shell history, or policy message.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| hard_contradiction | macOS Endpoint Security process audit tokens | Four backward allocations among new fork children on MAC-MROSS-02 | Decisive native identity/timing defect; supports 82 despite generally credible endpoint relationships. Undocumented sanitization remains an alternative. |

## Realism Score by Category

- **Field format accuracy:** 7 — Most source fields parse and have plausible meanings, but native audit-token allocation values contradict their kernel semantics.
- **Temporal patterns:** 6 — Broad lifecycle ordering works; four new-fork identity allocations disagree with advancing event and Mach clocks.
- **Cross-source correlation:** 9 — Strong Windows process alignment and credible Linux/macOS identity correspondence in the checked records.
- **Behavioral realism:** 8 — Platform-specific launch chains and user/tool variation are present; no narrative-cleanliness penalty applied.
- **Environmental consistency:** 8 — Windows, Linux, and Mac source distinctions are maintained; exact macOS release and any identity sanitization remain unspecified.

## Recommendations

- If this were synthetic, allocate macOS native process identity versions in actual fork/exec execution order from a host-wide sequence, then carry the values unchanged into ES tokens and corresponding normalized identity fields. Recheck the four cited fork pairs after any changes to event scheduling.
- If the values were deliberately anonymized from real telemetry, document that transformation explicitly and preserve the relevant ordering semantics, or identify the field as a surrogate rather than a native `pidversion` value. That would materially change this assessment.
