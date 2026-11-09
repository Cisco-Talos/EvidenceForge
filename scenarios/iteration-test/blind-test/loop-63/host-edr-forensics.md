# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 91
**Synthetic-Confidence Score:** 82

## Executive Summary

Most endpoint evidence is internally coherent: Windows process trees, Linux SSH/PAM sequencing, and macOS fork/exec identity transitions show considerable source awareness. The deciding defect is repeated backwards allocation of macOS native process identity versions across newly created processes, supported by both wall-clock and monotonic timestamps and present on both Macs; this is substantially stronger evidence than behavioral tidiness or source completeness.

## Evidence For Synthetic

- [hard_contradiction] **Native macOS process identity allocation runs backwards.** In `data/MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson`, line 75 creates PID `64190` with `event.fork.child.audit_token.pidversion=88` at `16:00:08.553321Z`; line 77 creates PID `64367` with version `70` at `16:02:01.753084Z`. The corresponding child `start_time` values agree with those later creation times, and `mach_time` increases from `25142605279704` to `25145322074016`. These are new child identities, not old processes merely appearing in later records. Apple's upstream XNU allocates new-process identity versions from the shared incrementing `nextpidversion` counter. [Apple XNU fork implementation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_fork.c)
- [hard_contradiction] **The same defect recurs independently on the second Mac.** In `data/MAC-MROSS-02.meridianhcs.local/macos_endpoint_security.ndjson`, line 34 creates PID `21882`, version `42`, at `13:42:47.073295Z`; line 38 creates PID `22291`, version `39`, at `13:47:08.148869Z`. Lines 92 and 96 repeat the pattern: PID `44126`, version `83`, at `15:47:08.753533Z`, followed by PID `45089`, version `81`, at `15:57:28.381371Z`. Each pair has increasing native `mach_time`, increasing `global_seq_num`, and creation-consistent child `start_time`. This is the same underlying indicator, counted once in the score rather than inflated into several separate defects.

## Evidence For Real

- **Windows interactive process ancestry is credible and preserves session ownership.** `data/WS-MCHEN-01.meridianhcs.local/windows_event_sysmon.xml` events beginning at lines 200, 245, and 290 show `winlogon.exe` PID `7192` → `userinit.exe` PID `7204` → `explorer.exe` PID `7208`. `userinit` and Explorer share user `MERIDIANHCS\marcus.chen`, `LogonId=0x6c37b70`, and terminal session `1`; the parent switches from SYSTEM-owned winlogon to the user's process naturally.
- **Cross-source process relationships survive normalization.** The same chain appears in `data/WS-MCHEN-01.meridianhcs.local/ecar.json`, lines 8, 10, and 11. Security 4688 at `windows_event_security.xml:386` names Explorer as `NewProcessId=0x1c28`, creator `ProcessId=0x1c24`, and subject logon `0x6c37b70`; these are decimal PIDs `7208` and `7204`. Source timestamps differ slightly rather than conflicting in identity.
- **Linux SSH records have reasonable operational sequencing.** `data/DB-PROD-01.meridianhcs.local/syslog.log:89` reports the TCP peer `10.10.1.21:44955` at `15:21:49.737983Z`; lines 90–92 progress through accepted password, PAM session open, and logind session `277757`. Lines 108–109 close that same SSH PID `1068713` and remove the same logind session at about `16:00:27Z`.
- **Failures are not silently converted to successful sessions.** `data/DB-PROD-01.meridianhcs.local/syslog.log:117–119` shows connection, failed password for `svc_mgmt`, and pre-authentication closure on the same PID/tuple. In `data/MAC-MROSS-02.meridianhcs.local/ecar.json:371,414,419`, failed local attempts explicitly carry `outcome=failure` and `session_lifecycle=attempt_failed`, rather than claiming a successful live session.
- **macOS records distinguish process lifetime from executable image.** `data/MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson:1–3` follows PID `42158` from a launchd fork through xpcproxy to Terminal, preserving its lifetime start while changing executable identity. Lines 4–7 then create the login and zsh descendants. These are materially more realistic than treating every exec as an unrelated process creation.
- **Binary hash formatting and local identity stability hold up.** Across parsed Sysmon records, the 1,108 SHA1, MD5, and SHA256 values each have their expected hexadecimal lengths; 1,097 IMPHASH values also have the expected length. Within a given host, repeated Event 1 occurrences of the same image path did not vary their recorded hash set. Windows version differences between hosts were not treated as defects.

## Detailed Analysis

### Inputs, provenance, and method

Actual inputs were the complete neutral briefing `/private/tmp/log-study-if4zptfd/host-prompt.md`, the inventory beneath `/private/tmp/log-study-if4zptfd/data`, and the supplied endpoint files within that directory. All shell execution used the explicit neutral working directory `/private/tmp/log-study-if4zptfd`; parsing used system `python3`, not a project environment. Commands quoted in logs were inspected as text and were not executed.

I parsed all 24 endpoint `ecar.json` files: 37,089 rows, including 2,219 PROCESS/CREATE, 2,049 PROCESS/TERMINATE, 150 PROCESS/MODIFY, 995 USER_SESSION/LOGIN, 555 USER_SESSION/LOGOUT, and 27,430 FLOW/CONNECT rows. The observed eCAR window is approximately `2026-11-02 13:00:01Z` through `18:59:52Z`. I parsed the supplied Windows Security/Sysmon XML event structures, all 317 native macOS Endpoint Security rows, and sampled actual Linux syslog/session/history content after counting 3,991 syslog rows. I inspected both macOS zsh histories and the native Unified Log rows. Network directories were inventoried but their records were not analyzed; the FLOW discussion here concerns normalized endpoint evidence, not a completed independent Zeek audit.

External reference use was limited to official Apple upstream XNU source and Microsoft documentation: `kern_proc.c`, `kern_fork.c`, and `kern_exec.c` under `apple-oss-distributions/xnu` (plus the Apple `darwin-xnu` result returned by the same constrained search), Microsoft's Sysmon documentation, and Microsoft's Security 4688 reference. A GitHub-domain-filtered reference search also returned unrelated non-primary result snippets; these were not used as evidence. No task-project public pages were sought or read. No repository files, scenario files, worklogs, prior results, or other reviewers' reports were accessed. Inherited workspace operating instructions were present as an environment limitation; they were not used to identify the data's origin or support any scored finding.

All data citations use physical, one-based file lines. XML citations point to the opening `<Event>` line unless a particular field line is specified. Findings describe the supplied export, without assuming it is an untouched vendor export or that every possible event family was collected.

### Deciding native macOS identity defect

`audit_token.pidversion` is not a user ID, audit-session ID, POSIX session ID, or per-file execution count. Apple's process lookup uses it together with PID to authenticate process identity, and the upstream fork implementation assigns a fresh child's version using the shared incrementing `nextpidversion` counter. Exec also refreshes process identity, so old processes can quite normally retain lower versions while other processes execute; I did **not** flag that situation. [Apple process identity implementation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c), [Apple fork implementation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_fork.c), [Apple exec implementation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_exec.c)

The problematic records are specifically fresh `event.fork.child` identities:

| Host | Earlier creation | Later creation | Other ordering evidence |
|---|---|---|---|
| MAC-MROSS-01 | ES line 75: PID 64190, version 88, 16:00:08.553321Z | ES line 77: PID 64367, version 70, 16:02:01.753084Z | `mach_time` 25142605279704 → 25145322074016; `global_seq_num` 74 → 76 |
| MAC-MROSS-02 | ES line 34: PID 21882, version 42, 13:42:47.073295Z | ES line 38: PID 22291, version 39, 13:47:08.148869Z | `mach_time` 56048809759080 → 56055075572856; `global_seq_num` 33 → 37 |
| MAC-MROSS-02 | ES line 92: PID 44126, version 83, 15:47:08.753533Z | ES line 96: PID 45089, version 81, 15:57:28.381371Z | New-child `start_time` values reproduce the same wall-clock ordering |

Ordinary record delivery reordering does not explain agreement between native wall time, native monotonic time, child lifetime start, and source sequence order. PID reuse also does not explain fresh identities drawing smaller global versions. Counter wrap would require billions of intervening identity allocations and is not a credible repeated explanation for these nearby low-valued sequences. The records declare message `version=11`; this finding does not depend on assigning a particular marketing release to that message version.

A privacy transform could conceivably have rewritten native identity versions, but no such transformation is documented in the supplied inputs. That alternative would still mean the supplied native identity fields cannot be interpreted with their source semantics. This limitation keeps verdict confidence below certainty, while the repeated source-native contradiction supports a score in the rubric's 81–100 range.

### Windows process, session, and hash checks

The visible Windows tree includes source-appropriate service ancestry rather than indiscriminately placing everything beneath Explorer. For example, `data/DC-01.meridianhcs.local/windows_event_sysmon.xml:846` places SYSTEM `taskhostw.exe` PID `3712` beneath `svchost.exe` PID `2352`; Security 4688 at `windows_event_security.xml:1556` confirms `NewProcessId=0xe80` and creator `0x930`. On WS-MCHEN, Explorer subsequently starts `mstsc.exe /v:MAIL-FIN-01` at Sysmon event line 335, with matching normalized ancestry at `ecar.json:12`.

Windows sessions are not all one type. The parsed WS-MCHEN Security data has 18 type-3 logons, seven type-5, two type-9, two type-7, and one type-2. DC-01 has 164 type-3, 117 type-5, and three type-10 logons. That distinction fits a workstation versus a domain infrastructure host better than a single homogeneous logon stream. Different counts between source families were not scored merely for failing to match exactly.

I scanned eCAR object/actor references against visible same-object process creation and termination records. This did not reveal references more than one second before a visible creation or after a visible termination. The analogous Sysmon ProcessGuid scan did not reveal a same-source dependency timestamp outside a visible create/terminate interval. These are bounded checks, not proof that every conceivable lifecycle rule holds. Missing pre-window creation and post-window termination records were treated as neutral.

Microsoft documents process GUIDs as durable correlation keys and 4688 creator/target fields as distinct contexts; the comparisons above respect those roles rather than equating every subject with the newly created process's owner. [Microsoft Sysmon reference](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon), [Microsoft Security 4688 reference](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688)

### Linux and macOS behavioral interpretation

Linux sudo messages include invoking principal, TTY, working directory, target root account, command, and separated PAM open/close phases. For example, DB-PROD syslog lines 4–7 show lina.nguyen's `find` invocation at `13:03:41.688391Z`, PAM opening approximately 111 ms later, and closure at `13:03:47.946203Z`. Cron/sysstat, irqbalance, multipath, and other daemon records provide background behavior. These records support plausibility without requiring a particular Linux distribution from the hostname alone.

Both Macs show local terminals and remote SSH as different ancestry/session contexts. I did not require Linux PAM/systemd rows from the Macs, treat normalized eCAR LOGIN as a native ES event, or call successive exec images duplicate lifetimes. MAC-MROSS-01 Unified Log line 2 says policy **would not allow** MeetingAssist; that statement was not treated as proof of successful execution or as sufficient evidence of denial followed by successful effects. Thin Unified Log coverage alone was not penalized.

MAC-MROSS-02 includes repeated `cat` reads of Office/PDF-like paths, such as `ecar.json:306,348,354`, and corresponding native command observations. Such usage is unusual for interactive document consumption but could be automation or intentional byte inspection; I did not make it a scored authenticity indicator. Similarly, domain spelling, compact activity, lack of mistakes, and complete correlations were excluded from the score.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| hard_contradiction | macOS Endpoint Security native process identity | Both Macs; multiple new-child allocation inversions, with exact examples above | Decisive: claimed native identity versions contradict chronological new-process allocation semantics. Counted as one recurring defect family. |

## Realism Score by Category

- **Field format accuracy:** 7 — XML/JSON structures and hashes are convincing, but macOS native identity semantics have a significant defect.
- **Temporal patterns:** 7 — Many realistic phase delays and durations; native identity allocation contradicts the otherwise coherent macOS timestamps.
- **Cross-source correlation:** 9 — Sampled Windows ancestry, PID/logon relationships, and normalized process identities align well; no broad visible lifecycle break was found by the bounded scans.
- **Behavioral realism:** 8 — Distinct service, workstation, shell, and administrative activity; unusual document-byte reads remain explainable.
- **Environmental consistency:** 8 — Host/source roles and platform-specific session evidence are generally credible; no coverage-only penalty applied.

## Recommendations

- If this were synthetic, allocate macOS native process identity versions in final host execution order from one host-wide identity allocator shared by fork and exec, while preserving unchanged identities on observations of an existing execution. Verify fresh-child allocation against monotonic event time and lifetime start, rather than simply sorting already-numbered rows afterward.
- If these native fields were transformed during sanitization, document that transformation and preserve ordering semantics in replacement identity versions. This would make the export's interpretation explicit and prevent an avoidable native-identity contradiction.
