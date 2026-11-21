# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 74
**Synthetic-Confidence Score:** 63

## Executive Summary

The endpoint evidence is substantially realistic: Windows process and authentication identities correlate well, Linux administrative activity has credible process ownership, and the Mac exports distinguish fork, exec, and exit correctly. I lean synthetic because both Macs exhibit conspicuously compact, similarly initialized process-identity and executable-inode numbering patterns despite showing long-running systems and files with varied installation histories. These are distribution indicators, not demonstrated impossible lifecycles; privacy-related identity remapping remains a credible alternative explanation and limits my confidence.

## Evidence For Synthetic

- [distribution_texture] Both native Mac Endpoint Security exports begin their newly observed process identities at `audit_token.pidversion=12` and then cover every integer through their respective final versions: **12–112, 101 distinct values**, on `MAC-MROSS-01`, and **12–132, 121 distinct values**, on `MAC-MROSS-02`. These counters are embedded in process audit identities, separately from the export's `seq_num` and `global_seq_num`. The first file shows launchd's `start_time` as `2026-10-21T13:00:00.000000Z`; the second shows `2026-10-06T13:00:00.000000Z`. The same small starting value and uninterrupted numbering of the selected visible activity across two systems with such different, older lifetimes look more like a freshly numbered activity model than naturally aged host identities. I treat this as a probabilistic pattern, not proof that any individual token is impossible.
- [distribution_texture] Executable inode identities also occupy unusually compressed ranges across diverse software. The 29 executable paths represented in `MAC-MROSS-01.../macos_endpoint_security.ndjson` occupy inode numbers **2,992,447–2,992,542**, a span of only 95; the 32 paths on `MAC-MROSS-02` occupy **2,509,761–2,509,868**, a span of 107. These groups include operating-system utilities, complete application bundles' executables, SSH components, and user-installed software. For example, Mac 01 records `/usr/bin/id` at inode `2992456`, birth time May 31; `/usr/bin/uname` at `2992484`, birth time August 10; and Google Chrome at `2992509`, birth time October 15. The narrow catalog-like allocation across unrelated installation histories repeats on both hosts. Image deployment or identity sanitization could contribute, so this is not labeled a hard contradiction.

## Evidence For Real

- All **873 Sysmon Event 1** records could be matched within their host to a Security **4688** record using PID and executable path; those matched records also agreed on command line. Host-level totals differ slightly because some Security creations lack a corresponding visible Sysmon creation, which I do not penalize under the collection rules.
- Windows process GUID references remain internally consistent with executable path and PID wherever a visible Sysmon creation establishes the identity. Repeated executions of the same exact executable path retain the same hash set within each host. Machine-specific Sysmon GUID prefixes differ between hosts, rather than sharing one universal prefix.
- Direct scans of eCAR actor relationships found no actor use before its visible creation or after its visible termination. I also found no overlapping visible create-to-terminate intervals for different process identities sharing one host PID. These checks explicitly permit processes that began before the window or end after it.
- Windows authentication supports actual session behavior: the visible events include network, interactive, service, unlock, reconnect/disconnect, and lock/unlock evidence. Matching non-system Sysmon process logon IDs agree with visible initial successful Security logon GUIDs and principals; later Type 7 unlocks were treated as session reuse, not new session initiation.
- Linux sudo ownership is unusually well supported. Across **103** sudo command records matched by PID to eCAR process creations, each parent shell kept a consistent sudo `TTY` value. Sudo command, PAM session-open, and PAM session-close records have separate timestamps and identify the invoking user and elevated account.
- Mac 01's Terminal launch at `13:07:32` progresses from launchd to xpcproxy to Terminal, followed by login and zsh. Mac 02's iTerm launch at `13:12:07` includes iTermServer and ShellLauncher. Exec changes the execution image and token version while retaining the process PID and start time; the normalized evidence uses `PROCESS/MODIFY` for those image transitions.
- The Linux hosts show service-specific background behavior, including mail delivery processes on mail hosts, Samba activity on the Linux file server, and desktop services on workstations. The recurring `debian-sa1 1 1` jobs are corroborated by cron messages and have an expected ten-minute schedule; scheduled periodicity itself is not an authenticity defect.

## Detailed Analysis

### Examination scope and method

I examined only the supplied data directory, comprising 116 files from 23 endpoint directories plus network and perimeter source directories. The endpoint population consists of ten hosts with Windows event XML, eleven with Linux-style syslog, and two with native Mac exports. There are 36,715 eCAR rows, 17,375 Windows Security events, 11,315 Sysmon events, 322 Mac Endpoint Security notifications, and six Mac Unified Log records. The visible interval is approximately November 2, 2026, 13:00–19:00 UTC.

I parsed the endpoint JSON and XML, inspected actual records and shell histories, and checked process creation, termination, parent/actor ownership, binary identity, and authentication relationships. I examined network-related fields where they supported host interpretation; this is an endpoint assessment, not a full protocol validation. File modification times, sanitized domains, missing selected Sysmon types, and mere completeness of matching did not enter the score.

### Windows process trees and binary identities

The Windows records contain plausible parent classes and user context. For example, on `WS-MCHEN-01`, Sysmon records Firefox PID `7184` at `2026-11-02T13:03:50.5186568Z`, with parent explorer PID `6780`, user `MERIDIANHCS\\marcus.chen`, logon ID `0x6c29844`, and terminal session `5`. Its command line opens an internal web page. Service activity includes services.exe children, WMI provider hosts, COM surrogates, task hosts, and indexing helper processes; it is not composed exclusively of user shells or attacker utilities.

For each host, I compared Sysmon GUID references against visible Event 1 identities and compared repeated same-path process hashes. Neither check established a changing PID/image behind one established GUID or changing hashes for repeated executions of the same path on that host. This is positive evidence of a coherent endpoint model, although a careful generator could also achieve it.

All 873 visible Sysmon process creations matched Security 4688 PID/path identities and command lines. Sysmon `TimeCreated` preceded the matching Security timestamp by roughly 0.035–0.649 seconds across the comparisons. This consistent ordering is worth documenting, but I did not score it as impossible: source emission and processing delays can differ, and these offsets alone do not establish a causal failure.

PID reuse was checked using visible create and terminate intervals rather than assuming monotonically increasing PIDs. No established overlapping same-PID lifetimes were found. I did not demand boot records or pre-window parent creations.

### Windows logon sessions

I compared non-system process logon IDs to initial successful Security 4624 entries, excluding Type 7 unlocks from the set of session-creation boundaries. That distinction matters: a process launched before a later unlock is not evidence that the process preceded its original logon. In the comparisons supported by visible initial logons, account names and logon GUIDs agreed and no process preceded its initial session by more than one second.

The workstations also contain 4800/4801 lock/unlock records, and relevant hosts contain 4778/4779 reconnect/disconnect records. I did not equate a disconnect with logoff. Similarly, unmatched logouts near the beginning and unmatched logins near the end are compatible with the slice-of-time collection and did not affect the verdict.

### Linux activity and shell evidence

The Linux evidence includes realistic distinctions between a privileged sudo monitor process and its elevated command child, plus different SSH, local-login, graphical-terminal, and daemon parentage. For example, `DB-PROD-01/syslog.log` records sudo PID `1366413` at `13:01:01.185662Z`, invoking `/bin/systemctl is-active mysql` as root for maya.ross, followed by a PAM session open at `13:01:01.257511Z` and close at `13:01:03.031146Z`.

The matched sudo records passed a useful terminal-consistency check: 103 matched command records across the Linux hosts showed no parent shell randomly switching its reported terminal between its sudo children. Command histories also preserve pipeline structure in corresponding endpoint evidence. On `DB-PROD-01`, Lina's `pt-query-digest ... | head -50` history entry has separate eCAR children for the query tool and head under bash PID `1380858` at `15:03:41.718Z` and `15:03:41.783Z`, respectively.

Background cadence has a plausible reason where it is regular. For example, APP-INT-01's cron message at `13:05:00.241545Z` records the sysstat command, and the endpoint evidence contains the resulting `debian-sa1 1 1` execution at `13:05:01.488Z`, followed by comparable ten-minute executions. I did not treat the common count of 36 executions over six hours as a synthetic tell for an explicitly scheduled job.

Some history commands probe client/package names as if they were services, such as `systemctl is-active smbclient` on APP-INT-01. A real administrator can make such a query or have custom units, and no command output proves an impossible result. I therefore did not use those commands as a scored authenticity indicator.

### Mac process and policy semantics

The Mac Endpoint Security records declare message `version=11` and carry fork, exec, and exit payloads. I evaluated their visible identities and lifecycles without assuming that they were Linux audit messages or substituting normalized eCAR semantics for the native records.

Mac 01 PID `25527` is first observed as a launchd fork at `13:07:32.811343Z`, then execs xpcproxy at `13:07:32.820534Z` and Terminal at `13:07:32.835499Z`. It retains its original start time while its audit-token version changes `12→13→14`. Mac 02 similarly preserves PID `88255` while it transitions from ShellLauncher to zsh at `13:12:07.954212Z`. These are correct distinctions between a process lifetime and successive executable images. Native file identities also remain consistent on repeated observations; I found no one inode mapped to conflicting executable paths in these exports.

SSH is distinct from local terminal login. Mac 02's Unified Log reports keyboard-interactive/PAM acceptance from `10.10.1.41:61289` at `14:24:38.278034+0000`; the native process evidence subsequently shows the remote session shell at `14:24:38.487065Z`, with audit session `100003`, separate from the local shell's `100002`. Mac 01's public-key acceptance at `16:02:08.147068+0000` likewise precedes the observed remote zsh exec at `16:02:08.299168Z`.

The Mac 01 Unified Log includes an AppleSystemPolicy message at `15:42:09.009673+0000` saying policy would not allow PID `42008`, MeetingAssist. I found no normalized process/effect evidence claiming successful execution of that named binary. I did not generalize this into an expectation that every prompt represents denial, or demand unavailable authorization event families.

Launch-item file operations were interpreted separately from execution. An eCAR write/create to a LaunchDaemons plist does not by itself prove registration, and removal does not by itself prove an unload. I found no basis for scoring a contradiction by collapsing those stages.

The remaining concern is metadata texture rather than these lifecycle semantics. Despite launchd lifetimes beginning 12 and 27 days earlier, both native files introduce their visible process-token numbering at 12 and use every subsequent value, and both executable catalogs occupy barely more than a hundred inode numbers. For Mac 01, `/usr/bin/id`, `/usr/bin/uname`, Google Chrome, and Homebrew curl all fall inside this small inode neighborhood despite differing file birth dates and software provenance. Mac 02 independently shows the same compact-allocation shape, including user-library iTerm components and multiple third-party applications.

A real image deployment can preserve old birth times; a sanitizer can remap process and file identifiers. Neither pattern alone proves fabrication, and I have not alleged a verified native-schema violation. Their repetition in two different classes of native identity is nevertheless enough to shift this endpoint assessment toward synthetic, while the successful semantic checks keep the score well below the hard-contradiction band.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on synthetic-confidence score |
|---|---|---|---|
| distribution_texture | Mac Endpoint Security process audit tokens | Both Macs; complete visible ranges 12–112 and 12–132, alongside older launchd lifetimes | Primary indicator: similarly initialized, uninterrupted token numbering resembles identities allocated for the selected activity set. Sanitization remains an alternative. |
| distribution_texture | Mac Endpoint Security executable file identities | 29 and 32 executable paths; inode spans 95 and 107 | Secondary indicator: compact identity neighborhoods encompass unrelated system, application, and user-installed binaries with varied birth histories. Deployment/sanitization could partly explain it. |

No demonstrated hard contradiction, impossible visible process lifetime, or verified source-native schema defect was established. No points were added merely for full cross-source matching, source omissions, attack narrative structure, or absence of visible mistakes.

## Realism Score by Category

- **Field format accuracy:** 9 — Detailed native and normalized structures are internally credible; no verified schema defect established.
- **Temporal patterns:** 8 — Process, SSH authentication, and scheduled-task ordering are plausible within the visible window.
- **Cross-source correlation:** 9 — Windows creation identities and command lines align; Linux ownership and Mac exec/lifetime distinctions hold up.
- **Behavioral realism:** 8 — Host roles, administrative pipelines, desktop applications, services, and session types are reasonably differentiated.
- **Environmental consistency:** 6 — Repeated compact Mac process/file identity allocations sit uneasily with the visible older host and installation histories.

## Recommendations

- If this were synthetic, retain process audit-token version allocation as part of each host's pre-window identity history. Avoid initializing two otherwise independent, long-running hosts at the same small version and allocating versions only across the activities chosen for export. Keep those identities separate from collector sequence numbers.
- If this were synthetic, derive executable inode identities from a fuller per-host filesystem inventory and installation history. Preserve stable identities while allowing realistic separation among system files, large application bundles, and user-installed software; do not merely expand or randomize an inode number independently on every observation.
- If this were sanitized production data, document any remapping of native process-version and inode fields. Such remapping could explain the two principal findings and would materially change this assessment without requiring additional event-source coverage.
