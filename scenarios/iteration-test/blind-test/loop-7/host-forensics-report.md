# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 83
**Synthetic-Confidence Score:** 66

## Executive Summary

The endpoint evidence is substantially more convincing in process identity, lifecycle ordering, and platform distinctions than in its Linux PID distribution. My strongest reason to judge it synthetic is a shared exact minimum PID increment of 940 in recurring cron processes across ten unrelated Linux hosts, with a pronounced point mass at that value. I did not establish an impossible process lifecycle or a hard native-schema contradiction; the verdict rests mainly on this repeatable distribution artifact, with a smaller macOS behavior-pattern concern.

## Evidence For Synthetic

- [distribution_texture] Ten Linux `syslog.log` files contain 36 `CRON` records each for `command -v debian-sa1 > /dev/null && debian-sa1 1 1`. Across their 350 successive within-host PROCID differences, **67 differences (19.1%) are exactly 940, every difference is at least 940, and no other individual difference occurs more than twice**. Each of the ten hosts exhibits the exact-940 increment at least five times. The concern is the identical PID-growth floor and large point mass across different workloads, rather than the entirely normal ten-minute cron schedule.
- [distribution_texture] The repeated increment forms conspicuous arithmetic runs. In `LT-MRIVERA-02.meridianhcs.local/syslog.log`, lines 57, 66, 77, 81, 88, and 95, the 14:05 through 14:55 UTC cron PIDs are `3178864, 3179804, 3180744, 3181684, 3182624, 3183564`. In `LOG-MON-01.meridianhcs.local/syslog.log`, lines 134, 141, 150, 157, 177, and 190, the 15:06 through 15:56 UTC PIDs are `711413, 712353, 713293, 714233, 715173, 716113`. These are examples of the same finding, not independent defects added to inflate the score.
- [weak_signal] On `MAC-MROSS-02`, all ten visible execs involving `/Volumes/` use `cat`, `ls`, or `tee`, including seven direct `cat` reads of PDF, XLSX, or DOCX files and a `tee` write of a DOCX. For example, Endpoint Security records PID `45881` executing `/bin/cat /Volumes/ClinicalResearch/Archive/2025/service-review.xlsx` at `16:05:48.670374Z` and PID `63836` executing `/usr/bin/tee /Volumes/Users/Downloads/draft.docx` at `18:42:09.886846Z`. This is possible as scripted testing or inspection, but it is a narrow and unusual texture for ordinary document access on a Mac that also visibly launches Word and Outlook. It receives little weight compared with the Linux PID finding.

## Evidence For Real

- All **933 Sysmon Event 1 records** have a Security 4688 counterpart on the same host and PID within five seconds. Among those joins, I found no image-path, parent-image, parent-PID, or command-line disagreements. Of these Sysmon starts, **925** also have an eCAR `PROCESS/CREATE` counterpart within five seconds, without image or parent-PID disagreement; the remaining eight are not treated as defects under the collection assumptions.
- Across all ten Windows Sysmon files, checks using process GUIDs found no visible dependent process references before the corresponding visible Event 1 or after its visible Event 5. Binary hashes remain stable for each image path within each host. Multiple hashes across hosts were not treated as contradictions because host builds can differ.
- Windows session evidence contains meaningful variety: interactive and network activity, service logons, explicit credentials, failed authentications, RDP disconnects, and workstation lock/unlock events. There are four Security 4800 and four 4801 records overall; a late type-7 unlock is compatible with a pre-window interactive session and is not a process-before-logon violation.
- Linux SSH evidence has sensible native phases. On `APP-INT-01`, `syslog.log` shows a connection from `10.10.1.32:51175` at `13:21:12.508569Z`, accepted public-key authentication for `priya.patel` at `13:21:13.987134Z`, a PAM session opening at `13:21:14.117499Z`, and logind session `228` at `13:21:14.739851Z`. eCAR records the corresponding successful SSH login at `13:21:15.577Z` with the same user, tuple, and session number.
- macOS records distinguish fork from successive exec images. On `MAC-MROSS-02`, the launchd-originated SSH chain uses PID `30028` through `xpcproxy`, `sshd-keygen-wrapper`, `sshd`, and `sshd-session`; subsequent authentication and user-shell processes have separate identities. The accepted authentication at `14:24:35.110736Z` precedes the user zsh exec at `14:24:35.242255Z`.
- Visible Linux administrative histories include role-appropriate commands and untidy details: database checks with both MySQL and PostgreSQL tools, Docker service work on `APP-INT-01`, `ll`, short diagnostic commands, and a literal `nev` entry. The observation is about the records' content, not an assumption that mistakes must occur in real incidents.

## Detailed Analysis

### Scope and method

I examined only the supplied data directory and assigned briefing. The endpoint collection spans approximately `2026-11-02 13:00–19:00 UTC`, with 23 eCAR host files containing **37,747 records**, ten Windows Security files containing **17,631 events**, ten Sysmon files containing **11,699 events**, eleven Linux syslog files containing **4,406 lines**, and two macOS Endpoint Security exports containing **324 records**, plus shell histories and the small Unified Log exports.

I parsed the Windows XML and endpoint JSON, inspected actual records, checked same-host process references, compared Security/Sysmon/eCAR process starts, inspected session transitions, and measured recurring Linux process-ID sequences. I did not infer dataset origin from filesystem timestamps, domain names, source completeness, or the shape of the suspicious narrative. Native schema details that cannot be independently verified from the declared export were not promoted to defects.

### Linux process identity distribution: primary finding

The recurring cron command provides a useful like-for-like sample of newly created processes at approximately ten-minute intervals. Hosts with the sample are `APP-INT-01`, `FILE-LNX-01`, `LOG-MON-01`, `LT-MRIVERA-02`, `MAIL-CLIN-01`, `MAIL-EDGE-01`, `PROXY-01`, `WEB-EXT-01`, `WS-LNGUYEN-01`, and `WS-OHADDAD-01`. `DB-PROD-01` has no such cron sample and was excluded rather than assigned a missingness penalty.

The number of exact-940 PID increments among 35 comparisons per host is:

| Host | Exact-940 increments |
|---|---:|
| APP-INT-01 | 5 |
| FILE-LNX-01 | 8 |
| LOG-MON-01 | 8 |
| LT-MRIVERA-02 | 12 |
| MAIL-CLIN-01 | 6 |
| MAIL-EDGE-01 | 5 |
| PROXY-01 | 6 |
| WEB-EXT-01 | 6 |
| WS-LNGUYEN-01 | 5 |
| WS-OHADDAD-01 | 6 |

Some intervals have larger and varied growth; this is not a claim that all PID sequences are uniform. The issue is the shared sharp lower boundary and repeated exact value beneath that otherwise diffuse distribution. A workstation, monitoring server, proxy, public web server, and mail servers can share a cron configuration; that does not naturally explain the same exact number of intervening PID allocations repeatedly becoming a floor across all of them.

For another directly inspectable example, `WS-OHADDAD-01/syslog.log` has PIDs `4071018`, `4071958`, `4072898`, and `4073838` at `16:16:00.097069Z`, `16:26:00.184899Z`, `16:36:00.110045Z`, and `16:46:00.228319Z`. The increments are all 940 despite timestamp jitter. The cron timestamps themselves are reasonable.

My inference is that the process identities may incorporate a common deterministic churn floor. This is a statistical authenticity concern, not an impossible PID value or proof of any specific implementation. A privacy transformation that deliberately remapped PID growth could also create such a pattern; no such transformation is established by the records. That uncertainty, and the strong lifecycles elsewhere, keep the score below the confidently-synthetic 81–100 band.

### Windows process trees, hashes, and source agreement

The process relationships inspected include SearchIndexer spawning search workers, services.exe spawning service processes, svchost-hosted infrastructure, WmiPrvSE administration, userinit/explorer session trees, and user-specific PowerShell/OpenSSH activity. The collection is not just a succession of isolated attacker process starts.

For a specific three-source join on `WS-AJOHNSON-01`, Security 4688 at `13:02:46.2523418Z` reports `SearchFilterHost.exe`, new PID `0x1440` (5184), creator PID `0x121c` (4636), parent `SearchIndexer.exe`, and SYSTEM logon `0x3e7`. Sysmon Event 1 at `13:02:46.1434289Z` gives PID 5184, parent PID 4636, the same command `SearchFilterHost.exe 0 828 0 0 0`, and matching identities. eCAR line 4 reports the same process at `13:02:46.391Z`. Small differences among source timestamps are plausible observation differences.

All parsed hash fields inspected have the expected hexadecimal lengths: 40 for SHA1, 32 for MD5 and IMPHASH, and 64 for SHA256. There were 1,064 Hashes-bearing Sysmon records; 1,053 included IMPHASH. I found no within-host same-image hash variation among process starts. I did not demand that all machines have identical binary hashes.

The GUID-based lifecycle check found no same-source create/terminate inversion. An additional eCAR check across the host files found no actor/object process occurrence more than one second before its visible creation or after its visible termination. This is a bounded consistency result, not proof that every process is represented or every possible semantic relationship is correct.

### Session interpretation

Pre-window state matters here. For example, `WS-MCHEN-01` has process activity under logon ID `0x6c29844` before a visible 4624 at `18:04:00.9719889Z`, but that 4624 is **type 7**, an unlock, not evidence that the session first came into existence at that time. I excluded it from causality findings. SYSTEM's shared `0x3e7` was likewise not treated as a newly created unique session on each service logon.

Linux SSH examples preserve the connection/authentication/PAM/logind progression and source tuple. A pre-window SSH session closing early in the collection is also ordinary slice-of-time evidence; I did not penalize those records for lacking an in-window opener.

### macOS process and document-access evidence

The native Endpoint Security exports declare `schema_version:1`, message `version:11`, and separate fork, exec, and exit notifications. I used the audit-token PID and pidversion, image transitions, parents, and start times together rather than treating every exec as a new PID. Recursively inspected executable file identities were internally stable: 33 distinct device/inode pairs on `MAC-MROSS-01` and 34 on `MAC-MROSS-02`, without changing serialized file objects for an identical pair in these exports.

The local Terminal/login/zsh and iTerm-related chains differ appropriately from the remote SSH chains. The macOS SSH example above has user-shell activity before its exit and transport/session cleanup, with the outgoing client on the other Mac also ending around the same session close. Unified Log entries are treated as messages from loginwindow or sshd-session, not as interchangeable Endpoint Security process notifications.

The mounted-document commands remain a weaker concern. On `MAC-MROSS-02`, seven binary-format document reads use `cat`, two directory operations use `ls`, and one write uses `tee`. They are rooted in the visible user zsh process, rather than attributed to Word or Outlook. The corresponding 19-line zsh history has no `/Volumes/` commands; `MAC-MROSS-01` has three such execs and none in its 27-line history. History exclusions, sourced functions, or automation can explain that absence, so I do not call it a required missing companion or a hard contradiction. The unusual repeated document-access tool choice is the scored observation.

The plist creation/deletion rows are not evidence by themselves that a job was activated or unloaded. I did not infer that removing a plist terminates its job, nor infer execution denial or success from a policy prompt.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | Linux syslog CRON PROCID | Ten hosts; 67 of 350 increments exactly 940; none below 940 | Primary and substantial: repeated common identity-growth boundary across different host roles |
| weak_signal | macOS ES and normalized process/file evidence | MAC-MROSS-02 mounted-share activity: seven cat reads of PDF/XLSX/DOCX and one tee DOCX write | Small: an unusually narrow tool distribution; scripted use remains possible |

No established hard contradiction, generator identity leak, or native-schema impossibility is included in the score. The two PID bullets describe one underlying issue.

## Realism Score by Category

- **Field format accuracy:** 9 — Parsed native and normalized records are internally well structured, with correctly sized hashes and coherent platform-specific identifiers.
- **Temporal patterns:** 7 — Lifecycle ordering is convincing; the repeated cross-host PID-growth boundary is an artificial-looking rate/identity pattern.
- **Cross-source correlation:** 9 — Windows process joins and inspected SSH sessions agree on identities, tuples, and ordering.
- **Behavioral realism:** 7 — Varied role-specific activity is present, with an unusually narrow shell-tool pattern for Mac document access.
- **Environmental consistency:** 8 — Windows, Linux, and macOS are meaningfully distinguished, although the shared Linux PID floor cuts across unrelated workloads.

## Recommendations

- If this were synthetic, remove the common exact PID-growth floor visible in recurring cron jobs. Newly allocated process IDs should reflect host-specific process churn and intervening workloads while preserving the existing identity and lifecycle joins. Do not change the legitimate ten-minute sysstat schedule merely to make it less regular.
- If this were synthetic, make the Mac document-access process distribution reflect the intended activity. Ordinary Word/Excel document work should have appropriate application-owned access; intentional command-line probing or scripted writes should retain their actual shell/script lineage. The specific concern is the repeated `cat`/`tee` treatment of binary document formats.
- Preserve the existing distinctions between fork and exec, pre-window state and newly established sessions, unlock and first logon, and source-native observation times. The consistency checks here give no basis for adding arbitrary gaps, broken joins, or timestamp noise.
