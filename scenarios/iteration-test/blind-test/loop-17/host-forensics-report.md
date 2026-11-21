# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 76
**Synthetic-Confidence Score:** 66

## Executive Summary

The endpoint activity is substantially more convincing than the executable filesystem metadata exposed by the macOS Endpoint Security records. Windows process/session relationships and Linux SSH evidence survive basic causality checks, but both Macs show the same unusual combination of densely allocated executable inode numbers, months of perfectly ordered birth timestamps, and a separate pair of adjacent directory identifiers; this repeated metadata texture tips my assessment toward synthetic without establishing an impossible process timeline.

## Evidence For Synthetic

- [distribution_texture] In `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson`, the 29 distinct executable paths observed in process, fork-child and exec-target objects occupy inode numbers **2,992,447–2,992,542**, a span of only 96 identifiers. Their birth timestamps span May–October 2026 and never decrease when sorted by inode. Examples include `/bin/ls` inode `2992447`, birth `2026-05-10T15:58:35.678529976Z`; `/usr/bin/login` inode `2992472`, birth `2026-07-20T16:43:46.943828860Z`; `/sbin/launchd` inode `2992491`, birth `2026-09-09T07:01:57.377461702Z`; and Homebrew curl inode `2992537`, birth `2026-10-15T00:00:00.000000000Z`. This is an unexpectedly compact chronological allocation for unrelated OS files, application bundles and a package-manager installation spread across months.
- [distribution_texture] The independent Mac repeats the pattern: the 31 distinct executable paths in `MAC-MROSS-02.meridianhcs.local/macos_endpoint_security.ndjson` occupy **2,509,761–2,509,868**, only 108 identifiers, again with zero inversions between inode order and birthtime order. `/usr/bin/uname` is `2509761`, born May 9; `/bin/zsh` is `2509783`, born July 25; the user-owned iTerm server is `2509820`, born October 15; `/sbin/launchd` is `2509863`, born October 29. Reproduction of this very narrow, chronologically sorted allocation across both hosts is stronger evidence than either example alone.
- [distribution_texture] Directory identities use a strikingly different but repeated arrangement. Exec `cwd` objects on MAC-MROSS-01 give `/` inode `2061341048677` and `/Users/maya.ross` inode `2061341048678`; MAC-MROSS-02 uses `2176108086486` and `2176108086487` respectively. Both pairs have identical directory size `128`, blocks `0`, mode `16877` and link count `1`, and each directory has all four filesystem timestamps identical. In particular, the adjacent directory identifiers coexist with executable inode populations near 2.5–3 million. Identical metadata strategies on both hosts resemble construction from separate directory and executable catalogs. Individual fields can be legitimate; the combined repeated arrangement carries the weight.
- [environment_or_collection_plausibility] Within each Mac's ES records, Apple system executables, third-party applications and user or Homebrew executables share the same `st_dev`: `2876` on MAC-MROSS-01 and `692` on MAC-MROSS-02. Examples are `/sbin/launchd` versus `/opt/homebrew/opt/curl/bin/curl`, and `/sbin/launchd` versus `/Users/maya.ross/Library/Application Support/iTerm2/iTermServer-3.7.6`. A typical contemporary Mac separates the system and writable data volumes. This strengthens the metadata concern but is secondary: the records do not include a mount table or OS version output, and an atypical deployment or sanitization could explain it.

## Evidence For Real

- Across the ten Windows Sysmon files, **900 of 901 Event 1 rows** have a Security 4688 partner with the same host, PID and image. All 900 paired command lines agree; the median absolute source timestamp difference is approximately **141 ms**, maximum **649 ms**. Different timestamps are consistent with separate observations of the same creation.
- GUID-based checks found no visible Sysmon dependent event preceding a matching process creation or following its matching termination in the fields checked. Likewise, eCAR actor references across the 23 endpoint files did not precede an observed actor creation or follow an observed actor termination. This is positive lifecycle evidence, not an authenticity penalty for completeness.
- `WS-MCHEN-01/windows_event_sysmon.xml` records Firefox at `2026-11-02T13:18:26.2852416Z`, PID `6808`, parent `explorer.exe` PID `6780`, user `MERIDIANHCS\marcus.chen`, integrity `Medium`, terminal session `5`, and a user-profile current directory. Its explicit internal wiki URL fits interactive use; Windows service processes instead use system identities and different parents.
- Windows logon coverage includes service and network logons as well as local interactive, remote interactive, NewCredentials and unlock activity. For example WS-AJOHNSON-01 has Type 2, 3, 5, 7, 9 and 10 successful logons, plus visible lock/unlock and RDP reconnect/disconnect families. It is not just a sequence of generic Type 3 events.
- Linux SSH logs distinguish transport arrival, authentication, PAM session opening and logind registration. In `LOG-MON-01/syslog.log`, PID `796663` receives `10.10.1.32:57204` at `18:58:26.122104Z`, accepts Priya Patel's public key at `18:58:32.760089Z`, opens PAM at `18:58:32.890517Z`, and registers logind session `434` at `18:58:33.519843Z`. The visible window ends shortly thereafter; an absent later close is not suspicious.
- The Mac ES records distinguish fork from exec and preserve a process lifetime across successive images. Terminal on MAC-MROSS-01 uses PID `25527` through launchd-child, xpcproxy and Terminal images; corresponding normalized eCAR records use CREATE followed by MODIFY operations. No incompatible image was found for the same native PID/pidversion identity in my checks.

## Detailed Analysis

### Scope and method

I examined only the supplied data directory. It contains 23 endpoint eCAR files, ten Windows Security/Sysmon pairs, Linux syslog and shell histories, and two Macs with ES, Unified Log and zsh history exports. The visible endpoint window is approximately **2026-11-02 13:00–19:00 UTC**. I parsed the JSON and XML, inspected representative native records, compared Windows process creations, and tested process actor/session ordering where the relevant identifiers were visible.

I did not infer missing pre-window starts from unmatched terminations or demand post-window closes. Source selection, differing record counts and missing Sysmon event families were not used as indicators. The assessment concerns endpoint authenticity; it is not an exhaustive network-protocol review.

### Windows process identities and session semantics

The source pairs show useful detail rather than merely similar process names. On WS-MCHEN-01, the `13:08:44.0500053Z` Sysmon Adobe service creation uses PID `6852`, parent services PID `5872`, `NT AUTHORITY\SYSTEM`, LogonId `0x3e7`, session `0`, system integrity and a system working directory. At `13:18:26.2852416Z`, Firefox has the user, parent and session described above. On the same host, generic service activity, browser launches, PowerShell, OpenSSH clients and console hosts have distinguishable command lines and parents.

Hashes remained stable for repeated image paths within each host's Sysmon Event 1 records. I found no parent GUID/PID/image disagreement where the parent's own Event 1 was visible. Comparing non-service Security 4624/4634 identifiers with 4688 session identifiers also produced no process creation before its visible session start or after its visible session end. These checks have limits: unmatched entities can be outside collection, and PID-only matching would require care about reuse. The Windows cross-source comparison therefore matched host, PID and image together and inspected the timestamp proximity.

Repeated service logons to well-known built-in logon identifiers were not treated as impossible identity reuse. Nor did I interpret fewer logoffs than logons as proof of an incomplete lifecycle without considering service sessions, failed attempts and the collection boundary.

### Linux sessions, process ownership and routine activity

The Linux records include root versus named-user execution, SSH privilege separation, shell descendants, sudo commands and root command children. FILE-LNX-01, for example, has Samba child processes and SMB sessions alongside SSH administration, while WS-LNGUYEN-01 shows user shells, git commands, database-related work and SMB client commands. DB-PROD-01's Lina Nguyen history includes MySQL and PostgreSQL status queries, log inspection and administrative diagnostics; those commands are plausible for a mixed database environment, although shell history cannot prove their success.

Sysstat cron execution is highly regular, including 36 shell and 36 `debian-sa1` creations on several Linux hosts over six hours. I did **not** score that periodicity as synthetic: a ten-minute monitoring cron job naturally produces it. Linux daemon warnings and maintenance messages also vary by host and include network, printing, snap, storage and forwarding concerns. Some messages are repetitive, but repetition alone is normal for malfunctioning daemons and does not establish fabricated telemetry.

### macOS execution and policy evidence

The native ES records declare message `version: 11` and separate event payloads for fork, exec and exit. I did not equate that message version with the OS release. PID/pidversion image identities were internally consistent in the checked process snapshots, including exec targets. Fork snapshots initially retaining the parent's executable were correctly interpreted as fork semantics, not as child processes mysteriously running their final executable too early.

MAC-MROSS-01's Unified Log policy message at `15:42:09.009673Z` says `ASP: Security policy would not allow process: 42008, /Applications/MeetingAssist.app/Contents/MacOS/MeetingAssist`. That wording alone does not establish an actual denied exec, and I found no basis to score successful execution after a demonstrated denial. The SSH accepted messages likewise occur after the relevant native session executable is visible. Sparse Unified Log coverage is not itself a defect.

The concern is instead the native-looking `stat` payload. Both machines combine closely packed executable inode allocations with extensive calendar-time spread and exactly ordered birthtimes; directory metadata follows a separate adjacent-ID recipe. Snapshotting, packaging, preserved timestamps or sanitization could account for individual observations. They are less convincing as a joint explanation for the same catalog-like structure on both hosts, including unrelated third-party and per-user paths. I regard this as substantial distribution evidence, not a demonstrated kernel or parser impossibility.

### Weight and uncertainty

No hard process ordering contradiction was established. Consequently I have not assigned a score in the 81–100 range. The substantial Windows/Linux consistency keeps the score well below a confident generator-identity verdict; the repeated macOS filesystem metadata pattern is the principal reason it nevertheless reaches the likely-synthetic band. If inode/device/stat metadata were explicitly disclosed as privacy-rewritten, my conclusion would weaken materially.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | macOS Endpoint Security executable `stat` | 29 executable paths on one Mac, 31 on the other | Principal indicator: month-spanning birthtimes perfectly track inode order within spans of only 96 and 108 identifiers. |
| distribution_texture | macOS Endpoint Security exec `cwd` | Both Macs' root and home directories | Supporting indicator: adjacent enormous inode pairs and the same fixed directory-stat shape suggest a separate metadata construction rule. |
| environment_or_collection_plausibility | macOS Endpoint Security filesystem device identities | System, app and user/package-manager executables on both Macs | Secondary concern: system/writable paths share a device identity; actual mount layout and privacy transformations are unknown. |

## Realism Score by Category

- **Field format accuracy:** 8 — XML/JSON and process identity fields are coherent; Mac filesystem-stat texture reduces confidence in native fidelity.
- **Temporal patterns:** 9 — Checked process/session lifecycles respect ordering and source timing differs plausibly; legitimate cron periodicity was not penalized.
- **Cross-source correlation:** 9 — Windows creation identities and command lines agree, with realistic source latency; the comparison is not exhaustive across all event families.
- **Behavioral realism:** 8 — User, service, SSH, Samba and administrative activity have plausible ownership and process trees.
- **Environmental consistency:** 6 — The repeated Mac device/inode/stat arrangement is difficult to reconcile with ordinary lived-in installations without an additional transformation explanation.

## Recommendations

- If this were synthetic, build executable filesystem identities from representative native filesystem inventories, preserving their allocation density, actual volume boundaries and relationship to installation history. Avoid assigning a small block of consecutive inode identifiers to executables whose birthtimes span months.
- If this were synthetic, derive `cwd` directory metadata from the same filesystem inventory as executable metadata. The root/home adjacent-ID pairs, separate enormous inode range and repeated fixed directory-stat shape should reflect a demonstrated host filesystem rather than a separate catalog convention.
- If these fields were privacy-transformed production data, document that transformation in the collection notes so native filesystem identifiers are not mistaken for original forensic artifacts.
