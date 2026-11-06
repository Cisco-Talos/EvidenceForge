# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 90
**Synthetic-Confidence Score:** 68

## Executive Summary

The endpoint data has substantial realistic structure, especially Windows process identity correlation and Linux SSH/sudo lifecycles. My synthetic verdict rests primarily on demonstrable timestamp construction patterns in the macOS Endpoint Security records: numerous separate shell forks preserve exactly the same microsecond fraction, and all six visible inventory processes have exactly two seconds from fork to exit. These are strong timing/distribution fingerprints rather than impossible process-tree relationships; I did not establish a dataset-wide hard contradiction.

## Evidence For Synthetic

- [distribution_texture] Thirty of the 58 visible `/bin/zsh`-parented forks across the two Macs belong to 13 groups in which separate commands preserve the exact six-digit fractional second. For example, `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson` lines 51, 54 and 57 record forks at `14:38:18.173001000Z`, `14:38:55.173001000Z` and `14:39:47.173001000Z`. These produce `df`, `ps` and `find`, with different child PIDs, at exactly 37- and 52-second intervals. Another group on MAC-MROSS-02, lines 64, 67 and 70, preserves `.560051000` at `14:27:10`, `14:27:23` and `14:27:56`. These are native fork observation times, not the one-second resolution of shell history.
- [distribution_texture] All six inventory `/usr/bin/sw_vers` lifetimes are exactly `2.000000` seconds from fork to exit, despite differing exec delays. On MAC-MROSS-01, native lines 28/30/31 show fork `13:31:25.866513000Z`, exec `13:31:25.873119000Z`, exit `13:31:27.866513000Z`; lines 66/68/69 and 126/128/129 repeat the exact two-second fork-to-exit duration. MAC-MROSS-02 repeats it at lines 31/33/34, 94/96/97 and 135/137/138. Scheduled inventory is plausible, but a fixed microsecond-exact lifetime of the actual utility across every observed instance is not natural execution variability.
- [environment_or_collection_plausibility] The visible Mac document operations have a narrow shell-based texture. MAC-MROSS-01 eCAR lines 110 and 331 attribute writes to `.pptx` and `.xlsx` files to `/usr/bin/tee`; lines 153, 182 and 280 attribute reads of spreadsheets/PDFs to `/bin/cat`. MAC-MROSS-02 eCAR lines 456 and 611 similarly use `cat` for a PDF and spreadsheet. This is possible scripting or inspection, so I give it low weight; its recurrence across both systems is less convincing as ordinary document-work activity than the otherwise realistic application launches.

## Evidence For Real

- Across all ten Windows hosts I examined 876 Sysmon Event 1 records. Where a Security 4688 record shared the PID, the process image and creator PID agreed in the comparison performed. The small source-count differences on two workstations were not themselves scored as defects.
- Windows same-identity process lifecycles were coherent: I found no Sysmon process observation after its matching Event 5 termination, and no visible child creation after the termination of its identified parent. For visible parents with Event 1 records, parent image/PID references matched the parent record and did not precede its creation.
- Within each Windows host, each observed `(Image, FileVersion)` pair had a consistent `Hashes` value. This supports realistic binary identity rather than per-launch hash invention.
- `APP-INT-01.meridianhcs.local/syslog.log` lines 14–17 show a plausible SSH sequence: connection from `10.10.1.21:35355` at `13:03:41.885680Z`, accepted password at `13:03:47.566502Z`, PAM session opened at `13:03:47.732667Z`, and logind session `376027` at `13:03:48.188377Z`. eCAR lines 12, 14 and 15 supply the privileged sshd process, matching session login, and subsequent user shell with the matching session ID.
- Linux privilege transitions have distinct invoking and target processes. APP-INT-01 eCAR lines 8–11 show user `aisha.johnson` running sudo PID `2931608`, its root apt-cache child PID `2931611`, and child-before-parent termination; syslog lines 9–11 give the corresponding sudo request and PAM open/close.
- The macOS process records distinguish fork from successive exec images. MAC-MROSS-01 native lines 1–3 show launchd forking PID `42171`, then that PID executing xpcproxy and Terminal with changing pidversion. MAC-MROSS-02 lines 4–10 model the iTerm helper/login/ShellLauncher/zsh path rather than applying Linux login assumptions.

## Detailed Analysis

### Scope and method

I confined examination to the supplied data directory. I parsed the Security/Sysmon XML, eCAR JSON, both Mac Endpoint Security streams and selected Unified Log, syslog and shell-history entries. The strongest conclusions here are about host evidence; I did not attempt an exhaustive network-sensor reconstruction.

For Windows, the lifecycle checks used `ProcessGuid`, not PID alone. I compared visible parent GUIDs to their Event 1/5 records and checked hash consistency per image/version within each host. For eCAR, I checked visible process `objectID` and `actorID` relationships against process creation/termination. There were no observed process creations after the recorded termination of their identified parent, and no post-termination process updates in that check. Starts before collection and absent post-window termination were treated as neutral.

### Windows host evidence

The Windows data is comparatively convincing. WS-MCHEN-01 Sysmon EventRecordID `525178` at `13:05:02.8117220Z` shows SYSTEM `SearchProtocolHost.exe` PID `7208`, parent `SearchIndexer.exe` PID `6072`, logon `0x3e7`, and a Windows Search pipe command line. User GUI ancestry is also represented: WS-AJOHNSON-01 Sysmon records `30987`, `31017` and `31021` show explorer launching Outlook/Chrome, followed by a Chrome child.

Security records include service, network, interactive, remote interactive and new-credentials logons, with unlock-type logons present on some workstations. The distribution varies among servers and workstations. I did not penalize the absence of a particular optional event type or demand closure for pre-window/bounded sessions.

One unusual individual record is WS-AJOHNSON-01 Sysmon `31448` at `18:00:28.0582446Z`: `runas.exe /netonly /user:marcus.chen "cmd.exe /d /q"` runs as aisha.johnson with `winlogon.exe` as parent. That deserves forensic investigation, but an unusual parent in potentially compromised data is not sufficient evidence of synthesis. I did not use it to materially raise the score.

### Linux evidence

Linux evidence contains practical source-specific details: named SSH users and source ports, PAM and logind session IDs, sudo PIDs/TTYs/working directories, cron/sysstat commands, resolver degradation/recovery, snap refresh messages and rsyslog queue diagnostics. For example, APP-INT-01 syslog lines 18–23 alternate resolver and logging subsystem messages rather than solely presenting user activity.

The SSH and sudo examples above have believable ordering and ownership. Bash histories are per-user and include both routine administration and development commands. Some commands target service-like names such as `smbclient` or `cifs-utils`; those commands can fail or query locally customized services, and the logs supplied do not establish that they successfully controlled a real service. I therefore did not classify them as hard contradictions.

### macOS evidence and timing

The six fixed-duration inventory processes are the clearest anomaly. On MAC-MROSS-02, PID `21921` forks at `13:43:12.852095000Z`, execs `/usr/bin/sw_vers` at `13:43:12.859126000Z`, and exits at `13:43:14.852095000Z`. The same utility at `15:47:17.579489000Z` and `17:52:26.343304000Z` repeats the fork-plus-exactly-two-seconds endpoint. MAC-MROSS-01 supplies three independent repetitions. Normal timer periodicity does not explain why recorded process termination preserves the original fork microsecond exactly on every run.

Separately, groups of shell forks retain a six-digit fractional-second anchor while command gaps change by whole seconds. MAC-MROSS-01 lines 32/35/38 show `13:48:35.351324000Z`, `13:49:05.351324000Z`, `13:49:55.351324000Z`; lines 104/107 show `16:34:22.030570000Z` and `16:35:13.030570000Z`. MAC-MROSS-02 lines 151/154/157 show `18:24:27.675443000Z`, `18:25:32.675443000Z`, `18:26:32.675443000Z`. Exec timestamps then add variable millisecond delays. The repeated preservation specifically at fork boundaries suggests scheduled intent timestamps with variable downstream offsets. Automated scripts are an alternative, but actual OS scheduling would normally introduce variation at these boundaries, and these streams also tie the commands to interactive shell history.

I found no native Mac process event after a visible exit for that PID. Per-event-type sequence numbers and global sequence numbers increased in file order. File-object samples retained stable path/device/inode/size identities, and different paths did not reuse the sampled file identity. These checks temper the score.

Native Mac exit coverage differs by activity: none of the 11 eCAR READ/WRITE actor processes had a corresponding native EXIT in the supplied ES streams, although eCAR does record termination. Without the collection/filter policy, this is a limitation rather than a scored missing-companion defect. Likewise, sparse Unified Log exports do not establish missing native collection. The MAC-MROSS-01 Unified Log policy message at `15:42:28.922523+0000` says policy “would not allow” MeetingAssist; that alone is not proof of a denied execution, and I did not infer child activity or command effects from it.

## Synthetic Indicator Summary

| Category | Source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | macOS Endpoint Security fork observations | 30 of 58 zsh-parented forks, 13 repeated-fraction groups across two hosts | Primary indicator: changing command intervals repeatedly retain the exact microsecond anchor. |
| distribution_texture | macOS Endpoint Security fork/exec/exit | All six visible inventory sw_vers processes on two hosts | Primary indicator: identical 2.000000-second fork-to-exit duration despite different exec delays. |
| environment_or_collection_plausibility | Mac eCAR process/file evidence | Repeated cat/tee handling of PDFs, spreadsheets and presentations on both Macs | Low weight: possible automation, but narrow tool/operation texture. |

## Realism Score by Category

- **Field format accuracy:** 9 — Parseable source-specific records with useful identities; no demonstrated native schema impossibility.
- **Temporal patterns:** 5 — Plausible broad activity timing, weakened by repeated exact fork fractions and six fixed process lifetimes.
- **Cross-source correlation:** 9 — Windows process fields and sampled Linux auth/process chains agree; collection-policy limits remain.
- **Behavioral realism:** 7 — Varied user/admin/application behavior, with narrow shell-based document operations on the Macs.
- **Environmental consistency:** 8 — Platform-specific process/session structures largely fit; isolated unusual process ancestry remains investigable.

## Recommendations

- If this were synthetic, introduce variation at the actual native fork boundary for separate interactive commands rather than retaining a shared microsecond timestamp and changing only whole-second offsets.
- If this were synthetic, derive inventory process exit times from utility execution behavior. Avoid the exact two-second fork-to-exit duration across every instance; timer launch cadence and process runtime are separate properties.
- If this were synthetic, make Mac document access tools reflect the intended operation. Use cat/tee for explicit scripting, and application/helper processes for ordinary spreadsheet, presentation and PDF interaction when that is the modeled behavior.
