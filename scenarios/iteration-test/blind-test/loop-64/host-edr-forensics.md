# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 77
**Synthetic-Confidence Score:** 64

## Executive Summary

The endpoint evidence is substantially coherent: visible process ancestry and termination ordering hold up well, Windows process identities align across providers, and the Mac records distinguish forked lifetimes from subsequent exec images. I lean synthetic because several Linux hosts' native session numbers track elapsed time almost exactly, while both Mac hosts show an unusually orderly relationship between executable path names and filesystem inode numbers. These are distribution fingerprints rather than demonstrated impossible activity, so the verdict remains qualified.

## Evidence For Synthetic

- [distribution_texture] **Linux session identifiers resemble a clock-derived counter.** In `LOG-MON-01.meridianhcs.local/syslog.log`, lines 82, 109, 176, 254 and 261 report `New session` IDs 39284, 39696, 40706, 42045 and 42133 at 13:41:58.287074, 14:27:26.518247, 16:19:55.135074, 18:48:35.169919 and 18:58:05.710528 UTC. A least-squares fit of session ID against elapsed seconds gives **9.00544 IDs/minute, R²=0.999998852, maximum absolute residual 1.698 IDs**. The same relationship occurs on unrelated hosts: `LT-MRIVERA-02.../syslog.log` lines 30, 60, 92 and 149 yield **8.99064/minute, R²=0.999999402, maximum residual 1.065**; `MAIL-CLIN-01.../syslog.log` lines 9, 119, 130 and 238 yield **8.00123/minute, R²=0.999999020, maximum residual 1.326**. The issue is the near-exact integer rate over hours, not merely increasing IDs or missing intervening records. Hidden scheduled sessions or identifier sanitization are viable alternatives, but require unusually steady rates on several hosts.
- [distribution_texture] **Both Mac executable inventories have inode numbers strictly ordered by executable path.** Extracting every `process.executable` and fork/exec child/target executable from the native ES files gives 26 unique paths on MAC-MROSS-01 and 32 on MAC-MROSS-02; in both inventories, sorting paths lexicographically also sorts `stat.st_ino` without a single inversion. Examples on MAC-MROSS-01 are Chrome renderer line 21 inode 2992454, Chrome helper line 23 inode 2992455, Chrome main line 19 inode 2992456, `/bin/df` line 48 inode 2992493, `/bin/ls` line 36 inode 2992495, `/bin/ps` line 51 inode 2992496 and `/bin/pwd` line 33 inode 2992497. The same pattern appears on MAC-MROSS-02, including lines 24, 26, 28, 32 and 45. Of 23 common executable paths, the cross-host inode difference is 482684 for 20 and 482685 for three. This looks like a shared ordered inventory mapped into host-specific identity ranges. An ordered installation or image-building process could produce it, so this is a moderate indicator, not an impossible filesystem state.
- [distribution_texture] **A small native Mac exit sequence has mechanically minimal spacing.** `MAC-MROSS-02.../macos_endpoint_security.ndjson` lines 175–178 report exits of `/bin/cat` PID 65767, its shell PID 19009, `/usr/bin/login` PID 19008 and iTermServer PID 19007 at `18:56:59.150935000Z`, `.150936000Z`, `.150937000Z` and `.150938000Z`. Three successive ancestor transitions are exactly one microsecond apart. The ordering itself is correct, and simultaneous logout can explain the cluster; the repeated minimum-sized timestamp increment is the limited tell. This is a small supporting observation and does not establish an impossible scheduler sequence.

## Evidence For Real

- **Visible process lifecycles are sound in the tested relationships.** Across all 23 eCAR files, checks against process `objectID`/`actorID` found no child created after its visible parent termination, no actor used after its visible termination, and no process observation preceding its matching visible creation. Missing pre-window parents and post-window terminations were treated as neutral.
- **Windows provider agreement extends to token ownership.** All **972** Sysmon Event 1 rows had a matching Security 4688 by host, PID, image and a three-second maximum time window. Each matched Sysmon `LogonId` agreed with the Security target logon ID, or creator logon ID when the target was absent/zero. For example, WS-MCHEN eCAR lines 8–11 show the plausible `smss.exe → winlogon.exe → userinit.exe → explorer.exe` startup chain with the interactive user's logon ID `0x6c37b70` on userinit/explorer.
- **Binary identity is internally stable.** There were no conflicting hash sets for the same image path within each Windows host's visible Sysmon process-creation records, and no conflicts when matching visible process-creation and image-load hashes for the same binary path. On the Mac hosts, the same device/inode executable identity retained its path, size, mtime and cdhash across repeated observations.
- **Mac source distinctions are handled plausibly.** MAC-MROSS-01 ES lines 1–7 show launchd fork, xpcproxy exec, Terminal exec, Terminal's child exec into login, and a shell child. MAC-MROSS-02 lines 1–10 use the different iTerm/iTermServer/login/ShellLauncher chain. PID continuity across exec is preserved rather than manufacturing a new process for each image.
- **Linux activity has recognizable operational detail.** APP-INT syslog lines 65–67 show accepted public-key authentication, PAM session opening, and logind session registration; lines 97–98 later close and remove that session. APP-INT eCAR lines 1–4 represent a cron shell invoking `debian-sa1`, with the child ending before the shell. Bash histories contain host-relevant database, service, development, and diagnostic commands rather than one universal command sequence.

## Detailed Analysis

### Scope, input provenance and limitations

Actual local inputs were the complete neutral briefing `/private/tmp/log-study-pifdrjj7/host-prompt.md` and files under its specified `/private/tmp/log-study-pifdrjj7/data` directory. I inventoried that data directory, parsed all 23 eCAR files (**37,089 rows**), all ten Windows Security files (**19,272 events**), all ten Sysmon files (**12,097 events**), both Mac ES files (**317 rows**) and both Mac Unified Log files (**five rows**). I scanned all supplied Linux syslogs for session relationships and read selected Linux bash histories plus both Mac zsh histories. I did not parse the separate network-sensor, firewall, proxy or web-access datasets, and do not claim an exhaustive network correlation review.

Parsing used system `python3` with an explicit neutral working directory. No quoted command from the logs was executed. No project files, authored scenario, TODO, worklog, previous assessment or other reviewer's material was read. Generic inherited operating/project instructions were present as an environment limitation and were not used as evidence about the supplied data's origin.

Official primary references consulted included [Apple's ES exec structure documentation](https://developer.apple.com/documentation/endpointsecurity/es_event_exec_t), [Microsoft's 4688 documentation](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688), [Microsoft's Sysmon reference](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) and the [Apple OpenSSH upstream repository](https://github.com/apple-oss-distributions/OpenSSH). Vendor-domain-filtered searches and upstream repository browsing also returned unrelated search snippets; none exposed project or prior-assessment information, and none of the unrelated secondary material supports a scored finding. I did not establish an exact macOS release from command output: an invocation of `sw_vers` does not supply its stdout. Consequently I make no release-specific native-schema allegation.

For reproducibility, selected raw input SHA256 digests are:

| File, relative to supplied data | SHA256 |
|---|---|
| `LOG-MON-01.meridianhcs.local/syslog.log` | `7eceaed7eb753aa49454846fd17b66f3143d96f1cbb6813ce514dac801be8df6` |
| `LT-MRIVERA-02.meridianhcs.local/syslog.log` | `3f15d61ff02089c925246b19ca1f7bef6b6c69262415bc00937a075a321b5456` |
| `MAIL-CLIN-01.meridianhcs.local/syslog.log` | `91a1b3ce25e8bbb93824c3d1c40812dacc21c6c1168a9b683909117210c1d27d` |
| `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson` | `1819491ec7dc9811dcdadda7442c46965f7565f4f7b413c0de26fa8d8fe907b7` |
| `MAC-MROSS-02.meridianhcs.local/macos_endpoint_security.ndjson` | `ebf259ac0e6134a3d1e085989001c679797077b12622b61e00c6302143b6a177` |

All line references are one-based physical file lines. Abbreviated host directory names elsewhere retain the suffix `.meridianhcs.local`.

### Windows process trees, sessions and hashes

I parsed XML into event/data fields rather than comparing textual escaping. For each host, I indexed Sysmon Event 1 by `ProcessGuid` and Event 5 by the same GUID. I compared visible child creation to visible parent creation/termination and compared subsequent same-GUID observations against the creation/termination interval using event-data `UtcTime`. These tests found no ordering defect. A parent outliving or dying before its child is not itself an error; only creating a child after the parent's visible death would have counted.

For the 4688 comparison, each Sysmon Event 1 was matched to Security by integer PID, case-insensitive image path and nearest timestamp within three seconds. Matching does not prove authenticity, but the absence of token/logon mismatches materially weighs against simple independent row fabrication. Image hash checks likewise found no contradictions. Source counts differ somewhat, which can reflect filtering; those differences were not scored as missing required evidence.

The visible session mix includes interactive, network and service logons, and workstation lock/unlock events on several Windows workstations. For example, WS-MCHEN has 30 events 4624, 20 events 4634, and one each 4800/4801. I did not require a type 7 unlock event merely because lock/unlock telemetry exists, nor did I interpret open sessions at the slice boundary as lifecycle defects.

### Linux session identity texture

The strongest concern is not that session IDs have gaps: collection can omit records, and background sessions can consume numbers. It is that the gaps encode elapsed wall time to exceptionally high accuracy on several differently named systems.

The regression is reproducible by extracting timestamps and decimal IDs from `systemd-logind ... New session N of user ...`, setting the first observed timestamp and ID to zero, and fitting `ID = intercept + slope × elapsed_seconds` separately per host. Every listed row was used; no outlier trimming was performed. LOG-MON has five observations spanning 5h16m07s; LT-MRIVERA has four spanning 4h09m46s; MAIL-CLIN has four spanning 5h09m01s. Their maximum deviations from the fitted line are about one or two session numbers despite totals advancing by thousands.

Other hosts are less exact: APP-INT has 13 observations with R² 0.987636 and maximum residual 261 IDs; WEB-EXT has six with R² 0.947136 and maximum residual 379 IDs. This limits the scope: it is a repeated strong pattern on a subset, not an asserted invariant on every Linux system.

A real alternative is a fixed-rate background login workload whose sessions are excluded by collection, plus occasional jitter. Another is a sanitizer that deliberately remapped session IDs with a time-based scheme. Neither is disproved by this slice. However, steady rates near exactly eight or nine IDs per minute on three systems are more consistent with manufactured identity allocation than ordinary varied interactive activity. I assign this the greatest weight and do not call it a hard contradiction.

### Mac native identities, ancestry and policy observations

The ES documents carry message `version: 11`; I evaluated their internal relationships without assuming that version number was an OS release. In particular, `event.exec.target` describes the post-exec process, while the enclosing process describes the prior image. An incrementing pidversion at exec is therefore not a duplicate-process defect. Audit user/session identifiers were also kept separate from normalized eCAR `logon_id` values.

The inode observation was computed over unique paths, not repeated process rows, to avoid inflating its sample size. Within each host, I recursively collected objects containing both an `audit_token` and an `executable`, then retained the executable path and `stat.st_ino`. Every pair of adjacent lexicographically sorted paths had increasing inode numbers. The metadata is otherwise internally stable: I found no same-device/inode pair claiming multiple executable paths, sizes or code hashes. Shared binary cdhash/size values across two machines can reflect a common installation image and are not independently suspicious. The suspicious aspect is the orderly inode allocation over both inventories.

The one-microsecond exit chain is a small local timing artifact. It is not an impossible parent/child order, and it does not justify treating the whole day's logout as invalid. Many other ES events have varied subsecond spacing and legitimate child-before-parent termination ordering.

MAC-MROSS-01 Unified Log line 2 reports an AppleSystemPolicy message about `/Applications/MeetingAssist.app/Contents/MacOS/MeetingAssist`. The corresponding native ES input does not show a successful exec of that path. I did not infer that an absent exec alone proves a denial, or that a policy message creates a child. Similarly, eCAR's plist create/delete facts were not treated as proof of launch activation or unload. With the selected native event families, neither a missing launch event nor thin Unified Log coverage is a scored defect.

### Weight of evidence and alternatives

I found no demonstrated impossible same-identity lifecycle, stable-binary hash contradiction, account-SID collision, or native schema violation in the checks performed. The synthetic verdict is driven by two repeated metadata distribution patterns, with a small timing corroboration, rather than the shape or completeness of suspicious activity. It could be wrong if real telemetry underwent systematic identifier remapping or arose from unusually regular image-building/background-login workloads. That uncertainty keeps both confidence and the synthetic appearance score well below the rubric's highest band.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `distribution_texture` | Linux syslog/logind | 13 session registrations across LOG-MON, LT-MRIVERA and MAIL-CLIN; other hosts less exact | Largest contribution: IDs nearly linear in time at eight/nine per minute with residuals under two IDs over hours. Hidden workloads/remapping remain alternatives. |
| `distribution_texture` | Native macOS ES executable metadata | 26 and 32 unique executable paths on two hosts; 23 common paths | Moderate contribution: perfect lexical-path/inode ordering and nearly constant cross-host offset resemble an assigned inventory. Ordered installation is possible. |
| `distribution_texture` | Native macOS ES exits | Four related process exits, MAC-MROSS-02 lines 175–178 | Small contribution: exactly one-microsecond steps across three ancestor transitions. Correct ordering; no impossible lifecycle claimed. |

## Realism Score by Category

- **Field format accuracy:** 9 — Parsable native-looking XML/JSON, stable field identities, and no established version-specific schema defect.
- **Temporal patterns:** 7 — Most lifecycles are coherent; an exact microsecond exit chain and clock-like session-number progression reduce authenticity.
- **Cross-source correlation:** 9 — All 972 visible Sysmon creations matched Security process/token context under the stated comparison; no checked lifecycle inversion.
- **Behavioral realism:** 8 — Plausible platform-specific process trees, varied administration, development and user activity; no score penalty for narratable activity.
- **Environmental consistency:** 7 — Broadly plausible mixed estate, with highly ordered Mac inode inventories and repeated Linux identity-rate patterns needing explanation.

## Recommendations

- If this were synthetic, derive logind IDs from the modeled sequence of session allocations, including any explicitly modeled background sessions, rather than a near-exact elapsed-time rate. Preserve legitimate gaps, but make those gaps arise from session activity.
- If this were synthetic, use a believable filesystem installation/allocation history for native executable identities, preserving stable device/inode relationships without ordering both sampled inventories perfectly by full path.
- If this were synthetic, use realistic wait/reap and exit-notification timing for the MAC-MROSS-02 terminal ancestry rather than successive one-microsecond increments. Preserve the already-correct child-before-parent ordering.
- If this were sanitized real telemetry, document whether inode/session identifiers and timestamps were transformed. Such a transformation could explain the strongest observed artifacts and would materially change the authenticity assessment.
