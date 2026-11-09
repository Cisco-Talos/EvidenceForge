# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 72
**Synthetic-Confidence Score:** 43

## Executive Summary

The endpoint evidence is substantially coherent across Windows, Linux, and macOS. Repeated macOS command/startup timing has a modest scripted texture, but the bounded checks did not establish a hard contradiction, so the available endpoint evidence does not support a confident synthetic verdict.

## Evidence For Synthetic

- [distribution_texture] The two Macs repeat nearly identical interactive command vocabulary and some nearly identical relative timing. In `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson`, lines 33, 36, and 39 execute `/bin/pwd`, `/bin/ls -la /Users/maya.ross/Documents`, and `/usr/bin/du -sh /Users/maya.ross/Documents` at 13:48:48.728362, 13:49:18.729299, and 13:50:08.724928 UTC: gaps of 30.000937 and 49.995629 seconds. The other Mac repeats the ls/du pair at 14:11:58.431282 and 14:12:28.438281 (lines 39 and 42), a 30.006999-second gap. These round relative intervals suggest scripted interaction, although a shared user, deliberate diagnostic routine, or automation could explain them. This is a moderate texture observation, not an impossible timeline.
- [weak_signal] Both initial Chrome launches have renderer/GPU/network helper creation paced at almost exactly +2, +3, and +5 seconds: MAC-MROSS-01 ES lines 19/21/23/25, 13:13:31.656549 through 13:13:36.664432; MAC-MROSS-02 lines 24/26/28/30, 13:27:10.354352 through 13:27:15.351084. The repeated timing shape across separate hosts is somewhat artificial-looking. Shared application behavior and similar fleet configuration remain credible explanations; this receives little independent weight.

## Evidence For Real

- Process lifetime integrity is strong in the checked data. Across the ten Windows Sysmon files, joining Event 1 children to visible Event 1/Event 5 parents by `ParentProcessGuid`/`ProcessGuid` found no child creation after the matched parent's visible termination and no child creation before the matched parent's visible creation. Missing pre-window parents were excluded.
- Representative native Windows process correlations agree on executable identity. WS-MCHEN-01 has 105 Sysmon Event 1 records; all 105 match a Security 4688 PID with the same image. WS-AJOHNSON-01 matches 105 of 106 Sysmon creations, all matched images agree; DC-01 matches 129 of 130, all matched images agree. The unmatched rows were not automatically treated as defects.
- Linux SSH sequences contain credible differentiated timing rather than collapsing transport, authentication, PAM, and logind into one timestamp. APP-INT-01 `syslog.log` lines 59–62 show connection 13:42:55.560078, accepted key 13:43:00.702475, PAM open 13:43:00.878347, and logind session 376026 at 13:43:01.565641.
- macOS records distinguish fork from successive exec images, preserve one process identity across exec, and distinguish audit sessions from POSIX sessions. MAC-MROSS-01 ES lines 1–3 have PID 42169 move from inherited launchd through xpcproxy to Terminal; lines 4–7 model login and zsh separately. MAC-MROSS-02 instead includes iTermServer and ShellLauncher (lines 4–10), giving the two hosts meaningfully different process trees.
- Executable file identity is stable in the two Mac ES files: a bounded recursive check grouping executable observations by `(st_dev, st_ino, path)` found no differing `(st_size, cdhash, signing_id)` tuples within a group. Windows Security SID-to-username checks also found no conflicting username assignments in the supplied files.

## Detailed Analysis

### Scope and reproducibility

I inventoried only the supplied data directory and parsed its endpoint files. Mechanical checks covered 23 eCAR files, ten Sysmon XML files, ten Security XML files, and the two Mac ES exports; close reading sampled APP-INT-01 Linux events, three Windows hosts, and both Macs. This was a representative consistency review, not exhaustive validation of every field or network protocol. All cited timestamps are UTC on 2026-11-02. Paths above are relative to the supplied data directory; XML citations below use source-native EventRecordID because XML records span multiple lines.

The process-tree check builds maps of Sysmon Event 1 and Event 5 keyed by GUID, then compares each child's `UtcTime` against any visible matching parent creation and termination. A separate eCAR check maps PROCESS/TERMINATE by `objectID` and checks later references to that identity as `actorID`; none exceeded termination by more than one second. This tolerance avoids treating small collection offsets as impossible execution. No absent out-of-window initiation or closure contributed to the score.

### Windows processes and sessions

For a concrete matching example, WS-MCHEN-01 Sysmon EventRecordID 525189 reports PID 7260, `C:\Windows\System32\svchost.exe`, at 13:07:20.918, with command `svchost.exe -k netsvcs -p -s LanmanServer`. Security 4688 EventRecordID 948745 reports the same PID/image/command. Similar comparisons produced the match counts above; PID joins within the bounded window are useful checks, not proof that every possible reuse or timestamp relationship is correct.

Visible parentage includes service processes under services.exe, WmiPrvSE under svchost.exe, and SearchProtocolHost under SearchIndexer. Session types are differentiated: WS-MCHEN-01 Security contains type 2, 3, 5, 7, and 9 logons. Repeated reserved service LogonIDs such as 0x3e7 and repeated unlock logons were not counted as duplicate-session errors. A type-2 session already underway at window start can legitimately terminate inside the window: WS-MCHEN-01 Security EventRecordID 948726 logs 4634 for marcus.chen, LogonID 0x6b459f6, at 13:01:02.1040589.

### Linux observations

APP-INT-01 combines sysstat cron, dbus activation, systemd-resolved fallback/recovery, sudo PAM sessions, and SSH activity. For example, lines 17 and 19 show DNS degraded mode at 13:07:09.694351 followed by restored full feature set at 13:07:25.008130. Anacron lines 35–36 and 53–55 form a delayed logrotate lifecycle rather than an isolated generic maintenance message.

Ten Linux syslog files each contain twelve sysstat cron messages over the six-hour window, with host-specific minute offsets. A common centrally managed 30-minute schedule fully explains this regularity; scheduled maintenance periodicity alone is not a synthetic indicator. Likewise, selected shell history is not an exhaustive record of every command, so I did not infer missing execution from absent history lines.

### macOS observations and limits

The Terminal and iTerm trees are more faithful than generic shell-as-GUI-parent records. Exec records keep PID and process start time while changing executable and pidversion. File-stat identity remains coherent in the checked grouping. ES notification action fields were not interpreted as authorization denials, and the policy message at MAC-MROSS-01 Unified Log line 2 was not used to infer successful or denied downstream activity without the matching event chain.

The command vocabulary remains narrow: MAC-MROSS-01 history has 23 entries including three `/usr/bin/id` invocations and several repeated Documents-directory inspections; MAC-MROSS-02 has 18 entries including three `/bin/ps aux` invocations. This could be a constrained exercise or a diagnostic user routine. The score is driven by the quantified repeated timing and vocabulary together, not by thin coverage or an assumption that every user must show more varied commands. I did not verify the complete native schema of the declared version-11 ES export and therefore make no schema-defect allegation about unfamiliar fields.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | macOS ES and zsh history | Two Macs, same named user; repeated command groups with near-round 30/50-second intervals | Modest upward pressure; plausible scripted or human diagnostic routine prevents a confident verdict |
| weak_signal | macOS ES browser startup | Two initial Chrome launches with matching +2/+3/+5-second helper timing | Small upward pressure; shared application behavior is an alternative |
| No demonstrated hard contradiction | Windows, Linux, macOS endpoint evidence | Bounded identity/lifecycle checks and representative cross-source joins | Keeps score in the mixed/inconclusive range |

## Realism Score by Category

- **Field format accuracy:** 8 — Parsed native XML/JSON and consistent checked identities; complete platform-schema verification was outside this bounded review.
- **Temporal patterns:** 7 — Credible varied SSH/session timings, with a few conspicuously repeated relative command/startup intervals.
- **Cross-source correlation:** 9 — Representative Windows PID/image matches and coherent shared process identities; no demonstrated hard ordering failure.
- **Behavioral realism:** 7 — Plausible service/admin and application activity, with narrow repeated Mac diagnostic command groups.
- **Environmental consistency:** 8 — Platform-specific process trees and Linux maintenance behavior are coherent with visible records.

## Recommendations

- If this were synthetic, vary the repeated interactive command groups according to the actual task, including the near-exact 30/50-second gaps across the Macs, unless the intended activity is explicitly automated.
- If this were synthetic, derive browser-helper startup relationships from a broader set of observed application startups rather than repeatedly using the same +2/+3/+5-second pattern. Preserve the already coherent process identity, exec, and session relationships while doing so.
