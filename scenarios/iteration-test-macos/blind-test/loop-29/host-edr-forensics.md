# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 78
**Synthetic-Confidence Score:** 65

## Executive Summary

The sampled endpoint evidence has credible process identities, Windows source correlation, and Linux/macOS session lifecycles. My synthetic verdict rests chiefly on repeated, near-integer-second command spacing in the two Macs' native Endpoint Security records, supported by an unusual shell-based document-access texture; I found no demonstrated impossible lifecycle or native-schema contradiction in the bounded checks.

## Evidence For Synthetic

- [distribution_texture] Diagnostic commands on both Macs repeatedly preserve their fractional-second phase across gaps of tens of seconds. In `MAC-MROSS-02.meridianhcs.local/macos_endpoint_security.ndjson`, lines 115, 118 and 121 execute `du`, `df` and `ps` at `17:33:09.354077`, `17:33:57.356931` and `17:34:45.358394` UTC: gaps of **48.002854** and **48.001463** seconds. Across the specified diagnostic executable set below, **19 of 21** consecutive gaps between 10 and 100 seconds are within 20 milliseconds of an integer second, spread across both hosts and many separate clusters. This resembles scripted timing more than independent human command entry.
- [environment_or_collection_plausibility] Both Macs use their interactive zsh processes to access mounted documents through `cat` and `tee`, including binary Office/PDF documents. Mac01 ES lines 45, 59, 61, 73 and 99 show `tee ...team-roadmap.pptx`, `cat ...contacts.xlsx`, `cat ...action-items-review.pdf`, `cat ...risk-register-draft.pdf`, and `tee ...team-roadmap.xlsx`; Mac02 lines 110 and 128 similarly show `cat ...status-update-review.pdf` and `cat ...schedule.xlsx`. These are possible shell operations, but repeated use for mixed office-document activity is an unusual behavioral texture. I assign it secondary weight, not a claim that those commands cannot run.

## Evidence For Real

- Windows parent-child relationships include services-owned svchost, SearchIndexer-owned SearchFilterHost, and explorer-owned browser/PowerShell processes. On WS-MCHEN-01, the svchost creation at `13:07:20` has PID 7260, parent PID 5872, and matching `svchost.exe -k netsvcs -p -s LanmanServer` in Sysmon 1 and Security 4688. The corresponding XML `TimeCreated` fields are at Sysmon line 382 and Security line 538.
- Linux SSH evidence preserves source tuples and orders connection, authentication, PAM session opening and closure. DB-PROD-01 syslog lines 8–10 show aisha.johnson from `10.10.1.35:59353` at `13:08:29.587455`, `13:08:31.088422`, and `13:08:31.205701`; line 71 closes that same sshd PID 1044253 session at `14:01:28.698990`. Invalid-user and failed-service-account attempts have distinct preauthentication closure paths.
- Mac terminal launches distinguish forked process lifetimes from successive executable images. Mac02 ES lines 9–10 keep PID 18979 and start time `13:11:56.176806Z` through ShellLauncher → zsh while changing pidversion 18 → 19. Terminal and iTerm have visibly different launch chains rather than one generic shell tree.
- In representative eCAR checks, no actor used an observed process identity after its visible termination, and no observed child was created after its identified parent's visible termination. This supports lifecycle realism without treating completeness as an authenticity signal.

## Detailed Analysis

### Scope and method

Only the supplied data directory and briefing were inspected. This was a bounded representative endpoint review, not an exhaustive audit of every host or every cross-source relationship. I parsed Windows XML for WS-MCHEN-01, WS-PPATEL-01 and DC-01, additionally counted DC-02 service logons, read DB-PROD-01, APP-INT-01 and WS-LNGUYEN-01 Linux examples/history, and examined all **303** ES records across the two Macs. eCAR identity checks covered those two Macs plus WS-MCHEN-01, WS-PPATEL-01, DC-01, DB-PROD-01 and APP-INT-01.

All line references are physical file lines, and all paths below are relative to the supplied data directory. Times cited above and below are on 2026-11-02 UTC.

### Command timing: strongest finding

For reproducibility, select ES rows with `event.exec.target.executable.path` in this exact set:

`/usr/bin/id`, `/usr/bin/sw_vers`, `/usr/bin/uname`, `/bin/pwd`, `/bin/ls`, `/usr/bin/du`, `/bin/df`, `/bin/ps`, `/usr/bin/find`, `/sbin/ifconfig`, `/usr/bin/dscl`.

Preserve file order separately per host, calculate timestamp differences between consecutive selected rows, and retain differences strictly between 10 and 100 seconds. Count `abs(delta - round(delta)) < 0.02`.

- Mac01: **8/9** retained gaps meet the criterion. ES lines 33→36→39 give `13:48:48.728362` → `13:49:18.729299` → `13:50:08.724928`, gaps **30.000937** and **49.995629** seconds. Lines 50→53→56 yield **36.984507** and **52.002200** seconds.
- Mac02: **11/12** meet it. Lines 39→42 give **30.006999** seconds; lines 89→92 give **44.000066** seconds. The three-command sequence at lines 115/118/121 repeats almost exactly 48-second gaps.

The command pool includes routine inventory commands, so automation is a viable real-data explanation. However, the effect recurs across several unrelated command pairs, including interactive history-backed `ls`, `du`, `df`, `ps` and `find` activity, at separate times on both machines. The commands are recorded in the respective `zsh_history/maya.ross.zsh_history` files with normal shell-history epoch timestamps. This combination supports a distribution concern; it does not prove fabrication or establish a hard timing contradiction. The 19/21 result is descriptive of the declared bounded subset, not a dataset-wide statistical estimate or a formal hypothesis test.

### Document access behavior

Mac01's six `/Volumes/` execs are two `tee` and four `cat` operations; Mac02 has five `cat` operations. Both sets are owned by the interactive zsh (Mac01 parent PID 42172; Mac02 parent PID 18979), with auid/euid 501 and audit session 100001. They are therefore not simply network sensor labels standing in for unknown endpoint applications.

On Mac01, ES line 59's `cat /Volumes/Users/Documents/contacts.xlsx` is also an eCAR PROCESS/MODIFY exec at eCAR line 119 for PID 55151. This establishes that the shell interpretation exists in both endpoint views. It is plausible to inspect or copy bytes using these tools, and filename suffixes do not prove actual file contents. I therefore treat this as a moderate host-behavior concern only. Neither the absence of GUI file events nor incomplete shell history is independently scored.

### Windows field and lifecycle checks

The reviewed event counts were:

| Host | Security records | Sysmon records | Selected process-create counts (Security/Sysmon) |
|---|---:|---:|---:|
| WS-MCHEN-01 | 669 | 434 | 96 / 94 |
| WS-PPATEL-01 | 674 | 358 | 66 / 65 |
| DC-01 | 6,539 | 4,350 | 142 / 140 |

Small count differences are neutral under source selection/observation uncertainty. Examined native values included hexadecimal Security PIDs versus decimal Sysmon PIDs, SID/principal alignment, service and user logon identities, and per-binary hashes. All parsed SHA1/MD5/SHA256/IMPHASH fields in these three Sysmon files had the expected hexadecimal-string lengths; sampled repeated binary images retained the same hashes.

No Security 4688 in those three hosts used a SubjectLogonId after that ID's visible 4634. The eCAR checks likewise found no post-termination actor/child relationship in the seven-host sample. Processes starting before the collection window or ending after it were not penalized.

DC-01 has 133 Type 5 service logons (51 SYSTEM, 42 NETWORK SERVICE, 40 LOCAL SERVICE), and DC-02 has 106 (31/42/33). DC-01 includes two LOCAL SERVICE logons only 3.4502971 seconds apart at `13:08:37.7233841` and `13:08:41.1736812` (Security XML lines 5707 and 5839). Built-in service identities legitimately reuse well-known logon IDs, and service restarts or policy activity can create repetition. Without accompanying service-control evidence proving an inconsistency, I do **not** score this as a defect.

### Linux and Mac source interpretation

DB-PROD-01 and APP-INT-01 contain distinct accepted-password/public-key sessions, invalid-user attempts, sudo records, and different session lengths. Shell history contains concrete role-specific work, such as MySQL diagnostics and developer repository commands, alongside generic shell activity. APP-INT-01's pre-window session closure at `13:00:25.526710` is neutral.

On the Macs I keyed visible lifetime checks by PID plus start time, preserving changing exec identities. No ES observation occurred after an exit for that same keyed process. I did not infer schema errors from unfamiliar version-11 fields, mistake notifications for authorization requests, or require Linux audit artifacts on macOS. The Mac01 Unified Log policy message `ASP: Security policy would not allow process: 62464, ...MeetingAssist` was not used to assert denied execution or successful child effects: that inference is not established by the wording alone.

## Synthetic Indicator Summary

| Category | Affected source family | Observed scope | Effect on synthetic-confidence score |
|---|---|---|---|
| distribution_texture | macOS Endpoint Security; history corroborates commands | 19/21 short diagnostic gaps across two hosts within 20 ms of an integer second | Primary reason for the likely-synthetic band; repeated timing phase suggests scripted command scheduling, with automation as an alternative |
| environment_or_collection_plausibility | macOS ES and normalized eCAR | Eleven mounted-document shell execs across two hosts, including Office/PDF names | Secondary upward weight for unusual repeated application ownership; possible behavior, not impossible execution |

No hard contradiction, native-format failure, or demonstrated lifecycle contract gap was established in this review.

## Realism Score by Category

- **Field format accuracy:** 9 — Parsed Windows/macOS/Linux representations are credible; no verified native schema defect found.
- **Temporal patterns:** 5 — Strong near-integer spacing in several Mac command clusters, despite credible lifecycle ordering.
- **Cross-source correlation:** 9 — Sampled Windows process and Mac exec identities correlate credibly; bounded checks found no impossible visible lifecycle.
- **Behavioral realism:** 6 — Good role-aware Linux and Windows activity, with unusual repeated shell access to office documents on Macs.
- **Environmental consistency:** 8 — Multiple platforms and source-specific launch chains are coherent; document-tool ownership remains questionable.

## Recommendations

- If this were synthetic, model the timing of human-entered diagnostic commands with independent subsecond variation rather than preserving a fractional phase through integer-second command gaps. Retain exact schedules where the visible activity is explicitly automated.
- If this were synthetic, represent mounted-document access with the actual intended application or an explicitly modeled shell workflow. Keep `cat`/`tee` when those are truly the intended operations, and preserve the proper shell/process ownership already present.
- Preserve the observed distinction between fork and exec, source-native PID representations, coherent hashes, and session lifecycle ordering. These were strengths in the reviewed sample.
