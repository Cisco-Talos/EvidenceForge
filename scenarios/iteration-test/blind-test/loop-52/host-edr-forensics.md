# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 78
**Synthetic-Confidence Score:** 43

## Executive Summary

The endpoint evidence is largely coherent, with credible Windows process/session relationships and macOS fork/exec identities, but one application-lifecycle pattern is difficult to reconcile with ordinary Chrome behavior. Two same-user Chrome browser leaders on MAC-MROSS-02 survive concurrently for hours without visible profile separation; this raises suspicion but is not an established impossibility because effective browser configuration is not supplied. The available endpoint evidence therefore supports a mixed assessment rather than a confident real/synthetic classification.

## Evidence For Synthetic

- [environment_or_collection_plausibility] On `MAC-MROSS-02.meridianhcs.local/macos_endpoint_security.ndjson`, line 30 executes Chrome PID 21393 at `13:37:33.942757Z`; line 85 executes a second browser leader PID 40213 at `15:09:08.159136Z` with `--new-window https://grafana.meridianhcs.local/d/system-overview`. Both target tokens identify UID 501, audit session 100001, the same executable inode 2509771/device 692, and the same `HOME=/Users/maya.ross`. Neither argument/environment array identifies a distinct user-data directory. The second leader creates GPU and renderer helpers (lines 86–89), and both leaders remain until exits at `18:56:59.115160Z` and `18:56:59.599378Z` (lines 181, 183). Chromium normally enforces a singleton per user-data directory. This is a substantive application-lifecycle plausibility concern, qualified by the absence of effective profile/policy configuration.
- [weak_signal] A remote `/usr/bin/id` execution on MAC-MROSS-01 lasts **77.797978 seconds**: native ES line 82 executes PID 64569 at `16:04:10.090417Z`, and line 83 records its successful exit at `16:05:27.888395Z`. Other visible `id` executions finish in about 0.08–0.24 seconds. A blocked directory-service lookup or terminal backpressure can explain this, so it carries little independent authenticity weight.

## Evidence For Real

- Windows process identity and lifecycle checks are unusually sound in the ordinary forensic sense: across all supplied Windows Sysmon files, no checked same-GUID dependent event preceded its visible process creation or followed its visible termination; no visible child creation occurred after its matching parent's termination. This is positive semantic quality, not evidence that perfect coverage itself proves either origin.
- There are **948 Sysmon Event 1 records**. A PID-based comparison found **947 matching Security 4688 records** with identical executable and command-line fields; the remaining unmatched record is neutral under the collection constraints. Per-host repeated Event 1 image paths also retained consistent hash sets.
- The Security log-clear lifecycle is handled correctly. In `DC-01.meridianhcs.local/windows_event_security.xml`, event starts at lines 272426 and 272461 have record IDs 28261463 and 28261464, then the 1102 event at line 272496 has record ID **1**, followed by IDs 4, 5 and 9 at lines 272528, 272569 and 272608. The clear event uses `Microsoft-Windows-Eventlog`, its native UserData namespace, and SYSTEM logon ID `0x3e7`.
- Lock/unlock behavior is plausible and retains the existing session identity. `WS-PPATEL-01.meridianhcs.local/windows_event_security.xml` contains three 4800/4624-Type-7/4801 sequences: lines 7109/7618/7673, 19010/19494/19549, and 28774/30701/30756, with roughly 5-, 4-, and 7-minute lock periods. These are not three newly created long-lived user sessions.
- macOS evidence distinguishes process lifetime from image changes. For example, MAC-MROSS-01 native ES lines 1–7 show launchd fork, xpcproxy exec, Terminal exec, Terminal child/login, and login child/zsh. PID 42171 persists through the first two exec images while `pidversion` changes 10→11→12. Matching normalized eCAR records retain a process UUID and explicit execution IDs rather than treating every exec as a new PID lifetime.
- Linux DHCP timer text and subsequent activity agree. `WS-LNGUYEN-01.meridianhcs.local/syslog.log` line 4 reports renewal in 1886 seconds at `13:01:20.059769Z`; line 29 requests renewal at `13:32:45.290758Z`, within about one second of that deadline. Its later renewals also track their preceding timer values rather than a fixed wall-clock grid.

## Detailed Analysis

### Inputs, provenance and limitations

I read the complete neutral briefing `/private/tmp/log-study-wxj1n2j_/host-prompt.md`. Actual analytical inputs were supplied files under `/private/tmp/log-study-wxj1n2j_/data`: the endpoint inventory, all 23 `ecar.json` files, all 20 Windows XML files across 10 hosts, all 11 Linux `syslog.log` files, both macOS ES files, both Unified Log files, and shell-history samples across the Linux and Mac hosts. Programmatic checks parsed 37,046 eCAR rows, 31,672 Windows events, and 304 macOS ES notifications. These are full-file structural/lifecycle checks accompanied by selected record-level examination, not a claim to have manually interpreted every event.

Only direct upstream Chromium and Apple public source URLs were consulted for the narrow application/command semantics below. No general web searches, project pages, project source, scenarios, TODO/worklogs, earlier assessments, other reviewer files, or neighboring inventories were examined. Inherited generic operating instructions identify the surrounding software workspace; that environment limitation was not used as evidence of origin.

One initial attempt to run the parsing script through `uv run python` in the inherited working directory failed with a cache-lock permission error before the script executed; no project/source/scenario information was returned. Parsing then used system `python3`, with later invocations explicitly rooted in the neutral data directory. I did not investigate the failure or inspect project configuration. All logged commands were treated as inert strings; none were executed.

Line references are one-based physical lines relative to the supplied data directory. For XML, a cited line is the start of the enclosing `<Event>` record. Most observations concern the approximately 13:00–19:00 UTC slice on 2026-11-02. Missing pre-window initiators and post-window closures are neutral. The supplied ES records declare message version 11/schema version 1; this does not independently establish an exact macOS release. I did not use unfamiliar native fields as schema defects.

### Windows process and session reconstruction

The Sysmon checks used GUID identity, not just PID order. They compared Event 1 creations, Event 5 terminations, ordinary `ProcessGuid` dependencies, Event 8/10 source and target GUIDs, and parent GUIDs. No impossible visible ordering was found in those tests. The matching-parent records also agreed on parent PID and executable path. This does not prove all events outside the slice exist; it does establish that the supplied visible relationships survive basic causal scrutiny.

For a concrete process pair, the first WS-MCHEN Sysmon Event 1 names `SearchProtocolHost.exe`, PID 6792, parent SearchIndexer PID 6072, SYSTEM user and logon `0x3e7`, at `13:00:31.9809210Z`. Its Security 4688 counterpart at `13:00:32.0907714Z` uses `NewProcessId=0x1a88`, creator `ProcessId=0x17b8`, and the same named-pipe command line. Security timestamps need not be identical to Sysmon timestamps.

Native Security session-use checks found no in-window references earlier than the first non-unlock 4624 for the same identity, nor references after its visible 4634. An initial mechanical last-4624 comparison would incorrectly flag Type 7 unlocks as new-session starts; I excluded that false interpretation. Network/service-heavy DC counts differ from workstation counts: DC-02 has 171 Type 3, 116 Type 5 and two Type 10 logons, whereas WS-PPATEL has three Type 3, nine Type 5, three Type 7 and one Type 2. The mix is plausible for the apparent roles. I did not penalize absent Sysmon event types or demand a boot sequence from this slice.

### macOS process, SSH and policy evidence

All 304 native ES records parsed: MAC-MROSS-01 has 38 forks, 44 execs and 37 exits; MAC-MROSS-02 has 58 forks, 70 execs and 57 exits. Repeated `(PID, pidversion)` identities did not disagree on executable path or process start time. Repeated executable device/inode identities did not disagree on path, file size or cdhash in the tested records. These observations support internal fidelity while leaving native message-version details outside the checked claims.

The two Mac SSH directions have distinct remote process chains. MAC-MROSS-01 lines 66–80 show launchd→xpcproxy→sshd-keygen-wrapper→sshd→sshd-session, short-lived authentication helpers, then session child and zsh. Its Unified Log line 3 reports public-key acceptance from `10.10.1.42:57354` at `16:02:03.740308Z`, before the interactive zsh target exec at `16:02:03.829876Z`. eCAR line 291 places the inbound TCP/22 observation at timestamp 1793635319913, before its successful SSH session record at line 297, timestamp 1793635325439. These are compatible source-specific observations, not a transport-after-authentication contradiction.

MAC-MROSS-01 Unified Log line 2 contains an AppleSystemPolicy message that policy “would not allow” MeetingAssist at `15:41:46.254163Z`. I did not infer successful execution from a notification, treat policy prose as an authorization result, or assume a plist removal terminated a loaded job. Native process evidence and normalized EDR evidence were interpreted separately.

The Chrome issue is the strongest concern. It is **not** merely multiple browser processes, which are expected: both contested processes have browser-leader argument vectors, and the later one visibly starts its own renderer/GPU descendants. The first leader is not shown terminating before the second starts; both have visible later exits, establishing a real overlap rather than an out-of-window ambiguity. Their eCAR process identities independently preserve that overlap (`MAC-MROSS-02/ecar.json`, lines 83 and 213 for Chrome exec transitions; lines 522–523 for their terminations).

The upstream [Chromium ProcessSingleton contract](https://raw.githubusercontent.com/chromium/chromium/main/chrome/browser/process_singleton.h) explains the per-user-data-directory exclusion; its [macOS implementation](https://raw.githubusercontent.com/chromium/chromium/main/chrome/browser/process_singleton_mac.mm) also forwards URL events to an existing browser. This is an inference about ordinary configuration, not an assertion that logs disclose the actual user-data directories. An unseen policy/configuration change or exceptional browser state could account for the overlap. That qualification prevents a `hard_contradiction` label.

The 77.8-second remote `id` is an outlier worth investigating, but not impossible: directory-service stalls and output blocking remain plausible. I assign it little score weight. All 94 visible ES exit records have `stat=0`, but the selection contains largely ordinary successful utilities/apps and no demonstrated forced failure; I do not score the zero statuses alone.

### Linux and user activity

Linux records provide SSH/PAM closures, sudo command/session triplets, cron, service messages and environment-specific background noise. At DB-PROD syslog lines 5–7, a `sudo` record for lina.nguyen running `/usr/bin/needrestart -b` is followed by root PAM session open/close under the same sudo PID. Pre-window SSH closures are not treated as orphaned sessions. The shell histories differ by visible activity: developer git/test commands on WS-LNGUYEN, auth-log investigation on PROXY/FILE-LNX, and service checks on server hosts. This is compatible with varied operator use, while a six-hour single-day slice cannot establish multi-day personal routines.

I checked a possible platform concern rather than assuming it: native Mac `/usr/bin/find ... -maxdepth 2` is not inherently a GNU-only contradiction. Apple's current upstream [find manual](https://raw.githubusercontent.com/apple-oss-distributions/shell_cmds/main/find/find.1) and [implementation](https://raw.githubusercontent.com/apple-oss-distributions/shell_cmds/main/find/function.c) explicitly support `-maxdepth`. No defect is scored for those command strings.

## Synthetic Indicator Summary

| Indicator | Category | Affected source family | Scope | Score effect |
|---|---|---|---|---|
| Two overlapping Chrome browser leaders under the same visible user/home with no visible profile separation; later leader starts helper tree | environment_or_collection_plausibility | macOS ES and normalized eCAR | MAC-MROSS-02, 15:09–18:56 UTC overlap | Main reason the score enters the mixed band; qualified by unknown effective configuration |
| Remote `id` takes 77.8 seconds while peer executions take fractions of a second | weak_signal | macOS ES | One MAC-MROSS-01 execution | Very small weight; plausible stall/backpressure explanations |

No verified hard contradiction or native-schema defect was established. Broadly successful causal checks and credible source-specific details counterbalance the application concern. Confidence in the *inconclusive* verdict is separate from the score of 43 describing how synthetic the observed data appears.

## Realism Score by Category

- **Field format accuracy:** 9 — Parsed records and checked identities are consistent; no verified native schema error.
- **Temporal patterns:** 8 — Visible lifecycles and DHCP timers are credible; one utility-duration outlier remains unexplained.
- **Cross-source correlation:** 9 — Windows process pairs and Mac SSH/EDR identities align without impossible checked ordering.
- **Behavioral realism:** 7 — Workstation/server activity is plausible, but the concurrent Chrome leaders need an application-level explanation.
- **Environmental consistency:** 8 — OS-specific process trees and role mix make sense; effective Chrome profile configuration is unknown.

## Recommendations

- If this were synthetic, model Chrome's per-profile running browser ownership. A subsequent `--new-window` launch using the same data directory should normally forward to that leader and exit; a separate sustained helper tree needs an explicitly distinct effective user-data directory or an evidenced exceptional state. Keep that choice consistent in ES and eCAR.
- If this were synthetic, derive utility lifetimes from the actual activity/IO conditions. An ordinary `id` should usually finish quickly; preserve a long duration when a modeled directory-service or terminal stall accounts for it. The single long execution here is a review target, not proof that every utility must obey a rigid runtime cap.
