# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 96  
**Synthetic-Confidence Score:** 93

## Executive Summary

The endpoint records contain credible Windows process trees and macOS Endpoint Security–style fields, but repeated timestamp patterns and questionable macOS lifecycle details outweigh those strengths. The clearest tell is a batch of unrelated Mac process exits placed at 100 ms intervals near the end of the window, alongside sparse Unified Log coverage and a cross-source file-creation gap.

## Evidence For Synthetic

- **distribution_texture** — `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson` has many unrelated process exits from `18:56:58.400Z` through `18:56:59.800Z` in exact 100 ms steps: zsh, login, Chrome helpers, iTerm, Zoom, Outlook, and Terminal.
- **distribution_texture** — `com.meridianhcs.endpoint-inventory` runs at `13:30:38`, `15:16:14`, and `17:52:03`; each `/usr/bin/sw_vers` execution exits exactly two seconds after its fork.
- **contract_gap** — `MAC-MROSS-01.meridianhcs.local/ecar.json` records a root-owned create of `/Library/LaunchDaemons/com.meridianhcs.endpoint-inventory.plist` attributed to `/bin/sh`, but the visible Endpoint Security file has only event types 9, 11, and 15, with no corresponding file-create event. Partial source coverage may explain this.
- **environment_or_collection_plausibility** — The Mac Unified Log file has only two records across the window: loginwindow at `13:04:26` and SSH acceptance at `14:24:27`. Sparse coverage alone is not decisive, but it limits native-log support for the visible activity.
- **weak_signal** — All 181 Mac Endpoint Security events have `action.result.result.auth = 0`; uniformity across forks, execs, and exits is suspicious but not conclusive.

## Evidence For Real

- Windows records preserve plausible process relationships. `WS-AJOHNSON-01` Sysmon shows `winlogon.exe` → `userinit.exe` → `explorer.exe` around `14:13:50.976Z`; its Security log includes process, logon, and logoff families.
- Mac Endpoint Security uses recognizable event shapes: type 11 fork, type 9 exec, type 15 exit, audit tokens, signing IDs, executable paths, and PID versions. Terminal starts zsh at `13:07:43Z`; shell history includes `sw_vers`, `uname`, and file-inspection commands that also appear in endpoint execs.
- Unified Log records SSH acceptance from `10.10.1.41` at `14:24:27Z`, aligned with endpoint SSH service processes.

## Detailed Analysis

The visible environment is a mixed Windows/Linux/macOS fleet in `meridianhcs.local`, with host names suggesting workstations, file servers, mail, proxy, database, and application roles. Windows Sysmon has plausible paths and parent chains; the sampled Aisha workstation includes Outlook, Firefox, and `mstsc.exe` launched by Explorer.

On `MAC-MROSS-01`, Endpoint Security begins with launchd, XPC proxy, Terminal, login, and zsh. The shell launches `sw_vers`, `uname`, `pwd`, `ls`, `du`, `ssh`, and `cat`; audit UID 501 and command paths are plausible. Unified Log corroborates SSH acceptance. The mass-exit sequence is the strongest concern: diverse long-lived application and shell processes terminate within 1.4 seconds at exact 100 ms spacing. That could be a bounded session close, but the identical cadence is mechanical.

The EDR-normalized launch-daemon file-create record has no corresponding native file event in the visible ES data. Since only selected ES event types appear, this is treated as a contract gap rather than a hard contradiction. Two Unified Log records are sparse relative to the endpoint stream, but source coverage alone does not establish an error.

## Synthetic Indicator Summary

- **distribution_texture** — macOS Endpoint Security lifecycle — mass exits at exact 100 ms intervals; strong score increase.
- **distribution_texture** — Mac inventory process — repeated two-second command lifetimes; small increase.
- **contract_gap** — eCAR versus Endpoint Security file creation — launch-daemon plist create lacks a visible native companion; moderate increase, tempered by scope.
- **environment_or_collection_plausibility** — Sparse Unified Log coverage; small increase.
- **weak_signal** — Uniform `auth: 0` field across Mac ES events; small increase.

## Realism Score by Category

- **Field format accuracy:** 8/10 — Windows XML and macOS Endpoint Security fields are recognizable and mostly coherent.
- **Temporal patterns:** 4/10 — The near-window-end exits are evenly spaced at 100 ms; inventory commands also have fixed two-second lifetimes.
- **Cross-source correlation:** 7/10 — Shell commands and SSH align across endpoint, history, and Unified Log, but plist creation lacks visible native file evidence.
- **Behavioral realism:** 6/10 — User and application activity is plausible overall; the coordinated mass exit is suspiciously regular.
- **Environmental consistency:** 6/10 — The mixed fleet is plausible, but sparse Unified Log coverage limits confidence in the Mac collection picture.

## Recommendations

- Vary Mac process-exit timestamps to reflect application and session shutdown timing rather than fixed 100 ms spacing.
- If the capture scope records the launch-daemon plist creation, include its native file event; otherwise qualify the normalized EDR create record.
- Include additional Unified Log records only if the modeled collection scope is intended to cover that activity.
