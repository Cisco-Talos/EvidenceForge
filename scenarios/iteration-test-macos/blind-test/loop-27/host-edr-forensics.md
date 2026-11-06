# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 70
**Synthetic-Confidence Score:** 35

## Executive Summary

The representative endpoint evidence is mostly production-like: Windows process identities and hashes remain stable, Linux SSH sessions have sensible authentication and close sequences, and macOS records distinguish forks from successive executable images. I found limited repeated background-process texture but no demonstrated impossible lifecycle or source-native contradiction in the bounded checks; the remaining clues do not reliably distinguish a carefully modeled collection from real filtered telemetry.

## Evidence For Synthetic

- [weak_signal] Two different Windows servers have identical counts for two sampled background process families: `DC-01` and `FILE-SRV-01` each contain 30 Sysmon Event 1 `taskhostw.exe` creations and 19 `WmiPrvSE.exe` creations during the visible window. They also draw their `dllhost.exe /Processid:` commands from the same three CLSIDs. Reproduce by filtering EventID 1 and grouping `Image`/`CommandLine` in their `windows_event_sysmon.xml` files. This is a modest texture clue, not an impossibility: common Windows software and management can explain shared commands, and two hosts are insufficient for a strong statistical claim.
- [weak_signal] The two macOS ES streams begin with audit-session values 100000/100001 and successive `pidversion` values starting at 10; their first terminal TTY snapshots both use `st_ino=100000001`, `st_dev=16777217`, and `st_rdev=268435456`. See `MAC-MROSS-01.../macos_endpoint_security.ndjson` lines 1–7 and `MAC-MROSS-02.../macos_endpoint_security.ndjson` lines 1–7. The rounded inode and matching initial counters look constructed, but matching independent host-local counters and device numbers are possible. I assign little weight and do not allege a native schema error.

## Evidence For Real

- A concrete Windows process aligns across independent source shapes: `WS-AJOHNSON-01.../windows_event_sysmon.xml` EventRecordID 30297 (record ID at line 44) has `taskhostw.exe /Run`, PID 5204, parent PID 4356, SYSTEM, and LogonId `0x3e7` at `2026-11-02 13:06:37.575`. Security EventRecordID 129949 (line 56) uses hexadecimal `NewProcessId=0x1454`, `ProcessId=0x1104`, the same command and subject, at `13:06:37.6251808Z`. Sysmon EventRecordID 30298 closes the same ProcessGuid at `13:06:53.073`.
- In three sampled Windows hosts, each `(Image, FileVersion)` among visible Sysmon process creations has one hash set, and no visible Sysmon occurrence with the same `ProcessGuid` follows its visible Event 5 exit by `UtcTime`. This supports consistent identities without treating completeness as evidence against authenticity.
- `DB-PROD-01.../syslog.log` lines 8–11 show SSH connection, accepted public key, PAM session opening, and logind session 276589 in that order at `13:08:29.587455Z` through `13:08:31.845124Z`; lines 71–72 close and remove the same session at `14:01:28.698990Z` and `14:01:29.037735Z`.
- The Mac streams contain distinct terminal implementations. `MAC-MROSS-01` lines 1–7 show launchd → xpcproxy → Terminal, followed by login and zsh; `MAC-MROSS-02` lines 1–7 show xpcproxy → iTerm2 → iTermServer → login. Same-PID exec changes are represented as image transitions rather than unrelated process creations.
- DC Security clearing has appropriate native shape: `DC-01.../windows_event_security.xml` EventID 1102 at line 260257 uses the Microsoft-Windows-Eventlog provider and namespaced `UserData/LogFileCleared`, with EventRecordID 1 at `18:42:31.1287936Z`. Following visible records restart at small IDs, including 4689 record 8 at `18:42:38.5160252Z`. The pre-clear `wevtutil cl Security` process is visible.

## Detailed Analysis

### Scope and method

I inspected only the supplied data directory. Detailed Windows checks covered `WS-AJOHNSON-01`, `DC-01`, and `FILE-SRV-01`; Linux checks covered representative `DB-PROD-01`, `WS-OHADDAD-01`, and `APP-INT-01` syslog/history content; macOS checks covered both `MAC-MROSS` hosts. I parsed the selected XML and JSON files, examined actual records, grouped process image/version/hash combinations, and checked process identity relationships. This is representative review, not an exhaustive assertion that every supplied record is correct. Paths abbreviated with `...` refer to `.meridianhcs.local` under the supplied data directory.

### Windows process trees and lifecycle

The sampled process trees are materially richer than a flat sequence of user commands. `WS-AJOHNSON-01` includes winlogon/userinit/explorer chains, console hosts under csrss, service processes under services, task/WMI/COM processes under svchost, and user applications under explorer. Its Sysmon file contains 103 process creations and 83 exits; the difference alone is neutral within the bounded window.

The three sampled hosts contain 329 Sysmon Event 1 records in total: 103 workstation, 132 domain-controller, and 94 file-server creations. Grouping each host's creations by exact `Image` and `FileVersion` found no changing hash set. Checking visible process GUIDs against visible Event 5 records found no later same-GUID occurrence using `UtcTime`. I also checked eCAR process relationships on seven hosts: the same three Windows hosts, `DB-PROD-01`, `WS-OHADDAD-01`, and both Macs. For each visible process object, no nontermination object/actor reference preceded its visible creation or followed its visible termination by more than one second. That tolerance avoids treating subsecond source-rendering/collection differences as hard lifecycle failures.

The server background counts are the main Windows suspicion, but their timestamps are not a shared fixed schedule. For example, `DC-01` taskhost starts include `13:02:15.877`, `13:07:53.149`, and `13:12:33.802`; `FILE-SRV-01` starts include `13:09:47.475`, `13:24:46.916`, and `13:50:06.810`. Shared CLSIDs are ordinary COM vocabulary; exact family-count coincidence carries only weak evidential weight. Examples of the common COM pool are DC records 3289358/3289370 (`AB8902B4-09CA-4BB6-B78D-A8F59079A8D5`, record-ID lines 15264/15622) and file-server records 1644332/1644390 (other CLSIDs, lines 1537/2545).

### Logon sessions and Linux evidence

The workstation has local interactive, remote interactive, network, service, and unlock evidence. Security LogonId `0x25c400f` starts as Type 2 at `13:41:49.8255363Z` (record 130057), then has Type 7 unlock records at `16:45:04.9774697Z` and `18:34:33.4853728Z`. Remote session `0x26d7ab7` starts Type 10 at `15:59:40.5346887Z` and has a Type 10 logoff at `18:55:02.0116647Z`. Network session `0x26b719f` lasts approximately 3.6 seconds. These are differentiated session behaviors rather than a single universal duration.

Linux syslog supports both server and desktop interpretations. The database SSH example above has coherent username, PID 1044253, client `10.10.1.35:59353`, server `10.10.4.10:22`, and logind session ownership. Its eCAR shell creation uses parent PID 1044253, principal `aisha.johnson`, and session ID 276589. `WS-OHADDAD-01.../syslog.log` lines 2–3 instead show a gdm-password login for `omar.haddad` and logind session 207416. The sampled files include cron/anacron, package-related authorization, multipath, desktop, and service messages. I did not penalize the limited volume of any individual family or require unselected audit facilities.

### macOS source interpretation

The ES exports declare message `version=11`; I evaluated visible identity and lifecycle relationships without asserting undocumented field incompatibilities. On `MAC-MROSS-01`, PID 42169 proceeds from forked launchd image (`pidversion=10`) to xpcproxy (`11`) to Terminal (`12`); the Terminal target has UID 501 and audit session 100001. Subsequent child PID 42171 executes `/usr/bin/login` with effective UID 0, then its child PID 42172 executes zsh with effective UID 501 and `/dev/ttys000`. The eCAR stream separately expresses CREATE and MODIFY/exec transitions with execution identifiers. These distinctions support plausible source semantics.

The small Unified Log samples include a kernel message saying policy “would not allow” an application. I did not infer denial of all execution from that text, and did not count sparse Unified Log coverage as a defect. I did not verify the native ABI of every version-11 ES field or application entitlement; unfamiliar details are uncertainty, not scored contradictions.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| weak_signal | Windows Sysmon process creation | Two sampled servers; identical 30 taskhost/19 WMI counts and shared COM command pool | Small upward adjustment; ordinary software and chance remain credible explanations |
| weak_signal | macOS Endpoint Security metadata | Initial terminal sequences on two hosts | Small upward adjustment for matching rounded inode/counters; no impossible native value demonstrated |

No hard contradiction or required-companion failure was demonstrated in the bounded checks. No score derives from intrusion linearity, successful activity, source completeness, sanitized domains, missing event types, or out-of-window lifecycle records.

## Realism Score by Category

- **Field format accuracy:** 9 — Sampled XML/native JSON structures and Windows hexadecimal/decimal identity representations are credible; full native ABI validation was outside this review.
- **Temporal patterns:** 8 — Varied timings and plausible session durations; weak background-count similarities remain.
- **Cross-source correlation:** 9 — Concrete process and SSH identity checks agree, with no demonstrated impossible same-identity ordering.
- **Behavioral realism:** 8 — Credible system/user process trees and differentiated desktop/server/terminal behavior; some shared background vocabulary.
- **Environmental consistency:** 8 — Sampled Windows servers, Linux desktop/server roles, and Mac terminal implementations fit their visible evidence.

## Recommendations

- If this were synthetic, examine why two distinct Windows servers have exactly equal taskhost and WMI creation totals; tie these starts to host-specific visible workloads if the equality comes from a shared count budget. Preserve legitimate shared Windows command vocabulary.
- If this were synthetic, check whether initial Mac audit/device/inode values are actual platform-derived values or placeholders. Replace placeholders only with source-valid metadata; matching host-local counters alone do not justify artificial variation.
- Preserve the demonstrated stable process identities/hashes, explicit macOS exec transitions, Security clear/reset behavior, and SSH authentication/session ordering. These are substantive strengths, not “too complete” tells.
