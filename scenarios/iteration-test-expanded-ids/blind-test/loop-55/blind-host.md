# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 84
**Synthetic-Confidence Score:** 74

## Executive Summary

The endpoint corpus is technically strong: 893 sampled Windows process creations aligned across Security 4688, Sysmon 1, and eCAR without image mismatches, and no impossible visible lifecycle ordering was found. However, command semantics and repeated actor-incompatible registry effects provide concrete synthetic tells, especially a commandless `runas.exe` producing explicit-credential evidence while remaining alive for 43 minutes, and six of six Office registry records being attributed to the wrong Office application.

## Evidence For Synthetic

- `[hard_contradiction]` On `WS-MCHEN-01`, Sysmon Event 1 records PID 8812 as `C:\Windows\System32\runas.exe` with the complete command line `runas.exe` at `2024-03-18T14:50:25.5605486Z`. Security Event 4648 follows at `14:50:26.1570134Z`, naming that PID/process as the explicit-credential caller, although the visible command has neither `/user:` nor a target program. eCAR keeps the commandless process alive from `14:50:26.552Z` until `15:33:52.238Z`, a lifetime of 2,605.686 seconds. A bare `runas.exe` invocation should display usage and exit; it cannot perform the represented credentialed launch. Sources: `WS-MCHEN-01.meridianhcs.local/windows_event_sysmon.xml`, `windows_event_security.xml`, and eCAR records 770 and 909 in `ecar.json`.
- `[contract_gap]` All six Office-specific registry records are owned by the wrong executable. At `2024-03-18T13:50:13.970Z`, `WINWORD.EXE` writes both `...\PowerPoint\File MRU\Item 4` and `...\Excel\File MRU\Item 13`; at `14:59:47.369Z`, `OUTLOOK.EXE` twice writes `...\Word\Reading Locations\Document 1\Datetime`; and at `15:40:16.850Z`, Outlook writes `...\Excel\File MRU\Item 21`. Another Outlook-to-Word mismatch occurs on `WS-MCHEN-01` at `12:31:45.124Z`. Sources: `WS-AJOHNSON-01.meridianhcs.local/ecar.json` and `WS-MCHEN-01.meridianhcs.local/ecar.json`.
- `[distribution_texture]` Fourteen Defender exclusion-path writes occur on three hosts in six hours, all targeting numbered `C:\ProgramData\Vendor\Cache\<n>` entries and all attributed directly to `MsMpEng.exe` or `MpCmdRun.exe`. Examples include `DC-01` at `12:51:03.380Z` (`Cache\80`) and `WS-PPATEL-01` at `17:39:47.206Z` (`Cache\37`). This repetitive administrative-policy mutation pattern is much less plausible than exclusions being changed by management policy, PowerShell, an installer, or an administrator. Sources: the eCAR files for `DC-01`, `FILE-SRV-01`, and `WS-PPATEL-01`.
- `[weak_signal]` Every one of the nine Windows hosts exposes the same broad Sysmon family palette—Events 1, 3, 5, 7, 10, 13, and 22, with Event 11 on eight hosts and Event 8 on seven. Central configuration can explain this, but the uniformity adds modest synthetic texture when combined with the stronger defects above.
- `[weak_signal]` Startup module fan-out is highly templated in places: one exact five-DLL palette appears 44 times and a seven-DLL palette appears 29 times, commonly completing within tens of milliseconds. Sysmon filtering can legitimately create this shape, so this affected the score only slightly.

## Evidence For Real

- The bounded window is exactly represented in eCAR from `2024-03-18T12:00:01Z` through `17:59:58Z`; I did not penalize unpaired state at either boundary.
- Across 24,868 eCAR rows, testing visible process identities found zero dependent events before their visible actor creation, zero dependent events after their visible actor termination, and zero process terminations before creation.
- For 3,006 non-create eCAR events whose actor process was visibly created in-window, PID, principal, and source-image attribution all agreed with the actor’s process identity.
- Across the nine Windows hosts, 893 process PIDs were simultaneously present in Security 4688, Sysmon Event 1, and eCAR PROCESS/CREATE; all 893 used the same executable path. Security-to-Sysmon timestamp offsets showed varied sub-60-ms jitter rather than exact timestamp cloning.
- Windows channel sequencing is convincing. EventRecordIDs are monotonically increasing on every channel except when `DC-01` records Security Event 1102 at `2024-03-18T17:42:26.3595316Z`; its record ID correctly resets to 1, and the next event advances to 2.
- The `DC-01` PsExec chain has credible staged timing and parentage: service creation at `16:00:04.020Z`, `PSEXESVC.exe` creation at `16:00:07.123Z`, and its `cmd.exe /c whoami && hostname` child at `16:00:08.847Z`.
- The Linux evidence includes differentiated host roles and reasonable noise: mail hosts carry Postfix/Dovecot activity, `DB-PROD-01` has multipath/IRQ activity, and `WEB-EXT-01` has high-volume kernel UFW blocks. All 300 timestamped bash-history commands are monotonic within their respective history files, with 218 distinct commands.

## Detailed Analysis

### Process and lifecycle integrity

The corpus contains 3,968 eCAR PROCESS records and 2,134 USER_SESSION records across 18 endpoint hosts. Same-identity visible-order checks found no impossible lifecycle inversions. Visible parent process UUIDs, PIDs, images, and principals also remained coherent through downstream FLOW, MODULE, FILE, REGISTRY, and PROCESS/OPEN events.

The principal process defect is semantic rather than chronological. `runas.exe` PID 8812 is created by `explorer.exe` under `marcus.chen`, but its command line contains no operands. Security 4648 then claims it used explicit credentials against `DC-01`, and Security 4689/eCAR termination does not arrive until roughly 43 minutes later. The lifetime alone would be suspicious; the commandless invocation plus 4648 makes it source-visible and functionally contradictory.

### Windows cross-source correlation

Security/Sysmon/eCAR process correlation is unusually well executed but was not scored negatively for completeness. Representative common-process counts were 163 on `DC-01`, 161 on `WS-AJOHNSON-01`, 121 on `WS-MCHEN-01`, and 98 on `FILE-SRV-01`, with no image mismatches. Security-to-Sysmon deltas generally ranged from approximately -21 to +58 ms, while eCAR introduced varied host-dependent observation delays.

EventRecordID behavior is similarly credible. The `DC-01` Security channel climbs into the 28-million range, logs Event 1102 with record ID 1, then continues at 2. That is convincing native behavior associated with a cleared Security log rather than an arbitrary sequence reset.

### Registry and application ownership

The registry telemetry is the clearest recurring model weakness. Every Office record selected by the `Microsoft\Office\16.0\<application>` path disagrees with the producing executable: Word writes PowerPoint and Excel MRUs, while Outlook writes Word reading state and Excel MRUs. Two identical Outlook-owned Word-reading writes also share the same `14:59:47.369Z` timestamp on `WS-AJOHNSON-01`.

Defender exclusion writes show a related ownership/distribution problem. Fourteen records repeatedly mutate numbered vendor-cache exclusion paths from Defender engine/CLI processes across `DC-01`, `FILE-SRV-01`, and `WS-PPATEL-01`. The repetition across roles and the arbitrary numeric suffixes look like a generalized artifact pool rather than software-specific state changes.

### Linux and user texture

The Linux hosts exhibit useful role differentiation, and command history is not globally uniform: 300 commands reduce to 218 unique strings. Repeated entries such as `id`, `uptime`, `crontab -l`, and `free -h` are normal administrative vocabulary. SSH, sudo/PAM, systemd-logind, cron, workstation desktop services, and server-specific daemons supply credible supporting texture. No bash-history timestamp reversal was found.

### Collection and distributions

The common Sysmon event-family footprint across all Windows endpoints is plausible under a centrally deployed configuration, so it is not independently decisive. The same caution applies to common DLL startup palettes. They become weak supporting indicators only because stronger command and registry contradictions show that some event families are assembled from generalized behavioral templates.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---:|---|
| `hard_contradiction` | Sysmon, Security, eCAR process/auth | One process across three sources | Commandless `runas.exe` cannot produce the visible 4648 behavior, and its 43-minute lifetime compounds the contradiction. |
| `contract_gap` | eCAR/Sysmon registry | 6 of 6 Office-specific writes on 2 hosts | Producer executable and application-specific registry state disagree systematically. |
| `distribution_texture` | eCAR/Sysmon registry | 14 writes on 3 hosts | Repeated Defender-owned numbered cache exclusions resemble a generalized artifact template. |
| `weak_signal` | Sysmon | Dataset-wide over 9 Windows hosts | Nearly uniform event-family deployment is possible but unusually even. |
| `weak_signal` | eCAR/Sysmon module loads | 73 repeated startup palettes | Reused short DLL palettes provide limited generator-like texture but remain collection-filter explainable. |

## Realism Score by Category

- **Field format accuracy:** 8 — XML, eCAR, identifiers, paths, timestamps, and native EventRecordID behavior are generally convincing.
- **Temporal patterns:** 7 — Cross-source jitter and visible lifecycle ordering are strong, but the commandless `runas.exe` lifetime is not credible.
- **Cross-source correlation:** 9 — Process identity, executable paths, parentage, and lifecycle ordering correlate exceptionally well without relying on completeness as an authenticity clue.
- **Behavioral realism:** 5 — The runas semantics and repeated application-incompatible registry behavior are substantial endpoint-forensics tells.
- **Environmental consistency:** 6 — Linux role texture is good, while repeated Defender exclusion mutations and uniform Windows collection shape reduce confidence.

## Recommendations

- If this were synthetic, make executable semantics authoritative. A successful `runas.exe` activity must include a valid `/user:` target and target command, align Event 4648 with those values, and use an outcome-appropriate lifetime. A bare invocation should terminate within seconds and must not emit successful explicit-credential evidence.
- Make registry effects actor-native. Word should own Word reading/MRU state, Excel should own Excel MRUs, PowerPoint should own PowerPoint MRUs, and Outlook should own Outlook-specific state; do not attach generalized Office artifacts to whichever Office process happens to be alive.
- Move Defender exclusion changes to a credible administrative producer and trigger—such as policy application, PowerShell `Add-MpPreference`, or an installer—and sharply reduce their frequency. Bind paths to the actual installed product or workload rather than numbered generic cache templates.
- Retain the existing visible-order, parent/process identity, EventRecordID, and cross-source timestamp contracts; these are among the most production-like aspects of the corpus.
- If broad Sysmon coverage is intentional, introduce host/cohort-specific filter texture and less repetitive selected-module palettes while preserving parseability and correlation.
