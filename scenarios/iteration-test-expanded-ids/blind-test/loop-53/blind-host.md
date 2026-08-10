# Host/EDR Forensics Reviewer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 92  
**Synthetic-Confidence Score:** 86

## Executive Summary

The corpus has strong structural realism: endpoint lifecycles, identities, timestamps, and Windows source correlations are generally coherent. However, dataset-wide file-path fingerprints and implausible process-to-file/registry ownership recur across unrelated hosts, including 272 uniformly formatted Windows temporary filenames and duplicated Thunderbird profile identifiers across different users and operating systems. These patterns are much more consistent with reusable generation pools than production telemetry.

## Evidence For Synthetic

- `[distribution_texture]` Of 438 Windows eCAR FILE records, 272 (62.1%) use exactly `C:\Windows\Temp\<five decimal digits>.tmp`. Per-host proportions range from 60.5% to 94.9%, affecting all nine Windows systems. Examples include `WS-PPATEL-01/ecar.json:15` (`smss.exe` writing `17003.tmp`), `:99` (`SearchIndexer.exe` reading `35599.tmp`), and `DC-01/ecar.json:88` (`lsass.exe` reading `49482.tmp`). The uniform filename grammar and indiscriminate spread across unrelated executables are a generator-like fleet-wide fingerprint.
- `[contract_gap]` File ownership is frequently behaviorally implausible. `smss.exe` writes `C:\Windows\Temp\17003.tmp` at 12:10:02 and later creates `49826.tmp` at 15:08:54 (`WS-PPATEL-01/ecar.json:15,530`); `userinit.exe` reads `45076.tmp` (`:127`); and `lsass.exe` reads `49482.tmp` on the DC (`DC-01/ecar.json:88`). The process IDs and actor UUIDs are internally coherent, but the assigned behaviors resemble randomly paired process/path/action pools.
- `[distribution_texture]` Thunderbird profile identifiers leak a repeated construction pattern. Four of five distinct observed profile names begin with `1000`, and the exact identifier `100043h4g4.default-release` appears for unrelated users on different OSes: Lina Nguyen on Linux (`WS-LNGUYEN-01/ecar.json:143`) and Priya Patel on Windows (`WS-PPATEL-01/ecar.json:278`). Omar Haddad’s single Thunderbird process also creates INBOX files under two different generated profiles (`1000icp4ie` and `1000u4oanq`) at `WS-OHADDAD-01/ecar.json:129,367`.
- `[contract_gap]` Registry modifications are attributed to processes whose visible activity does not plausibly own the setting. Examples include an Outlook process modifying `ContentDeliveryManager\SubscribedContent-338389Enabled` (`WS-AJOHNSON-01/ecar.json:141,662`), and a PowerShell process whose command is only `Get-ChildItem C:\Logs ... | Measure-Object` modifying the same setting (`:1444`). Similar broad pairings recur with `dllhost.exe` modifying firewall policy (`FILE-SRV-01/ecar.json:43`) and `services.exe` writing the `SecurityHealthSystray` Run key (`WS-MCHEN-01/ecar.json:688`).
- `[distribution_texture]` Linux process texture is heavily cloned: the exact parent/child pair `"/bin/sh -c 'command -v debian-sa1 ...'"` and `debian-sa1 1 1` occurs 88 times each across eight Linux hosts, with each host contributing 10–12 pairs. The activity itself is legitimate, but the near-uniform sampled count across servers, workstations, mail systems, proxy, and web roles adds to the templated fleet impression.

## Evidence For Real

- Process lifecycle integrity is strong. Across 25,104 eCAR records, there are 1,686 process creates, 1,422 terminations, and 1,341 directly paired process object IDs. A probe of all dependent records found zero events occurring before their known actor process creation or after its known termination.
- Windows source correlation is convincing. Matched Sysmon process events and eCAR process records agree on PID and image; observed timing differences remain small and plausible. Across hosts, matched create delays stayed within roughly 2.1 seconds and termination differences within roughly 3.2 seconds.
- Windows identity mappings are stable: each named user maps to one SID, with no SID shared by different named users.
- Source-native event sequencing is well handled. On `DC-01`, Security Event 1102 at `2024-03-18T17:42:17.7438087Z` correctly uses EventRecordID 1 after the audit log is cleared (`windows_event_security.xml:312677-312700`), followed by newly incrementing record IDs. This is a realistic detail.
- Host roles are reflected in the telemetry: the DC has heavy Kerberos/authentication volume; file-server network logons are short-lived and largely paired; mail hosts contain Postfix/Dovecot activity; and `WEB-EXT-01` has substantially more firewall/kernel noise than internal Linux systems.
- Format and field rendering are generally careful: Windows XML providers, channels, Event IDs, GUIDs, hex PIDs/logon IDs, Sysmon hash sets, RFC5424 syslog framing, and eCAR actor/object references are consistently parseable.

## Detailed Analysis

The reviewed endpoint corpus contains 25,104 eCAR records, 14,396 Windows Security events, 4,107 Sysmon events, and 4,087 Linux syslog records spanning six hours on 18 hosts.

### Process and session lifecycle

The canonical endpoint relationships are one of the corpus’s strongest features. Known process actors are temporally valid, PID/image correlations hold, and common interactive chains such as `winlogon.exe → userinit.exe → explorer.exe` preserve session and logon ownership. Type 3 Windows sessions are usually closed quickly: on the DC, 468 matched sessions have a median lifetime of 17.47 seconds; on `FILE-SRV-01`, 312 have a median of 30.8 seconds.

Unpaired service and interactive sessions are explainable at the edges of a six-hour window. I did not find impossible dependent-event ordering.

### File telemetry

This is the clearest authenticity failure. The Windows side uses a dominant `C:\Windows\Temp\NNNNN.tmp` grammar regardless of host role or source process:

- `DC-01`: 29/32 FILE records.
- `FILE-SRV-01`: 28/30.
- `MAIL-FIN-01`: 37/39.
- `WS-AJOHNSON-01`: 23/28.
- Across all Windows hosts: 272/438.

Production temporary-file telemetry normally reflects multiple application-specific naming schemes, GUIDs, hexadecimal identifiers, installer conventions, and subdirectories. Here one five-digit decimal template overwhelms the fleet and is attached to core processes such as `lsass.exe`, `smss.exe`, `csrss.exe`, `wininit.exe`, `dwm.exe`, and `svchost.exe`.

Thunderbird artifacts reinforce this finding. The same synthetic-looking profile identifier is reused cross-user and cross-platform, while one long-running Thunderbird actor writes to two distinct profile trees without visible profile-selection semantics.

### Registry telemetry

Many ordinary registry records are credible, including UserAssist ROT13 paths and scheduled-task/cache activity. Nevertheless, several exact process/key pairings are semantically disconnected. The PowerShell `Get-ChildItem` example is especially revealing because the recorded command does not explain a ContentDeliveryManager setting change, yet eCAR asserts that exact PowerShell process as the source. Similar questionable pairings recur enough to suggest independent sampling of process actors and registry keys.

### Temporal and cross-source behavior

Windows timing and source relationships are strong. EventRecordIDs progress appropriately, filtered-source gaps are plausible, and the DC audit-clear reset is modeled correctly. The main temporal weakness is not impossible ordering but repeated scheduled texture: Linux hosts show nearly identical retained counts for the same sysstat process pair despite differing roles and overall activity levels.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Impact |
|---|---|---:|---|
| `distribution_texture` | eCAR FILE | 272/438 Windows FILE records; all 9 Windows hosts | Dominant five-digit temp-file grammar is a dataset-wide generator fingerprint. |
| `contract_gap` | eCAR process/file | Multiple core Windows processes and hosts | File operations are attached to implausible owners despite valid IDs and lifetimes. |
| `distribution_texture` | eCAR FILE | Windows and Linux workstations | Reused `100043h4g4.default-release` and repeated `1000...` profile construction expose pooled identifiers. |
| `contract_gap` | eCAR REGISTRY | Several Windows hosts | Process command/identity does not plausibly own the recorded registry mutation. |
| `distribution_texture` | Linux eCAR | 176 process records across 8 hosts | Nearly uniform cloned sysstat process-pair sampling weakens host-specific texture. |

## Realism Score by Category

- **Field format accuracy:** 8/10 — Formats are highly parseable and source-native fields are mostly convincing, but generated path grammars stand out.
- **Temporal patterns:** 8/10 — Lifecycles and cross-source delays are strong; repeated scheduled sampling is somewhat templated.
- **Cross-source correlation:** 9/10 — PID, image, session, identity, and ordering correlations are consistently good.
- **Behavioral realism:** 4/10 — File and registry ownership frequently conflicts with the asserted source process’s plausible behavior.
- **Environmental consistency:** 7/10 — Host roles are visible and sensible, but artifact pools are reused too uniformly across the fleet.

## Recommendations

- If this were synthetic, make file and registry activity process-owned rather than independently sampling an active actor, action, and artifact. Encode behavioral contracts for core Windows processes, application caches, Defender, installers, browsers, mail clients, and system services.
- Replace the fleet-wide five-digit Windows temp-name template with source-specific naming distributions and paths. Core processes should emit only artifacts they plausibly access.
- Allocate browser/mail profile identifiers once per user installation and preserve them for the entire dataset. Prevent reuse across users and operating systems, and prevent one process from silently switching profile trees.
- Validate registry telemetry against the visible command and executable role. A command such as `Get-ChildItem ... | Measure-Object` should not own an unrelated ContentDeliveryManager mutation.
- Diversify Linux periodic-task observation by host configuration, package version, scheduling convention, uptime, and collection loss while retaining the existing strong lifecycle and timestamp integrity.
