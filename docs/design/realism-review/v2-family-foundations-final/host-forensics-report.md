# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 99
**Synthetic-Confidence Score:** 96

## Executive Summary

The dataset contains substantial, convincing endpoint detail, including realistic process trees, SSH/PAM lifecycles, role-specific activity, and strong Security/Sysmon/eCAR correlation. However, repeated source-native timestamp impossibilities, build-incompatible hash reuse, invalid RDP bootstrap ancestry, blank mandatory identity fields, and visible process-lifecycle inversions are decisive synthetic fingerprints.

## Evidence For Synthetic

- `[hard_contradiction]` There are 105 Sysmon records across seven of nine Windows hosts whose embedded `UtcTime` is more than one second later than the event’s own `System/TimeCreated`, with a maximum discrepancy of 7,564.947 seconds. This is not collection delay: the event header records the event before the event payload claims the activity occurred.

- `[hard_contradiction]` In `WS-AJOHNSON-01.meridianhcs.local/windows_event_sysmon.xml`, Firefox PID 5116 has header time `2024-03-18T12:08:03.7276029Z` but `UtcTime=2024-03-18 12:26:58.408`. Its module-load event has `UtcTime=12:08:03.822`, placing dependent activity almost 19 minutes before the declared process creation; Security and eCAR place the actual creation near `12:08:04Z`.

- `[hard_contradiction]` In `WS-MCHEN-01.meridianhcs.local/windows_event_sysmon.xml`, unrelated `mmc.exe`, Webex, `taskhostw.exe`, Postman, PowerShell, and SSH records have headers spanning `14:55:09Z` through `17:00:20Z`, yet repeatedly embed `UtcTime` values around `17:01:14.451`–`.453`. The recurrence of one future anchor across unrelated processes is generator-like.

- `[hard_contradiction]` `WS-SMARTINEZ-01` Sysmon Event 1 record 121356 creates Outlook PID 7460 at header time `13:42:38.3695434Z`, but its payload says `UtcTime=15:05:15.252`. Module and registry events for the same ProcessGUID begin at `13:42:38.464Z`, 4,956 seconds before its payload-declared creation.

- `[distribution_texture]` `winlogon.exe` and `userinit.exe` reuse identical SHA1, MD5, SHA256, and IMPHASH values across hosts visibly running Windows builds 17763, 19041, 20348, and 22621. For example, every observed `winlogon.exe` uses SHA256 `6B0FA04BC5E8CE24A5DB36851D4A6CDBBB1030B9C471A3E4FC3BD613B85080E7`, while `explorer.exe` correctly varies by build on those same systems.

- `[contract_gap]` Four RDP bootstrap trees create `winlogon.exe` from PID 4/System with no parent image: two on DC-01 and two on WS-AJOHNSON-01. Other visible interactive bootstrap trees correctly use `smss.exe -> winlogon.exe -> userinit.exe -> explorer.exe`, making the RDP-specific ancestry internally inconsistent.

- `[hard_contradiction]` Five Security 4688 records timestamp a child before its visible parent. DC-01 creates `userinit.exe` PID 4668 at `14:42:47.3773834Z` before its `winlogon.exe` parent PID 4660 at `14:42:47.4584681Z`; other inversions affect `cmd.exe -> net.exe`, `cmd.exe -> sc.exe`, and two `userinit.exe -> explorer.exe` chains. Sysmon and eCAR order the DC command chains correctly, isolating this as a Security-source timing defect.

- `[hard_contradiction]` In `WS-AJOHNSON-01.meridianhcs.local/ecar.json`, PowerShell PID 6496 is created at `17:19:40.220Z` and terminated at `17:19:40.246Z`, but then loads `kernel32.dll`, `kernelbase.dll`, `ucrtbase.dll`, `advapi32.dll`, and `rpcrt4.dll` through `17:19:40.293Z`.

- `[schema_or_format]` Ten FILE-SRV-01 successful Type 3 logons between `16:04:44.582Z` and `17:00:44.797Z` have empty `SubjectUserSid`, `SubjectUserName`, `SubjectLogonId`, `LogonGuid`, `LogonProcessName`, and `LmPackageName`. Their `WorkstationName` is the destination `FILE-SRV-01` even when `IpAddress` identifies a remote workstation, such as `10.10.1.34`.

- `[schema_or_format]` Four successful Type 10 logons have empty `TargetUserSid` and `LogonGuid`. Twelve associated RDP bootstrap 4688 records omit `ParentProcessName`, and four `winlogon.exe` records additionally omit subject SID, username, and logon ID.

- `[weak_signal]` All 776 Sysmon Event 1 records use `{00000000-0000-0000-0000-000000000000}` for `LogonGuid`, including 173 domain-user process creations. This uniformly suppresses a normal session-correlation field despite otherwise rich endpoint correlation.

## Evidence For Real

- 776 of 778 Security 4688 process creations have a matching Sysmon Event 1 within three seconds, agreeing on PID, image, and command line. Ordinary records also agree on parent, user, and logon ID.

- Security 4689, Sysmon Event 5, and eCAR termination evidence generally preserve process identities and valid lifecycle ordering. No Sysmon ProcessGUID has duplicate creations or terminations, and the PowerShell module-ordering defect is the only eCAR actor-after-termination case observed.

- Executable and module hashes are otherwise stable for the same path and version. Explorer and PowerShell hashes vary consistently with the Windows build visible on each host.

- RDP transport evidence is convincingly correlated. For example, the AJOHNSON-to-DC tuple `10.10.1.35:59308 -> 10.10.2.10:3389` appears in source and destination eCAR evidence before DC-01 records the Type 10 logon from the same address and port at `14:42:47.2466972Z`.

- A PsExec-style sequence on DC-01 has plausible source-native staging: a Type 3 logon, Sysmon file creation, Security 4697 service installation, and subsequent `PSEXESVC.exe -> cmd.exe` process evidence.

- Account creation, password reset, enablement, group membership, and deletion use appropriate Security event IDs 4720, 4724, 4738, 4728, and 4726 with consistent subject and target SIDs.

- Security-log clearing is correctly represented as Event 1102 using `UserData`; the Security record ID resets to 1 and then resumes at later IDs.

- Linux SSH sessions show credible sequencing. On APP-INT-01, the `13:45:49Z` connection from `10.10.1.35` proceeds through public-key acceptance, PAM session open, `systemd-logind` session creation, PAM close at `14:00:35Z`, and session removal.

- Linux background activity is host-sensitive: mail systems contain Postfix and Dovecot activity, database infrastructure shows `multipathd`, and workstations show GDM, NetworkManager, DHCP, firmware, and desktop services.

- Bash histories contain role-specific activity and human texture. Lina Nguyen performs database and development work, Marcus Chen performs mail and system administration, and the `uptiem` typo in MAIL-CLIN-01 is an organic-looking mistake rather than a polished command sequence.

## Detailed Analysis

### Sysmon temporal integrity

Most Sysmon records have header and payload times separated by only a few milliseconds. The 105 anomalous Event 1 and Event 5 records therefore form a distinct broken population, not an alternative timestamp convention.

The strongest example is Firefox PID 5116 on WS-AJOHNSON-01. Security and eCAR place its creation around `12:08:04Z`, while Sysmon’s Event 1 header is `12:08:03.7276029Z`; nevertheless, that same record declares `UtcTime=12:26:58.408`. A module-load event for its ProcessGUID is timestamped `12:08:03.822`, meaning the payload model says the process loaded modules before it existed. The process-termination payload then jumps to `14:00:33.984`, despite a header at `12:54:23.2688859Z`.

This defect recurs across unrelated applications and users. On WS-MCHEN-01, several process records converge on nearly identical future payload times around `17:01:14.45Z`. On WS-SMARTINEZ-01, Outlook’s payload creation time is over 82 minutes later than its header and immediate module events. These are source-visible impossibilities within the observation window.

### Windows process trees and lifecycle

Ordinary process relationships are convincing: `services.exe` launches service executables, `svchost.exe` launches WMI and scheduled activity, `csrss.exe` launches `conhost.exe`, user applications descend from `explorer.exe`, and admin SSH clients descend from PowerShell or `cmd.exe`.

The RDP bootstrap path is materially weaker. Four remote-session trees parent `winlogon.exe` directly to PID 4 and lose parent-image fields, while local interactive trees correctly model `smss.exe` as the parent. Associated Security 4688 records also omit subject and parent identity. The defect follows one activity family rather than host configuration, which is characteristic of a separate synthetic construction path.

Security timestamps create five additional inversions. The clearest DC-01 case creates `userinit.exe` 81 milliseconds before its `winlogon.exe` parent. Separate command chains place `net.exe` or `sc.exe` before `cmd.exe`, while Sysmon and eCAR render those same chains in the correct order.

The eCAR PowerShell PID 6496 lifecycle is also impossible: after termination at `17:19:40.246Z`, five foundational DLL loads occur over the next 47 milliseconds. A short process lifetime is plausible; loading core modules after termination is not.

### Field and hash fidelity

Windows event envelopes, provider GUIDs, event IDs, versions, tasks, and most data fields are accurately shaped. Event 1102’s `UserData` representation and record-ID reset are particularly convincing.

The explicit remote-logon paths are much less complete. FILE-SRV-01’s ten Type 3 logons use blank XML values where source-native events normally provide an identity or sentinel such as `S-1-0-0`, `-`, or `0x0`. They also identify the destination server as `WorkstationName` despite remote client IPs. Four RDP logons likewise omit the authenticated account SID.

Hash handling is mostly excellent and build-aware, but `winlogon.exe` and `userinit.exe` are conspicuous exceptions. Their complete hash sets are identical across four Windows build families and their version metadata is always `-`, while adjacent system binaries vary appropriately. That selective reuse is a strong deterministic fingerprint.

Every Sysmon Event 1 also carries a zero `LogonGuid`. Zero can occur in real telemetry, but 776 out of 776—including 173 domain-user processes with populated logon IDs—is implausibly uniform and removes a correlation facility the rest of the dataset otherwise models carefully.

### Cross-source endpoint correlation

Cross-source construction is generally strong. Security 4688 and Sysmon Event 1 agree on nearly every process, and eCAR usually preserves the same actor, PID, parent, user, command line, and lifecycle. Network tuples also align with endpoint identities and remote logons.

This completeness was not treated as synthetic evidence. The scored issues are concrete contradictions: payload timestamps that claim future events, parent/child inversions, invalid RDP ancestry, missing source-native fields, and post-termination module loads.

### Linux and user-behavior realism

Linux evidence is among the most convincing portions. Successful SSH sequences contain connection, authentication, PAM, and logind stages with realistic subsecond spacing and session durations. Failed sessions similarly progress through connection, invalid-user identification, failed authentication, and pre-auth close.

Background activity provides environmental texture: `cron`, `anacron`, `snapd`, unattended upgrades, rsyslog queue state, DNS degraded-mode recovery, IRQ balancing, mail daemons, desktop services, and DHCP behavior differ by apparent host role.

Bash histories are varied rather than exact copies. Database queries, mail administration, application troubleshooting, editors, build tools, and remote access align with different users and systems. Occasional misspellings and unsuccessful-looking commands add credible human variability.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on synthetic-confidence score |
|---|---|---:|---|
| `hard_contradiction` | Sysmon Event 1/5 | 105 records across 7 Windows hosts | Decisive: embedded event time occurs minutes or hours after the record header and after dependent activity |
| `distribution_texture` | Sysmon hashes | Dataset-wide across 4 Windows builds | Strong generator fingerprint: identical bootstrap hashes selectively reused across incompatible builds |
| `contract_gap` | RDP Security/Sysmon/eCAR | 4 remote session trees | RDP-only path uses PID 4 rather than `smss.exe` and loses parent identity |
| `hard_contradiction` | Security 4688 | 5 process chains | Visible children precede their visible parents; sibling sources order some chains correctly |
| `hard_contradiction` | eCAR process/module lifecycle | 1 PowerShell process, 5 late module loads | Core DLL loads occur after termination |
| `schema_or_format` | Security 4624/4688 | 10 file-server logons plus 4 RDP sessions | Blank mandatory/sentinel fields and incorrect workstation semantics |
| `weak_signal` | Sysmon Event 1 | 776 records | Universal zero `LogonGuid` suppresses normal session correlation |

## Realism Score by Category

- **Field format accuracy:** 5/10 — Most schemas are accurate, but blank Security fields, incorrect workstation semantics, and fixed cross-build hashes are substantial defects.
- **Temporal patterns:** 2/10 — Linux and ordinary endpoint timing are plausible, but 105 future-valued Sysmon timestamps and visible lifecycle inversions are decisive.
- **Cross-source correlation:** 7/10 — Most Security, Sysmon, eCAR, and transport evidence correlates well; the RDP and process-lifecycle gaps prevent a higher score.
- **Behavioral realism:** 8/10 — User roles, commands, process trees, and administrative activity generally look lived-in and differentiated.
- **Environmental consistency:** 8/10 — Host-specific services, software, OS builds, and Linux background behavior are coherent aside from the highlighted bootstrap artifacts.

## Recommendations

If this were synthetic, the highest-value improvement would be to enforce one canonical occurrence time for each Sysmon event and derive both `System/TimeCreated` and payload `UtcTime` from it. Add assertions that process creation precedes all same-GUID dependent events, termination follows them, and header/payload times remain within a small provider-appropriate tolerance.

Make executable identity build-aware. `winlogon.exe`, `userinit.exe`, and other operating-system binaries should receive version metadata and hashes from the same per-build catalog used successfully for Explorer and PowerShell; identical hashes should be reused only when the underlying binary version is genuinely identical.

Route RDP bootstrap through the same lifecycle contract as other Windows interactive sessions: `smss.exe -> winlogon.exe -> userinit.exe -> explorer.exe`. Preserve parent GUID, PID, image, subject SID, user, and logon ID across Security, Sysmon, and eCAR.

Populate Security fields with source-native values or sentinels instead of empty strings. For remote Type 3 logons, derive `WorkstationName` from the initiating client rather than the destination, and populate the logon process and subject section consistently with the selected authentication package.

Finally, apply a lifecycle-aware ordering pass after source timing jitter. It should prevent child-before-parent Security events and module loads after eCAR process termination, while also generating nonzero Sysmon `LogonGuid` values where a real authenticated session exists.
