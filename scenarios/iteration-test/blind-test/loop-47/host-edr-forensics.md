# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 87
**Synthetic-Confidence Score:** 78

## Executive Summary

Most endpoint evidence has convincing process, session, platform and source-correlation semantics. My synthetic verdict rests chiefly on four reversals of the native macOS fork identity-version allocation sequence on one host, while substantial Windows and Linux lifecycle checks passed; this is a localized identity-field problem rather than a dataset-wide failure of behavioral realism.

## Evidence For Synthetic

- [hard_contradiction] `MAC-MROSS-02.meridianhcs.local/macos_endpoint_security.ndjson` records a new fork at line 44, `2026-11-02T14:22:52.776507000Z`, whose child is PID `29633`, `pidversion:69`, and another new fork at line 47, `14:24:42.387235000Z`, whose child is PID `30060`, `pidversion:47`. These are newly created children, not later observations of older processes. Their child `start_time`, message `time`, `mach_time` and `global_seq_num` all establish the forward chronology. Native XNU fork allocation consumes a shared atomic `nextpidversion` counter, so this small backward jump is incompatible with ordinary native allocation in that chronology. Three further fork-to-fork reversals occur at lines 80→82 (`84→72`), 101→105 (`95→88`), and 117→120 (`111→97`). See the qualification and primary references below.

## Evidence For Real

- Windows process identity is internally coherent in the tested scope: across all ten Sysmon files, I found no same-`ProcessGuid` event timestamp before its visible creation or after its visible termination, and no child creation after the visible termination of its `ParentProcessGuid`. Pre-window processes were allowed.
- Windows executable hashes remain stable within host and `Image`/`FileVersion`. Across hosts, the same path and specified version also retained the same hashes; the small number of path-level variants had an unspecified `FileVersion` of `-`, which is insufficient to establish a contradiction.
- Windows logs contain differentiated session behavior, including Type 2 interactive, Type 3 network, Type 5 service, Type 7 unlock, Type 9 new-credentials and Type 10 remote-interactive activity. `WS-MCHEN-01` has an actual lock/unlock interval at Security XML lines 21968 and 25767, `18:04:45.7065290Z` to `18:53:45.5926181Z`, associated with the same user/session.
- A concrete process matches across three views: on `WS-MCHEN-01`, Sysmon Event 1 at XML line 133 (`13:03:21.9551241Z`) identifies SearchFilterHost PID `6852`, parent SearchIndexer PID `6072`; Security 4688 at line 172 (`13:03:22.0078938Z`) has `NewProcessId:0x1ac4`, parent `0x17b8`; eCAR line 6 has PID `6852`, PPID `6072`, the same images/command and SYSTEM ownership at `13:03:22.066Z`.
- Linux SSH evidence includes authentication, PAM session opening, logind registration, shell/command activity and session closure. For example, `APP-INT-01` syslog lines 172–175 and eCAR lines 406–422 retain Maya's source `10.10.1.41:56813`, sshd PID `2975377`, shell PID `2975396` and session `378050` through the visible session.
- macOS distinguishes fork from exec: `MAC-MROSS-01` ES lines 1–7 show launchd child creation, xpcproxy, Terminal, login and zsh, while `MAC-MROSS-02` lines 1–10 include iTermServer and ShellLauncher. Exec image changes retain process lifetime/start-time identity instead of creating an unrelated process at every image change.

## Detailed Analysis

### Inputs, boundaries and method

I read the complete neutral briefing at `/private/tmp/log-study-p29dfwbp/host-prompt.md` and inventoried only its supplied `data` directory. I parsed all 19,030 Security XML events, 11,785 Sysmon XML events, 35,805 eCAR records and 283 Endpoint Security records. I inspected the 3,861 Linux syslog lines, all six Unified Log records, and shell-history content from the 27 supplied history files (531 physical lines, including timestamp lines). The longest history was displayed only through line 80 during the initial history inspection; no conclusions depend on unread later commands. I did not read network-sensor, proxy-access, firewall, IDS or web-access file contents.

I used local Python standard-library analysis as a reader. Logged commands were inert data and were never executed. Public reference research was limited in substantive reliance to Apple's XNU source described below. No project files, scenarios, implementation code, worklogs, prior assessments or other reviewers' reports were accessed. Inherited generic project metadata is an environmental limitation and was not origin evidence.

Checks included exact Sysmon GUID relationships, image/hash grouping, visible logon/logoff ordering, eCAR process ownership timing and macOS fork/exec/exit identity transitions. For normalized eCAR timing comparisons I allowed a two-second source delay margin; a clean result therefore does not certify subsecond semantics or every possible target-identity relationship.

### macOS native identity allocation defect

The affected file declares ES message `version:11` and `schema_version:1`; no explicit macOS product/build release was supplied, so I do not infer one from a network row or invent a specific OS release.

For the principal example:

| ES line | UTC time | Operation/child | Child pidversion | mach_time | global_seq_num |
|---|---|---|---:|---:|---:|
| 44 | 14:22:52.776507 | Fork, PID 29633 | 69 | 56106546636168 | 43 |
| 45 | 14:22:52.780163 | Exec xpcproxy, PID 29633 | 70 | 56106546723912 | 44 |
| 46 | 14:22:52.787475 | Exec Zoom, PID 29633 | 71 | 56106546899400 | 45 |
| 47 | 14:24:42.387235 | Fork, PID 30060 | 47 | 56109177293640 | 46 |
| 48 | 14:24:42.471747 | Exec xpcproxy, PID 30060 | 48 | 56109179321928 | 47 |

The child `start_time` equals its corresponding fork time in each fork record. Thus sorting older processes by observation time cannot explain this pair. The use of the same host and advancing Mach time also defeats ordinary file sorting, wall-clock adjustment or a pre-window initiating event as explanations.

Apple's [XNU fork implementation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_fork.c) assigns a new fork's identity version by atomically incrementing `nextpidversion`. Apple's [exec implementation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_exec.c) similarly obtains a new identity version from that counter during exec. These are native allocation semantics, not a requirement that every process or every event be collected. Omitted events can create upward gaps; they cannot normally produce these backward allocations. Four counter wraparounds in this short interval would require extraordinary unseen process churn and have no support in the supplied telemetry.

Additional examples within the same ES file are:

- Lines 80→82: new child PID `38957` at `15:00:21.710528Z`, version `84`; then PID `41771` at `15:23:41.846670Z`, version `72`.
- Lines 101→105: PID `45878` at `16:05:46.686677Z`, version `95`; then PID `47721` at `16:25:23.065029Z`, version `88`.
- Lines 117→120: PID `52334` at `17:12:27.393377Z`, version `111`; then PID `53037` at `17:19:29.440742Z`, version `97`.

This is a source-native allocation contradiction across visible newly created processes; I did not find an impossible same-process create/exit ordering and do not describe this as one. A disclosed sanitization scheme that intentionally replaces opaque audit identity versions could explain a transformed real export. Such a scheme was not supplied, so it remains a material alternative and limits certainty about origin. The lower score than a wholesale hard-failure dataset reflects that limitation and the localized scope.

### Windows processes, sessions and environment

The ten Windows host pairs parse successfully and use credible source shapes: hexadecimal Security process IDs align with decimal Sysmon/eCAR IDs; command lines, parent images, principals and session identifiers are preserved in spot checks. Security 4688 versus Sysmon Event 1 counts differ slightly on a few hosts, but source observation differences are allowed and do not establish bad collection by themselves.

I checked visible non-well-known logon IDs with both 4624 and 4634. None had a logoff earlier than its only visible initiation. SYSTEM's well-known `0x3e7` is not treated as a unique ordinary interactive session. Likewise, a missing creation before the window or missing termination after the window was neutral.

The logs differentiate native Windows binary versions by host: DC-01/DC-02 use `10.0.20348.1` in their visible native-process records; FILE-SRV-01 uses `10.0.17763.1`; workstation groups include `10.0.19041.1` and `10.0.22621.1`. I found no reason to apply one workstation's native expectations to all servers. Parentage includes SearchIndexer→SearchFilterHost, services and service-host activity, userinit/explorer, shell tools and remote-access clients, rather than putting every process under explorer.

### Linux and normalized EDR semantics

Process durations span short commands, multi-second administrative tools and long-lived shells/SSH sessions. For example APP-INT-01's matched eCAR process lifetimes range from `0.070` to `13338.618` seconds; its median is approximately `3.414` seconds. I did not find a fixed one-duration process model in that aggregate.

The Maya SSH example is ordered meaningfully: inbound FLOW eCAR line 406 at `17:01:36.190Z`; password acceptance in syslog line 172 at `17:01:45.272641Z`; PAM opening at `17:01:45.438653Z`; logind session registration at `17:01:45.993437Z`; normalized LOGIN at `17:01:46.263Z`; shell creation at `17:01:47.702Z`. Shell-history `id` and `uname` timestamps precede their corresponding eCAR observations by modest source delays, and close evidence occurs around `17:11:00Z`. This is a credible transport/authentication/shell distinction.

### macOS interpretation limits and positive correlations

The two Macs have separate local process trees and differing terminal implementations. I found no same PID+pidversion message emitted after its visible exit, and executable-file stat objects remained stable for a path within each host in the supplied ES records. I did not equate an exec target's image with a newly forked process.

On MAC-MROSS-02, inbound SSH FLOW at eCAR line 88 (`14:24:37.976Z`) precedes Unified Log password/PAM acceptance at line 2 (`14:24:44.399410Z`) and normalized session LOGIN at eCAR line 94 (`14:24:45.375Z`). On MAC-MROSS-01 the comparable FLOW at eCAR line 281 (`16:01:34.505Z`) precedes public-key acceptance in Unified Log line 3 (`16:01:38.551396Z`) and LOGIN at eCAR line 287 (`16:01:40.288Z`). These correlations receive realism credit, not a penalty for completeness.

The ASP policy message on MAC-MROSS-01 Unified Log line 2 is not used to assert successful denied execution, and the plist CREATE/DELETE rows are not treated as proof of registration, activation or unload. Native file/policy event coverage is too narrow to establish those extra transitions. Thin Unified Log coverage and the selected ES event families are neutral by themselves.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| hard_contradiction | macOS native Endpoint Security audit tokens | Four fork pidversion reversals in MAC-MROSS-02 ES: lines 44→47, 80→82, 101→105, 117→120 | Principal origin indicator: new-child identities run backward despite forward start/message/Mach chronology. Localized to one host; intentional opaque-ID remapping remains an alternative. |

No separate score penalty was assigned for complete matching, thin coverage, missing selected Sysmon types, incident narratability, compactness, domain sanitization, or out-of-window lifecycle boundaries.

## Realism Score by Category

- **Field format accuracy:** 7 — Strong Windows/Linux structures and rich macOS records, with a consequential native audit-token allocation defect on one Mac.
- **Temporal patterns:** 8 — Broad duration variation and credible auth/shell sequencing; the Mac identity-counter chronology is the important exception.
- **Cross-source correlation:** 9 — Concrete process and SSH examples agree across endpoint views; no broad same-identity lifecycle violation was found.
- **Behavioral realism:** 8 — Differentiated users/tools, unlocks, remote sessions and background activity; no narratability-based deductions.
- **Environmental consistency:** 9 — Platform-specific trees, terminal differences and host-specific Windows versions fit the visible environment.

## Recommendations

- If this were synthetic, allocate macOS native `pidversion` values from one host-wide chronological identity allocator shared by all fork and exec activity families. Validate newly allocated values using actual execution chronology and Mach time, while preserving older values in later snapshots of already-existing processes.
- If the field values were instead intentionally replaced during sanitization, document that transformation explicitly and preserve the native ordering invariant, or clearly identify the replacement field as a normalized opaque identifier. This would remove the ambiguity behind the principal authenticity finding.
