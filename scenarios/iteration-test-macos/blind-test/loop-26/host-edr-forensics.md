# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 82
**Synthetic-Confidence Score:** 68

## Executive Summary

The endpoint evidence has credible process identities, Windows session behavior, and Linux administrative activity, and the sampled visible lifecycles are generally coherent. My synthetic verdict rests primarily on repeated, exactly preserved microsecond fractions across separate macOS fork notifications, including unrelated shell commands and the same browser startup offsets on both Macs; this is a concrete timing texture rather than an inference from how complete the activity appears. I found no demonstrated impossible process lifetime in the bounded checks, so the score stays in the “likely synthetic” band.

## Evidence For Synthetic

- [distribution_texture] Separate macOS shell commands repeatedly fork at precisely the same six-digit fractional second, tens of seconds apart. In `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson`, lines 32, 35, 38 are forks at `13:48:48.715405000Z`, `13:49:18.715405000Z`, `13:50:08.715405000Z` for PIDs 46145, 46192, 46270; their following exec records identify `pwd`, `ls`, and `du`. Lines 49, 52, 55 repeat `.314210000Z` for `df`, `ps`, and `find` at `14:37:48`, `14:38:25`, `14:39:17`. These are native notification timestamps, not second-resolution shell history timestamps.
- [distribution_texture] The behavior repeats on the second Mac. `MAC-MROSS-02.meridianhcs.local/macos_endpoint_security.ndjson` lines 114, 117, 120 have forks at `17:33:09.349034000Z`, `17:33:57.349034000Z`, `17:34:45.349034000Z`; lines 129, 132, 135 repeat `.610141000Z` at `18:24:27`, `18:25:32`, `18:26:32`. Across the two native files, the 51 and 49 fork notifications have only 41 and 35 distinct fractional seconds respectively. Excluding browser startup groups still leaves 31 fork notifications in 13 groups sharing an exact fractional second within each group.
- [distribution_texture] The initial Chrome process trees use identical whole-second launch offsets on both machines. MAC-MROSS-01 lines 17, 20, 22, 24 fork Chrome, renderer, GPU, and network helper at `13:13:31.649335`, `:33.649335`, `:34.649335`, `:36.649335`. MAC-MROSS-02 lines 22, 25, 27, 29 repeat the same `0, +2, +3, +5` second offsets at `13:27:10.342871` through `:15.342871`. Common software explains similar process roles, but exact microsecond-preserving offsets in native fork times strengthen the timing-template interpretation.
- [weak_signal] MAC-MROSS-01 has four adjacent exit-to-next-fork gaps of exactly 1 millisecond: native lines 112–113, 115–116, 135–136, 138–139. For example, PID 78270 exits at `18:15:31.531726000Z`, then PID 78271 forks at `18:15:31.532726000Z`. Short shell command transitions are legitimate; repeated exact boundaries provide only supporting weight and are not counted as an independent hard contradiction.

## Evidence For Real

- Windows creation evidence agrees on process ownership across three endpoint views. WS-MCHEN-01 Sysmon XML beginning at line 1297 identifies SSH PID 7396, parent PowerShell PID 7320, user `MERIDIANHCS\marcus.chen`, and LogonId `0x6c2f76f` at `13:20:44.1350436Z`. Security XML beginning at line 2048 has 4688 NewProcessId `0x1ce4` (=7396), creator `0x1c98` (=7320), the same command and session; eCAR line 80 has PID 7396/PPID 7320 with that session and command at `13:20:44.303Z`.
- The sampled Windows interactive startup chains are credible. WS-MCHEN-01 Sysmon lines 4801 and 4846 show `winlogon.exe → userinit.exe → explorer.exe` at `14:46:26.0488662Z` and `14:46:26.3343870Z`, with userinit PID 7832 and explorer parent PID 7832. WS-EBROOKS-01 Sysmon lines 879 and 924 show the equivalent chain with different process identities and timing.
- Linux SSH logs contain plausible transport, acceptance, PAM, logind, and closure stages. DB-PROD-01 `syslog.log` lines 8–11 show connection `10.10.1.35:59353`, accepted RSA public key, PAM open for aisha.johnson UID 2528, then logind session 276589; line 71 closes the same sshd PID 1044253 at `14:01:28.698990Z`. Lines 87–90 separately show an invalid-user password failure and preauth close.
- Linux scheduled maintenance has coherent scheduling. WS-LNGUYEN-01 `syslog.log` lines 22–23 announce anacron at `13:26:03` and a five-minute delay; line 29 starts `cron.daily` at `13:31:13`, and line 34 records its termination. Lines 4–6 and 30–32 show DHCP renewal with matching address/server and a plausible interval.
- macOS evidence distinguishes fork, successive exec images, credential/session changes, and process exit. MAC-MROSS-01 native lines 1–3 preserve PID 42169 through launchd fork, xpcproxy exec, and Terminal exec while pidversion changes; MAC-MROSS-02 native lines 46–60 preserve the remote SSH process family and later user shell. The native file identities checked did not reuse one device/inode pair for different executable paths/sizes.

## Detailed Analysis

### Scope and method

I inspected only the supplied data tree. This was a bounded representative review, not an exhaustive audit of every host or every source: Windows Security/Sysmon on WS-MCHEN-01, WS-EBROOKS-01, FILE-SRV-01, DC-01; eCAR on those relevant endpoints and DB-PROD-01, WS-LNGUYEN-01, MAC-MROSS-01/02; representative Linux syslog; and both Mac native Endpoint Security files plus their short Unified Log exports. All line numbers are one-based physical lines; XML citations refer to the opening line of the relevant `<Event>`.

The primary computations used the standard-library XML and JSON parsers. For the four Windows hosts, I indexed Sysmon Event 1 and Event 5 by ProcessGuid, then checked later process-bearing Event 1/3/7/8/10/11/13/22 references against visible termination times. I also compared process creation LogonId against visible Security 4634 closure, and checked hashes grouped by image path and FileVersion. The results were:

| Host | Visible Sysmon creations | Visible terminations | Later use of terminated process GUID | Creation after same-session 4634 | Image/version groups with multiple hash sets |
|---|---:|---:|---:|---:|---:|
| WS-MCHEN-01 | 97 | 78 | 0 | 0 | 0 of 34 |
| WS-EBROOKS-01 | 80 | 58 | 0 | 0 | 0 of 31 |
| FILE-SRV-01 | 94 | 92 | 0 | 0 | 0 of 11 |
| DC-01 | 132 | 129 | 0 | 0 | 0 of 22 |

These counts do not treat absent pre-window creations or post-window terminations as defects. There were also no sampled children created after the visible parent GUID's termination. Separate objectID checks on eCAR for DB-PROD-01, WS-LNGUYEN-01, and both Macs found no later event on the same process objectID after its visible termination; this check does not establish that every indirect actor reference was exhaustively validated.

### macOS timestamp texture

The strongest evidence is in native fork notification times, rather than normalized EDR formatting. A reproduction requires only loading each `macos_endpoint_security.ndjson`, selecting records whose `event` contains `fork`, and grouping `time` by its substring after the decimal point within each file. Count the groups and inspect the associated child PIDs and following exec arguments. This yields the exact repetitions cited above, including multiple command families on each host.

The important distinction is between realistic semantic repetition and implausible timestamp precision. Users routinely execute `pwd`, `ls`, `du`, `df`, and `ps`; those command names are not synthetic tells. Forks preserving all six meaningful fractional digits across 30-, 37-, 44-, 48-, 50-, 52-, 58-, 60-, and 65-second offsets repeatedly resemble activities placed relative to a shared timestamp anchor. Automated scripts can produce regular intervals, and collection software can transform timestamps, so this is not a proof of impossible activity. However, true native fork execution normally introduces scheduling and command-execution variation; both files retain smaller variable deltas for following exec notifications, making the exact fork anchor repetitions especially conspicuous.

I treat the identical Chrome helper offsets as another manifestation of that same timing issue, not as a wholly independent defect. Likewise, the four 1 ms exit/fork transitions receive little extra weight.

### Windows process and session semantics

The Windows sample is substantially more convincing. ProcessGuid identity, decimal/hex PID conversion, parent process IDs, logon IDs, and image/hash consistency survive the bounded checks. Foreground activity includes browsers, SSH clients, administrative shells, editors, and remote desktop clients, while server telemetry contains service-owned processes and network activity. I did not infer realism simply from the completeness of the source matching.

WS-MCHEN-01 Security records show a lock at `13:38:55.0073156Z`, Type 7 unlock at `13:49:51.2820703Z`, and 4801 at `13:49:51.7721121Z`, all associated with marcus.chen and session `0x6c2f76f`. This addresses a common lack of workstation lock/unlock texture without requiring the entire environment to follow one user behavior pattern. The presence of older-session exits near the collection start is neutral.

### Linux and macOS lifecycle interpretation

The Linux sample separates sudo caller and elevated child identities: DB-PROD-01 eCAR lines 21–22 have lina.nguyen's sudo PID 1044648 and root lsof PID 1044649; syslog lines 16–18 name the sudo caller, elevated command, PAM open, and close. SSH and anacron sequences described above have plausible ordering.

On macOS, I did not equate one exec image with a new process lifetime, audit-session ID with a Windows logon ID, or responsible process with immediate parent. I found no log-visible demonstration of a denied program later executing successfully. MAC-MROSS-01 Unified Log line 2 reports the AppleSystemPolicy message about MeetingAssist at `15:41:46.250414`; a policy message alone does not justify a denied-execution/child-execution allegation. I did not penalize the limited native event selection or short Unified Log exports, and did not make unverified claims about version-specific native schema details.

### Limits and alternative explanation

A timestamp-normalizing export layer or intentionally scripted endpoint workload could explain part of the macOS timing texture. No such behavior is declared in the supplied records, and the repeated exact fractional seconds across numerous separate commands and both browser startups makes a synthetic timing model the more likely explanation to me. The bounded lifecycle checks and cross-source agreements argue against a much higher score; I did not identify a hard contradiction, generator identifier leak, or source-wide impossible lifecycle.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected the score |
|---|---|---|---|
| distribution_texture | Native macOS Endpoint Security | 100 fork records across two hosts; 24 repeated-fraction surplus observations; 13 non-browser same-fraction groups | Repeated exact microsecond anchoring across separately executed shell commands is the primary synthetic indication. |
| distribution_texture | Native macOS Endpoint Security | Both initial Chrome process trees | Identical `0/+2/+3/+5 s` fork offsets with preserved fractional seconds strengthen the same timing-template finding. |
| weak_signal | Native macOS Endpoint Security | Four adjacent exit/fork pairs on MAC-MROSS-01 | Exact 1 ms boundaries provide limited corroboration; shell scheduling can also create short gaps. |

## Realism Score by Category

- **Field format accuracy:** 9 — XML and JSON parse successfully; sampled native and normalized identities are coherent, without a demonstrated schema contradiction.
- **Temporal patterns:** 5 — Windows/Linux timing is credible, but repeated native Mac fork fractions materially weaken authenticity.
- **Cross-source correlation:** 9 — Sampled Windows PID, parent, command, user, and session alignment is strong; bounded lifetime checks passed.
- **Behavioral realism:** 8 — Administrative tasks, interactive sessions, browser trees, sudo, cron, and SSH are plausible in the examined records.
- **Environmental consistency:** 8 — Sampled OS-specific evidence and service/process roles are compatible; collection limitations prevent broader claims.

## Recommendations

- If this were synthetic, generate each actual macOS fork occurrence with its own realistic execution/scheduling time rather than preserving one microsecond anchor across a batch of commands. Keep fork-to-exec and parent/child ordering intact.
- If this were synthetic, vary browser child startup timings according to the shared startup activity while avoiding identical exact `+2/+3/+5` second fork schedules on different hosts.
- If this were synthetic, review the four exact 1 ms exit/fork boundaries and model shell readiness/next-command execution with source-appropriate timing variation. Do not add arbitrary delays that reverse existing lifecycle relationships.
- Preserve the demonstrated Windows identity/hash consistency, Linux sudo ownership, and SSH/session semantics while improving timing; the review supplies no evidence-based reason to add unrelated sources or arbitrary failures.
