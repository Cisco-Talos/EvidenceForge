# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 92
**Synthetic-Confidence Score:** 84

## Executive Summary

The Windows and Linux evidence has substantial endpoint realism, including credible process ancestry, varied session types, stable executable hashes, and coherent SSH lifecycles. The decisive contrary evidence is in MAC-MROSS-02's native Endpoint Security audit tokens: newly created process/execution identities repeatedly receive lower `pidversion` values than identities already created earlier on the same boot, while both wall-clock and Mach time advance. Repeated exact one-millisecond shell scheduling boundaries provide a smaller, separate indication of constructed timing.

## Evidence For Synthetic

- **[hard_contradiction] Native macOS identity allocation runs backward.** In `MAC-MROSS-02.meridianhcs.local/macos_endpoint_security.ndjson`, line 1 creates child PID 19775 with `pidversion=31` at `2026-11-02T13:20:29.875707000Z`; line 2 execs it with version 32. At line 3, `2026-11-02T13:37:11.846603000Z`, a new launchd child PID 21356 instead receives version 10. Its source `mach_time` is later as well. These are new fork/exec target identities, not later references to old processes. Apple's XNU assigns these versions from a shared incrementing counter at fork and exec. Further reversals occur at lines 15–17 and 80–99, ruling out one isolated malformed row. See the detailed qualification about transformations and wraparound below.
- **[distribution_texture] Repeated exact scheduling offsets in native notifications.** The same MAC-MROSS-02 file contains seven adjacent exit→fork transitions separated by exactly 1,000 microseconds, despite otherwise microsecond-varying timestamps: line pairs 18→19, 21→22, 24→25, 85→86, 88→89, 94→95, and 97→98. Examples include `13:37:33.139751`→`13:37:33.140751` and `15:48:46.207061`→`15:48:46.208061`. Scripted command sequences are entirely plausible; the repeated exact numerical boundary, rather than the existence or compactness of a sequence, is the indicator. This receives limited weight.
- **[distribution_texture, corroborative to the first finding] Native identity versions behave like a closed allocation list.** The 82 fork-child/exec-target observations on MAC-MROSS-01 contain exactly every integer from 10 through 91; the 124 on MAC-MROSS-02 contain exactly every integer from 10 through 133. The second list is interleaved out of numerical order. Over the approximately six-hour records, there are no intervening values attributable to any unobserved fork or exec. Because the field is a kernel-wide allocation counter, selective collection would normally leave gaps; this is allocation/volume texture, not a complaint that coverage is thin. I treat this as supporting evidence for the same identity-allocation defect, not a third independent hard contradiction.

## Evidence For Real

- Windows ancestry and token distinctions are credible. In `WS-MCHEN-01.meridianhcs.local/windows_event_sysmon.xml`, the events beginning at lines 1660, 1705, and 1750 show `winlogon.exe` → `userinit.exe` → `explorer.exe` near `13:37:29–13:37:32`. The SYSTEM parent and medium-integrity `MERIDIANHCS\marcus.chen` descendants are distinguished; the user processes share LogonId `0x6c7dbd5` and terminal session 5.
- The Windows sources agree without requiring identical timestamps. Across all ten Windows hosts, 1,000 of 1,001 Sysmon process creations have a Security 4688 match by host, PID, and image; every matched command line agrees. The median Sysmon-minus-Security timestamp difference is approximately −139 milliseconds, with maximum absolute difference approximately 642 milliseconds. A single unmatched creation is not evidence of fabrication under the supplied collection assumptions.
- Executable hashes remain stable for repeated same-path process creations within each Windows host. Across hosts, common Windows executables have different hashes associated with file versions `10.0.17763.1`, `10.0.19041.1`, `10.0.20348.1`, and `10.0.22621.1`, supporting a mixed estate instead of one universal binary identity.
- Linux SSH evidence has realistic multi-stage timing. `APP-INT-01.meridianhcs.local/syslog.log` lines 3–6 show transport arrival from `10.10.1.35:65202` at `13:00:15.633505`, public-key acceptance at `13:00:22.231675`, PAM open at `13:00:22.298841`, and logind session 376068 at `13:00:22.829575`. Lines 47–48 close the same sshd PID/session at `14:01:11.365187` and `14:01:11.711903`.
- Native macOS records correctly distinguish a process lifetime from successive executable images. On MAC-MROSS-01, native ES lines 1–7 keep PID 42154 across launchd→xpcproxy→Terminal exec transitions, retain start time, then show Terminal→login→zsh with separate child PIDs. Responsible-process audit tokens for shell commands point back to Terminal instead of simply equaling each command PID.
- Background and user activity are not interchangeable across the estate. Examples include sysstat cron, snapd, logind and sudo activity on Linux; GUI and shell activity on the Macs; and role-relevant Git/build commands for lina.nguyen versus database client commands for omar.haddad. These observations improve plausibility, although they do not negate the native identity defect.

## Detailed Analysis

### Input provenance, method, and qualifications

I read the supplied `host-prompt.md` and files under `/private/tmp/log-study-0sx5q8_q/data` only. I used system `python3` from the neutral study directory for read-only XML/JSON/text parsing, aggregate checks, and specific record inspection. I did not inspect the project directory, code, scenario, TODO, prior results, other assessments, or neighboring study inputs. Inherited generic operating instructions were an environment limitation and were not authenticity evidence. Logged shell commands were treated as inert text throughout.

The external references actually consulted were Apple Developer documentation for Endpoint Security message/exec semantics and Apple's public XNU source, accessed through Apple-domain filtered searches and direct upstream Apple repository URLs. No project-related public pages or snippets were consulted. The principal references supporting the finding are [Apple XNU fork identity allocation](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/kern/kern_fork.c), [Apple XNU exec identity allocation](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/kern/kern_exec.c), and [Apple's ES exec target definition](https://developer.apple.com/documentation/endpointsecurity/es_event_exec_t).

Parsed coverage comprised 19,411 Security XML events and 12,058 Sysmon XML events across ten Windows hosts, 37,394 eCAR rows across 23 endpoint directories, 4,291 Linux syslog rows, 299 native macOS ES rows, and the supplied shell histories. I examined individual records as well as aggregates. Network-only sources were inventoried but not used to infer native endpoint platform behavior. This was an endpoint-focused review, not a complete independent validation of every protocol row.

The Mac JSON declares `schema_version=1` and ES message `version=11`; this does not itself identify the exact OS build or exporter. I therefore do not allege a schema defect merely because a field is unfamiliar, or infer that these files must be exact stock eslogger exports. Normalized eCAR fields, including hexadecimal logon IDs on Unix hosts, are not treated as native kernel fields. A documented identity anonymization/remapping step could explain the primary contradiction as a transformation artifact; none was supplied. That alternative contributes to the verdict confidence remaining below 100.

### macOS identity allocation: decisive finding

The problematic field is `event.fork.child.audit_token.pidversion` or `event.exec.target.audit_token.pidversion`. It is not a POSIX PID, an audit session ID, an event-type sequence number, or a reference to a previously allocated identity. Apple's fork path assigns the new process identity version by incrementing `nextpidversion`; the exec path also increments that shared counter when replacing an image. Consequently, newly allocated values should advance in temporal order under ordinary operation. This interpretation comes from the two primary XNU references above.

Examples from `MAC-MROSS-02.meridianhcs.local/macos_endpoint_security.ndjson`:

| Lines | Native occurrence | New identity value | Conflict |
|---|---|---|---|
| 1–2 | `13:20:29.875707` fork and `13:20:29.882486` exec, PID 19775 | 31 → 32 | Establishes values already allocated before the later GUI launch. |
| 3–5 | `13:37:11.846603` fork through `13:37:11.874837` iTerm exec, PID 21356 | 10 → 11 → 12 | New identities fall below values allocated 16 minutes earlier. |
| 13–15, then 16–17 | Zoom fork/exec at `13:37:12.603536–13:37:12.611415`; shell child and cat exec at `13:37:14.145407–13:37:14.154514` | 22 → 23 → 24, then 20 → 21 | A second independently visible reversal, within two seconds. |
| 79–80, 81–83, 86–87 | SSH PID 41975 at `15:25:40.506474–15:25:40.511790`; inventory PID 44085 at `15:46:42.616461–15:46:42.628448`; shell child PID 44280 at `15:48:46.208061–15:48:46.223777` | 88 → 89, then 83 → 84 → 85, then 72 → 73 | Multiple temporally separated branches reuse lower parts of the new-allocation range. |

Using only fork-child and exec-target allocations, 54 of 124 observations on this host fall below an earlier observed high-water mark. This count describes the reach of the one allocation defect; it does not claim 54 independent bugs. MAC-MROSS-01's 82 analogous observations have no such reversals.

The earlier and later rows also have increasing `mach_time`: for instance, line 1 is `56016717016968`, while line 3 is `56040764318472`. Thus a wall-clock correction alone does not rescue the order. The long-lived launchd identity shown in these snapshots has start time `2026-10-06T13:00:00Z`; the supplied Unified Log rows for MAC-MROSS-02 share a boot UUID. There is no visible reboot explaining an identity allocator restart. Routine 32-bit counter wraparound is also not a credible account of repeated reversals within a tiny 10–133 range; it would require enormous unobserved allocation cycles, repeatedly, during this short slice.

This is a source-native identity/ordering contradiction, not a deduction from a tidy activity narrative, missing process rows, or complete matching between sources. It is the primary reason for entering the rubric's 81–100 band.

### macOS timing, sessions, and policy evidence

The seven exact 1-ms exit→fork transitions are localized to MAC-MROSS-02. MAC-MROSS-01 has zero adjacent exit→fork pairs at that exact interval. The first group follows native `/bin/cat` PID 21360 exiting at line 18, followed by `sw_vers`, `uname`, and `pwd` children of zsh PID 21359; the second group follows SSH PID 36406 exiting at line 85. These are plausible commands. A script or queued shell input can legitimately run them quickly. The weakly plausible feature is the repeated exact scheduling constant retained to the microsecond across unrelated command exits; it is a limited timing-texture deduction, not an assertion that humans must pause between commands.

Several Mac modeling details otherwise withstand scrutiny. PID/start-time continuity survives exec, PID versions change between images, child processes inherit parent and responsible audit tokens coherently, and audit UID/session identifiers are not conflated with the normalized eCAR logon identifier. Local Terminal and iTerm launch chains are distinct from SSH's sshd-session→user session→shell chain.

On MAC-MROSS-01, Unified Log line 3 records SSH public-key acceptance for maya.ross at `16:01:39.035681`; native ES lines 78–80 subsequently show the session child and zsh creation at `16:01:39.133869–16:01:39.174059`. The source does not claim the shell precedes visible authentication. The kernel policy message concerning MeetingAssist at Unified Log line 2 is not followed by a visible successful MeetingAssist exec in the supplied native ES stream. I do not infer a denial solely from an ES notification or require command effects after that policy message.

The eCAR plist creation/deletion and inventory process launches are separate facts. Deleting a LaunchDaemon plist does not prove that a registered job unloaded; the supplied slice does not justify an unload/termination contradiction. Sparse Unified Log and selected ES event families are neutral collection choices.

### Windows process and logon consistency

I joined Sysmon Event 1 records by host and ProcessGuid, checked visible parent ProcessGuids and images, checked Event 5 termination relationships, and compared process-linked supplied Sysmon records to those lifetimes. I found no visible child-before-parent, child-after-visible-parent-termination, same-identity image mismatch, or process-linked event-after-visible-termination in those checks. No penalty was assigned for parents or closures outside the slice.

There are 1,004 Security 4688 rows and 1,001 Sysmon Event 1 rows. The command-line agreement and subsecond relative offsets described above are strong practical correlation. Stable per-host hashes coexist with OS-version differences across hosts. This supports realism without turning completeness into an authenticity indicator.

The 4624 mix includes 400 network type 3, 392 service type 5, 14 remote-interactive type 10, 10 unlock type 7, eight interactive type 2, and four new-credentials type 9 records. Distribution varies by host: DC-01 has 147 network and 121 service logons, while WS-MCHEN-01 includes 22 network, six service, two interactive, two unlock and two new-credentials logons. This is consistent with distinct server/workstation behavior. Repeated SYSTEM `0x3e7` and unlock-related logon IDs were not mistaken for newly created unique session lifetimes; doing so would yield spurious causality findings.

### Linux processes, administration, and histories

The Linux data includes PAM/logind lifecycle messages, cron, sudo success/denial, package/service status noise, network-management messages, and host-specific application activity. The APP-INT SSH session cited above lasts about 61 minutes and retains both sshd PID and logind session identity through close. This is more convincing than isolated accepted-login messages.

The eCAR scan across endpoints found no FLOW row using a visible actor process before that process's CREATE timestamp or after its visible TERMINATE timestamp, and no visible child creation after its linked parent's termination. This is a bounded identity-based check, not a claim that every normalized field or network relationship was exhaustively verified. Shell histories preserve plausible administrator/developer commands and host destinations. I did not score common commands, a compact suspicious sequence, or absent retries as evidence of synthesis.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| hard_contradiction | Native macOS Endpoint Security | MAC-MROSS-02; 54/124 newly allocated fork/exec identity observations below an earlier high-water mark | Dominant: contradicts ordinary shared kernel identity-version allocation, independently of collection completeness. |
| distribution_texture | Native macOS Endpoint Security | Both Macs have gapless observed version sets; MAC-MROSS-02 interleaves them out of allocation order | Corroborates the allocator issue; not counted as an independent contradiction. |
| distribution_texture | Native macOS Endpoint Security timing | Seven exact 1-ms adjacent exit→fork intervals on MAC-MROSS-02 | Small additional weight; scripts could explain rapid execution, but not naturally the repeated exact offset. |

## Realism Score by Category

- **Field format accuracy:** 7 — Most XML, JSON, identities and hashes are well formed, but a native audit-token field violates its allocation semantics.
- **Temporal patterns:** 6 — Generally credible timing, weakened by backward new-identity allocation and repeated exact scheduling boundaries on one Mac.
- **Cross-source correlation:** 9 — Strong Windows process agreement, coherent Linux SSH lifecycle, and convincing native/normalized process identity reuse in examined examples.
- **Behavioral realism:** 8 — Varied role-specific application, administrative and background activity; the narrow scheduling texture is the main behavioral reservation.
- **Environmental consistency:** 8 — Mixed Windows versions and distinct Unix/Mac behavior are plausible; native allocator values imply an implausibly closed set of system-wide process allocations.

## Recommendations

- If this were synthetic, allocate native macOS `pidversion` values in actual chronological fork/exec order from one host-wide counter, after final scheduling. Preserve existing process identity snapshots when a row references an old image; do not allocate versions separately by activity branch and then interleave those branches.
- If modeling selective telemetry, account for intervening unobserved process allocations in the native counter rather than making every captured allocation consecutive. If privacy remapping is intentional, document it and preserve native ordering constraints.
- Replace repeated fixed 1-ms exit→next-fork boundaries with plausible measured or modeled shell/scheduler timing while maintaining causal order. Retain rapid scripted sequences where appropriate; the fix concerns the repeated exact numerical offset.
- Preserve the credible Windows PID/ProcessGuid/hash relationships, differentiated Mac process/exec/responsibility semantics, and Linux SSH PAM/logind lifecycle evidence. No additional event families are recommended merely to fill gaps in the selected collection.
