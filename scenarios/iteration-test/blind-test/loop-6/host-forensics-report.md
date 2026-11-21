# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 82
**Synthetic-Confidence Score:** 43

## Executive Summary

The endpoint evidence is substantially production-like: process identities remain stable, visible lifecycles are coherent, and Windows, Linux, and macOS records preserve meaningful platform differences. Repeated shell-to-SSH launch intervals provide a concrete timing fingerprint, but I did not establish a hard contradiction; automation or timestamp processing could explain the remaining concerns.

## Evidence For Synthetic

- [distribution_texture] Repeated fresh terminal launches reproduce destination-specific SSH startup delays to approximately a millisecond. In `WS-MCHEN-01.meridianhcs.local/windows_event_sysmon.xml`, the three separate `powershell.exe` → `ssh.exe marcus.chen@APP-INT-01.meridianhcs.local` pairs at approximately 16:48, 17:06, and 18:34 have `System/TimeCreated` differences of 3.921258, 3.920926, and 3.921114 seconds. The distinct parent/child PIDs are 9152→9164, 9352→9372, and 9580→9584. The recurrence across fresh parent processes is more specific than ordinary repeated administration, although an automated launcher remains a plausible explanation.
- [distribution_texture] The same form of timing reuse occurs for other destinations and users: the two Marcus `cmd.exe` → SSH connections to MAIL-EDGE-01 are separated from their parents by 5.209803 and 5.210154 seconds, while his DB-PROD-01 pairs are 3.419041 and 3.418612 seconds. In `WS-PPATEL-01.meridianhcs.local/windows_event_sysmon.xml`, the LOG-MON-01 pairs are 5.428931 and 5.431679 seconds. These are supporting examples of the same issue, not independent defects to add together.
- [weak_signal] For all 955 Sysmon Event 1 processes with matching Security 4688 records, the Security XML `TimeCreated` timestamp follows the Sysmon XML `TimeCreated`, with differences from about 35 to 643 milliseconds across ten Windows hosts. This narrowly bounded, one-direction relationship is a possible source-timing template. It receives little weight because a consistent exporter or provider timing convention could produce it; complete matching itself is not an indicator.

## Evidence For Real

- Windows process identity checks found no GUID changing PID, image, or user across the observed Sysmon records. Repeated Event 1 executions of an image on the same host also retained consistent hash strings. All 955 Sysmon process creations had a corresponding Security 4688 with matching image, command line, and parent image.
- Checks of visible Sysmon process creation, termination, process-access, and related references found no process observation more than 500 milliseconds before its visible creation or after its visible termination. Equivalent eCAR actor-lifetime checks across 23 hosts also found none. This supports coherent event construction, without making the matching completeness itself evidence of provenance.
- `WS-MCHEN-01` correctly distinguishes local identity from outbound credentials in a Type 9 logon: at 14:13:49.0088763Z, LUID `0x6cc5e46` retains `marcus.chen` locally while `TargetOutboundUserName` is `marcus.chen-admin`. Its `cmd.exe` child and 14:14:02.2915327Z logoff use that same LUID.
- Linux SSH evidence contains ordered connection, authentication, PAM/session, and logind stages. For example, DB-PROD-01 receives source `10.10.1.21:56040` at 13:07:31.361606Z, accepts Lina's password at 13:07:39.480631Z, records logind session 342 at 13:07:40.254608Z, and later removes session 342 at 14:00:32.609714Z.
- The two Macs have materially different local terminal chains: Terminal → login → zsh on MAC-MROSS-01, and iTerm2 → iTermServer → login → ShellLauncher → zsh on MAC-MROSS-02. Their native records distinguish a forked process from successive exec images and preserve the process lifetime start time through exec.
- macOS executable snapshots remain internally consistent for the same PID/version and for the same device/inode/path identity. Chrome helpers have the pipe descriptor 3 referenced by `--seatbelt-client=3`; the apparent argument/descriptor concern disappears when the actual `fds` arrays are inspected.
- Host behavior differs visibly: Marcus has numerous administrative shells, SSH clients, RDP clients, and event-log tools; other Windows users have Office, browser, synchronization, and communications applications. Linux includes cron, sudo, resolver, DHCP, mail, Samba, and desktop-specific activity rather than one universal endpoint vocabulary.

## Detailed Analysis

### Scope and method

I examined only the supplied data directory and the assigned briefing. The endpoint corpus includes 17,832 Windows Security XML events, 11,624 Sysmon XML events, 37,537 eCAR records across 23 hosts, Linux syslogs and bash histories, and 330 macOS Endpoint Security records across two hosts, together with their Unified Log and zsh-history exports. The visible period is approximately 2026-11-02 13:00–19:00 UTC.

I parsed all Windows XML and eCAR files for the identity and lifecycle checks described above, inspected actual records and histories, and reviewed the native macOS process transitions. I did not infer a full boot-to-shutdown collection, require absent Sysmon event types, treat domain sanitization as evidence, or score the narrative shape of suspicious activity.

### Windows process trees and authentication

The observed relationships generally have sensible roles: services.exe launches service processes; userinit.exe precedes explorer.exe; explorer launches user applications; and command shells launch command-line administration tools. For example, WS-MCHEN-01's 13:01:29 Sysmon Event 1 identifies PID 7192 as `svchost.exe -k netsvcs -p -s Winmgmt`, with services.exe PID 5872 as parent, SYSTEM identity, LUID `0x3e7`, and session 0. Security 4688 independently preserves the same process, parent, and command line.

I compared parent GUIDs with visible parent creations, checked GUID/PID/image/user stability, and compared Event 1 hash strings by host and image path. I found no contradiction in those checks. Hash consistency establishes internal continuity only; it does not verify the supplied hashes against executable bytes.

Successful logon types have plausible variation: the DCs carry substantial network and service authentication, while workstations show interactive, network, new-credentials, and occasional unlock activity. WS-AJOHNSON-01 and WS-SMARTINEZ-01 both contain Type 7 unlock records. Reuse of well-known builtin LUIDs `0x3e4`, `0x3e5`, and `0x3e7` is not evidence that later service logons are the first existence of those identities. After excluding that misleading interpretation, I found no user process clearly preceding its visible initiating logon or following its visible logoff by more than one second.

The strongest concern is timing texture rather than tree structure. Fresh shell-to-SSH pairs reproduce nearly identical delays for a specific actor and destination, even hours apart. These delays are not fixed at round seconds and differ by destination, making repeated manual typing an incomplete explanation. Conversely, saved terminal workflows, shell initialization, or automation could explain them, and the supplied records do not establish that these sessions were manually initiated. I therefore treat this as a moderate indicator rather than an impossible lifecycle.

The 955 paired Security/Sysmon creation records show variable positive source-time differences, not literal identical timestamps. Although their universal ordering and bounded spread are noteworthy, provider/export timing remains an unresolved explanation. I do not claim that Event 4688 must always precede Sysmon Event 1.

### Linux sessions, processes, and history

Linux process and session evidence supports actual host roles. FILE-LNX-01 has smbd and Samba audit records; the mail hosts have Postfix and Dovecot sequences; workstations contain GNOME, NetworkManager, firmware, and desktop-service messages. Shell histories contain role-specific commands alongside routine inspection commands. DB-PROD-01's root history, for example, records mysqldump, gzip, and scp activity; I did not use the convenience or completeness of that sequence as an authenticity indicator.

An important timing ambiguity is FILE-LNX-01's eCAR creation time relative to native syslog. Its 36 cron CMD records precede the matching eCAR shell CREATE records by approximately 1.273–1.775 seconds, with a median of 1.529 seconds. At 15:26:10.469261Z, syslog smbd PID 2708564 records a share connection while eCAR places its CREATE at timestamp_ms 1793633172339, about 1.870 seconds later. APP-INT-01 exhibits a smaller version of this skew, whereas other hosts have different relative offsets.

Those source differences could reflect collection time, source clock correction, or exporter delay. Because eCAR exposes only `timestamp_ms` here, without an independent source-occurrence timestamp or collection-time field, I cannot establish that the underlying process actually began after its own syslog messages. The offset is therefore documented as an interpretive limitation and is not scored as a hard contradiction.

Likewise, a cron CMD message and the child shell creation are different stages. Their PID relationship alone does not justify treating every subsecond ordering difference as impossible.

### Native macOS process semantics and policy evidence

Both Endpoint Security exports declare `schema_version:1` and message `version:11`. I checked internal relationships rather than alleging undocumented native schema errors from unfamiliar fields.

On MAC-MROSS-01, PID 42154 forks from launchd and then execs xpcproxy and Terminal, incrementing `pidversion` while preserving the lifetime start time. Terminal's login and zsh descendants have distinct PIDs. MAC-MROSS-02 includes iTermServer and ShellLauncher, with PID 19001 execing ShellLauncher and then zsh. Successive images in one PID are not duplicate process creations. Audit session identifiers are also kept distinct from the eCAR hexadecimal logon identifiers.

For all executable snapshots examined in the two ES files, a given `(pid, pidversion)` retained its executable path, cdhash, and start time; a given `(st_dev, st_ino, path)` retained the compared birth time, modification time, size, and cdhash. The records also distinguish parent and responsible-process tokens. The Chrome helper argument `--seatbelt-client=3` is accompanied by an actual FD 3 pipe and `last_fd:3`; it is not a missing-handoff defect.

MAC-MROSS-01's Unified Log at 15:42:09.009673Z states that security policy would not allow PID 62500, `/Applications/MeetingAssist.app/Contents/MacOS/MeetingAssist`. I found no corresponding successful process creation for that PID in the endpoint records. This does not establish every downstream policy decision, but there is no visible successful child chain that contradicts this rejected attempt.

The plist file creation/deletion observations for `com.meridianhcs.endpoint-inventory.plist` are separate from the launchd/xpcproxy executions of sw_vers. I did not infer that removing the plist must immediately kill a loaded job, or demand a launchctl command merely because activation occurred.

### Weighing the alternatives

A synthetic explanation fits the reproducible SSH launch delays and the narrowly bounded source-time ordering. A real-data explanation fits the differentiated terminal chains, consistent native identities, coherent netonly logon semantics, variable process durations, and the possibility of managed administration workflows and exporter-specific timestamps.

Neither internal consistency nor a few repeated intervals proves provenance. The available endpoint evidence supports a mixed assessment, with a mild synthetic tilt in its timing texture, insufficient to support a confident synthetic verdict or an 81–100 score.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on synthetic-confidence score |
|---|---|---|---|
| distribution_texture | Windows Sysmon process creation; corroborated in eCAR timing | Repeated fresh shell/SSH pairs on WS-MCHEN-01, WS-AJOHNSON-01, and WS-PPATEL-01 | Moderate: destination-specific startup delays recur to milliseconds across separate sessions. Automated launchers remain a credible alternative. |
| weak_signal | Windows Security and Sysmon | 955 matched process creations across ten hosts | Small: Security source time always follows Sysmon by approximately 35–643 ms. An exporter/provider convention could explain this. |

No demonstrated hard contradiction or native schema failure contributed to the score. The Linux source-time skew was not scored because its timestamp semantics remain ambiguous.

## Realism Score by Category

- **Field format accuracy:** 9 — XML, normalized EDR, and native macOS records are internally coherent; no demonstrated field-shape defect.
- **Temporal patterns:** 7 — Lifecycles are coherent, but repeated actor/destination startup delays are conspicuous.
- **Cross-source correlation:** 9 — Process attributes and session relationships agree; eCAR/syslog clock semantics limit exact timing conclusions.
- **Behavioral realism:** 8 — User and host tool use differ meaningfully, with believable administrative and desktop activity.
- **Environmental consistency:** 9 — Windows, Linux server/desktop, and the two macOS terminal environments retain distinct semantics.

## Recommendations

- If this were synthetic, vary repeated terminal-to-SSH startup intervals across independent launches unless the evidence explicitly models a fixed-delay automated launcher. Preserve any intended automation explanation in the actual launcher/profile telemetry.
- If this were synthetic, model and validate Security/Sysmon timing from the actual collection convention being represented, including whether timestamps represent provider occurrence, emission, or export. Avoid imposing a universal bounded ordering merely to create source separation.
- For the Linux/eCAR timing ambiguity, include source-occurrence and collection timestamps, or an explicit clock-normalization convention, so analysts can distinguish a real causality inversion from a delayed observation. The visible skew warrants clarification rather than an unsupported authenticity penalty.
