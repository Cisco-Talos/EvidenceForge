# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 82
**Synthetic-Confidence Score:** 65

## Executive Summary

The endpoint evidence has strong identity and lifecycle consistency, with realistic Windows session bootstrap and detailed macOS fork/exec semantics. My synthetic verdict rests on repeatable, millisecond-exact process timing patterns and an implausible accumulation of independent Chrome browser process trees using the same macOS user/profile context; I did not establish a hard impossible-ordering contradiction.

## Evidence For Synthetic

- [distribution_texture] Repeated Windows SSH launches reproduce the same parent-to-child delay to the millisecond over several hours. In `WS-MCHEN-01.meridianhcs.local/windows_event_sysmon.xml`, EventRecordID pairs `525198/525199`, `525323/525324`, and `525454/525455` all put `ssh.exe marcus.chen@MAIL-EDGE-01.meridianhcs.local` exactly **5.715 seconds** after its newly created PowerShell parent. The records are identifiable at lines 698/743, 4942/4987, and 9341/9386. A separate workstation repeats a different destination-specific delay five times: `WS-AJOHNSON-01` launches its LOG-MON-01 SSH child exactly **4.980 seconds** after a newly created command shell, at parent EventRecordIDs `30718`, `30850`, `31057`, `31262`, and `31492`. These are repeated underlying `UtcTime` relationships, not an objection to complete source matching.
- [distribution_texture] The initial macOS Chrome trees use exactly the same helper-spawn offsets on both machines. In `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson`, the main process starts at `13:14:00.135114` and forks helpers at `13:14:02.135114`, `13:14:03.135114`, and `13:14:05.135114` (lines 17, 20, 22, 24). On MAC-MROSS-02 the corresponding start is `13:27:27.996507`, with helper forks at `13:27:29.996507`, `13:27:30.996507`, and `13:27:32.996507` (lines 22, 25, 27, 29). All six offsets are exactly 2, 3, or 5 seconds despite microsecond precision. The subsequent exec notifications have small varied delays, making the identical fork scheduling particularly conspicuous.
- [environment_or_collection_plausibility] Both Macs retain multiple independent Chrome main processes for the same effective UID, audit session, executable, and HOME, each launching its own helper tree. MAC-MROSS-02 has main PID `20433` from `13:27:28`, then PIDs `53468` and `53511` at `17:23:19` and `17:23:41`; all three remain until approximately `18:56:59`. Native ES lines 24, 120, 129, 173, 174, and 179 show these lifetimes. The latter two invocations specify `--new-window` and a GitLab URL; their complete visible args and environments do not contain distinct user-data/profile directories. Normally another default-profile Chrome invocation hands its request to the existing browser, rather than maintaining another independent browser/helper tree. An unrecorded special configuration could explain this, so this is a plausibility issue rather than a hard contradiction. MAC-MROSS-01 repeats the pattern with PIDs `42861` and `69186` (lines 19, 112, 146, 148).

## Evidence For Real

- Windows process/session bootstrap is coherent. On WS-PPATEL-01, Sysmon EventRecordIDs `739646`–`739648` show `smss.exe -> winlogon.exe -> userinit.exe -> explorer.exe`, with userinit and explorer using the same `LogonId=0xd8b39ef`, user, LogonGuid, and terminal session 2. The corresponding Security 4624 and 4688 evidence agrees on the relevant IDs and binaries.
- Across all ten supplied Sysmon files, checking visible GUID-associated process creation, termination, and process/source/target references found no use before creation or use after termination by the source timestamps. Repeated process images also retained consistent hashes within a host/version. Across 876 Sysmon Event 1 records, the 119 SHA256 values did not map to contradictory MD5/SHA1/IMPHASH sets.
- macOS evidence correctly distinguishes process lifetimes from successive executable images. For example, MAC-MROSS-02 PID `18969` executes ShellLauncher and then zsh without inventing a second PID (native ES lines 9–10). The iTerm2 -> iTermServer -> login -> ShellLauncher -> zsh chain is substantially more convincing than a generic shell-parent substitution.
- SSH authentication evidence has source-specific detail. DB-PROD-01 syslog lines 47–52 show a public-key acceptance, PAM open, logind session activity, and later PAM close for aisha.johnson. Later sessions retain the same user's key fingerprint. MAC-MROSS-01's Unified Log line 3 instead identifies `/usr/libexec/sshd-session` and an accepted ED25519 key; the native ES stream includes sshd-keygen-wrapper, sshd, sshd-session, sshd-auth, and the session shell.
- DHCP renewals have coherent stateful timing. WS-LNGUYEN-01 syslog lines 2–4 announce a renewal in 1885 seconds at `13:01:20`; lines 27–29 show the next request/ack/bound sequence at `13:32:45`. Subsequent renewals continue with varied lease timers. This is appropriate periodic infrastructure activity, not suspicious uniform human timing.

## Detailed Analysis

### Scope and method

I examined the supplied host directories only. I parsed every supplied Windows Security/Sysmon XML file, summarized eCAR activity for all endpoints, checked eCAR process creation/use/termination order by object identity with a one-second allowance for observation timing, and inspected both macOS ES streams and Unified Logs. Linux syslog review included source-family distributions, representative sudo denials, DHCP renewal chains, and SSH authentication/session sequences. XML citations use the stable EventRecordID plus relevant text line; NDJSON and syslog citations use one-based record lines. Times below are UTC on 2026-11-02.

### Windows identity, trees, and sessions

The Windows streams contain background WMI, COM, scheduled-task, indexing, update, antivirus, service, interactive, and remote-administration activity. Workstations have user applications as well as background processes, and server distributions emphasize WMI/task/COM activity. This variation supports plausibility. I did not infer a defect from absent boot records, selected-out Sysmon families, long-running processes at the collection boundary, or repeated use of the well-known SYSTEM/LOCAL SERVICE/NETWORK SERVICE logon identifiers.

The strongest Windows concern is the timing fingerprint, not the activity itself. On WS-MCHEN-01 the relevant `UtcTime` pairs are:

| PowerShell creation | SSH creation | Difference |
|---|---|---:|
| 13:18:02.956 | 13:18:08.671 | 5.715 s |
| 15:04:18.719 | 15:04:24.434 | 5.715 s |
| 16:14:15.319 | 16:14:21.034 | 5.715 s |

The same user's LOG-MON-01 pair repeats at 5.097 seconds and MAIL-CLIN-01 at 4.235 seconds. WS-AJOHNSON-01 independently repeats its LOG-MON-01 pair at 4.980 seconds five times. Automation or a launcher could create repeated waits, but these are tightly clustered arbitrary destination-specific fractional delays across newly created shells, without a visible launcher argument explaining the delay. Together with the macOS exact scheduling, this substantially exceeds an isolated coincidence. I assign moderate weight, preserving automation as an alternative explanation.

### macOS process and application behavior

The native records include audit tokens with pidversion, original/current parent information, start times, responsible process tokens, executable file metadata, code-signing fields, and explicit fork/exec transitions. Checking process snapshots by PID plus start time found no visible post-exit use or unexplained pidversion switch. File identities retained coherent size/birth metadata, and checked stat times did not lie in the future relative to their events. I did not equate audit session IDs with POSIX session IDs.

The Chrome issue is about actual browser-instance ownership. On MAC-MROSS-02, PID `53468` forks children `53476`, `53478`, and `53479`; PID `53511` forks `53519` and `53520`, while the earlier browser PID `20433` remains alive. This is stronger evidence than simply finding several Chrome-named processes, because helpers are distinguished from main browsers. The visible complete exec arguments and HOME are shared. Although multiple profiles or custom launch behavior can exist, those facts do not explain the observed default-profile browser topology.

I did not treat the policy message at MAC-MROSS-01 Unified Log line 2, `ASP: Security policy would not allow process ... MeetingAssist`, as proof of a successfully executed child. It is an observation of policy handling, and I found no basis here to infer effects from that wording alone.

### Linux and collection limits

Sudo-denial rows on PROXY-01 and WEB-EXT-01 did not have an observed matching privileged child that would contradict the denial. SSH session lifecycles and DHCP timer behavior are positive realism evidence. Linux systems have appropriately differentiated desktop, mail, SMB, and server messages; apparent sparseness of a particular source was not scored.

Some macOS cat/tee lifetimes have eCAR termination records but no corresponding native ES exits in the supplied stream, whereas ordinary command exits are present. Because the ES subscription/filter policy is unspecified and this does not create an impossible visible same-identity relationship, I have **not** used that absence in the score. Likewise, I did not require native file-write notifications merely because the eCAR source contains file activity.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | Windows Sysmon process creation | Repeated SSH session bootstrap on two Windows endpoints | Exact repeated destination-specific millisecond delays suggest parameterized scheduling; moderate weight, automation remains possible. |
| distribution_texture | macOS native ES fork events | Both initial Chrome trees | Identical 2/3/5-second fork offsets at microsecond precision provide an independent timing fingerprint; moderate weight. |
| environment_or_collection_plausibility | macOS native ES process trees | Two and three concurrent main browsers on the two Macs | Separate durable main/helper trees share visible default-profile identity/context; strongest behavioral concern, not rated impossible. |

## Realism Score by Category

- **Field format accuracy:** 9 — Well-formed XML/NDJSON, source-specific fields, and coherent process/hash identities; no demonstrated native schema defect.
- **Temporal patterns:** 6 — Good lifecycle order and infrastructure timing, but repeated exact process-spawn offsets reduce authenticity.
- **Cross-source correlation:** 9 — Checked identifiers, lifecycles, and representative bootstrap/authentication evidence agree; incomplete collection is treated neutrally.
- **Behavioral realism:** 6 — Credible administration and application mix, weakened by default-profile Chrome instance duplication.
- **Environmental consistency:** 8 — Platform-specific terminal/session/authentication behavior and differentiated host roles are generally convincing.

## Recommendations

- If this were synthetic, vary session-launch timing between repeated executions of the same source/user/destination relationship, including the observed fractional parent-to-SSH gaps. If deliberate automation explains those waits, preserve the launcher or command evidence that makes that explanation observable.
- If this were synthetic, let actual startup relationships determine helper creation timing instead of repeating the same exact 2/3/5-second fork schedule on both Macs.
- If this were synthetic, model Chrome's existing-instance request handoff, retaining one browser instance with its helper ownership for a default profile. Where concurrent independent instances are intentional, include the actual distinct profile/user-data context in the recorded invocation rather than implying identical defaults.
