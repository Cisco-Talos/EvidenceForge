# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive  
**Verdict Confidence:** 58  
**Synthetic-Confidence Score:** 47

## Executive Summary

The host evidence is internally coherent across the Windows, Linux, and macOS records reviewed. Windows process starts, terminations, logons, and network observations have plausible parent/session ownership; Linux SSH and local sessions have sensible PAM/logind lifecycles; and the macOS Endpoint Security stream expresses native fork/exec state changes. eCAR often agrees with the native source records at close time and by identity.

I found no hard contradiction that establishes synthesis. The score remains near the midpoint because the logs provide no independent provenance, and the macOS Unified Log sample is very small relative to the other host telemetry. That is a coverage limitation, not standalone evidence of fabrication.

## Evidence For Synthetic

- **Weak signal — limited macOS Unified Log sample:** each Mac has two Unified Log records spanning a substantial interval, while its eCAR stream contains hundreds of endpoint/network events and Endpoint Security has 186 or more records. For example, `MAC-MROSS-02` has two Unified Log messages (loginwindow and sshd-session) but 186 Endpoint Security records. A narrow Unified Log predicate or export can explain this; the volume difference alone does not establish synthetic data. **Category: weak_signal.**
- **Weak signal — partial process lifecycle matching in the visible window:** Windows hosts commonly have more process-creation than termination records (for example, `WS-EBROOKS-01` has 61 Sysmon Event ID 1 records and 45 Event ID 5 records; eCAR has 61 `PROCESS:CREATE` and 45 `PROCESS:TERMINATE`). This is compatible with processes that were already running or outlived the collected interval, and is not treated as a defect. It leaves lifecycle completeness unverified. **Category: weak_signal.**

## Evidence For Real

- **Windows session agreement:** on `WS-EBROOKS-01`, eCAR records `lina.nguyen` logon ID `0xa4b6c8e`, type 3, source `10.10.1.21` at `15:29:10.302Z`. Security Event 4624 records the same user, logon ID, type, and IPv4-mapped source at `15:29:10.309Z` (about 8 ms later). The same host's `evelyn.brooks` type 7 unlock/session record (`0xa375308`, `18:19:15.031Z`) matches Event 4624 at `18:19:15.042Z`.
- **Windows process-tree plausibility:** Sysmon Event ID 1 records ordinary service and desktop ancestry, such as `explorer.exe` → Edge/Teams and `services.exe` → service-hosted processes. On `WS-EBROOKS-01`, the record for `powershell.exe` at `13:15:27Z` names the logged-in user and `explorer.exe` parent; a separate `cmd.exe` → `ssh.exe` chain at `14:59Z` preserves direct parentage. Security 4688/4689 and Sysmon 1/5 are both present in the Windows collection.
- **Windows network source agreement:** on `DC-02`, Sysmon Event ID 3 and Security Event 5156 show the same `dns.exe` PID and tuple (`10.10.3.20:55801` → `10.10.2.11:53`) within tens of milliseconds. The corresponding eCAR FLOW record carries the same process and tuple. This is specific multi-source consistency rather than generic correlation completeness.
- **Linux session lifecycle:** `MAIL-EDGE-01` syslog records PAM closing `aisha.johnson`'s SSH session at `13:00:23.214Z`, followed by logind removing session 302 at `13:00:24.081Z`; eCAR records the matching SSH logout with session 302 and source `10.10.1.35`. `FILE-LNX-01` likewise contains PAM and logind local-session events, and eCAR represents the same named user/session activity.
- **Linux process ownership and history:** eCAR process records on Linux retain user, parent image, PID, and session fields; for example, `DB-PROD-01` shows a user shell created under `sshd` and a later logout. Bash-history files use the standard epoch-comment plus command layout, with timestamps and commands that fall within the observed host activity window. Entries include routine operational commands as well as host-role-specific administration.
- **macOS-native execution semantics:** Endpoint Security records on `MAC-MROSS-01` show `launchd`/`xpcproxy` and Terminal/login transitions with audit tokens, PID versions, parent audit tokens, and executable paths. The subsequent shell process is associated with the interactive user. eCAR records corresponding process create/modify transitions and later shell-command lifecycles, including the user's zsh session and process termination. This is consistent with macOS execution and audit semantics rather than Windows-style session assumptions.
- **Mixed but role-consistent host activity:** the reviewed Linux servers show systemd/PAM/SSH and service activity; Windows servers show service and domain-controller activity; employee workstations show interactive user and application activity; and macOS endpoints show native process/session telemetry. No reviewed record requires an implausible platform or role assignment.

## Detailed Analysis

### Windows Event and Sysmon process trees

The Windows exports use parseable Event XML with standard Security and Sysmon channels, event IDs, timestamps, host names, and event data fields. Across the hosts, Sysmon includes process create/terminate, network connection, DNS, image-load, file, registry, and access events in differing proportions. Security logs include logons/logoffs, process creation/termination, filtering-platform connections, and other host-appropriate events. No absence of a selected Sysmon event ID was used as evidence.

Sample process trees are credible: `WS-EBROOKS-01` has user-launched `explorer.exe` children and ordinary service children of `services.exe` or `svchost.exe`; `DC-02` includes DNS service activity. I checked selected process lifecycle counts and found more creates than terminates on several workstation exports. Because the window can begin after process start and end before process termination, that mismatch is not a hard contradiction. I found no sampled create record that had a matching same-PID/image termination earlier than its start.

### Linux syslog and shell history

Syslog uses RFC 5424-style records with UTC timestamps, host, application, PID, and message text. PAM session-open/close lines and systemd-logind session additions/removals occur in plausible order. A representative SSH close on `MAIL-EDGE-01` precedes logind removal by less than one second and agrees with the eCAR logout/session identity. Other reviewed records include ordinary DHCP renewal, cron, unattended upgrade, system service, and SSH messages.

Bash-history entries use epoch timestamp comments before commands. The sampled commands and timestamp placement are plausible for the named users and systems. Histories are not treated as complete command transcripts, and blank or sparse histories are not treated as evidence against authenticity.

### macOS Unified Log and Endpoint Security

The Endpoint Security JSONL records retain native fields such as event type, audit tokens, PID version, executable path, signing identity, and fork/exec payloads. On `MAC-MROSS-01`, a short sequence progresses from launchd to XPC proxy/Terminal, `login`, and a user zsh process with parent/PID ownership carried across events. eCAR renders process creation/modification and termination records for the same host activity. The two Unified Log samples per Mac show native subsystem/process messages; their low count cannot distinguish a narrow collection predicate from incomplete coverage.

### eCAR ownership and endpoint correlation

eCAR process records generally carry object/actor identifiers, PID/PPID, principal, image, command line, and session or logon properties. On Windows, the native security log and eCAR independently agree on selected logon IDs, types, principals, source addresses, and times. On Linux, eCAR session records align with PAM/logind messages. On macOS, eCAR's process ownership fields align with Endpoint Security's native parent and audit-token transitions in sampled sequences. This supports shared event identity and does not by itself prove that the underlying events are real.

## Synthetic Indicator Summary

- No hard contradictions identified in the reviewed host evidence.
- The small macOS Unified Log sample limits conclusions about that source; it is a **weak_signal**, not a synthetic finding.
- Unpaired process starts are compatible with collection-window boundaries; they are a **weak_signal** only in the sense that lifecycle closure cannot be confirmed from this view.
- Cross-source matching was treated as corroboration of consistency, not as evidence that records are authentic.

## Realism Score by Category

- Field format: 8/10
- Temporal patterns: 8/10
- Cross-source correlation: 9/10
- Behavioral realism: 8/10
- Environmental consistency: 8/10

## Recommendations

- Preserve the source collection predicates and coverage metadata with the exports, especially for the macOS Unified Log stream, so a small sample can be distinguished from intentionally selective collection.
- For a stronger lifecycle review, include the collection-window boundaries and process state at both boundaries; do not infer missing process events from unpaired starts alone.
- Retain native event IDs, PIDs, logon/session identifiers, parent identifiers, and source timestamps during any normalization so future reviewers can independently reproduce the cross-source checks.
