# Host/EDR Forensics Analyst Report — Loop 8

## Verdict

**Likely synthetic or heavily synthesized/normalized endpoint telemetry.** The host evidence is coherent and often convincingly rendered, but the unusually close cross-source timing and one Mac Endpoint Security sequence-number pattern reduce confidence that these are independent production captures.

## Verdict Confidence (0–100)

**81**

## Synthetic-Confidence Score (0–100; lower is more production-like)

**78**

## Executive Summary

Windows process events, Windows authentication evidence, eCAR process records, Linux shell history, and macOS endpoint records mostly form coherent host-local timelines. I found no strong contradiction such as a visible process termination preceding its creation, an impossible Windows process parent, or a clearly malformed authentication lifecycle. Several of the Windows Sysmon process records align to the same PID in eCAR within roughly 0.06–1.18 seconds across the reviewed hosts, which is plausible for integrated collection but unusually uniform across hosts and logs. On both Macs, Endpoint Security `seq_num` restarts independently for each event type (fork, exec, and exit) while `global_seq_num` carries the merged ordering; that looks like a serialization shortcut rather than a single endpoint client's message sequence. Together these cues favor synthetic/normalized evidence over unmodified production collection.

## Evidence For Synthetic

- **Highly repeatable cross-source process timing:** On eight Windows hosts with both Sysmon and eCAR, process create/terminate PID matches were generally within one second. For example, DC-01 had 138/138 Sysmon process starts and exits with eCAR PID matches; median differences were about 0.15s and 0.11s, respectively. Similar close agreement appears on the workstation and file-server logs. This is internally useful correlation, but the consistency across separate host datasets suggests shared event construction or normalization.
- **Mac Endpoint Security sequence counters appear event-type-local:** In each Mac NDJSON stream, `seq_num` advances separately for event types 9, 11, and 15: the first fork and first exec both have `seq_num: 0`, followed by separate per-type counters. `global_seq_num` provides the combined ordering. This counter pattern is suspicious for a raw, single-client event stream and merits verification against the collector's intended semantics.
- **Coordinated lifecycle rendering:** eCAR process create/terminate records largely echo Sysmon's process PID and image data with small, similarly bounded timestamp differences. The agreement is stronger and more uniform than independent logs commonly are, even though it is possible when the sources share an endpoint pipeline.
- **Very regular six-hour collection envelope:** Most host eCAR records span approximately 13:00–19:00 UTC on the same date, despite differing host roles and record volumes. A common exercise collection window can explain this, but it is a dataset-level regularity rather than organic host uptime diversity.
- **Curated Unix histories:** The bash/zsh histories contain plausible admin and user commands with timestamps that fit the observed window. They are compact and orderly; this is a mild signal only, since histories are naturally incomplete and the task window is bounded.

## Evidence For Real

- **Windows source-native structure is detailed and mostly plausible:** The XML includes ordinary Sysmon process, network, DNS, image-load, registry, and process-access event families, plus Windows Security logons, logoffs, special privileges, explicit credentials, share access, lock/unlock, and filtering-platform events. Process ancestry such as `taskeng.exe` → PowerShell and `explorer.exe` → user applications is credible.
- **Process lifecycle records are sensible:** Most Windows Sysmon Event ID 1/5 records pair by PID and image with plausible lifetimes. eCAR process lifecycle counts are close to the Sysmon and Security counts, with small gaps that can arise from source coverage or retention boundaries.
- **Authentication/session patterns are plausible:** Service logons use familiar service accounts and type 5; network logons use type 3 and often have a matching short-lived logoff; workstation interactive type 2 logons and lock/unlock records appear. Failures on WS-SMARTINEZ use a coherent bad-password status/substatus and recur as retries rather than appearing as malformed successes.
- **macOS records use credible native shapes:** Endpoint records have nested fork/exec/exit payloads, audit tokens, process versions, code-signing metadata, and paths. Unified log entries include recognizable loginwindow, Apple System Policy, and sshd-session messages. The ES events and eCAR process transitions are broadly compatible in ordering.
- **Unix operational behavior is plausible:** Histories include routine inspection, service checks, SSH use, database administration, and developer work. The DB-PROD-01 root history's `mysqldump` activity and the cross-host SSH/admin activity are plausible operational actions, not standalone evidence of artificiality.

## Detailed Analysis

### Process trees and lifetimes

Windows process starts and ends are generally paired and use credible parent images, users, paths, and command lines. Most direct Sysmon-to-eCAR PID matches are close in time: DC-01 process start deltas had a median near 0.15 seconds and a maximum under 0.75 seconds; WS-AJOHNSON-01 had a median near 0.19 seconds and a maximum near 0.52 seconds. FILE-SRV-01's 73 process starts all had PID matches, also within about 0.81 seconds. This demonstrates good internal correlation, but the similar tight windows across separate hosts make the eCAR and Sysmon streams look like correlated renderings of common event objects rather than independent sensor captures.

Small unmatched create/terminate counts occur on several hosts (for example, DC-02 and WS-EBROOKS-01). These are not treated as defects: the capture is bounded, source coverage can differ, and most matched lifecycles remain coherent. On Linux eCAR, several processes have only one visible lifecycle side; that is compatible with the six-hour boundary and absent pre-window initiators.

### Authentication and sessions

Windows Security events show common service logons, Kerberos network logons, local interactive logons, logoff records, workstation lock/unlock, and failed password attempts. The type 3 network logons commonly use machine accounts and are followed by logoff records with the same target logon ID. Service logons recur with stable built-in IDs as expected. I did not find a concrete same-host contradiction in the reviewed sample.

Linux/macOS login-related evidence is thinner than the Windows records, but the available eCAR sessions, SSH process activity, shell history timestamps, and macOS sshd-session unified log messages broadly agree. A bounded window can omit the initiating login or later close, so those omissions are not counted against authenticity absent a visible contradiction.

### Shell and administrative behavior

The histories are operationally plausible: Linux operators inspect services, logs, network interfaces, sessions, packages, and storage; the developer account uses Git, pytest, and Docker; and the Mac user uses ordinary system commands and SSH. The DB host's root history includes a database export to `/tmp`, a high-impact action that is still realistic for an administrator. No shell command was visibly followed by a contradictory process identity or host attribution in the reviewed records.

### Native Windows, Linux, and macOS semantics

Windows event IDs and fields are generally used in plausible combinations. Sysmon UtcTime and the XML SystemTime are close, and process termination events reference the expected process image/PID. Linux evidence is primarily eCAR and shell history, so it provides less independent native process detail than the Windows set.

The macOS Endpoint Security payloads appear intentionally structured: fork events carry child details, exec events carry targets, and exit events appear as type 15. The main concern is the sequence-number pattern described above. It is a field-level concern, not proof that the process behavior itself is impossible. Unified log entries have plausible process paths and timestamps, including a denied process execution message and accepted SSH public-key messages.

### eCAR and endpoint correlation

Across Windows, eCAR process records track Sysmon PIDs very closely, while eCAR also carries common session, flow, file, module, process-open, and registry evidence. The broad relationships make sense, and the close timestamps are plausible if eCAR is produced from a coordinated endpoint pipeline. Their consistency, together with the Mac ES counter pattern, is the clearest reason to prefer a synthesized or normalized source over raw independent production exports.

## Synthetic Indicator Summary

| Category | Finding | Weight |
|---|---|---:|
| Cross-source timing | Sysmon/eCAR process PID matches are consistently sub-second across hosts | Moderate |
| Mac telemetry field pattern | `seq_num` advances independently per event type in both Mac streams | Moderate |
| Collection envelope | Most hosts share a near-identical six-hour UTC window | Mild |
| Unix history texture | Histories are plausible but compact and curated-looking | Mild |
| Concrete impossible event | None established from the reviewed host evidence | None |

## Realism Score by Category

| Category | Score / 100 | Notes |
|---|---:|---|
| Windows process trees and lifetimes | 76 | Credible paths and parentage; very close eCAR/Sysmon alignment lowers independence confidence. |
| Windows authentication and session lifecycle | 78 | Logon types and short-lived network sessions are plausible; no hard contradiction found. |
| Linux/macOS authentication and sessions | 64 | Plausible but less independently corroborated in the available host-native sources. |
| Shell and admin behavior | 70 | Commands fit user and server roles; histories are sparse but not contradictory. |
| Native OS event semantics | 65 | Windows semantics are strongest; Mac ES sequence handling is suspicious. |
| eCAR/endpoint correlation | 58 | Correlation is strong, but unusually uniform timing suggests shared construction. |
| Overall host authenticity | 69 | Coherent and useful for analysis, with several synthetic/normalization indicators. |

## Recommendations

1. Preserve a single host-local Endpoint Security message sequence across event types, or document why the emitted `seq_num` intentionally resets by type; retain `global_seq_num` for combined ordering and make any sequence gaps reflect explicit observation loss.
2. Vary source collection and forwarding latency by host and event family while retaining the correct PID, process image, and session relationships. Keep source-local timestamp semantics clear so close correlation does not look mechanically identical everywhere.
3. Give hosts naturally different collection start/end points and coverage profiles. Keep bounded-window process and session omissions where they are plausible, but avoid applying the same envelope to nearly every endpoint.
4. Retain the strong native Windows parent/child, logon-ID, and logoff relationships; they are the most convincing host evidence in this set.
