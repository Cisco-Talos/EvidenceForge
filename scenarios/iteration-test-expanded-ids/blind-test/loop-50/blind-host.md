# Host/EDR Forensics — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 91/100  
**Synthetic-Confidence Score:** 76/100

The corpus is substantially more realistic than a simple templated dataset: host roles are differentiated, process trees are coherent, Windows Security/Sysmon/eCAR timestamps are sensibly offset, SSH sessions have plausible transport/authentication/open/close sequences, and process/session identifiers generally remain consistent. However, several cross-host implementation artifacts and locally incoherent “background noise” patterns are difficult to reconcile with independently operating real systems.

## Executive Summary

The strongest synthetic indicator is in Windows Security Event 5156 metadata. Every Windows host uses the exact same complete set of 38 execution thread IDs—52 through 200 in increments of four—regardless of host role or whether the file contains 361 or 4,376 such events. That exact cross-machine universe looks like selection from a shared generator pool, not independently evolved kernel execution state.

Linux background telemetry provides a second strong indicator. `irqbalance` emits unusually frequent informational/debug-like messages across many hosts, and on APP-INT-01 the same IRQ 154 is reported minutes apart as banned by two different affinity masks (`00000001` and `00000008`) without supporting reconfiguration evidence. DB-PROD-01 likewise produces 75 `multipathd` messages from a small phrase/device pool, repeatedly “adding” missing paths and alternating active-path counts without a convincing storage-failure/recovery lifecycle. These messages add texture but do not behave like persistent state.

Against that, the dataset has good process and authentication integrity. No paired eCAR process termination preceded its visible creation, PID intervals did not overlap, recurring binary hashes were stable per host, SSH PID/user/key/source-tuple relationships were maintained, and Windows Security versus Sysmon process-create timestamps differed by plausible sub-millisecond amounts rather than being copied exactly.

## Evidence For Synthetic

### Windows provider metadata

- All nine Windows hosts expose exactly the same 38-value `Execution ThreadID` set for Event 5156: every multiple of four from 52 through 200.
- This remains true across very different sample volumes: DC-01 has 4,376 Event 5156 records, while workstations have roughly 361–477.
- Independent real hosts can have similar kernel-worker patterns, but exact set equality across every machine and role is a strong shared-pool artifact.
- Several other provider fields use bounded, highly regular value families. On their own they are plausible; combined with the exact cross-host 5156 set, they reinforce programmatic construction.

### Linux background-state coherence

- `irqbalance` is extremely prominent across servers, contributing dozens to 150 records per host despite the absence of a clearly documented debug state.
- APP-INT-01 reports IRQ 154 as banned by affinity mask `00000001`, then six minutes later by `00000008`, with the same device and no visible configuration or topology transition.
- DB-PROD-01 emits 75 `multipathd` records drawn from a narrow set such as `sda/sdb/dm-0: add missing path` and `remaining active paths: 1/2`.
- Those storage messages repeatedly imply state transitions without a durable sequence of removal, restoration, map degradation, recovery, or operator response. They read as independently sampled lines rather than a stateful multipath daemon narrative.

### Behavioral distribution

- A small number of executable archetypes dominate repeatedly across most Windows machines: `dllhost.exe`, `WmiPrvSE.exe`, `taskhostw.exe`, `wsqmcons.exe`, Google updater, Dropbox updater, and search hosts.
- Linux servers similarly reuse `debian-sa1`, generic health checks, SSH administrative shells, and a common daemon-message vocabulary.
- Individual timing is jittered well, but the population-level regularity and common behavioral palette remain visible.

### Activity authoring

- Several command histories resemble curated examples of operator activity: compact command clusters, broad coverage of common diagnostic commands, and few obvious mistakes, corrections, partial commands, aliases, copied fragments, or abandoned workflows.
- The root DB-PROD-01 sequence is especially narratively compact: database enumeration, dump, sizing/inspection, compression, checksum, and SCP transfer.
- This is supporting evidence only; coherent administrator workflows can occur in real evidence.

## Evidence For Real

### Process and lifecycle integrity

- Across all eCAR files, paired process objects had no termination earlier than their visible creation.
- No overlapping PID intervals were found for distinct visible process identities on the same host.
- Many processes correctly remain unmatched at the observation-window boundary, which is realistic rather than suspicious.
- Windows workstation process lifetimes are materially longer than short-lived Linux command processes; lifetimes are not globally uniform.

### Windows Security/Sysmon/eCAR correlation

- Security 4688 and Sysmon Event 1 records correlate on process identity while retaining plausible provider-specific timestamp differences. For example, the WS-MCHEN-01 Edge creation is at `12:02:42.7856198Z` in Sysmon and `12:02:42.7861643Z` in Security.
- Sysmon process GUIDs are reused correctly by dependent image-load and network events.
- Hashes remain stable for repeated executions of the same binary within a host. They are not regenerated per process occurrence.
- Security record IDs contain realistic gaps rather than being a naive contiguous sequence.

### Authentication and session semantics

- SSH evidence uses consistent server PIDs across connection, accepted-key, PAM-open, and PAM-close messages.
- Source address, source port, user, key type/fingerprint, and target port remain aligned through each visible SSH sequence.
- User UIDs are stable across Linux hosts: for example, `aisha.johnson` consistently appears as UID 2528, `lina.nguyen` as 5302, and `marcus.chen` as 4119.
- Initial session-close records without visible opens are compatible with sessions that began before the captured window.

### Host-role differentiation

- DC-01 has Kerberos-heavy 4768/4769 activity and dense network-logon evidence.
- FILE-SRV-01 is dominated by network logons, object access, and server-side flows.
- MAIL-FIN-01 contains Exchange-role processes.
- MAIL-CLIN-01 and MAIL-EDGE-01 contain Postfix/Dovecot activity.
- WEB-EXT-01 has heavy host-firewall exposure noise, while PROXY-01 has a much larger flow population.
- Workstations have richer user processes, search/updater activity, browser execution, and interactive sessions.

### Source-native detail

- Windows records use plausible provider versions, tasks, keywords, integrity labels, hexadecimal PIDs/logon IDs, domain SIDs, and Sysmon image metadata.
- Linux syslog uses plausible RFC 5424 structure, facilities, PIDs, daemon names, PAM phrasing, SSH key fingerprints, and session-open/close ordering.
- Bash history timestamp encoding is structurally correct and aligns with observed process activity in multiple cases.

## Detailed Analysis

### Windows Security and Sysmon

The Windows telemetry is internally strong at the semantic layer. Process creation and termination, network flows, module loads, registry operations, process access, and remote-thread records retain consistent PID, image, principal, and process GUID relationships. Event 4624/4634 pairings, privileged-logon 4672 records, and server-side network logons are broadly appropriate to host roles. DC-01’s account/service/security-log-clear activity also has coherent supporting process evidence.

The defect is chiefly source-envelope realism rather than event semantics. Exact reuse of the 5156 execution-thread universe across all Windows systems is too regular. Thread IDs are host-local runtime artifacts; independent machines with different roles, traffic, boot histories, and event counts should not converge on an identical exhaustive 38-element set.

### eCAR/EDR

eCAR is one of the better-realized sources. Object/action families vary meaningfully by platform and role. Process object IDs are stable through lifecycle events, dependent flows often carry actor IDs and ownership, and principal attribution is generally compatible with image and session context.

Coverage is selective, but thinness was not used as an authenticity indicator. Some process creates or terminations fall outside the window, and some flows omit actors; those can be natural endpoint collection outcomes.

### Linux syslog and Bash history

SSH and PAM evidence is convincing. Sessions are not all the same duration, concurrent sessions occur, failed/unknown users exist, and close timing is compatible with transport and shell activity. Workstation-oriented daemons appear on Linux workstations, while server roles have mail, proxy, application, or database-specific processes.

The lower-quality portion is generic background noise. `irqbalance`, `multipathd`, `snapd`, and resolver messages are varied lexically but insufficiently stateful. Repeated multipath “missing path” and active-path messages would ordinarily reflect persistent device/map transitions, not independent random selections. The changing IRQ affinity-mask report is another concrete sign that lines were sampled for texture.

Bash histories are plausible at the command level and do contain repeated habits, especially SSH and Git activity. Still, many server-user histories resemble small curated diagnostic command sets more than organically accumulated shell histories.

### Ownership, trees, and host roles

Parent-child ownership is generally credible. User applications descend from user shells or Explorer; SYSTEM maintenance processes descend from service-oriented parents; SSH privileged processes lead to user shells; administrative commands retain the session user.

Role placement is also coherent. There are no major cases of Windows-only paths contaminating Linux records or obvious user/workstation applications dominating infrastructure servers. This substantially reduces confidence from the “confident synthetic” range into “likely synthetic.”

## Synthetic Indicator Summary

| Category | Indicator | Weight |
|---|---|---:|
| Windows metadata | Identical 38-value Event 5156 execution-thread set on every Windows host | Very high |
| Linux state | Repeated multipath state phrases without coherent remove/recover lifecycle | High |
| Linux metadata | Same IRQ/device reported with changing banned affinity masks without transition evidence | High |
| Population texture | Common process/daemon palettes repeated across many hosts | Medium |
| Human activity | Compact, curated-looking shell command clusters | Low–medium |

## Realism Score by Category

| Category | Score |
|---|---:|
| Windows Security/Sysmon/eCAR fidelity | 7/10 |
| Linux syslog and Bash-history fidelity | 6/10 |
| Process/session/authentication lifecycle | 8/10 |
| Process trees, identity, and ownership | 8/10 |
| Host-role and population realism | 7/10 |

## Recommendations

1. Generate Windows provider-envelope metadata from per-host evolving state. Do not select Event 5156 execution thread IDs from one global fixed pool; model host-specific thread populations and reuse them according to provider/process behavior.

2. Make background daemons stateful. For multipath, explicitly model path removal, degraded map state, retry/failure, restoration, and updated active-path counts. Prevent contradictory independent message selection.

3. Tie `irqbalance` messages to a stable host IRQ/device/affinity model. Affinity masks should change only after a visible or modeled reconfiguration, and verbose messages should appear only when daemon logging settings justify them.

4. Broaden per-host background-process mixtures and version/config differences so hosts do not share the same small set of Windows and Linux activity archetypes.

5. Add more organic shell-history texture: corrections, failed commands, environment-specific aliases, repeated navigation, partial investigations, session-to-session continuity, and user-specific habits.

6. Preserve the existing strengths: provider-specific timestamp offsets, stable hashes, non-overlapping PID lifetimes, SSH lifecycle correlation, stable UID mappings, and strong role-aware process placement.
