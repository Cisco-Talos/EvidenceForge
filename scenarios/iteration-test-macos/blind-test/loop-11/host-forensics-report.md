# Host/EDR Forensics Review — Loop 11

## Verdict

Indeterminate, with a slight synthetic lean. The host evidence is generally production-like and cross-source coherent, but some repeated baseline and workstation patterns look templated.

## Verdict Confidence (0–100)

56

## Synthetic-Confidence Score (0–100; lower is more production-like)

55

## Executive Summary

Across Windows, macOS, and Linux hosts, process trees and session evidence mostly make sense at the host level. Windows EDR process creation records agree with Sysmon process images and PIDs, and Windows session identifiers usually agree with Security logons. On macOS, Endpoint Security fork, exec, and exit records have credible process relationships; eCAR `CREATE`/`MODIFY`/`TERMINATE` events and shell history line up for sampled commands. Linux histories also have corresponding process, file, and network observations, including a database dump followed by compression and SCP, and a diagnostic archive followed by a proxy-mediated upload.

The main synthetic-looking cues are identical 30-minute `debian-sa1` parent/child runs across the Linux estate, with host-specific offsets but very regular spacing, and repeated, similar macOS command sequences on two hosts. These can occur in real managed environments, so neither is a decisive contradiction. I found no high-confidence host-local PID, parent-image, or session-ID contradiction in the reviewed evidence.

## Evidence For Synthetic

- **Highly regular Linux baseline schedule:** On ten Linux hosts with eCAR data, a `/bin/sh -c ... debian-sa1 1 1` process and its `debian-sa1` child recur every 30 minutes through the six-hour window. The cadence is exact to the second on several hosts; for example, APP-INT-01 runs at 13:00:01, 13:30:01, 14:00:01, and onward. Hosts have slightly different start offsets, which is plausible cron staggering, but the same duration, pair structure, and interval across the estate look templated.
- **Repeated macOS command profile:** The two Maya Ross endpoints repeat a similar inventory/troubleshooting set (`id`, `sw_vers`, `uname`, `ps`, `df`, `find` under Documents) and each has repeated SSH hops. This is plausible operator behavior, but the similar command vocabulary and repeated order make the six-hour activity look rehearsed.
- **High Linux process IDs:** Several Linux hosts show ordinary short-lived processes with PIDs in the millions (roughly 0.7–4.1 million in sampled host eCAR records). These values are valid on common Linux PID ranges and may reflect uptime or churn, so this is only a weak cue without host uptime or `pid_max` evidence.

## Evidence For Real

- **Windows process identity agreement:** On all ten Windows hosts with Sysmon data, eCAR `PROCESS/CREATE` PIDs overlap nearly completely with Sysmon Event ID 1. For overlapping PIDs, the image paths agree. This includes both server and workstation hosts, with no sampled image-path mismatch.
- **Windows session agreement:** eCAR `USER_SESSION/LOGIN` records with logon IDs usually have matching Security Event ID 4624 `TargetLogonId` values on the same host. For example, the domain controllers and file server show near-complete overlap between the identifiers present in eCAR and the Security log.
- **Credible macOS process lifecycle:** On MAC-MROSS-01, Endpoint Security shows PID 42180 executing `/usr/bin/id`; eCAR has PID 42180 created from the zsh fork and then modified to `/usr/bin/id`, followed by termination. The same fork/exec/exit shape appears on MAC-MROSS-02. This is a coherent native lifecycle, not a process-image contradiction.
- **Host-local command and artifact alignment:** DB-PROD-01 eCAR records `mysqldump`, creation of `/tmp/rpt_0318.sql`, `gzip`, creation of the compressed file, and `scp` to 10.10.2.30, with matching commands in root's shell history. WS-LNGUYEN-01 similarly records the diagnostic tar archive, a curl upload command, a read of the archive, and associated proxy flows in the same time window as Lina Nguyen's shell history.
- **Plausible lifecycle variation:** Windows and Linux process create/terminate counts are generally close but not mechanically identical, while sessions and other events vary by host. Event times span about six hours and show host-specific offsets rather than one shared start instant.

## Detailed Analysis

### Process and session semantics

Windows Security and Sysmon records have recognizable native event structure and plausible process paths. Across ten Windows hosts, process PIDs and image paths in eCAR align with Sysmon process creation records. The relevant Security logon IDs also align with eCAR session IDs in almost all instances where both sources expose an ID. This is strong evidence of internally consistent host state; it does not by itself establish whether the data came from production or a renderer.

The macOS Endpoint Security logs show recognizable `fork` (event type 11), `exec` (event type 9), and `exit` (event type 15) sequences. For the sampled Terminal shell commands, the zsh fork creates a child; eCAR records that initial process state as `CREATE`, its executable change as `MODIFY`, and the later exit as `TERMINATE`. The process IDs, executable paths, and command arguments agree in the checked `id`, `sw_vers`, and `uname` activity. Several applications and shells terminate near the end of each host's observed window. That could be a host shutdown or collection boundary; the evidence does not establish which.

Linux eCAR process records show parent/child relationships for cron-style system jobs and interactive sessions. Short-lived command processes generally have a matching termination. The sampled database and workstation command sequences also have corresponding file and flow observations. No impossible parent/child or image/PID pairing stood out in the bounded review.

### Shell and administrative behavior

The Linux shell histories contain routine diagnostics and administrative commands, as well as higher-risk actions. Root on DB-PROD-01 runs a database export, compresses it, and sends it to another internal host over SCP. Lina Nguyen on WS-LNGUYEN-01 packages connector logs and submits them to an external support endpoint through a configured proxy. The histories and eCAR process/file/flow records agree on the commands and timing. Those actions warrant security review in an operational investigation, but their presence is compatible with either authentic activity or a well-modeled exercise and is not evidence of synthetic origin by itself.

### Timing and volume

Most host event streams cover approximately 13:00–19:00 UTC on 2026-11-02. Windows host event times and eCAR timestamps are close, and macOS process events preserve sub-second ordering. Linux sysstat activity is the most conspicuous regular pattern: each reviewed Linux host has twelve paired runs in the window, spaced exactly 30 minutes apart with a per-host offset. A stable scheduled job is a reasonable explanation, so this raises suspicion without constituting a contradiction.

## Synthetic Indicator Summary

| Category | Observation | Weight |
|---|---|---|
| Temporal cadence | Paired sysstat executions recur every 30 minutes on each reviewed Linux host | Moderate |
| Repeated behavior | Similar macOS diagnostic command vocabulary and SSH hops on two hosts | Low to moderate |
| Process/session contradiction | No high-confidence contradiction found in reviewed PID, image, parent, or logon-ID evidence | None observed |
| Cross-source consistency | Strong Windows process and session agreement; coherent sampled macOS and Linux lifecycles | Evidence against a synthetic-looking failure |
| Host coverage | macOS unified logs are sparse relative to endpoint events; thin coverage alone is not diagnostic | Low / excluded |
| PID range | Million-range Linux PIDs are unusual but valid and context is insufficient | Low |

## Realism Score by Category

Scores are 0–100, where higher means more production-like.

| Category | Score |
|---|---:|
| Windows process and session semantics | 88 |
| macOS process lifecycle and shell behavior | 82 |
| Linux process and shell behavior | 72 |
| Cross-source host correlation | 86 |
| Timing and routine baseline variation | 62 |
| Overall host/EDR realism | 77 |

## Recommendations

- If this bundle is being tuned for production-like variation, vary or jitter the Linux sysstat schedule by host and avoid identical paired runs across the entire estate; preserve plausible cron-based periodicity.
- Keep the macOS fork-to-exec-to-exit relationship and its matching eCAR `CREATE`/`MODIFY`/`TERMINATE` representation. The sampled records are coherent and should not be “fixed” as image mismatches.
- For a higher-confidence authenticity judgment, compare the 30-minute job cadence with the expected sysstat schedule and host uptime/PID settings. Those facts are not established by the reviewed host records.
- Treat the database export and external diagnostic upload as operationally significant actions for a security review, while keeping them separate from the authenticity verdict unless independent host evidence contradicts the recorded actors or artifacts.
