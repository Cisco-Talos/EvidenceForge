# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

- **Assessment:** Inconclusive; the host/EDR slice leans production-like.
- **Verdict Confidence:** 62/100.
- **Synthetic-Confidence Score:** 34/100 (mostly realistic, with one explainable dataset-level regularity).

## Executive Summary

The endpoint evidence is internally credible across Windows, Linux, and macOS. The clearest checks are native process lifecycles: a Dell update process agrees across Sysmon, Security auditing, and eCAR within milliseconds; macOS Endpoint Security fork/exec observations preserve one PID while the exec image and PID version change; and Linux sudo records pair command audit entries with short-lived PAM sessions. I found no visible dependent event that requires a later initiator, no reversed process/session lifecycle, and no concrete cross-source identity contradiction.

The main caution is the unusually synchronized collection interval: Windows Sysmon and Security logs on nine hosts all cover roughly 13:00–19:00 UTC on 2026-11-02. That is compatible with a deliberate bounded export and does not by itself distinguish synthetic from real data. Sparse Unified Log rows on the two Macs also do not establish a collection mismatch because the separate Endpoint Security source records process activity and Unified Log coverage is a distinct source.

## Evidence For Synthetic

- **[weak_signal] Synchronized bounded capture window.** All nine Windows endpoint Security/Sysmon pairs begin between 13:00:03 and 13:05:10 UTC and end between 18:54:29 and 18:59:50 UTC on 2026-11-02. For example, `DC-01.meridianhcs.local/windows_event_security.xml` spans 13:00:04.391–18:59:50.707, while its Sysmon file spans 13:00:04.423–18:59:50.760. The repeated six-hour envelope across workstations, domain controllers, and a file server is more curated than a random set of retained host logs might be. A common collection window is an ordinary explanation, so this is weak evidence only.
- **[weak_signal] Small native-versus-normalized macOS lifecycle count differences.** On `MAC-MROSS-01`, Endpoint Security shows 44 fork, 50 exec, and 43 exit observations; the local eCAR process view has 43 fork creates, 49 exec modifies, and 42 terminates. These one-event deltas can arise at a bounded interval or collection boundary and do not show an impossible ordering, but they leave a small normalization/coverage uncertainty. On `MAC-MROSS-02`, fork and exec counts agree at 58 and 68 respectively; eCAR has 57 terminations versus 56 ES exit observations.

## Evidence For Real

- **Windows process identity and timing agree across three representations.** On `WS-MCHEN-01`, Sysmon Event ID 1 records PID 7188 / `dcu-cli.exe` with command `dcu-cli.exe /applyUpdates -silent`, parent `taskhostw.exe` PID 6144, and user SYSTEM at 13:07:46.935 UTC (`windows_event_sysmon.xml`, event around lines 250–274). Security Event ID 4688 records the same command, PID `0x1c14` (7188), parent `taskhostw.exe`, and SYSTEM at 13:07:47.070 (`windows_event_security.xml`, around lines 375–392). The eCAR process create for PID 7188 is at 13:07:47.067 (`ecar.json:11`), 3 ms before Security and about 132 ms after the Sysmon record. The agreement includes command, actor, parent, and process identifier, not just a shared timestamp.
- **Windows termination evidence is also coherent at the collection boundary.** `WS-MCHEN-01` Sysmon Event ID 5 ends PID 6736 / `AdobeARMservice.exe` at 13:00:18.084 (`windows_event_sysmon.xml`, around lines 136–150); eCAR records termination of that same PID and image at 13:00:18.079 (`ecar.json:8`). No visible start for this process is required: it is a long-lived service already active at the beginning of the six-hour window. Across the Windows Sysmon files I checked, matched start/exit pairs had no exit-before-start cases and no Event ID 3/10 network or process-access observation after a visible matching exit.
- **macOS process identity follows native exec semantics.** On `MAC-MROSS-01`, Endpoint Security version 11 records a launchd fork at 13:07:45.180; the child PID 42174 is observed through exec events at 13:07:45.188 and 13:07:45.201. The process audit token changes PID version across exec, while the PID remains 42174 (`macos_endpoint_security.ndjson:1–3`). eCAR represents the same progression as a fork create followed by image-changing exec modifications and an identity/service transition (`ecar.json:2–5`): launchd → xpcproxy → Terminal, with execution IDs and prior-image fields. This preserves a single process lifetime across successive images rather than treating each image as a new unrelated process.
- **macOS monotonic and wall-clock fields are mutually plausible.** Within each ES stream, `mach_time` advances with the wall-clock timestamps at a stable rate (about 24 million ticks per second). The launchd start time and first event’s monotonic clock are consistent with the host’s visible uptime, rather than indicating a clock reset or impossible start time (`MAC-MROSS-01/macos_endpoint_security.ndjson:1`; `MAC-MROSS-02/macos_endpoint_security.ndjson:1`).
- **macOS Unified Log preserves source-native meaning.** `MAC-MROSS-01/macos_unified_log.ndjson:2` reports that Apple System Policy would not allow PID 62451 to execute `MeetingAssist`; this is a policy-denial observation, not proof of a launch or its effects. A separate record at `:3` reports `sshd-session` accepting Maya Ross’s public key from 10.10.1.42 at 16:01:52 UTC. The records retain sender/process image paths, subsystem or message format, and event message. No unsupported claim about authorization or post-denial effects is needed to interpret them.
- **Linux command auditing has believable session boundaries.** For example, `APP-INT-01.meridianhcs.local/syslog.log` records Aisha Johnson’s sudo command, a PAM `session opened`, and `session closed` under the same sudo PID 2934171 at 13:16:00–13:16:02. `DB-PROD-01.meridianhcs.local/syslog.log` likewise pairs sudo audit lines and PAM open/close for Lina Nguyen. The RFC 5424-style records retain facility/priority, timestamp, host, service, PID, and message rather than flattening these into generic text.
- **Different source families have distinct roles and native structures.** Windows XML uses Security and Sysmon event IDs and their native named fields; macOS Unified Log remains separate from Endpoint Security JSON; Linux syslog and shell histories retain their own conventions. The dataset does not imply that Macs should emit Windows/Linux event families.

## Detailed Analysis

### Windows endpoints

The Windows sample includes domain controllers (`DC-01`, `DC-02`), user workstations, a Windows file server, and `MAIL-FIN-01`. The visible window is six hours on 2026-11-02. Event composition is plausible for this mix: the domain controllers are dominated by Windows Filtering Platform permits (Security 5156), Kerberos service/ticket activity (4768/4769), logons (4624), and Sysmon network observations (Event ID 3); user endpoints have process create/terminate, DNS, network, and registry/image-load events. The event families reflect the records actually present; I do not infer missing provider coverage from absent event IDs.

Process lifecycle matching is strong but not treated as proof of authenticity by itself. In the nine Sysmon files, all visible matched process-start/exit pairs had nonnegative lifetimes; matching process GUIDs did not have Event ID 3 or 10 observations after the visible Event ID 5. A few exits have no visible start (for example, three on DC-01, seven on WS-MCHEN-01), which is consistent with a capture boundary and not evidence of an orphaned lifecycle. The Sysmon/security/eCAR Dell updater correlation above is a more probative check because it matches source-native process fields and timing.

### macOS endpoints

`MAC-MROSS-01` and `MAC-MROSS-02` each have Endpoint Security version 11, separate Unified Log NDJSON, eCAR, and Maya Ross zsh history. The ES stream contains fork, exec, and exit events, plus audit tokens with PID versions and a distinct responsible-process token. This is enough to assess process transitions without assuming that ES event presence means an execution was authorized. The unified log has three records on MAC-MROSS-01 and two on MAC-MROSS-02; their low volume alone is not a defect. One record is a policy denial, and the two machines have distinct login applications (Terminal versus iTerm), process identities, and boot UUIDs.

### Linux hosts

Linux server trees include syslog and per-user bash histories for application, database, web, mail, file, monitoring, and proxy roles. Logs show routine service activity alongside sudo and SSH session evidence. The visible syslog records include process IDs and timestamped command/session messages that permit bounded lifecycle checks. Nothing in the host records requires assuming that every logged shell command has an EDR counterpart in the available source set.

### Scope and limits

This assessment uses only raw files in `dataset-hickory`. The shared date and bounded interval are recorded as weak collection texture, not treated as a defect without a contradictory source relationship. I found no concrete hard contradiction or contract gap in the host/EDR evidence reviewed. That leaves the verdict inconclusive rather than a claim that the records are genuine.

## Synthetic Indicator Summary

| Category | Finding | Weight |
|---|---|---|
| `hard_contradiction` | None observed in the reviewed host/EDR records. | None |
| `contract_gap` | No visible initiator-after-dependent ordering or reversed matching lifecycle. Small one-event macOS ES/eCAR deltas are consistent with bounded coverage. | Low / none |
| `distribution_texture` | Nine Windows Security/Sysmon host pairs share a tightly aligned six-hour UTC window on one date. | Weak |
| `schema_or_format` | Native Windows XML, macOS ES v11 and Unified Log records, and RFC 5424-style Linux syslog are internally readable; no format break stood out. | None |
| `environment_or_collection_plausibility` | A common capture window could be intentional; no host-role or OS/source contradiction was established. | Weak |
| `weak_signal` | Dataset is a curated multi-host, multi-source snapshot with bounded endpoints. No stronger host-level tell found. | Weak |

## Realism Score by Category

- **Field format:** 8/10 — native event IDs, named XML data, ES audit tokens and PID versions, and structured syslog fields are coherent.
- **Temporal patterns:** 8/10 — process and session timing is plausible, with millisecond cross-source variation and no reversed visible process lifetimes. The common capture window is the main reservation.
- **Cross-source correlation:** 9/10 — the Windows updater record agrees across Sysmon, Security, and eCAR; macOS fork/exec identities preserve PID and version transitions across ES and eCAR.
- **Behavioral realism:** 7/10 — the endpoint activity includes ordinary services, logons, shells, user processes, and an explicit macOS policy denial. The short time span limits broader behavioral judgment.
- **Environmental consistency:** 8/10 — host names, OS-specific source families, process paths, and inferred host roles are mutually plausible in the visible records.

## Recommendations

- Keep the shared six-hour capture envelope documented as a collection boundary if it is intentional; otherwise compare it with a wider host retention window before using timing texture as a synthetic indicator.
- For stronger provenance review, retain source-native event records alongside normalized eCAR rows and preserve the collection/version configuration for Windows, Endpoint Security, and Unified Log.
- Treat the macOS Apple System Policy entry as evidence of a denial observation only. Do not infer successful execution or downstream effects without an independent visible record.
- No host/EDR repair is indicated from the raw records reviewed.
