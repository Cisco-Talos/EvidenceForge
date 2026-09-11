# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 95
**Synthetic-Confidence Score:** 87

## Executive Summary

The Windows and eCAR evidence is unusually strong at the individual-event level: process identity, parentage, hashes, session ordering, and cross-source timing are internally coherent. The dataset nevertheless appears synthetic because the Linux syslog contains a repeated PID-allocation impossibility, source-family-specific timestamp quantization, and the same unlikely hardware and snap-package vocabularies spread across unrelated host roles.

## Evidence For Synthetic

- [hard_contradiction] Ten Linux hosts record a newly starting one-shot `anacron` process with a low PID while adjacent newly active processes remain in a much higher, continuously advancing PID range. On `FILE-LNX-01`, `anacron` PID 58853 announces `Anacron 2.3 started` at `2024-03-18T12:23:36.233000Z` (`syslog.log:46`), between `sudo` PID 1899975 at `12:13:29.191783Z` (`:35`) and `sudo` PID 1901684 at `12:29:18.717720Z` (`:58`). The same defect repeats on `APP-INT-01` with `anacron` PID 17919 between `sshd` PID 1893086 and `CRON` PID 1896997, on `MAIL-CLIN-01` with PID 29990 between PIDs 3548893 and 3549847, and on seven other hosts. A short-lived process cannot be allocated from the low range and then return immediately to the uninterrupted high range without millions of intervening allocations or a visible PID-namespace boundary.
- [distribution_texture] Syslog timestamp precision is deterministically tied to event family. All 110 `CRON` records on ten hosts have microseconds divisible by 1000, including `FILE-LNX-01` at `12:01:00.247000Z` and `12:31:00.171000Z` (`syslog.log:3,57`), while 0 of 494 `irqbalance` records and 0 of 215 `sudo` records have that property. Likewise, all ten `Anacron 2.3 started` records end in `000` microseconds, but their same-PID follow-on messages use unconstrained six-digit fractions. A single local syslog collection path would not normally quantize timestamps according to message semantics this perfectly.
- [environment_or_collection_plausibility] The `irqbalance` hardware vocabulary is repeatedly drawn from the same mixed pool across unrelated systems. `FILE-LNX-01` alone reports `mlx5_comp2` (`12:00:57.642878Z`), `mlx5_comp0` (`12:03:42.240200Z`), `virtio1-input` (`12:20:41.072014Z`), `ens192` (`13:03:03.492568Z`), `nvme0q2` (`13:04:19.952540Z`), and `ahci` (`13:15:16.775654Z`); `APP-INT-01` and `DB-PROD-01` show substantially the same mixed device set. Eight server-role hosts expose seven to ten members of the same ten-device universe, which looks like a shared message pool rather than persistent per-host hardware topology.
- [environment_or_collection_plausibility] The same snap workload appears on disparate application, file, logging, mail, proxy, and web roles. `APP-INT-01`, `FILE-LNX-01`, `LOG-MON-01`, `MAIL-CLIN-01`, `MAIL-EDGE-01`, `PROXY-01`, and `WEB-EXT-01` all reference `lxd`, `microk8s`, `core20`, `core22`, and `snapd-desktop-integration` during this six-hour slice. Examples include `APP-INT-01` repeatedly processing `snapd-desktop-integration` from `12:10:06.064124Z` onward (`syslog.log:18,22,27,29`) and `PROXY-01` doing the same at `12:22:16.325307Z`, `12:26:39.111093Z`, and `12:29:57.985917Z` (`syslog.log:48,55,57`), plus `microk8s` at `15:44:15.590134Z` (`:142`). A common golden image could explain some overlap, but the exact five-snap set and frequent desktop-integration activity on headless server roles are implausibly uniform.
- [weak_signal] Windows service-logon volume is highly templated. Across the ten Windows Security logs, all 428 visible type-5 4624 records use a zero `LogonGuid` and one of the three well-known LUIDs `0x3e7`, `0x3e5`, or `0x3e4`; `DC-01` alone emits 54 SYSTEM, 43 LOCAL SERVICE, and 37 NETWORK SERVICE type-5 logons, and `DC-02` emits 45, 49, and 44. Those values are individually legal, so this was only a low-weight indicator, but the repeated rate and identical shape are unusual for a healthy six-hour slice.

## Evidence For Real

- Windows process evidence correlates cleanly without visible causality violations. Of 993 Sysmon Event 1 records, 992 match a Security 4688 on the same host by PID and image within two seconds, with matching command line, parent PID, and user; 986 also match an eCAR `PROCESS/CREATE` record with those fields intact. The source delays vary rather than being fixed.
- A representative three-source process is `msedge.exe` PID 7396 on `WS-MCHEN-01`: Sysmon records it at `2024-03-18T12:02:39.4710206Z` (`windows_event_sysmon.xml:113`), eCAR records the same PID, image, command line, parent PID 6616, and principal at `12:02:39.578Z` (`ecar.json:4`), and Security 4688 records it at `12:02:39.6754849Z` (`windows_event_security.xml:55`). The parent is consistently `explorer.exe`, and all three sources preserve the same URL-bearing command line.
- Sysmon lifecycle state is convincing. No dependent Event 3/7/8/10/11/13/22 was found before a visible create for the same process GUID or after its visible Event 5 termination, and no Event 5 preceded its visible Event 1. Visible parent GUIDs also resolve to earlier process creations with matching parent PID and image.
- Hash behavior is realistic: none of the ten Windows hosts changes the hash of a given executable path during the slice. Cross-host differences track plausible OS cohorts; for example, `userinit.exe` is `10.0.20348.1` on the domain controllers and mail server, `10.0.22621.1` on `WS-MCHEN-01` and `WS-PPATEL-01`, `10.0.19041.1` on four other workstations, and `10.0.17763.1` on `FILE-SRV-01`, with a stable SHA-256 inside each cohort.
- Linux SSH lifecycles have credible ordering and identity reuse. On `FILE-LNX-01`, source `10.10.1.35:53713` connects at `12:11:14.355600Z`, authenticates as `aisha.johnson` at `12:11:22.393796Z`, opens PAM at `12:11:22.458525Z`, receives logind session 116966 at `12:11:23.165063Z`, closes PAM at `13:00:42.792693Z`, and removes session 116966 at `13:00:43.372486Z` (`syslog.log:29,31-33,91,93`). The same user retains UID 2528 across Linux hosts, while other users retain their own distinct UIDs.
- User and host roles are differentiated rather than cloned. `WS-LNGUYEN-01` shows developer-oriented `git`, `npm`, `docker`, editor, and SSH activity in both bash history and eCAR, while `FILE-LNX-01` is dominated by `smbd` children and audited file operations, and `DB-PROD-01` contains database and storage-administration activity. Exact bash commands are not broadly copied: only `pwd` and `tail -f /var/log/syslog &` occur in four or more history files.

## Detailed Analysis

### Windows process trees and Sysmon

The Windows process trees use appropriate parents: `SearchIndexer.exe` launches `SearchProtocolHost.exe` and `SearchFilterHost.exe`, `services.exe` launches service binaries, `csrss.exe` launches `conhost.exe`, and interactive applications descend from `explorer.exe`. RDP-created session stacks visibly follow `smss.exe` → `winlogon.exe` → `userinit.exe` → `explorer.exe`; all visible parent GUID relationships resolve backward in time and agree on PID and image.

Sysmon Event 1, Security 4688, and eCAR process creates agree at field level. Across the ten Windows hosts, the 992 Sysmon-to-Security matches have no command-line, parent-PID, or user mismatch. Security lags Sysmon by approximately 35-650 ms, and eCAR commonly follows within approximately 3-871 ms; the spread is more credible than a constant emitter offset. The handful of unmatched records are consistent with source-level filtering or bounded-window collection and were not scored as synthetic.

Sysmon hashes remain stable for every executable path within each host. The same executable varies between host cohorts only where the logged Windows build metadata also varies. Process GUID lifecycle checks found no visible child/dependent event before its own creation and no dependent activity after termination.

### Windows logon and session behavior

Interactive, network, service, unlock, new-credentials, and RDP logon types are present in role-appropriate proportions. RDP type-10 records carry remote workstation names and IPv4-mapped source addresses, then produce target session process stacks; no process tied to a visible non-service logon ID starts before that session's visible 4624. Unlock type-7 events correctly reuse an existing interactive LUID, such as `priya.patel` reusing `0xd8e0214` on `WS-PPATEL-01`.

The main weakness is service-logon texture: 428 type-5 events all collapse to the three well-known service LUIDs and a zero GUID, with very high rates on the domain controllers. This is legal enough that it is not a contradiction, and the absence of a System channel prevents a definitive service-start comparison, but the distribution looks modeled rather than collected.

### Linux process and session evidence

SSH and sudo lifecycles are generally strong. Connection, acceptance, PAM open, logind creation, command execution, PAM close, and logind removal occur in plausible order; stable user UIDs and stable public-key fingerprints survive across hosts. Bash histories are timestamped, user-specific, and substantially non-duplicative, while eCAR process trees use sensible parents such as `cron` → `sh` → `debian-sa1`, `sshd` → `sshd` → `bash`, and `bash` → `sudo`.

The `anacron` PID defect overrides much of that realism. Its `Anacron 2.3 started` message marks a new short-lived process, yet on ten hosts its PID comes from a low, daemon-like range while immediately surrounding short-lived processes continue in a much higher range. The pattern is fleet-wide and is coupled to the same event's millisecond-quantized start timestamp, making a shared generator path more likely than an isolated collector quirk.

The timestamp distribution independently reinforces that conclusion. Precisely 110 of 110 CRON timestamps have their final three microsecond digits zero, compared with none of 494 `irqbalance` and none of 215 `sudo` timestamps. Because those records share the same host-local RFC 5424 stream, application-semantic precision is a conspicuous generation artifact.

### eCAR correlation and source coverage

eCAR records are chronologically sorted and use unique record IDs. For every host, no eCAR actor with a visible process creation is used before that creation or after its visible termination, and no visible termination precedes creation for the same object ID. Windows eCAR process records closely match Security and Sysmon fields, while Linux process records preserve sensible principals, UIDs through the surrounding syslog, and command lineage.

I did not score complete correlation as synthetic, and I did not penalize sessions or processes whose initiators could fall before the six-hour window. Likewise, absent Windows System-channel events and selected Sysmon coverage were treated as collection boundaries rather than authenticity clues.

### Environmental consistency

Role-specific evidence is present, including Exchange processes on `MAIL-FIN-01`, `smbd` auditing on `FILE-LNX-01`, Apache on `WEB-EXT-01`, and developer tooling on `WS-LNGUYEN-01`. The weaker layer is shared background vocabulary: unrelated Linux roles repeatedly draw the same IRQ/device names and the same snap package set. The recurrence is too broad to look like ordinary fleet standardization, especially where server roles repeatedly report both `snapd-desktop-integration` and `microk8s` activity.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected the synthetic-confidence score |
|---|---|---|---|
| `hard_contradiction` | Linux syslog / process lifecycle | Repeated on 10 hosts | Newly starting `anacron` PIDs come from a low range between neighboring high, still-advancing short-lived PIDs; this is a fleet-wide process-identity impossibility without an unexplained namespace boundary. |
| `distribution_texture` | Linux syslog timestamps | Dataset-wide for CRON and `anacron` starts | 110/110 CRON timestamps and 10/10 `anacron` start timestamps are millisecond-quantized while adjacent source families in the same files are not. |
| `environment_or_collection_plausibility` | Linux syslog / irqbalance | Repeated across server roles | Disparate hosts report substantially the same mixed ten-device vocabulary, including Mellanox, virtio, NVMe, AHCI, and interface-specific names. |
| `environment_or_collection_plausibility` | Linux syslog / snapd | Repeated across 7 disparate roles | The exact `lxd`, `microk8s`, `core20`, `core22`, and `snapd-desktop-integration` set recurs on application, file, logging, mail, proxy, and web servers. |
| `weak_signal` | Windows Security / logon | Repeated, strongest on servers | All 428 type-5 logons use a zero GUID and three well-known LUIDs, with unusually high repeated rates on both domain controllers. |

## Realism Score by Category

- **Field format accuracy:** 8 — Windows XML, Sysmon, RFC 5424, bash history, and eCAR are structurally credible, but the `anacron` PID values are not credible in their visible host PID streams.
- **Temporal patterns:** 4 — Lifecycle ordering is strong, but perfect CRON/start-event millisecond quantization is a high-volume generator fingerprint.
- **Cross-source correlation:** 9 — Process, session, PID, image, command-line, hash, and eCAR relationships are unusually well preserved without visible ordering contradictions.
- **Behavioral realism:** 8 — User tooling, parent-child relationships, SSH sessions, sudo work, file-server activity, and server roles are differentiated and operationally plausible.
- **Environmental consistency:** 5 — Role-specific services are convincing, but the repeated hardware vocabulary and five-snap package set across unrelated Linux roles substantially weaken the environment model.

## Recommendations

- If this were synthetic, make each host's PID allocator the single source of truth for every short-lived process represented in syslog, including `anacron`. A start/execute/exit chain must consume from the same PID stream as CRON, SSH, sudo, and eCAR process events; add a regression check that rejects a new one-shot PID far below both neighboring allocations unless an explicit PID namespace is logged.
- Preserve source-native timestamp precision at the syslog transport layer. Do not assign millisecond-only anchors to selected semantic event families while giving sibling records microsecond entropy; CRON, `anacron`, sudo, SSH, and daemon messages traversing one host collector should share the same precision model.
- Bind IRQ names, storage devices, NICs, and snap installations to persistent per-host inventories. Generate `irqbalance` only from devices actually assigned to that host, and emit snap activity only for packages installed on that role; desktop integration should not appear broadly on headless servers without corroborating desktop software.
- Revisit the type-5 Windows logon model. If the high DC volume is intentional, add source-visible service context that explains it; otherwise reduce repeated well-known-session 4624 events and model service account/session identity according to actual SCM behavior.
- Preserve the current strengths: canonical process identity, stable per-host hashes, variable source delay, GUID-aware lifecycle ordering, RDP/SSH session sequencing, and role-specific command behavior.
