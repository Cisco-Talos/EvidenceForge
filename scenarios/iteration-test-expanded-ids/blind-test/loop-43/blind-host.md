# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 93  
**Synthetic-Confidence Score:** 87

## Executive Summary

The dataset has strong source-format fidelity and unusually good Windows/Sysmon/eCAR and Linux SSH lifecycle construction. However, repeated simultaneous instances of singleton Windows services—confirmed as active across multiple endpoint sources—are a hard host-semantic contradiction, while a precisely bounded clock-jitter pattern in 915 kernel records adds a dataset-generation fingerprint.

## Evidence For Synthetic

- `[hard_contradiction]` On `DC-01`, Sysmon Event 1 records create `svchost.exe -k netsvcs -p -s Schedule` as PID 4032 at `2024-03-18T12:54:11.2810617Z` and again as PID 4224 at `13:07:04.5182163Z`. PID 4032 has no intervening Sysmon Event 5, Security 4689, or eCAR termination, and eCAR records module loads from both PIDs after the second creation. A singleton Task Scheduler service cannot persist concurrently in multiple `-s Schedule` service hosts.
- `[hard_contradiction]` This is fleet-wide rather than isolated. Among still-active processes created inside the window, `DC-01` has six `Schedule`, five `LanmanServer`, four `BITS`, three `wuauserv`, three `AppXSvc`, and three `CryptSvc` instances with no intervening termination. Similar overlap appears for four `Winmgmt` processes on `FILE-SRV-01`, five `LanmanServer` processes on `MAIL-FIN-01`, and duplicate `EventLog` service hosts only 48 seconds apart on `WS-MCHEN-01`.
- `[contract_gap]` The contradictory service creations appear coherently in Sysmon Event 1, Security 4688, and eCAR `PROCESS/CREATE`, but their required predecessor terminations are absent from all three configured endpoint families. This is not merely incomplete source coverage: later eCAR activity attributed to the older PIDs proves that several predecessor processes remain modeled as live.
- `[distribution_texture]` All 915 `WEB-EXT-01` kernel UFW messages contain an embedded monotonic timestamp whose implied boot epoch varies over a precisely bounded `0–250 ms` interval. The minimum implied boot time is exactly `2024-02-20T12:00:00.000Z`, the median residual is approximately 137 ms, and the maximum is exactly 250 ms—consistent with independently sampled capped jitter rather than one host clock relationship.
- `[distribution_texture]` Of 915 UFW blocks, 911 come from only eight source IPs. Each dominant IP has an invariant packet length and TTL across dozens to 151 events, while selecting from narrow port-family sets and the same three TCP windows (`1024`, `14600`, `65535`). Scanner fingerprint stability is realistic, but this degree of pool reuse over six hours looks generated.
- `[environment_or_collection_plausibility]` Linux background noise repeatedly draws from a small shared vocabulary at high rates. On `WEB-EXT-01`, for example, six hours contain 127 `systemd-resolved`, 115 `snapd`, and 112 `irqbalance` records, while several other Linux hosts show the same three families dominating their non-authentication telemetry.

## Evidence For Real

- Windows event structures are source-native and detailed: Event IDs, versions, provider GUIDs, token-elevation values, integrity SIDs, hexadecimal PIDs, ProcessGUIDs, and hash fields are internally well formed.
- Process identities generally correlate correctly. For matched creations and terminations, Sysmon, Security, and eCAR agree on PID and image; known Sysmon process terminations occur after creation with matching GUID, PID, and image.
- Hashes remain stable for a path on a host while common Windows binaries have multiple hash sets across apparent OS groups. For example, `svchost.exe`, `conhost.exe`, and `WmiPrvSE.exe` each have four hash variants across nine Windows hosts rather than one fleet-wide placeholder.
- Linux SSH records show realistic ordering: connection, authentication, PAM session open, `systemd-logind` session creation, later PAM close, and session removal. Authentication methods, ports, users, key types, and durations vary.
- Host roles are differentiated. Exchange processes occur on `MAIL-FIN-01`, file/backup tooling on `FILE-SRV-01`, desktop applications on workstations, and Postfix/Dovecot activity on Linux mail hosts.
- The Security log clear on `DC-01` at `2024-03-18T17:42:15.8336571Z` is represented with Event 1102 and a plausible EventRecordID reset from 28261923 to 1.
- I did not count unmatched sessions or processes at the beginning or end of the six-hour capture as defects. Sessions closing just after 12:00 may have opened before the window, and processes still active at 18:00 may legitimately continue afterward.

## Detailed Analysis

The visible endpoint window is approximately `2024-03-18T12:00:00Z–18:00:00Z`. It includes nine Windows Security/Sysmon pairs, eCAR on 18 hosts, and syslog on nine Linux hosts.

### Windows process and service behavior

Ordinary process trees are often convincing. User applications commonly descend from `explorer.exe`; service workloads descend from `services.exe`; WMI and console relationships use `svchost.exe → WmiPrvSE.exe` and `csrss.exe → conhost.exe`; SSH clients descend from PowerShell or `cmd.exe`. Known in-window Sysmon Event 5 records match their Event 1 creation GUID, PID, and image without reversed lifecycles.

The decisive exception is service-instance ownership. On `DC-01`:

- PID 4032, ProcessGUID `{83eb9c06-3973-65f8-ea02-0000a94db485}`, starts `svchost.exe -k netsvcs -p -s Schedule` at `12:54:11.2810617Z`.
- PID 4224, ProcessGUID `{83eb9c06-3c78-65f8-0f02-00003ab2ef31}`, starts the identical service at `13:07:04.5182163Z`.
- Security 4688 independently records both at `12:54:11.2887438Z` and `13:07:04.5338412Z`.
- eCAR records both creations and later module activity from PID 4032 and PID 4224, including activity from each around `13:26Z`.

Thus this is not a bounded-window artifact or a missing initial state. The first process was created inside the window and is still producing telemetry after the second singleton service process starts. Four additional `Schedule` processes subsequently appear without resolving the earlier instances. The same failure mode affects several named services and hosts.

### Logon sessions

Security 4624/4634 relationships contain no negative durations. Network logons are generally brief, interactive/RDP sessions are longer, and workstation unlocks reuse an existing interactive LogonId as expected. I did not penalize open sessions at the right edge or close-only sessions at the left edge.

The mix of logon types is role-sensitive: the DC and file server carry many Type 3 and Type 5 logons, while workstations show sparse Type 2/7/10 activity. Failed logons also use plausible status/substatus pairs such as `0xc000006d/0xc000006a` for bad passwords and `0xc000006d/0xc0000072` for disabled accounts.

### Sysmon and eCAR correlation

Cross-source identity work is strong. Process create/terminate records normally align on PID, image, user, and ProcessGUID/object identity. Security and Sysmon provider timestamps for the same process event are usually within milliseconds, while eCAR shows plausible additional observation latency. No known in-window process termination precedes its creation, and no eCAR PID interval overlaps another object using the same PID.

These strengths make the singleton-service defect more significant: three source families consistently preserve the erroneous model rather than the issue being a parser-only artifact.

### Linux endpoint evidence

SSH sequences are detailed and temporally valid. For example, `APP-INT-01` records a connection from `10.10.1.21:53725` at `12:03:07.530081Z`, public-key acceptance at `12:03:09.706254Z`, PAM open at `12:03:09.785451Z`, and logind session creation at `12:03:10.482689Z`. It later closes the PAM session and removes the same logind session.

Cron/anacron, sudo, su, package, journal, resolver, desktop, mail, and hardware-daemon records add credible texture. Nevertheless, the same small message pools recur at high rates across unrelated Linux roles, especially resolver, snap, irqbalance, and rsyslog queue messages.

The `WEB-EXT-01` kernel timestamp relationship is particularly revealing. Subtracting each bracketed monotonic uptime from its RFC 5424 timestamp should yield approximately one boot epoch, allowing only natural timestamping/queue delay. Instead, 915 records yield exactly an integer-second boot epoch plus independent residuals spanning a hard `0–250 ms` cap. That is a concrete within-record timing artifact.

### Behavioral texture

Users and roles are not identical: administrators use SSH/RDP and management tools, desktop users launch mail/browsers/collaboration tools, and servers run role-specific processes. Counts are varied rather than uniform.

Some pools remain visibly compact. Eight scanner identities account for 99.6% of UFW blocks, and each dominant source retains one exact TTL/length pair over the entire window. Together with the capped timestamp residual, this looks more like parameterized scanner templates than raw Internet background traffic.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `hard_contradiction` | Sysmon, Security, eCAR | Multiple Windows hosts and singleton services | Persistent concurrent instances of `Schedule`, `LanmanServer`, `EventLog`, and other single-instance services are not valid Windows lifecycle behavior. |
| `contract_gap` | Sysmon, Security, eCAR | Fleet-wide | Required termination/ownership transitions are absent across all three endpoint views, while later activity proves predecessor PIDs remain active. |
| `distribution_texture` | Linux kernel syslog | 915 records on `WEB-EXT-01` | Embedded uptime-to-wall-clock residuals are constrained to an exact 0–250 ms sampling band. |
| `distribution_texture` | Linux UFW syslog | 911 of 915 blocks | Eight heavily reused scanner identities exhibit fixed packet fingerprints and narrow per-template port pools. |
| `environment_or_collection_plausibility` | Linux syslog | Several hosts | High-volume shared resolver/snap/irqbalance message pools produce similar background texture across different roles. |

## Realism Score by Category

- **Field format accuracy:** 9 — Windows XML, RFC 5424 syslog, Sysmon fields, hashes, SIDs, and eCAR records are well formed.
- **Temporal patterns:** 5 — Many lifecycles are sound, but concurrent singleton services and capped kernel-clock residuals are substantial defects.
- **Cross-source correlation:** 8 — Source identities align very well, although they consistently propagate the erroneous service lifecycle.
- **Behavioral realism:** 4 — User and role differentiation is good, but repeated impossible service concurrency dominates endpoint authenticity.
- **Environmental consistency:** 5 — Host roles are recognizable, while repeated service churn and narrow Linux noise pools weaken production plausibility.

## Recommendations

If this were synthetic, the following would improve it:

- Enforce singleton ownership for Windows services. Before starting a new `svchost.exe -s <service>` instance, terminate the previous service process and emit correlated Sysmon 5, Security 4689, and eCAR `PROCESS/TERMINATE` records.
- Maintain a per-host service state table so repeated baseline tasks use an already-running service process instead of creating a new one.
- Derive the bracketed kernel uptime and RFC 5424 timestamp from one canonical event time and one stable boot epoch. If collection delay is modeled, use an empirically shaped queue-delay distribution rather than independent uniform `0–250 ms` jitter.
- Expand Internet background sources and scanner fingerprints so a six-hour public-host window is not overwhelmingly generated from eight reusable profiles.
- Reduce or profile high-frequency `systemd-resolved`, `snapd`, and `irqbalance` noise by host role and logging configuration, and add a broader long tail of role-specific daemon messages.
