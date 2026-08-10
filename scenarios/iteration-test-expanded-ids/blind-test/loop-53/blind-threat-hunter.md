# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive  
**Verdict Confidence:** 76  
**Synthetic-Confidence Score:** 46

## Executive Summary

The six-hour corpus is operationally convincing: approximately 82,800 logical records across endpoint, Windows, Linux, network, proxy, web, firewall, and IDS sources support meaningful pivots and coherent lifecycle reconstruction. I found one repeated cross-source timing defect and one conspicuous administrative-activity texture, but neither is sufficient to overcome otherwise strong causal and environmental realism.

## Evidence For Synthetic

- `[contract_gap]` Seven visible Type-10 RDP sessions across three hosts show dependent endpoint processes before the same eCAR `USER_SESSION LOGIN`. Examples:
  - `DC-01.../ecar.json` lines 202-204: `userinit.exe` at `12:13:26.043`, `explorer.exe` at `12:13:26.245`, then logon ID `0x538eec1` login at `12:13:27.708`—1.665 and 1.463 seconds late.
  - Lines 2902-2904 repeat this for `0x54d91a0`; lines 4752-4754 for `0x55ad5a3`; lines 5423-5425 for `0x55df26f`.
  - `MAIL-FIN-01.../ecar.json` lines 781-782 put `userinit.exe` 0.322 seconds before logon `0xd8fb191`.
  - `WS-AJOHNSON-01.../ecar.json` has two further cases, including a dependent Outlook process 0.080 seconds before the login.
  Native Windows Security telemetry orders the same sessions correctly—for example, DC logon `0x538eec1` has Event 4624 at `12:13:24.457`, then Event 4688 `userinit.exe` at `12:13:25.561` and `explorer.exe` at `12:13:26.047`. The disagreement looks like an endpoint observation-timing contract defect rather than real source behavior.
- `[distribution_texture]` The corpus contains 97 visible `ssh`/`ssh.exe` process launches represented by only 30 exact command variants. `aisha.johnson → WEB-EXT-01` repeats the identical command 11 times over 334 minutes with a 21.9-minute median gap; `marcus.chen → WEB-EXT-01` repeats 11 times over 279 minutes with a 25.1-minute median gap; Aisha also repeats the same MAIL-EDGE command 10 times and DB-PROD command 8 times. Exact examples include `WS-AJOHNSON.../ecar.json` lines 1, 96, 287, 341, and 394. For such a small environment, this many fresh interactive SSH clients from multiple users resembles a recurring activity template more than organically persistent admin sessions.
- `[environment_or_collection_plausibility]` A custom binary appears as a service target and later executes without any visible arrival or creation record despite active eCAR file telemetry and Sysmon Event 11 coverage. `DC-01.../ecar.json` lines 4172/4179 create `DeviceSyncSvc`, line 4188 creates the service pointing to `C:\Windows\System32\DeviceSyncSvc.exe`, and line 4402 executes it about 9.6 minutes later; searches across DC eCAR, Security, and Sysmon find no file-create/write event for the binary. A pre-existing binary is possible, so this is not a hard contradiction.
- `[weak_signal]` Several source families look deliberately curated: Windows Security is dominated by 5156, endpoint telemetry maps heavily to canonical flow/process/session objects, and source coverage is unusually broad. Per the study rules, completeness itself was not scored; it only slightly reinforces the concrete timing defect above.

## Evidence For Real

- The intrusion is reconstructable through source-native pivots rather than narrative inference. `WEB-EXT-01/web_access.log` line 507 records a successful upload from `185.70.41.45` at `13:19:56`; Zeek DMZ `conn.json` line 1461 sees the inbound TLS connection at `13:19:56.318`; eCAR line 957 records Apache spawning the base64-decoding reverse-shell command at `13:19:58.131`; eCAR line 959 and Zeek line 1462 show the resulting outbound `10.10.3.10:57845 → 45.33.32.30:8443` connection.
- Later pivots retain ownership and artifacts. `DB-PROD-01.../ecar.json` lines 568-569 bind `mysqldump` to creation of `/tmp/rpt_0318.sql`; its later SCP has matching receiver-side file creation at `APP-INT-01.../ecar.json` line 651. File-server collection is similarly visible at `FILE-SRV-01.../ecar.json` lines 1667-1668, followed by SMB retrieval and local creation/read at `WS-AJOHNSON.../ecar.json` lines 1295 and 1333-1334.
- Domain persistence and cleanup have credible host evidence. `DC-01.../ecar.json` lines 4060/4067 create `svc_mhsync`, lines 4172-4196 establish service/task persistence, lines 6126/6134 clear Security logging, and lines 6294/6301 delete the account. Related Security events include account/group/service/task/audit-clear records rather than endpoint-only claims.
- Lifecycle probes over all 25,104 eCAR records found zero visible process termination-before-create cases, zero dependent events after the matching process termination, zero overlapping PID reuse, and zero session logout-before-login cases.
- The corpus has plausible volume variation rather than exact hourly quotas: eCAR hourly counts are `4432, 4093, 3926, 3854, 4597, 4202`; Zeek connection counts are `2168, 1796, 1822, 1750, 2127, 2000`.
- Noise is operationally useful and heterogeneous: web scanning, failed SSH and console authentication, stale/unknown accounts, routine browser/Office/service activity, scheduled Linux jobs, proxy denies, BitTorrent/curl policy alerts, and unrelated outbound traffic all compete with the main pivots.

## Detailed Analysis

### Observation Window and Source Mix

The visible window is approximately `2024-03-18 12:00:00–17:59:57 UTC`. Logical volumes are about:

- 25,104 eCAR records
- 20,323 Zeek records, including 11,663 connections
- 14,396 Windows Security events
- 4,107 Sysmon events
- 4,087 Linux syslog lines
- 11,821 Cisco ASA lines
- 1,918 proxy records
- 908 web-access records
- 165 Snort alerts

The distribution is dense but believable for a small, heavily instrumented environment. DC and file-server authentication/flow volumes dominate as expected; proxy and web systems dominate DMZ traffic; workstations carry lighter endpoint streams.

### Huntability and Pivot Quality

The strongest feature is that a hunter can pivot by tuple, user, process, logon ID, file path, and time without relying on privileged context. The initial web access, Apache child, reverse-shell flow, privilege expansion, Windows-domain persistence, staged archives, SMB/SCP movement, outbound upload behavior, and cleanup each leave usable evidence. Cross-source duplicates typically add a distinct observation rather than merely restating a row.

### Lifecycle and Temporal Coherence

Process and session lifecycle state is unusually sound. The one meaningful exception is eCAR RDP ordering: native Security Event 4624 timestamps correctly precede shell creation, while the eCAR session observation is delayed past `userinit.exe`/`explorer.exe`. Because this occurs seven times across three targets, it is systematic and score-relevant.

### Behavioral and Environmental Texture

The hourly volumes vary and the corpus includes failures and unrelated alerts. However, the SSH baseline is too dominated by repeated new client launches to feel fully organic. A few long-lived terminals with clustered commands, multiplexed sessions, dormant gaps, and host-specific maintenance habits would be more natural than 97 separate launches cycling repeatedly among a small server set.

### Strengths

- Strong end-to-end pivotability across host and network sources.
- Correct source/destination roles through most lateral-movement and exfiltration paths.
- Good process, PID, object-ID, session, and file ownership consistency.
- Credible host-role concentration and source-family mix.
- Useful background failures and red herrings.
- No broad fixed-rate hourly fingerprint.

## Synthetic Indicator Summary

| Priority | Category | Affected source family | Scope | Effect on score |
|---|---|---|---|---|
| P1 | `contract_gap` | eCAR RDP session/process timing | 7 sessions, 3 hosts | Highest-impact concrete defect; visible dependent processes precede session login |
| P2 | `distribution_texture` | Endpoint/SSH activity | 97 launches, repeated exact actor-target commands | Repetitive small-environment admin texture |
| P2 | `environment_or_collection_plausibility` | DC eCAR/Sysmon file/service evidence | One persistence chain | Custom service binary executes without a visible file-arrival artifact |
| P4 | `weak_signal` | Overall collection | Dataset-wide | Curated appearance, not independently scoreable |

## Realism Score by Category

- **Field format accuracy:** 8 — Fields are usable and source-native enough for hunting, with no obvious generator identity leak.
- **Temporal patterns:** 7 — Broad timing is varied and causal, but eCAR RDP ordering is repeatedly inverted.
- **Cross-source correlation:** 8 — High-quality tuples, principals, files, and logon pivots; the RDP observation disagreement is the main exception.
- **Behavioral realism:** 7 — Intrusion and background behaviors are plausible, while repeated SSH client launches reduce organic texture.
- **Environmental consistency:** 8 — Host roles, traffic concentration, and collection mix generally agree; the unexplained service-binary arrival is a modest gap.

## Recommendations

1. **P1 — Correct RDP endpoint observation ordering.** Ensure the eCAR `USER_SESSION LOGIN` timestamp for Type-10 sessions precedes all same-logon-ID `userinit.exe`, `explorer.exe`, and user-process observations. Preserve the already-correct native Security 4624→4688 relationship.
2. **P2 — Diversify administrative SSH behavior.** Reduce repeated exact actor-target launches; favor persistent shells, clustered work, session reuse, host-specific command habits, unequal administrator activity, longer inactive spans, and more varied outcomes.
3. **P2 — Complete custom service-binary provenance.** If `DeviceSyncSvc.exe` is newly introduced during the visible activity, emit the actual file transfer/create/write before service installation and execution. If it is intentionally pre-existing, provide a plausible earlier presence indicator rather than making provenance ambiguous.
4. **P3 — Preserve the current strengths.** Retain the heterogeneous noise, variable hourly volumes, stateful process/session lifecycles, and multi-source file/tuple correlations; these are the main reasons the corpus remains inconclusive rather than likely synthetic.
