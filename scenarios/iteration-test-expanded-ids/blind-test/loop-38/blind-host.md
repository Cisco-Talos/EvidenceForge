# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 84  
**Synthetic-Confidence Score:** 72

## Executive Summary

The endpoint data is unusually strong at schema fidelity, lifecycle handling, and cross-source identity correlation. However, two dataset-wide fingerprints—the bounded, triangular Security/Sysmon process-create timestamp deltas and host-specific Sysmon `CallTrace` offsets—look generated rather than source-native; homogeneous interactive sudo behavior and several questionable process-parent relationships reinforce a synthetic verdict.

## Evidence For Synthetic

- `[distribution_texture]` Across 921 matched Windows process creations, 919 Security 4688/Sysmon Event 1 pairs fall within ±20 ms. Their deltas form a near-triangular distribution centered close to zero: median +1.619 ms, 25th percentile -4.445 ms, 75th percentile +6.814 ms, and standard deviation 9.52 ms. This is consistent with two independently jittered renderings of one canonical timestamp, not organically different provider timing across nine hosts.
- `[schema_or_format]` All 66 distinct Sysmon Event 10 `CallTrace` strings are confined to a single host. The same process-access tuple receives a different module-relative stack for each machine. For `services.exe -> MsMpEng.exe`, `GrantedAccess=0x1000`, examples include:
  - `WS-DRAMIREZ-01`: `ntdll.dll+9E647|KERNELBASE.dll+2DE17|sechost.dll+1428C`
  - `WS-EBROOKS-01`: `ntdll.dll+9C23E|KERNELBASE.dll+2C96C|sechost.dll+1459B`
  - `WS-SMARTINEZ-01`: `ntdll.dll+9E1A4|KERNELBASE.dll+2DB1E|sechost.dll+1482E`
  
  Those three systems otherwise expose the same Windows 10 cohort: `svchost.exe` version `10.0.19041.1` with SHA256 `03812016...D4332C`, and `TiWorker.exe` version `10.0.19041.3636` with SHA256 `EEEB8F7D...AF53AD`. Module-relative offsets should follow the actual DLL build and call path, not independently vary by hostname.
- `[distribution_texture]` eCAR process-create timing reinforces the renderer-like source timing. Of 913 matched eCAR/Sysmon creates, the median eCAR offset is +631.6 ms, 908 are positive, and the 99th percentile is +1297.6 ms. Most hosts show a broadly bounded delay profile rather than a naturally skewed or heavy-tailed endpoint collection distribution.
- `[environment_or_collection_plausibility]` Generic accounts perform interactive sudo activity across nearly every Linux role, including end-user workstations and a laptop. `ops` appears in sudo command records on eight hosts, `backup`, `ubuntu`, and `svc_app` on six each, and `deploy` on five. Examples include `svc_app` running sudo from `TTY=pts/3` on `WS-LNGUYEN-01` at `12:00:00.875841Z`, `backup` on `WS-OHADDAD-01` at `14:19:25.243475Z`, and `svc_app` on `LT-MRIVERA-02` at `14:27:40.469447Z`. The broad account placement and shared administrative command pool are more homogeneous than expected for mixed workstation, laptop, mail, database, proxy, and application roles.
- `[contract_gap]` `WS-AJOHNSON-01` records Firefox directly spawning the Windows OpenSSH client five times. Examples are `firefox.exe -> ssh.exe aisha.johnson@MAIL-CLIN-01...` at `12:04:21.7078290Z` and `firefox.exe -> ssh.exe aisha.johnson@DB-PROD-01...` at `15:08:34.8969001Z`. A configured `ssh://` protocol handler could explain an isolated occurrence, but five launches to several administrative targets make the parent selection look templated.
- `[distribution_texture]` DHCP syslog is highly repetitive across Linux endpoints. `WS-LNGUYEN-01` emits 11 REQUEST/ACK/bound triplets with the identical text `renewal in 1938 seconds`; `LT-MRIVERA-02` repeats `1927 seconds` ten times; `WS-OHADDAD-01` repeats `1785 seconds` thirteen times. Stable T1 values are possible, so this is supporting rather than decisive evidence, but the six-hour recurrence texture is unusually clean.

## Evidence For Real

- Security 4688 and Sysmon Event 1 correlate exceptionally well on native identifiers: 921 matched PID/image pairs, no parent-PID mismatches, and only two Security creates without a corresponding Sysmon create. File metadata, command lines, users, logon IDs, hashes, and parent paths are internally coherent.
- The DC Security-log clearing sequence is source-native and particularly convincing:
  - `17:42:28.1680121Z`, record `28261968`: `WmiPrvSE.exe -> cmd.exe /c wevtutil cl Security`
  - `17:42:28.5455871Z`, record `28261969`: `cmd.exe -> wevtutil.exe`
  - `17:42:29.6787301Z`, Event 1102 resets the channel to record ID `1`
  - `17:42:32.6991620Z`, record `5`: termination of the same `wevtutil.exe` PID `0x180c`
- Event record IDs are monotonically increasing on every Windows channel except for the correctly explained DC Security reset after Event 1102. There are no duplicate record IDs.
- No visible eCAR process actor is used before its recorded creation or after its recorded termination. The same check found no Sysmon GUID-dependent event occurring before a visible Event 1 or after its Event 5.
- Logon lifecycles contain plausible duration spread. Matched network logons range from a few seconds to long-lived sessions; for example, DC type-3 logons have a median duration of 17.65 seconds but extend to 7560.555 seconds. No visible 4634 precedes the corresponding visible 4624.
- Linux SSH evidence has credible native sequencing. For example, `DB-PROD-01` logs an accepted public key for `marcus.chen` at `12:00:17.868039Z`, PAM session opening at `12:00:17.920280Z`, and session close at `12:27:45.448713Z`. User-specific key fingerprints remain stable across repeated sessions.
- Sysmon process metadata and hashes are stable within executable/build cohorts. Common third-party programs such as Outlook, Chrome, Firefox, Google Updater, and OpenSSH keep consistent hashes across hosts, while core Windows binaries divide into plausible OS-version groups.
- User behavior is meaningfully differentiated: Lina’s workstation history emphasizes Git, pytest, Docker, and SSH; Omar uses database/data-analysis commands; Windows users differ in office, browser, SSH, RDP, collaboration, and update activity.

## Detailed Analysis

### Windows Security and Sysmon

The Windows XML is structurally strong. Provider names, channel names, event versions, field names, numeric/hex PID conventions, integrity levels, token elevation values, and native timestamp precision are convincing. Security 4688 uses hex PIDs while Sysmon uses decimal PIDs, and the conversion matches throughout. Sysmon Event 1 also carries plausible version-resource metadata rather than leaving all fields blank: only 104 of 921 creates have all five metadata fields set to `-`.

The process-create correlation itself is realistic and useful. The suspicious part is specifically its timing distribution, not its completeness. Nearly every Security/Sysmon pair is generated inside the same narrow ±20 ms envelope, with a triangular concentration around zero replicated across all hosts. Provider timing in production can be close, but this aggregate shape is too bounded and symmetric.

Process termination timing is much more varied: 628 matched Security 4689/Sysmon Event 5 pairs range from -641.4 ms to +1859.9 ms. That contrast makes the process-create timing fingerprint more conspicuous.

### Sysmon Process Access

Sysmon Event 10 records have plausible process names, access masks, GUIDs, users, and call-stack module syntax. Within a host, recurring code paths correctly reuse a stack.

Across hosts, however, every `CallTrace` vocabulary is host-exclusive. The traces appear to have been diversified by assigning hostname-scoped module offsets. ASLR changes absolute virtual addresses, but these are module-relative offsets; identical module builds executing the same path should reproduce the same offsets. The common Windows 10 servicing/build evidence on `WS-DRAMIREZ-01`, `WS-EBROOKS-01`, and `WS-SMARTINEZ-01` makes their independently shifted traces particularly difficult to explain as production artifacts.

### Process Trees and eCAR

Most parent-child relationships are strong: `services.exe` launches services, `svchost.exe` launches task hosts, SearchIndexer launches filter/protocol hosts, browser children are sensible, and `csrss.exe -> conhost.exe` relationships are present. eCAR object IDs and actor IDs show no visible lifecycle inversion.

The repeated Firefox-to-OpenSSH relationship is the principal process-tree weakness. A protocol-handler explanation is technically possible, so I did not treat it as a hard contradiction. Its recurrence across multiple administrative destinations nevertheless makes it materially suspicious.

eCAR timing is coherent but stylized. Process creates nearly always follow Sysmon by a positive, bounded delay, with host-specific ceilings. A real collection pipeline may add latency, but production latency normally has queueing spikes, batching, and heavier tails rather than a broad, tidy bounded distribution.

### Windows Sessions and System Lifecycle

Security logs contain types 2, 3, 5, 7, and 10 in role-appropriate proportions. Type-7 records reuse the original interactive logon ID, which is valid unlock behavior. Service sessions often remain open through the end of the slice, and I did not penalize those or other unmatched starts/ends because the six-hour window is bounded.

The DC log-clear sequence demonstrates particularly good process/channel lifecycle modeling. Background processes, Windows servicing, Defender activity, Group Policy, search, software update, and scheduled work are present without obvious visible lifecycle contradictions.

### Linux Syslog and Bash History

RFC5424 framing, PAM sequences, SSH authentication wording, key types, usernames, UIDs, PIDs, and `systemd-logind` companions are generally convincing. Bash histories use epoch markers and show substantially different command vocabularies by user and host.

The weak point is environmental placement. Interactive `pts` sudo activity by `ops`, `backup`, `deploy`, `svc_app`, `ubuntu`, and `admin` is spread across production servers and personal endpoints with a common pool of status, log, disk, timer, network, and package commands. Central identity can explain consistent UIDs, but it does not fully explain why service-oriented identities perform similar interactive maintenance on laptops and workstations.

### Visible Ordering and Window Boundaries

I found no visible dependent process, session, or actor event whose matching visible initiator occurs later. Many referenced eCAR or Sysmon processes lack an Event 1/CREATE inside the slice, but those are compatible with pre-window processes and were not scored as synthetic. Likewise, high cross-source correlation was treated as positive or neutral except where the timing distribution itself showed a concrete repeated fingerprint.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---:|---|
| `distribution_texture` | Security 4688 / Sysmon 1 | Dataset-wide, 921 pairs | Very high: 919 pairs inside a narrow triangular ±20 ms envelope |
| `schema_or_format` | Sysmon Event 10 | Dataset-wide, 583 records/66 traces | High: module-relative call stacks vary by host rather than module build and path |
| `environment_or_collection_plausibility` | Linux syslog/sudo | Repeated across 8 Linux hosts | Medium: generic interactive admin/service identities are distributed too uniformly |
| `contract_gap` | Security/Sysmon process trees | Five records on one workstation | Medium-low: Firefox repeatedly launches `ssh.exe` to administrative targets |
| `distribution_texture` | Linux DHCP syslog | Repeated on three endpoints | Low: lease-renewal triplets and announced intervals repeat with very little texture |
| `distribution_texture` | eCAR process timing | Dataset-wide, 913 matches | Medium supporting evidence: highly positive, bounded source delay profiles |

## Realism Score by Category

- **Field format accuracy:** 7/10 — Windows XML, Sysmon, eCAR, syslog, and bash-history structures are strong, but Event 10 call-stack offsets undermine source-native fidelity.
- **Temporal patterns:** 5/10 — Lifecycle ordering is sound, while the process-create delta distribution and bounded eCAR latency look explicitly modeled.
- **Cross-source correlation:** 9/10 — PID, image, parent, user, session, hash, and lifecycle relationships correlate with very few omissions or contradictions.
- **Behavioral realism:** 6/10 — User histories and roles differ credibly, but Firefox-spawned SSH and generic sudo behavior are conspicuous.
- **Environmental consistency:** 6/10 — Host roles, OS cohorts, and services mostly fit, while Linux account placement and host-specific call-stack vocabularies do not.

## Recommendations

If this were synthetic, the following changes would improve it:

- Generate Sysmon `CallTrace` values from actual module-build cohorts and operation-specific call paths. Systems with identical DLL hashes/builds should share module-relative offsets; hostname should not independently perturb them.
- Replace independent symmetric timestamp jitter for Security 4688 and Sysmon Event 1 with provider-specific timing models that have stable causal skew, host load effects, occasional queueing, and natural tails. Preserve close correlation without a hard ±20 ms texture.
- Model eCAR timestamp latency with source/host load, batching, and long-tail delay rather than broad bounded intervals.
- Scope sudo-capable identities to plausible host roles. Keep service accounts non-interactive unless a concrete administrative session explains the `TTY`, and derive sudo users, working directories, and commands from that session’s owner and purpose.
- Parent Windows `ssh.exe` to a terminal, `cmd.exe`, PowerShell, Windows Terminal, or Explorer in ordinary use. Use Firefox as the parent only when explicitly modeling an `ssh://` handler and include enough source-native context to make that path exceptional rather than routine.
- Add modest lease-option and renewal-scheduling variation to DHCP clients where the server policy permits it, while preserving valid REQUEST/ACK/bound ordering.
