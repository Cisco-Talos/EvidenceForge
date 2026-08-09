# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 76  
**Synthetic-Confidence Score:** 66

## Executive Summary

The endpoint telemetry is unusually strong in process identity, session, and cross-source correlation, and most individual Windows, Sysmon, eCAR, SSH, and PAM sequences are technically credible. The deciding evidence is a collection-boundary fingerprint: after the apparent 12:00–18:00 six-hour window, normal activity stops and only lifecycle termination records continue—through 18:49—across eCAR, Security 4689, and Sysmon Event 5. Repeatedly absent executable-version metadata for well-known third-party binaries and one visibly incomplete unlock lifecycle add narrower synthetic indicators.

## Evidence For Synthetic

- `[contract_gap]` The bounded collection leaks lifecycle closures after its apparent 18:00 cutoff, and every post-cutoff record is a termination. eCAR contains 13 post-18:00 records on six hosts, all `PROCESS/TERMINATE`; corresponding Windows records are exclusively Security 4689 and Sysmon Event 5. Examples include `DC-01` WmiPrvSE termination at `18:34:31`, `FILE-SRV-01` at `18:35:28`, and `MAIL-FIN-01` at `18:49:42–18:49:43`. No comparable post-cutoff process starts, flows, registry activity, or syslog baseline appears. That selective lifecycle tail is unlike a genuine hard-bounded export and looks like deferred state cleanup being rendered beyond the observation window.
- `[schema_or_format]` Sysmon Event 1 repeatedly substitutes `-` for all five PE metadata fields (`FileVersion`, `Description`, `Product`, `Company`, `OriginalFileName`) on known third-party executables despite successfully hashing them. This affects 104 process-create records spanning 22 images, including 27 `GoogleUpdater.exe`, 22 `DropboxUpdate.exe`, 13 `AdobeARMservice.exe`, three Veeam Backup Service executions, and three Exchange `EdgeTransport.exe` executions. For example, `DC-01` at `12:00:33.747` records `Veeam.Backup.Service.exe` with four cryptographic hashes but no version/company/product metadata; `MAIL-FIN-01` does the same for `EdgeTransport.exe` at `12:01:01.442`.
- `[contract_gap]` `WS-AJOHNSON-01` has an incomplete visible unlock lifecycle. Security 4800 at `17:03:55.160` is followed by Type 7 4624 at `17:34:40.761` and 4801 at `17:34:41.187`, but another Type 7 4624 appears at `17:58:31.498` without an intervening 4800 or following 4801 even though that host continues logging until `17:59:43`. eCAR represents only the second unlock (`17:58:32.193`), not the first, creating a concrete source/lifecycle asymmetry.
- `[distribution_texture]` Linux background and administrative vocabulary is broad but noticeably fleet-pooled. Eight hosts produce 88 identical `debian-sa1 1 1` executions, all nine Linux hosts share the same normalized irqbalance “NUMA node … balancing pass complete” family (90 records), and exact interactive commands recur on unrelated systems—for example `/usr/bin/iostat -xz 1 3` on `APP-INT-01`, `DB-PROD-01`, `MAIL-EDGE-01`, and `PROXY-01`. This is only supporting evidence because fleet-standard cron and operator playbooks can explain some repetition.

## Evidence For Real

- Windows process creation correlation is excellent without visible identity contradictions. All 921 Sysmon Event 1 records matched a Security 4688 on the same host by PID and event time; almost all timestamp offsets were within roughly ±26 ms, with one `WS-MCHEN-01` outlier near 124 ms. Command lines, users, parent PIDs, images, and hashes were consistent.
- Process references remain lifecycle-safe. Across 7,094 resolvable eCAR actor/source/target process references, none occurred before a visible creation or after a visible termination for the same UUID.
- The attack-adjacent process trees are technically coherent. On `DC-01`, `PSEXESVC.exe` creates `cmd.exe /c whoami && hostname` at `16:00:06`; later WMI-owned `cmd.exe` processes spawn matching `net.exe`, `sc.exe`, and `schtasks.exe` children between `16:14:55` and `16:20:04`, with the child `ParentProcessGuid` resolving to the visible parent.
- SSH evidence is unusually well formed. All 98 visible `Accepted publickey/password` records across six Linux servers matched an eCAR SSH login by user, source IP, and source port. eCAR login followed the source-native accept/open sequence by approximately 0.18–0.74 seconds, and no PAM session-open preceded its corresponding authentication.
- Windows logon semantics are generally credible: domain controllers and file servers show substantial Type 3 and Type 5 activity, workstations show Type 2/3/5/7/10 mixes, and no matched 4634 precedes its 4624 for the same Logon ID. Short Type 3 durations and longer interactive/RDP sessions are distinguishable.
- Sysmon field shapes are mostly source-native: ProcessGuid values are stable across Event 1/3/5/7/10/11/13/22, UserAssist registry names are ROT13-encoded, DNS records include plausible process/user ownership, and hashes remain stable for repeated binaries and modules.
- Host roles have visible texture. Exchange, Veeam, IIS, browser/Office, developer, SSH-admin, postfix, proxy, database, and workstation activity are not collapsed into one universal process profile.

## Detailed Analysis

### Collection Scope and Source Mix

The collection covers nine Windows hosts and nine Linux hosts. Windows hosts provide Security XML, Sysmon XML, and eCAR; Linux hosts provide eCAR and syslog. The primary activity interval begins around `2024-03-18 12:00 UTC` and normal baseline activity ends near `18:00 UTC`. There is no standalone bash-history file in the reviewed directory, so shell behavior was assessed through Linux eCAR process creates and sudo/SSH/syslog records; its absence was not scored.

Windows source volumes are credible for a focused endpoint collection. `DC-01` has 7,466 Security events and 711 Sysmon events; `FILE-SRV-01` has 1,660 Security and 453 Sysmon; workstations contain approximately 500–727 Security and 383–601 Sysmon events each. Event families include 4624/4625/4634/4648/4672/4688/4689/4800/4801/5156 plus DC Kerberos/account-management records, and Sysmon 1/3/5/7/8/10/11/13/22.

### Process Trees and Lifecycles

The visible process trees are one of the strongest realistic features. PID-to-GUID use is stable, no ProcessGuid is duplicated among Event 1 records, and no termination precedes its matching creation. Most unresolved Sysmon parent GUIDs belong to persistent parents such as `services.exe`, `svchost.exe`, `csrss.exe`, `explorer.exe`, and `SearchIndexer.exe`, which could legitimately predate this bounded window.

Visible child chains resolve properly. On `WS-AJOHNSON-01`, explorer PID 6376 launches `cmd.exe` PID 6392 at `15:19:48`; that command shell visibly parents `whoami.exe` and several `net.exe` executions. On `DC-01`, the PsExec/WMI command sequences preserve parent GUID and PID identity. eCAR actor IDs for flows are also consistent with the process object ID assigned to the same PID; no host showed flow actor IDs diverging from the visible create identity.

The main process-lifecycle defect is at the collection boundary. After 18:00:

- `DC-01`: three eCAR terminations, three Security 4689s, and three Sysmon 5s, ending `18:34:31`.
- `FILE-SRV-01`: one matched WmiPrvSE termination at `18:35:28`.
- `MAIL-FIN-01`: two matched terminations, ending `18:49:43`.
- `WS-DRAMIREZ-01`: one matched termination at `18:16:57`.
- `WS-MCHEN-01`: four OpenSSH client terminations through `18:15:51`.
- `WS-LNGUYEN-01`: two eCAR SSH-client terminations through `18:09:45`.

The cross-source agreement of these records is good, but their exclusive appearance as lifecycle closures beyond a bounded cutoff is itself the defect.

### Sysmon and Security Correlation

Security 4688 and Sysmon Event 1 correlate exceptionally well: 921 matched process creates across nine Windows hosts, with only one Security-only 4688 each on `WS-AJOHNSON-01` and `WS-EBROOKS-01`. The timestamp relationship is source-plausible and not mechanically identical. Security 4689, Sysmon Event 5, and eCAR termination identities also agree.

Hash behavior is strong for binaries with populated metadata. Repeated Microsoft, Firefox, Office, and Defender images retain stable SHA1/MD5/SHA256/IMPHASH values across hosts. Module-load records contain plausible signing fields, versions, and companies.

The metadata omission pattern is nevertheless too categorical. Known third-party executables repeatedly have all five version-resource fields set to `-`, even though the same events contain four successful file hashes. Occasional missing PE resources would be realistic; 104 records concentrated in a reusable third-party executable pool looks like incomplete source-data enrichment.

### Logon and Session Lifecycles

No matched Windows logout occurs before its login. High-volume Type 3 sessions on `DC-01` and `FILE-SRV-01` commonly close within seconds to a minute, while interactive and RDP sessions persist much longer. Type 5 service sessions generally remain open through the bounded view, which is expected.

The lock/unlock modeling is mostly credible on `WS-PPATEL-01` and `WS-SMARTINEZ-01`: 4800 lock, Type 7 4624, then 4801 unlock appear in order with the same user, Logon ID, and Session ID. The final `WS-AJOHNSON-01` unlock is the exception described above. It is a one-off rather than a dataset-wide failure, but it is visible inside the window and cannot be dismissed as a missing pre-window initiator.

### Linux, SSH, and Shell Activity

SSH source-native sequences are strong. For example, `DB-PROD-01` at `12:00:17.868` accepts an ED25519 public key for `marcus.chen` from `10.10.1.31:61363`, opens PAM at `12:00:17.920`, and records the matching eCAR login shortly afterward with the same tuple. This contract holds for all 98 visible accepts. Pre-window sessions that only close inside the slice occur on several servers and were not treated as defects.

Sudo sequences preserve one process ID across command, PAM open, and PAM close, with plausible subsecond-to-several-second command durations. Server roles also affect syslog vocabulary: postfix/dovecot activity appears on mail hosts, multipathd on the database host, proxy-oriented volume on `PROXY-01`, and desktop services on Linux workstations.

The weaker concern is repeated fleet vocabulary. Identical cron jobs are expected, but the combination of exact recurring operator commands, common debug-like `systemd-resolved` state messages, and irqbalance message families across nearly every Linux host gives the baseline a curated-pool texture. This remains secondary to the boundary and metadata findings.

### eCAR/EDR Correlation

eCAR preserves stable process UUID ownership for flows and dependent process/file/registry/module operations. No resolvable reference falls outside the corresponding process lifetime, and Linux SSH login objects preserve user, address, port, session ID, and logout identity. Windows eCAR process counts closely track Security/Sysmon counts while retaining realistic source-specific omissions.

The eCAR issue is not general correlation quality; it is observation-boundary handling. eCAR continues emitting only process-termination objects after normal collection activity has stopped, and those tails are then mirrored in Security/Sysmon. That pattern is coherent internally but implausible for the stated bounded export.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `contract_gap` | eCAR, Windows Security, Sysmon | Repeated across six hosts; 13 eCAR and matched Windows post-cutoff terminations | Highest impact: selective lifecycle-only leakage through `18:49` contradicts the apparent six-hour observation boundary. |
| `schema_or_format` | Sysmon Event 1 | 104 records, 22 executable images | Medium-high impact: known third-party binaries are hashed successfully but repeatedly lack all version/company/product metadata. |
| `contract_gap` | Windows Security and eCAR session telemetry | One workstation unlock lifecycle | Medium-low impact: a Type 7 logon lacks an intervening lock and following 4801; eCAR coverage disagrees between the two visible unlocks. |
| `distribution_texture` | Linux syslog and eCAR process activity | Fleet-wide but explainable in part | Low-medium impact: repeated cron, irqbalance, resolver, and operator-command vocabulary suggests a shared event pool. |

## Realism Score by Category

- **Field format accuracy:** 7 — Core Security, Sysmon, syslog, and eCAR shapes are good, but systematic third-party PE metadata gaps remain visible.
- **Temporal patterns:** 6 — Within-window ordering is strong; selective termination-only events continuing nearly 50 minutes beyond the bounded window are a substantial defect.
- **Cross-source correlation:** 9 — Process, PID/GUID, SSH tuple, session, hash, and termination identities correlate with very few concrete contradictions.
- **Behavioral realism:** 8 — Process trees, logon types, command chains, user applications, and server/workstation roles are generally credible.
- **Environmental consistency:** 7 — Host-role differentiation is convincing, but fleet-pooled Linux message texture and the observation-boundary asymmetry reduce realism.

## Recommendations

- If this were synthetic, enforce the collection cutoff after lifecycle planning. Do not render Security 4689, Sysmon Event 5, or eCAR `PROCESS/TERMINATE` records beyond the configured end time; retain the process as open at window end instead. Verify that all source families share the same cutoff contract.
- Populate Sysmon Event 1 version-resource fields for common third-party executables from source-appropriate metadata. At minimum, remove the repeated all-`-` pattern for Google Updater, Dropbox Update, Adobe ARM, Veeam Backup Service, Exchange EdgeTransport, osquery, Wazuh, HP, Dell, Cisco, and OneDrive binaries.
- Make lock/unlock bundles atomic within Security telemetry: visible 4800 should precede Type 7 4624, which should be followed by 4801, with eCAR observation applied coherently to the same lifecycle group. Recheck the `WS-AJOHNSON-01` `17:58:31` sequence.
- Broaden Linux background and administrator-command texture by varying host eligibility, package/service versions, logging verbosity, and operator command parameters. Preserve legitimate fleet-standard cron behavior while reducing exact cross-host reuse of discretionary sudo commands and debug-like resolver/irqbalance message families.
