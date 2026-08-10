# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 94  
**Synthetic-Confidence Score:** 87

## Executive Summary

The endpoint telemetry is technically sophisticated: Windows process lifecycles, Security/Sysmon/eCAR correlation, and SSH/PAM sequencing are unusually strong and show no obvious visible causality failures. However, several dataset-wide statistical fingerprints—especially Linux session identifiers advancing as a near-perfect function of wall-clock time and identical IRQ/device mappings across unrelated machines—are difficult to reconcile with independently lived-in production hosts.

## Evidence For Synthetic

- `[distribution_texture]` Linux `systemd-logind` session IDs advance at nearly fixed wall-clock rates instead of according to visible session creation. On `MAIL-EDGE-01`, 30 visible new sessions progress from ID `272376` at `12:04:44.916291Z` to `275461` at `17:47:33.822335Z`: 3,085 counter increments in 20,569 seconds, almost exactly 0.15 IDs/second. The same rate appears on `APP-INT-01`, `LT-MRIVERA-02`, `WEB-EXT-01`, and `WS-OHADDAD-01`; another group tracks almost exactly 0.1333 IDs/second. Nine Linux hosts show 2,313–3,118 ID increments while exposing only 13–62 new sessions each. This clock-derived counter behavior is a strong generator fingerprint and implies a self-contradictory collection profile if the intervening thousands of sessions are assumed real.
- `[environment_or_collection_plausibility]` The `irqbalance` telemetry reuses the same exact IRQ-to-device topology across unrelated hosts: IRQ 16=`ahci`, 24=`ens160`, 32=`nvme0q1`, 45=`virtio0-input`, 64=`mlx5_comp0`, 86=`mlx5_comp1`, 122=`nvme0q2`, 137=`ens192`, 154=`virtio1-input`, and 181=`mlx5_comp2`. This mapping recurs on database, web, proxy, application, and mail servers; laptop/workstation hosts also inherit subsets containing VMware-style interfaces, virtio input devices, NVMe queues, and Mellanox completion queues. Exact IRQ allocation normally depends on each kernel, platform, PCI topology, and boot.
- `[distribution_texture]` Sysmon Event 11 has a conspicuous dataset-wide filename template: 103 of 111 file-create records use exactly `C:\Windows\Temp\<five decimal digits>.tmp`. Examples include `lsass.exe` creating `54866.tmp` on `WS-AJOHNSON-01` at `12:21:02.8239638Z`, `dns.exe` creating `31800.tmp` on `DC-01` at `13:21:44.2108859Z`, and `wininit.exe` creating `73063.tmp` on `WS-DRAMIREZ-01` at `13:32:26.6712655Z`. Even allowing for a Sysmon filter focused on temporary files, the exact five-digit decimal grammar across 18 unrelated process images is unusually pool-like.
- `[contract_gap]` `fwupd` state lacks temporal coherence on `LT-MRIVERA-02`: the same PID 22409 reports metadata as 14 days old at `15:07:11.130257Z`, 2 days old at `15:09:20.460812Z`, then 14 days old again at `15:14:28.351274Z`. Multiple configured remotes could explain differing ages, but the messages provide no remote identity and the age oscillation repeats the appearance of independently sampled templates rather than stateful daemon output.
- `[distribution_texture]` High-volume Linux background chatter repeatedly draws from the same small message/device pools across hosts. `irqbalance`, `snapd`, `fwupd`, `thermald`, and `cups-browsed` messages are individually plausible, but their cross-host vocabulary, device identities, and frequent randomized occurrence are more consistent with generated ambient noise than host-specific daemon state.

## Evidence For Real

- Windows process trees are generally source-native and coherent: `services.exe` launches service binaries, `csrss.exe` launches `conhost.exe`, `SearchIndexer.exe` launches search filter/protocol hosts, and user software launches from `explorer.exe` or an appropriate shell.
- Security 4688, Sysmon Event 1, and eCAR PROCESS/CREATE records correlate closely without impossible visible ordering. On `WS-AJOHNSON-01`, Dropbox updater PID 5216 appears in Security at `12:07:07.6145333Z`, Sysmon at `12:07:07.6195902Z`, and eCAR at `12:07:08.172Z`; the eCAR object ID is preserved through termination at `12:07:12.591Z`.
- Sysmon process GUIDs retain consistent PID and image identity across dependent Event 3/5/7/10/11/13/22 records. I found no dependent record visibly preceding its same-GUID Event 1 or following its same-GUID Event 5.
- eCAR lifecycle ownership is strong. Across all endpoint files I found no actor-referenced event after that actor’s visible process termination, no termination preceding the matching visible creation, and no visible login/logout reversal.
- SSH evidence has convincing source-native ordering. On `APP-INT-01`, Lina Nguyen’s session from `10.10.1.21:53725` progresses from connection at `12:03:07.530081Z`, public-key acceptance at `12:03:09.706254Z`, PAM open at `12:03:09.785451Z`, eCAR login at `12:03:10.110Z`, and logind session 376095 at `12:03:10.482689Z`; PAM and eCAR both close the session at `12:32:28.247Z`, followed by logind removal.
- User activity is differentiated by apparent role: Lina Nguyen’s workstation history contains development and build tools; Omar Haddad uses pandas, CSV, and SQL commands; Aisha Johnson and Marcus Chen conduct broader server administration. This is more credible than one command pool shared indiscriminately.
- Windows binary metadata varies appropriately by operating-system generation. Common binaries have distinct file versions and hashes for Windows builds 17763, 19041, 20348, and 22621.

## Detailed Analysis

### Windows Process and Lifecycle Evidence

The Windows sources cover realistic process, network, registry, file, module, and process-access activity. Parent-child relationships largely pass forensic scrutiny, including `services.exe → svchost.exe`, `svchost.exe → WmiPrvSE.exe`, `csrss.exe → conhost.exe`, and `explorer.exe → mstsc.exe` or office/browser applications.

Cross-source lifecycle checks were particularly strong. Security and Sysmon process-create records agree on PID, image, command line, principal, logon ID, and parent. Corresponding eCAR records preserve parent actor identities and process object IDs through termination. Bounded-window terminations without visible creates were present, but I did not count them as synthetic evidence; none had a later same-ID visible creation that would create impossible ordering.

Sysmon metadata is also richer than a superficial facsimile. Microsoft binaries carry plausible company/product/original-name values, hashes remain stable for a given binary version, and operating-system-specific versions receive different hashes. Process GUIDs remain consistent across follow-on events.

The main Windows weakness is distributional rather than causal: Event 11 is overwhelmingly populated by arbitrary core processes creating decimal five-digit `.tmp` files. A targeted Sysmon configuration could explain the directory concentration, but not the extraordinarily consistent filename grammar and broad process assignment.

### Logon Sessions

Windows Security logs contain a plausible mixture of Types 2, 3, 5, 7, and 10 according to host role. Visible same-ID 4624/4634 pairs all have non-negative durations. Long-lived interactive and RDP sessions coexist with short network sessions, and workstation unlock events reuse the owning interactive logon ID appropriately.

Linux SSH session sequencing is similarly convincing at the individual-event level. Connection, authentication, PAM, logind, and eCAR records use consistent users, addresses, ports, PIDs, session IDs, and close ordering.

The Linux session-number allocation is nevertheless a decisive statistical tell. New session IDs rise almost linearly with elapsed seconds across nine independent hosts, at one of two rates near 0.15 or 0.1333 IDs/second, regardless of whether the host exposes 13 or 62 new sessions. That relationship is not consistent with a counter allocated by actual PAM/logind session creation.

### Linux Background and Hardware Evidence

The Linux source includes useful lived-in texture—cron, package management, printing, thermal management, DHCP, sudo, SSH, mail services, firewall denials, and system logging. Individual lines mostly resemble RFC 5424 syslog and use stable host-local daemon PIDs.

The environment-level state is substantially weaker. Nearly all Linux systems expose the same IRQ/device map, including device combinations that are especially unlikely on nominal laptop/workstation systems. This is not merely shared message vocabulary; the same IRQ numbers are assigned to the same interfaces, storage queues, input devices, and Mellanox completion queues across machines with different roles.

`fwupd` metadata-age changes and frequent templated `irqbalance` state messages add to the impression that daemon records are independently sampled rather than emitted from persistent per-host state.

### eCAR/EDR Correlation

eCAR PROCESS, FLOW, USER_SESSION, FILE, REGISTRY, MODULE, and PROCESS/OPEN records are internally well structured. Actor object IDs point to earlier visible process creates when those creates occur within the window. Visible process-dependent activity stays within the source process lifetime.

I did not treat the strong correlation as synthetic evidence. The eCAR data is one of the most convincing parts of the collection and materially lowers the synthetic-confidence score from what the Linux fingerprints alone would warrant.

### Behavioral and Environmental Realism

User behavior and host roles are distinguishable, and the dataset avoids many elementary errors such as Windows paths on Linux, cross-host PID confusion, or mismatched SSH session tuples. Server-specific software such as Exchange, Veeam, Squid, web services, and database tools generally appears in plausible locations.

The repeated Linux hardware topology, session-counter function, and generic daemon-state pools cut against that realism. They occur across enough independent systems to outweigh the strong local event construction.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `distribution_texture` | Linux syslog / systemd-logind | Dataset-wide across 9 hosts | Near-perfect wall-clock-derived session IDs are the strongest generator fingerprint. |
| `environment_or_collection_plausibility` | Linux syslog / irqbalance | Dataset-wide across servers and workstations | Exact reuse of IRQ/device topology is inconsistent with independent host hardware state. |
| `distribution_texture` | Windows Sysmon Event 11 | 103 of 111 records across all 9 Windows hosts | Exact five-digit decimal temp naming and broad process assignment look template-driven. |
| `contract_gap` | Linux syslog / fwupd | Repeated on workstation-class hosts | Metadata-age changes do not read as persistent, identifiable daemon state. |
| `distribution_texture` | Linux ambient daemon telemetry | Repeated across host roles | Shared small message and entity pools weaken long-tail host individuality. |

## Realism Score by Category

- **Field format accuracy:** 8 — Windows XML, Sysmon fields, eCAR JSON, and SSH/PAM text are mostly source-native and detailed.
- **Temporal patterns:** 5 — Local lifecycle ordering is strong, but Linux session IDs track elapsed time with generator-like precision.
- **Cross-source correlation:** 9 — Process, session, and actor identities correlate without visible same-ID impossibilities.
- **Behavioral realism:** 7 — Users and host roles are differentiated, though background activity pools repeat broadly.
- **Environmental consistency:** 4 — Identical IRQ/device maps and weakly stateful daemon messages are difficult to reconcile with the diverse host estate.

## Recommendations

If this were synthetic, the following changes would improve it:

- Allocate Linux session IDs only when a real modeled PAM/logind session is created. Preserve a per-host counter and remove any timestamp-derived ID formula.
- Build a persistent per-host hardware inventory and derive IRQ/device messages from it. Laptop, workstation, VM, database, mail, and edge-server profiles should not share an identical IRQ topology.
- Make Linux daemon telemetry stateful. `fwupd` metadata age should be attached to an identified remote and evolve monotonically unless a recorded refresh changes it; `snapd`, `multipathd`, printer, and thermal events should operate on durable host-specific entities.
- Diversify Sysmon Event 11 filenames by originating process and actual Windows filename conventions. Avoid assigning one decimal-temp grammar to unrelated processes such as LSASS, DNS, CSRSS, wininit, services, SearchIndexer, and MSI.
- Retain the existing Windows Security/Sysmon/eCAR lifecycle and SSH/PAM correlation contracts; those are convincing and should not be weakened while correcting distributional defects.
