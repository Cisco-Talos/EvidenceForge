# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 91
**Synthetic-Confidence Score:** 78

## Executive Summary

The endpoint evidence is technically strong at the individual-event and cross-source levels, including excellent Security/Sysmon/eCAR process correlation and plausible Windows and Linux session sequences. The decisive defect is a systematic, termination-only telemetry tail extending as much as 49 minutes beyond the stated six-hour collection boundary, accompanied by highly replicated Linux hardware-noise vocabulary across dissimilar endpoints.

## Evidence For Synthetic

- `[hard_contradiction]` The stated six-hour collection begins around `2024-03-18T12:00:00Z`, but host records continue well beyond `18:00:00Z`. Examples include Security 4689 events for `WmiPrvSE.exe` on `DC-01` at `18:34:31.0386577Z`, `FILE-SRV-01` at `18:35:28.6886881Z`, and `MAIL-FIN-01` at `18:49:42.6793403Z`.
- `[contract_gap]` The out-of-window tail is not normal continuing collection: it consists almost exclusively of lifecycle closure records. The `MAIL-FIN-01` PID 5028 termination appears in Security 4689 at `18:49:42.6793403Z`, Sysmon Event 5 at `18:49:42.9743946Z`, and eCAR `PROCESS/TERMINATE` at epoch milliseconds `1710787783421`, while ordinary activity has already stopped. This looks like pending process lifecycles being flushed after the collection boundary.
- `[contract_gap]` The same boundary leakage occurs across several endpoint classes. `WS-MCHEN-01` emits only late SSH termination events at `18:00:46`, `18:01:09`, `18:01:12`, and `18:15:51`; `WS-DRAMIREZ-01` ends with a `WmiPrvSE.exe` termination at `18:16:57`; and `MAIL-FIN-01` has isolated WMI terminations at `18:14:40` and `18:49:42`.
- `[distribution_texture]` Linux hardware-noise vocabulary is extensively cloned across unrelated servers and workstations. `WS-LNGUYEN-01`, `WEB-EXT-01`, `APP-INT-01`, `DB-PROD-01`, mail hosts, and the proxy repeatedly share the same IRQ/device combinations: IRQ 32 on `nvme0q1`, IRQ 64 on `mlx5_comp0`, IRQ 122 on `nvme0q2`, IRQ 137 on `ens192`, plus `ahci`, `virtio*-input`, and `ens160`.
- `[environment_or_collection_plausibility]` Several Linux systems appear to possess the same unusually broad hybrid device inventory. For example, `WEB-EXT-01` logs `nvme0q1`, `nvme0q2`, `mlx5_comp0`, `mlx5_comp1`, `mlx5_comp2`, `ens160`, `ens192`, `virtio0-input`, `virtio1-input`, and `ahci`; subsets of the identical inventory and IRQ assignments recur on desktop-like and server-like hosts.
- `[distribution_texture]` Linux administrative texture is strongly pooled across hosts. Identical `sudo`/PAM identities and UIDs recur broadly—`ops(uid=6366)`, `backup(uid=3037)`, `svc_app(uid=2214)`, `deploy(uid=1002)`, and `admin(uid=1001)`—along with the same short command/session patterns. Central identity management can explain stable UIDs, but the repeated account mix and activity texture across nearly every role adds to the templated appearance.

## Evidence For Real

- Security 4688 and Sysmon Event 1 correlation is unusually robust without field-level contradictions. All 171 process creations on `DC-01`, all 101 on `FILE-SRV-01`, all 106 on `MAIL-FIN-01`, and all records on most workstations matched by PID and image. Only two isolated mismatches appeared across the Windows fleet.
- Cross-source termination evidence is coherent. The late `MAIL-FIN-01` WMI process uses PID `0x13a4` in Security, decimal PID `5028` and a consistent ProcessGUID in Sysmon, and PID `5028` with the corresponding eCAR process object.
- Windows log clearing is rendered convincingly. On `DC-01`, `wevtutil cl Security` executes at `17:42:28.5455871Z`; Event 1102 follows at `17:42:29.6787301Z` with `EventRecordID` reset to `1`, and subsequent Security record IDs continue from the reset sequence.
- The intrusion-related process and audit chain is internally credible. `net user svc_mhsync ... /add /domain` is followed by account-management events, Domain Admin group modification, service creation for `DeviceSyncSvc`, scheduled-task creation, process execution, and later account deletion.
- Linux SSH sessions have realistic causal ordering. On `DB-PROD-01`, a connection from `10.10.1.31:61363` at `12:00:15.664867Z` is followed by ED25519 public-key acceptance at `12:00:17.868039Z`, PAM session open at `12:00:17.920280Z`, and a `systemd-logind` session at `12:00:18.424459Z`.
- Host-role differentiation is visible: mail systems contain Postfix/Dovecot activity, `DB-PROD-01` contains multipath noise, Linux workstations contain GNOME, PackageKit, CUPS, and NetworkManager activity, while Windows workstations show interactive applications, lock/unlock events, RDP, and user-launched shells.
- Windows logon types are varied rather than uniform. Workstations contain interactive type 2, network type 3, service type 5, unlock type 7, and remote-interactive type 10 sessions, while server and domain-controller activity is dominated appropriately by types 3 and 5.

## Detailed Analysis

### Collection Boundary and Lifecycle Behavior

The collection’s ordinary activity begins shortly after `12:00Z`, making `18:00Z` the six-hour endpoint. Most workstation telemetry ends near that boundary: `WS-AJOHNSON-01` ends at `17:59:43`, `WS-EBROOKS-01` at `17:59:18`, and `WS-SMARTINEZ-01` around `17:58`.

Several hosts nevertheless contain isolated closures far beyond the boundary. On `MAIL-FIN-01`, Security 4689 records PID `0x13a4`, image `C:\Windows\System32\wbem\WmiPrvSE.exe`, user `SYSTEM`, at `18:49:42.6793403Z`. Sysmon Event 5 records the same process as decimal PID 5028 at `18:49:42.9743946Z`, and the final eCAR row is the same `PROCESS/TERMINATE` at `1710787783421`. There is no comparable stream of ordinary host activity during that additional 49-minute period.

The pattern repeats on `DC-01` with three isolated WMI terminations at `18:08:43`, `18:26:06`, and `18:34:31`; on `FILE-SRV-01` at `18:35:28`; and on `WS-DRAMIREZ-01` at `18:16:57`. `WS-MCHEN-01` has four post-boundary `ssh.exe` terminations through `18:15:51`. Because the spillover is overwhelmingly lifecycle termination telemetry, it resembles a renderer draining scheduled end events without clipping them to the observation interval.

### Windows Process Trees and Correlation

The Windows process evidence is otherwise strong. Security 4688 and Sysmon Event 1 counts agree exactly on most hosts, with matching process image and PID. Examples include 171/171 records on `DC-01`, 101/101 on `FILE-SRV-01`, and 106/106 on `MAIL-FIN-01`. Sysmon ProcessGUIDs remain stable through Event 5 termination records, while eCAR carries corresponding process identity and principal data.

Parent-child semantics are generally plausible. `services.exe` launches service processes, `cmd.exe` launches `net.exe`, `wevtutil.exe`, and `schtasks.exe`, and WMI-driven activity uses `WmiPrvSE.exe`. The malicious-looking `DC-01` sequence preserves technically viable parentage and audit companions rather than merely listing disconnected commands.

Repeated baseline commands such as `taskhostw.exe`, `WmiPrvSE.exe -secured -Embedding`, `dllhost.exe /Processid:{...}`, `GoogleUpdater.exe -Embedding`, and `DropboxUpdate.exe /svc` occur with host-level count variation. This is more realistic than a fixed per-host checklist, though the command pools remain visibly compact.

### Logon and Session Lifecycle

Windows logon distributions broadly fit endpoint roles. `DC-01` contains 414 type 3 and 134 type 5 logons, while workstations include interactive, service, network, RDP, and unlock sessions. `WS-AJOHNSON-01` and `WS-PPATEL-01` include paired 4800/4801 lock-state events, which gives user sessions some lived-in texture.

Many service or still-active sessions lack an in-window 4634, which is not inherently defective in a bounded excerpt. Network-session pairing is much stronger on servers: `DC-01` contains 552 total 4624 events and 415 4634 events, with most of the difference attributable to type 5 service sessions. No systematic logoff-before-logon ordering was observed.

Linux SSH sequences are particularly coherent. Connection, authentication, PAM open, logind session creation, close, and session removal appear in viable order, with stable users and source tuples. The stable per-user UIDs across hosts can be explained by centralized identity management.

### System and User Texture

The source mix includes credible role-specific material: mail queues and Dovecot on mail hosts, multipath behavior on the database host, heavy UFW denies on the external web server, and desktop services on Linux workstations. Windows users differ in application and remote-administration use; Marcus Chen performs frequent SSH/RDP and deployment activity, while other users show more office/browser-oriented processes.

The weakest Linux texture is hardware noise. Exact device/IRQ combinations recur on too many systems. At `13:20:13.265267Z`, `WS-LNGUYEN-01` reports IRQ 137 assigned to CPU 3 for `ens192`; the same mapping appears repeatedly on `WEB-EXT-01` and other hosts. Likewise, IRQ 64/CPU 3/`mlx5_comp0` and IRQ 32/CPU 2/`nvme0q1` recur fleet-wide. Homogeneous virtual-machine templates could explain some overlap, but the shared combination of VMware-style interface names, Mellanox completion queues, virtio input, AHCI, and NVMe is too broad and too invariant across roles.

### eCAR/EDR Semantics

eCAR uses a coherent object/action model with `PROCESS/CREATE`, `PROCESS/TERMINATE`, `FLOW/CONNECT`, `USER_SESSION/LOGIN`, file, registry, module, and process-access records. Principals, image paths, process IDs, and logon IDs generally agree with Security and Sysmon.

Lifecycle accounting is plausible inside the visible interval: no matched process termination preceded its create. Orphan terminations at the beginning and active processes at the end are expected in a bounded capture. The important exception is the deliberate-looking export of future terminations after the collection boundary, which affects all three Windows endpoint views simultaneously.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Impact |
|---|---|---|---|
| `hard_contradiction` | Windows Security, Sysmon, eCAR | Multiple Windows hosts | Records extend up to 49 minutes beyond the stated six-hour boundary. |
| `contract_gap` | Process lifecycle telemetry | DC, servers, and workstations | The post-boundary records are almost entirely process terminations, suggesting lifecycle draining rather than continued collection. |
| `distribution_texture` | Linux syslog | Most Linux hosts | Identical IRQ numbers, CPU assignments, and device names recur across unrelated roles. |
| `environment_or_collection_plausibility` | Linux syslog | Servers and workstation-like hosts | The same hybrid VMware/Mellanox/virtio/AHCI/NVMe inventory appears fleet-wide. |
| `distribution_texture` | Linux PAM/sudo/syslog | Broad fleet scope | The same administrative account and short-session pools recur across most host roles. |

## Realism Score by Category

- **Field format accuracy:** 9 — Windows XML, Sysmon fields, eCAR objects, and RFC5424-style syslog are consistently well formed.
- **Temporal patterns:** 5 — Internal sequences are convincing, but the termination-only tail violates the declared collection interval.
- **Cross-source correlation:** 9 — Security, Sysmon, eCAR, and Linux session evidence correlate very well with few mismatches.
- **Behavioral realism:** 7 — User, service, attack, and administrative behavior is operationally plausible, though some baseline pools repeat.
- **Environmental consistency:** 5 — Role-specific software is good, but cloned Linux hardware texture materially weakens fleet realism.

## Recommendations

- If this were synthetic, enforce the collection cutoff at the canonical observation layer. Processes still alive at `18:00Z` should remain open in the excerpt; their later termination records should not be emitted.
- Apply the same cutoff to every source rendering the lifecycle so Security 4689, Sysmon Event 5, and eCAR termination records cannot leak together beyond the requested interval.
- Generate Linux hardware and IRQ profiles per host or per infrastructure cohort. A workstation, database server, proxy, and public web server should not repeatedly share the same IRQ/device map.
- Keep centralized user UIDs where appropriate, but diversify which administrative accounts, commands, and maintenance sessions appear on each host according to its role.
- Add automated boundary validation that asserts every rendered timestamp lies within the requested interval, except where the collection specification explicitly permits a documented tail.
