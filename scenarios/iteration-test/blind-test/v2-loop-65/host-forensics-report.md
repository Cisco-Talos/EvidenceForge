# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 84
**Synthetic-Confidence Score:** 71

## Executive Summary

The dataset is high-fidelity and temporally coherent, with convincing process, RDP, SSH, and cross-source lifecycle relationships and no visible create-after-terminate contradiction. I nevertheless assess it as synthetic because several independent, high-volume endpoint patterns look generated: Sysmon PE metadata is selectively absent for hundreds of ordinary Microsoft binaries, workstation lock/unlock producer PIDs do not remain stable within the same session, Linux hosts reuse an unusually exact hardware/software vocabulary, and the web host's 821 UFW records are drawn from conspicuously narrow field-value pools.

## Evidence For Synthetic

- `[schema_or_format]` Sysmon Event 1 contains all five PE metadata fields as `-` in 659 of 911 records (72.3%). This is not random loss: every observed `taskhostw.exe` (141), `WmiPrvSE.exe` (103), `dllhost.exe` (92), and `conhost.exe` (88) creation lacks `FileVersion`, `Description`, `Product`, `Company`, and `OriginalFileName`, although these standard Microsoft binaries normally contain version resources and the same dataset successfully populates those fields for `explorer.exe`, PowerShell, `mstsc.exe`, and Office. Examples include `DC-01.../windows_event_sysmon.xml` at 2024-03-18 12:06:11.592Z (`taskhostw.exe`) and 13:09:19.899Z (`WmiPrvSE.exe`).
- `[contract_gap]` Security 4800/4801 producer identity changes repeatedly inside one continuing user session. On `WS-EBROOKS-01`, session 2 / LUID `0xa370ec7` is locked at 12:30:49 by System/Execution PID 500, unlocked at 12:42:30 by PID 516, locked again at 15:39:23 by PID 588, and unlocked at 15:46:20 by PID 508. `WS-MCHEN-01` similarly uses PIDs 500, 544, 524, 580, and 520 for the same session 1 / LUID `0x6b920ba`. The changing low PID pool does not look like a stable source process servicing one extant interactive session.
- `[environment_or_collection_plausibility]` Eight Linux server-role hosts expose essentially the same irqbalance hardware vocabulary: `ahci`, `ens160`, `ens192`, `mlx5_comp0/1/2`, `nvme0q1/2`, and `virtio0-input`/`virtio1-input`. The exact reuse spans the application, file, log, mail, proxy, web, and database systems. Homogeneous virtualization is possible, but the simultaneous mixture of multiple NIC/storage driver families and identical device naming on every role is much more consistent with a shared enumerable pool than independent lived-in hosts.
- `[environment_or_collection_plausibility]` Seven unrelated Linux servers also show the same five snap package names—`core20`, `core22`, `lxd`, `microk8s`, and `snapd-desktop-integration`—in frequent snapd messages. Within six hours, APP-INT has 51 snapd lines, FILE-LNX 56, LOG-MON 83, MAIL-CLIN 30, MAIL-EDGE 36, PROXY 40, and WEB-EXT 109. Installing both MicroK8s and desktop integration across mail, proxy, file, logging, integration, and exposed web roles is possible under a cloned image, but the fleet-wide combination and volume are implausibly uniform.
- `[distribution_texture]` `WEB-EXT-01.../syslog.log` contains 821 UFW blocked SYN records but only 12 source IPs; seven sources account for 813 records. The records use only three TCP window values—1024 (298), 14600 (267), and 65535 (256)—and the same source IP cycles among all three while retaining one exact TTL/LEN pair. For example, `185.220.88.13` always has TTL 45 and LEN 60 but appears 80/71/66 times with windows 1024/65535/14600. This small, nearly balanced value pool is a strong generator-like packet-fingerprint texture.
- `[distribution_texture]` Windows service-logon volume is unusually dense and narrow. Across the ten Security logs there are 399 Type 5 logons; DC-01 alone has 140 and DC-02 has 100 in six hours. They overwhelmingly recycle only the built-in principals and reserved LUIDs (`SYSTEM/0x3e7`, `LOCAL SERVICE/0x3e5`, `NETWORK SERVICE/0x3e4`), each followed by 4672 and with no Type 5 logoff. Built-in LUID reuse is individually valid, but the quantity and near-exclusive three-account texture across every Windows role are suspicious.

## Evidence For Real

- Process identity and ordering are strong. Across the ten Windows hosts, 911 Sysmon Event 1 records match Security 4688 records by PID and image; Security has 915 total creates, so only four Security creates lack a Sysmon counterpart. The matched Sysmon records precede Security by 35.1–649.7 ms (median 135.7 ms), a plausible independent-provider delay rather than identical timestamps.
- eCAR adds realistic, non-identical observation timing. It matches 909 of the 915 Security process creates, with eCAR minus Security delays from -618.3 to +801.2 ms (median +28.9 ms). The small selective gaps and asymmetric timing look like collection behavior rather than copied rows.
- ProcessGUID integrity is excellent without visible lifecycle contradictions. Across each host, no GUID maps to conflicting PID/image identities, no child with a visible parent is created after that parent's visible termination, and no eCAR event is attributed to a process after its visible termination.
- Process trees reflect plausible roles: `services.exe` launches Exchange and updater services; `svchost.exe` launches `taskhostw.exe`, `dllhost.exe`, and WMI providers; `SearchIndexer.exe` launches search hosts; `csrss.exe` launches `conhost.exe`; and user processes descend through `userinit.exe`/`explorer.exe` or SSH/login shells. The Linux file server's `smbd`-to-`smbd` worker forks are also source-appropriate.
- User behavior is differentiated by visible fields. Aisha and Marcus use PowerShell, MMC, RDP, SSH, and remote administration; Lina uses Git, Cargo, editors, and terminal tools; Diego, Evelyn, Priya, and Sophia predominantly use office, browser, collaboration, VPN, and updater software. Bash histories are mostly non-duplicative: the largest history, Lina's 62-command workstation history, has 58 unique commands.
- RDP transport/authentication ordering is coherent. All 21 visible eCAR Type 10 logins have a matching TCP/3389 flow 5.2–7.9 seconds earlier. One concrete sequence is LT-MRIVERA-02 outbound `10.10.1.99:59720 -> 10.10.1.35:3389` at 14:59:44.900Z, WS-AJOHNSON-01's inbound observation at 14:59:43.988Z, and the target Type 10 login for Aisha at 14:59:50.119Z using the same tuple.
- Linux SSH sequences are convincing. For example, APP-INT-01 logs the connection from `10.10.1.21:39472` at 12:02:04.504Z, password acceptance for Lina at 12:02:10.030Z, PAM open at 12:02:10.112Z, and logind session creation at 12:02:10.582Z. Across the Linux hosts, every visible accepted login examined has a PAM open; incomplete closes are attributable to the bounded window.
- The DC-01 audit-log clear is rendered with unusually good source-native continuity: Security 4688 shows WMI -> `cmd.exe /c wevtutil cl Security` at 17:42:13.062Z and child `wevtutil.exe` at 17:42:13.161Z; Event 1102 follows at 17:42:20.776Z with EventRecordID reset to 1; the child and parent terminate at 17:42:20.898Z and 17:42:21.878Z. This explains the one otherwise alarming Security record-ID discontinuity.

## Detailed Analysis

### Scope and source profile

The visible collection spans approximately 12:00:00–17:59:59Z on 2024-03-18. It includes ten Windows Security/Sysmon/eCAR hosts, eleven Linux-style syslog hosts, per-user bash histories, and eCAR coverage for 21 hosts. I treated starts before noon and terminations after 18:00 as unobserved state, not defects.

The Windows Security logs contain a credible role-dependent mix. DC-01 and DC-02 are dominated by 4768/4769 Kerberos and 5156 filtering-platform records, FILE-SRV-01 adds 4656/4663/4658 and 5140/5145 object/share evidence, and workstations carry interactive failures, workstation locks/unlocks, updater processes, and user applications. The source-family distribution is therefore not uniformly copied across roles.

### Windows process trees and lifecycle

I compared Security 4688, Sysmon 1, and eCAR PROCESS/CREATE using host, PID, normalized image, and a five-second time window. Security produced 915 creates, Sysmon 911, and eCAR 909. Every Sysmon and eCAR create found a matching Security create. The four Sysmon gaps and six eCAR gaps are isolated (`dllhost.exe`, `taskhostw.exe`, `WmiPrvSE.exe`, `GoogleUpdater.exe`, `conhost.exe`, and one `mstsc.exe`) rather than one missing source family.

The visible parent/child graph is coherent. No Sysmon child references a ProcessGUID with a conflicting PID/image, no child follows a visible parent termination, and hashes remain stable for the same image on the same host. Common binaries also vary across four distinct hash sets across the Windows fleet, consistent with several OS/build families rather than a single hash copied everywhere.

The main process-format weakness is PE resource metadata. At 2024-03-18 12:06:11.592Z on DC-01, Sysmon records full SHA1/MD5/SHA256/IMPHASH values for `taskhostw.exe` but returns `-` for every PE descriptive field. The same happens at 12:17:03.746Z for `dllhost.exe`, 12:25:38.507Z for `conhost.exe`, and 13:09:19.899Z for `WmiPrvSE.exe`, and repeats across all hosts. Because other Event 1 rows populate these fields normally, this looks like selective catalog enrichment rather than a host-wide Sysmon setting.

### Logon sessions and workstation state

Network and remote-interactive sessions generally behave well. Security Type 3 sessions have unique nonzero LUIDs and visible 4634 records where the close falls inside the window. RDP sessions preserve LUID from 4624 through 4779 and 4634; session names advance (`RDP-Tcp#5`, `#6`, and onward), and source address/port values stay aligned with eCAR transport.

Lock/unlock event ordering is correct—4800, then a Type 7 4624, then 4801—but the System/Execution ProcessID field is not stable. The two cycles for Evelyn Brooks reuse the same LUID and SessionId while rotating through four event-producer PIDs. Marcus Chen's three locks and two unlocks similarly use five distinct PIDs. This is not a missing-pre-window issue: the contradiction is inside a single visible session's repeated state transitions.

Service logons are less convincing as a distribution. DC-01 records 64 `SYSTEM/0x3e7`, 42 `LOCAL SERVICE/0x3e5`, and 34 `NETWORK SERVICE/0x3e4` Type 5 logons; DC-02 records 28, 38, and 34. The corresponding eCAR rows instantiate many separate USER_SESSION objects around the same persistent built-in LUIDs. While the source fields are individually legal, the volume and narrow principal pool make the service-session model look mechanically generated.

### Sysmon and eCAR correlation

Sysmon provider behavior is otherwise strong. Each host has a stable Sysmon service ProcessID and a small thread pool, ProcessGUIDs are reused consistently across Event 1/3/5/7/10/11/13/22, and ParentProcessGUID identity agrees with ParentProcessId/ParentImage. Process terminations do not precede creates for the same visible identity.

Network events retain process ownership and source-native differences. For example, WS-AJOHNSON-01's lsass DNS query for `DC-01.meridianhcs.local` at 12:02:38.948Z returns `10.10.2.10;`; a second query at 12:02:39.227Z returns `-`, consistent with separate A/AAAA outcomes despite the Event 22 schema not exposing query type. The subsequent Kerberos/LDAP flows use the same lsass PID/ProcessGUID. This kind of subtle dual-query behavior argues for realism.

### Linux SSH, shell, and daemon evidence

SSHD PID groups maintain source-native order. APP-INT has seven visible inbound connections, six complete accepted/open/close lifecycles, and no accepted event without a PAM open. DB-PROD has six of six complete; FILE-LNX has four complete among five visible connections; other incomplete groups sit at collection boundaries or represent nonaccepted connections. PAM, logind, and process evidence use consistent user identities and source tuples.

Shell activity has reasonable role texture and ordinary operator imperfections. Commands include Git/Cargo/editor work on Lina's workstation, database inspection on DB-PROD, Postfix/Dovecot checks on mail hosts, and file/share diagnostics. Commands such as checking a questionable unit name or querying a service that may not exist are realistic operator behavior. Exact command reuse across the fleet is low: no command appears more than three times in all visible bash histories.

The Linux background environment is the largest endpoint realism weakness. Nearly every server claims the same mixed controller/NIC device set in irqbalance messages. The same servers also repeatedly mention MicroK8s, LXD, both core snaps, and desktop integration regardless of role. Either pattern could be explained by an unusually uniform golden image, but both together—plus repeated high-volume template messages—look like shared generator catalogs.

### Host firewall texture

WEB-EXT-01's UFW lines are syntactically credible and keep kernel uptime aligned with wall time. Their distribution is not. The 821 blocked SYNs draw from 12 IPs and a fixed 20-port destination pool; counts for major destination ports are smooth (80: 122, 445: 111, 443: 105, 3389: 89). More importantly, only three TCP windows cover every common source and each source rotates among them while retaining a fixed TTL and packet length. That is a stronger synthetic indicator than the mere presence or high volume of Internet scanning.

### Overall balance

I found no impossible process ordering, identity collision, RDP auth-before-transport event, SSH auth-before-connection event, or unexplained Windows record-ID reset. Those strengths prevent a score in the 81–100 range. The verdict is nevertheless Synthetic because the metadata, lock/unlock producer identity, Linux hardware/software pool, and UFW field distributions are independent and repeated enough that a single collection quirk does not explain them all.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected the synthetic-confidence score |
|---|---|---|---|
| `schema_or_format` | Sysmon Event 1 | Dataset-wide; 659/911 creates | Selective absence of version-resource fields on standard Microsoft PEs is systematic and image-family specific. |
| `contract_gap` | Windows Security 4800/4801 | Three workstations; repeated within-session | Event-producing PIDs rotate while LUID and SessionId remain constant, weakening source-native session continuity. |
| `environment_or_collection_plausibility` | Linux syslog / irqbalance | Eight server roles | Nearly exact mixed hardware-device vocabulary recurs across otherwise distinct machines. |
| `environment_or_collection_plausibility` | Linux syslog / snapd | Seven server roles | The same desktop, container, and Kubernetes snap set appears with high message volume on every role. |
| `distribution_texture` | WEB-EXT-01 kernel/UFW | 821 records | Twelve sources and three nearly balanced TCP-window values create a narrow, generator-like packet fingerprint. |
| `distribution_texture` | Windows Security 4624/4672 and eCAR USER_SESSION | All Windows hosts; 399 Type 5 logons | Dense built-in-account service logons recycle three reserved LUIDs with little long-tail account behavior. |

## Realism Score by Category

- **Field format accuracy:** 7 — XML, eCAR, syslog, Event IDs, hashes, GUIDs, and log-clear semantics are strong, but Sysmon PE metadata and lock/unlock producer fields are materially weak.
- **Temporal patterns:** 8 — Process, RDP, SSH, logoff, termination, and audit-clear timing is coherent with realistic observation delay; no impossible visible ordering was found.
- **Cross-source correlation:** 9 — Security, Sysmon, eCAR, and syslog identities and tuples correlate closely while retaining plausible source-specific delays and a few gaps.
- **Behavioral realism:** 7 — Role-specific user and service behavior is convincing, but Type 5 logon and UFW value distributions are too narrow and smooth.
- **Environmental consistency:** 5 — Host roles are distinct, but Linux hardware and snap-package vocabularies are implausibly cloned across the fleet.

## Recommendations

- If this were synthetic, populate Sysmon Event 1 PE resource fields from an image/build-aware catalog for core Microsoft binaries, and vary them only when the corresponding file hash/build varies. A retrieval failure should be occasional or host/config scoped, not deterministic by image family.
- If this were synthetic, bind Security 4800/4801 System/Execution ProcessID to the stable process that owns the interactive session and retain it across repeated lock/unlock cycles for the same LUID/SessionId.
- If this were synthetic, model Linux hardware per host or per infrastructure class. Keep coherent combinations of hypervisor NIC, storage controller, interface names, IRQ numbers, and queue names rather than drawing every host from one combined vocabulary.
- If this were synthetic, make package and daemon inventories role-specific. Do not place `microk8s`, `lxd`, and `snapd-desktop-integration` together on every headless server unless other host evidence supports that golden-image decision; reduce snapd chatter to collection-profile-appropriate levels.
- If this were synthetic, generate Internet scanning from persistent per-scanner TCP/IP fingerprints with a larger long tail of source addresses and ports. Avoid independently sampling TCP window from a global three-value pool for every packet from the same source.
- If this were synthetic, derive Type 5 service-logon volume from concrete service activation behavior and include a longer tail of service identities where appropriate. Preserve Windows' built-in LUID semantics without treating every repeated built-in authentication as a separate normalized session object.
