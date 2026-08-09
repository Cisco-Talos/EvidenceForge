# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 80  
**Synthetic-Confidence Score:** 65

## Executive Summary

The suspicious activity is operationally coherent and unusually strong at source-native correlation: web exploitation, reverse shell, SSH pivots, PsExec, domain-account creation, collection, proxy-mediated exfiltration, and cleanup all have technically compatible timestamps and fields. The synthetic verdict instead rests on dataset-wide baseline fingerprints, especially a repeated Windows servicing pattern that scatters implausibly varied CBS package-state writes across nine hosts and cloned Linux `irqbalance` telemetry with identical IRQ/device mappings across unrelated systems.

## Evidence For Synthetic

- `[distribution_texture]` Windows background registry telemetry has a strong repeated generator-like shape across nine hosts. On `DC-01`, 91 distinct CBS package `CurrentState` keys appear in six hours, with identities such as `Package_for_ServicingStack`, `Package_for_RollupFix`, `Package_for_DotNetRollup`, `Package_for_KB5034122`, and `Microsoft-Windows-Client-Features`, almost always set to `DWORD (0x00000070)`. Their versions scatter broadly across `10.0.20348.1` through `.80`; `WS-AJOHNSON-01` similarly emits `10.0.19041.1`, `.13`, `.26`, `.27`, `.35`, `.38`, `.44`, `.45`, `.50`, `.56`, `.65`, `.77`, and `.80`.
- `[environment_or_collection_plausibility]` The same long-lived `msiexec.exe /V` texture appears on nine Windows hosts. On `DC-01`, PID 2460 produces 45 eCAR records from `12:00:53.885` through `17:26:06.819`, including 34 registry modifications, ten process opens, and a WER write. `FILE-SRV-01` PID 3736, `MAIL-FIN-01` PID 2660, and `WS-AJOHNSON-01` PID 4700 show the same multi-hour actor pattern. Simultaneous, near-continuous installer-service activity with randomized CBS identities on workstations, mail servers, file servers, and a DC is not a credible ordinary fleet-wide maintenance profile.
- `[distribution_texture]` Linux `irqbalance` records reuse the same small hardware vocabulary and exact mappings across dissimilar hosts. Examples include IRQ 32→CPU 2 on `nvme0q1`, IRQ 64→CPU 3 on `mlx5_comp0`, IRQ 122→CPU 1 on `nvme0q2`, IRQ 137→CPU 3 on `ens192`, IRQ 181→CPU 0 on `mlx5_comp2`, and IRQ 45→CPU 0 on `virtio0-input`. These recur on `APP-INT-01`, `MAIL-EDGE-01`, `WS-LNGUYEN-01`, `WS-OHADDAD-01`, and other Linux assets as randomly spaced isolated messages, suggesting a shared enumerable pool rather than host-derived hardware state.
- `[environment_or_collection_plausibility]` `WEB-EXT-01` launches 34 root-owned, PID-1-parented commands with the identical template `wget -q -e use_proxy=yes -O - https://<target>/`; 25 targets include advertising and browser-analytics infrastructure such as `connect.facebook.net`, `cdn.mouseflow.com`, `cdn.heapanalytics.com`, and `analytics.mixpanel.net`. `DB-PROD-01` has another 16 root/PID-1 invocations of the same template against `internal-service`. The nonuniform timing is good, but the actor, parent, command, and destination combination is weakly plausible server behavior.
- `[contract_gap]` The successful `WEB-EXT-01`→`APP-INT-01` SSH pivot has network and target-side evidence but no matching source-side eCAR process or flow on `WEB-EXT-01`, despite that host’s eCAR recording nearby root shell commands and individual Nmap probe flows. Zeek core records `10.10.3.10:59908 → 10.10.2.30:22` at `14:15:14.335` for 13,304.483 seconds, and `APP-INT-01` logs connection, password acceptance, login, shell, and logout, but the source endpoint view is absent.

## Evidence For Real

- The initial compromise has convincing source-native alignment. `WEB-EXT-01/web_access.log` records `185.70.41.45` posting `/ehr/admin/upload.php` with HTTP 200 at `13:20:10`. At `13:20:12.629`, eCAR records `www-data` PID 581448 executing a base64-decoded Bash reverse shell, followed by its outbound `10.10.3.10:49931 → 45.33.32.30:8443` flow at `13:20:14.353`.
- The same reverse-shell tuple appears independently in Zeek DMZ at `13:20:13.051` with UID `CzRN5LIdcz2A9mLUFm`, 20.719-second duration, bidirectional bytes, `missed_bytes:17`, and a nontrivial TCP history. ASA records the NATed connection build at `13:20:13` and teardown at `13:20:33`, with 3,148 bytes. The small timing and accounting differences look like real independent sensors.
- The Linux SSH lifecycle is technically credible. For the `14:15` pivot, Zeek sees the transport first; `APP-INT-01` syslog then records connection at `14:15:16.065`, password acceptance at `14:15:18.283`, PAM session open at `14:15:18.391`, and systemd-logind session creation at `14:15:19.048`. The long Zeek session ends near the endpoint logout at `17:57`.
- PsExec evidence on `DC-01` is source-native and ordered: two SMB flows from `10.10.1.35` at `16:00:01`, Type 3 login for `aisha.johnson`, creation of `C:\Windows\PSEXESVC.exe`, Security 4697 for `PSEXESVC`, service process creation under `services.exe`, and `cmd.exe /c whoami && hostname` under the service.
- Domain persistence is well represented. `net user svc_mhsync ... /add /domain` and `net group "Domain Admins" svc_mhsync /add /domain` align with Security 4720 and 4728. Later, Security 4697 records `DeviceSyncSvc`, 4698 contains a syntactically credible scheduled-task XML body, and the binary runs under `services.exe`.
- Collection and exfiltration remain pivotable. `FILE-SRV-01` logs the `svc_mhsync` Type 3 session and `Compress-Archive` creation of `C:\ProgramData\Microsoft\cache_7f3a.zip`. `DB-PROD-01` records `mysqldump`, gzip, file reads, and SCP; `APP-INT-01` records the receiving `sshd` file creation.
- The final upload has realistic proxy fan-out. `PROXY-01/proxy_access.log` attributes a `314,782,961`-byte POST to `aisha.johnson` at `17:24:57`, while Zeek observes the proxy’s `10.10.3.20:53023 → 45.33.32.30:443` TLS connection with `315,250,317` origin bytes and ASA reports a nearby 331,393,750-byte connection. TLS resumption, certificate chains, DNS TTLs, and proxy CONNECT/inspection semantics are present.
- Security-log clearing is modeled correctly: `wevtutil cl Security` precedes Event 1102, which uses the `Microsoft-Windows-Eventlog` provider, populated `LogFileCleared` user data, and `EventRecordID` reset to 1. Subsequent Security events continue from the reset sequence.
- Baseline network texture includes `S0`, `REJ`, `RSTO`, `SF`, retransmission histories, `missed_bytes`, TLS session resumption, proxy denies, UFW blocks, public scanning, ordinary browser clusters, DHCP, DNS, SMTP, and maintenance traffic. It is not uniformly clean.

## Detailed Analysis

### Scope and orientation

The visible window is approximately `2024-03-18 12:00–18:00 UTC`. It covers 18 named endpoint/server assets across workstation, domain-controller, file, application, database, mail, proxy, and public-web roles. Available telemetry includes 25,792 eCAR JSON records, 13,555 parsed Windows Security events, 4,610 parsed Sysmon events, 4,195 Linux syslog records, 20,817 Zeek records across core and DMZ sensors, ASA firewall logs, two Snort sensors, proxy access logs, web access logs, and Bash histories.

Source volume is large enough to require hunting. The DC alone has 7,463 Security events and 708 Sysmon events; Zeek core and DMZ have 6,152 and 5,624 connection records respectively. Suspicious events are embedded among public web scans, ordinary SMB, Kerberos, DNS, web browsing, updater, mail, and service activity.

### Initial access and external control

The web server is scanned by `185.70.41.45` before compromise, with repeated Nikto-style requests and Snort rapid-connection alerts. The decisive request is:

- `13:20:10`: `POST /ehr/admin/upload.php`, status 200, from `185.70.41.45`.
- `13:20:12.629`: `www-data` PID 581448 executes `bash -c 'echo ... | base64 -d | bash'`.
- The decoded content launches an interactive Bash connection to `45.33.32.30:8443`.
- `13:20:13.051`: Zeek DMZ sees `10.10.3.10:49931 → 45.33.32.30:8443`.
- `13:20:13`: ASA builds the corresponding NATed outbound connection.
- `13:20:14.353`: eCAR exposes the same tuple and process attribution.

This is a convincing transport/process sequence. The Apache error at `13:20:14.849` references the same client and worker PID, adding plausible application-layer texture rather than contradicting the process event.

### Discovery and lateral movement

A root SSH session reaches `WEB-EXT-01` from `10.10.1.36` at `13:39:44–13:39:49`. Its shell runs `ip addr show`, reads `/etc/hosts` and `/etc/resolv.conf`, searches `/opt/ehr` for credentials, executes two Nmap scans, and reads `/var/www/html/config.php` and `/root/.ssh/id_rsa`.

The Nmap scan is not merely a command-line artifact. Beginning at `13:52:23`, eCAR emits distinct root-attributed probe flows from `10.10.3.10` to the `10.10.2.0/24` subnet with realistic mixed outcomes; Zeek records `SF`, `REJ`, `RSTO`, and short successful sessions, and both Snort sensors alert on the SSH probe.

At `14:15:14`, a successful, long-lived SSH transport begins from `WEB-EXT-01` to `APP-INT-01`. Target syslog and eCAR show root authentication and shell creation, and later commands read `/etc/passwd` and `/etc/shadow`. The transport timing is coherent, but the absence of the source eCAR process/flow is a collection-contract weakness because `WEB-EXT-01` otherwise has detailed endpoint activity during this interval.

### Windows administrative compromise and persistence

The PsExec sequence at `16:00` is one of the strongest realistic portions. Source endpoint traffic from `WS-AJOHNSON-01` appears before target transport and authentication. On the DC, the service binary arrives, service installation is attributed to `aisha.johnson`’s network logon, `PSEXESVC.exe` starts under `services.exe`, and its child command executes as SYSTEM.

The subsequent WMI-parented commands create `svc_mhsync`, add it to Domain Admins, create `DeviceSyncSvc`, and register `\Microsoft\Windows\Maintenance\DeviceSync`. The Security 4720, 4728, 4697, and 4698 fields align with the process command lines and use consistent SIDs. This is technically credible attacker tradecraft.

The `DeviceSyncSvc.exe` process later runs under `services.exe`; the dataset does not expose the binary’s initial write. That is odd but not sufficient to score independently because the file could have been staged earlier or its observation dropped.

### Collection, staging, and exfiltration

At `17:01:02`, `FILE-SRV-01` receives an SMB Type 3 login as `svc_mhsync` from `10.10.1.35`. The account runs `net view` and then PowerShell `Compress-Archive` over finance and patient-export shares, creating `C:\ProgramData\Microsoft\cache_7f3a.zip`.

The database portion is similarly coherent. A root session on `DB-PROD-01` dumps the `ehr` database tables `patients` and `insurance_claims`, checks size, compresses the SQL file, and copies it by SCP to `APP-INT-01`. The source file read, SSH tuple `10.10.4.10:43584 → 10.10.2.30:22`, target SSH connection, and target file creation at `/tmp/.cache/rpt_0318.sql.gz` all line up.

At `17:24:57`, the proxy receives a large authenticated upload from `10.10.1.35` as `MERIDIANHCS\aisha.johnson`. The CONNECT tunnel reports 314,783,385 client bytes, and the inspected POST reports 314,782,961 request bytes. The proxy’s origin-side TLS connection, DNS resolution, certificate, Zeek accounting, and ASA teardown all support the same occurrence without bit-identical sensor counts.

### Cleanup

At `17:42:28`, DC eCAR, Security 4688, Sysmon, proxy, DNS/TLS, and network records capture encoded PowerShell contacting `api.westbridge-services.net`, followed by `wevtutil cl Security`. Event 1102 correctly resets Security `EventRecordID` to 1 and preserves actor information in `UserData`.

At `17:50:21`, SYSTEM executes `net user svc_mhsync /delete /domain`; Security 4726 records the same SID and account. Root histories on `WEB-EXT-01` and `APP-INT-01` are empty after visible history cleanup, while `DB-PROD-01` retains timestamped dump and SCP commands. These are internally consistent artifacts, though the completeness of the cleanup sequence was not used as an authenticity indicator.

### Baseline authenticity defects

The largest weakness is Windows maintenance texture. CBS package identities are produced as an apparently randomized stream rather than clustered around a bounded servicing transaction. On `DC-01`, one sees, minutes apart, `Package_for_ServicingStack ... 10.0.20348.29`, `Package_for_KB5034122 ... .63`, `Package_for_RollupFix ... .68`, the same KB at `.36`, `Package_for_DotNetRollup ... .80`, another servicing stack at `.6`, and a rollup at `.2`, all ending in the same state value. This continues for six hours and recurs on unrelated Windows assets.

The Linux equivalent is the shared `irqbalance` pool. Exact IRQ/device/CPU combinations recur across workstations, mail servers, and internal applications, often with mutually different message variants such as “classified,” “affinity hint keeps vector,” and “Skipping IRQ.” A genuinely cloned VM fleet can share hardware topology, but the breadth of roles and the sampled, pool-like record distribution make this a substantial synthetic signal.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected the synthetic-confidence score |
|---|---|---:|---|
| `distribution_texture` | eCAR and Sysmon registry telemetry | Nine Windows hosts; strongest on DC, file, and mail servers | Multi-hour randomized CBS identity/version streams and near-constant `DWORD (0x00000070)` values resemble an enumerable generator pool rather than servicing transactions. |
| `environment_or_collection_plausibility` | eCAR Windows process attribution | Nine Windows hosts | The same long-lived `msiexec.exe /V` actor pattern simultaneously produces CBS, process-access, WER, temporary-file, and Defender-history activity across heterogeneous roles. |
| `distribution_texture` | Linux syslog | Multiple workstations and servers | Exact IRQ/device/CPU mappings and a small wording pool recur across unrelated systems, creating a cloned baseline fingerprint. |
| `environment_or_collection_plausibility` | Linux eCAR process telemetry | `WEB-EXT-01`, `DB-PROD-01` | Repeated root/PID-1 `wget -q -e use_proxy=yes -O -` commands, especially to browser-advertising domains on a server, weaken role realism. |
| `contract_gap` | eCAR versus Zeek and Linux syslog | One important SSH pivot | `WEB-EXT-01` lacks source process/flow evidence for the successful `14:15` SSH session despite detailed nearby endpoint coverage. |

## Realism Score by Category

- **Field format accuracy:** 9 — Windows XML, Zeek JSON, ASA, Snort, proxy, web, and RFC 5424 syslog fields are predominantly source-native and internally well formed.
- **Temporal patterns:** 8 — Attack and lifecycle ordering are strong, with credible independent sensor jitter; the repeated maintenance-noise stream reduces the score.
- **Cross-source correlation:** 8 — Most important pivots correlate cleanly across host, network, firewall, proxy, and authentication sources, but the `14:15` SSH source endpoint gap is notable.
- **Behavioral realism:** 8 — Exploitation, discovery, PsExec, domain persistence, staging, exfiltration, and cleanup use technically credible commands and privileges.
- **Environmental consistency:** 5 — Fleet-wide Windows CBS/msiexec texture, cloned Linux IRQ mappings, and root/PID-1 Wget traffic are the clearest authenticity failures.

## Recommendations

- If this were synthetic, model Windows servicing as bounded transactions: coherent package identities and versions, a limited number of related registry changes, realistic actor lifecycles, variable values, and appropriate temporal clusters instead of scattering random package states across six hours.
- Derive Linux IRQ numbers, devices, CPU affinities, NUMA topology, and enabled logging level per host. Emit verbose `irqbalance` messages only on hosts whose configuration explains them, and avoid reusing exact hardware mappings across unrelated roles.
- Replace generic root/PID-1 Wget activity with role-specific application or timer lifecycles. Preserve the real parent/service chain and restrict destination pools to software or services the visible host plausibly uses.
- Make source-observation decisions coherent for SSH sessions. For the `10.10.3.10:59908 → 10.10.2.30:22` pivot, either render the source SSH process and eCAR flow or apply an explicit source-local collection gap that also explains adjacent omissions.
- Preserve the current independent timing and accounting differences between endpoint, Zeek, ASA, proxy, and Syslog sources; those differences materially improve authenticity.
