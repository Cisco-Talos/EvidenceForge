# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 72/100  
**Synthetic-Confidence Score:** 66/100

## Executive Summary

This six-hour dataset is a strong synthetic production-style corpus. It contains a credible enterprise topology, substantial benign noise, multiple endpoint and network source families, and unusually good cross-source agreement. The main intrusion can be reconstructed from web exploitation through reverse shell activity, discovery, credential access, lateral movement, persistence, collection, proxy-mediated exfiltration, and cleanup without relying on isolated “magic” records.

The strongest evidence for synthetic origin is not the completeness of that story. It is concrete lifecycle and distribution texture: a single RDP logon on `WS-AJOHNSON-01` produces two parallel `userinit.exe → explorer.exe` shell chains with the same LogonGuid and terminal session; Linux server activity repeatedly uses highly templated one-shot health-check commands; and the malicious sequence occasionally exposes scenario-shaped process construction and source-role behavior. These issues are material but do not overwhelm the dataset’s otherwise strong timing, protocol, and correlation realism.

No definitive hard contradiction was found. The verdict therefore rests on the cumulative weight of contract gaps and repeated operational texture.

## Evidence For Synthetic

1. **[contract_gap] Duplicate Windows interactive shell bootstrap for one RDP session.**  
   At `15:20:01.548`, ECAR shows one `aisha.johnson` Type 10 login to `WS-AJOHNSON-01` from `10.10.1.99`. Sysmon then records two distinct `userinit.exe` processes under the same LogonGuid `{47d9f745-42e3-4a6b-8f11-f16974effe6e}`, LogonId `0x2700aee`, and TerminalSessionId `4`:

   - PID 6624 at `15:20:01.977`, spawning explorer PID 6652 at `15:20:02.126`.
   - PID 6660 at `15:20:01.986`, spawning explorer PID 6676 at `15:20:02.134`.

   Both `userinit.exe` processes terminate about two seconds later. Two complete shell-bootstrap chains within milliseconds for the same visible session are characteristic of duplicated session expansion rather than normal RDP startup.

2. **[distribution_texture] Repeated Linux health-check behavior has a generator-like command shape.**  
   `DB-PROD-01` repeatedly launches root-owned commands such as:

   - `wget -e use_proxy=yes -e http_proxy=http://PROXY-01... https://pypi.org/`
   - The same command targeting `api.snapcraft.io`, `security.ubuntu.com`, `images.uptime.co`, `fonts.amplitude.com`, `cdn.formstack.io`, and other unrelated SaaS domains.

   The processes consistently use `/usr/bin/wget`, often parented by systemd, and fetch only a bare URL. `WEB-EXT-01` shows the same pattern, while `APP-INT-01` repeatedly runs `/opt/meridian/bin/proxy_healthcheck.py --target <domain>`. Health checks are plausible, but the cross-host repetition of one-command/one-domain templates and broad SaaS target pools lacks the stable application-specific endpoint concentration expected from most production systems.

3. **[environment_or_collection_plausibility] Human remote-administration activity is unusually broad and dense.**  
   Within six hours, `aisha.johnson`, `marcus.chen`, and `lina.nguyen` repeatedly SSH among workstations, the public web server, application server, database server, mail systems, and proxy. Examples include numerous separate `marcus.chen` SSH sessions from `WS-MCHEN-01` to both `WEB-EXT-01` and `DB-PROD-01`, and repeated `aisha.johnson` sessions to `MAIL-CLIN-01`, `MAIL-EDGE-01`, `APP-INT-01`, and `PROXY-01`. The breadth can exist in an operations team, but its concentration and repeated lifecycle shape look more like intentional coverage of topology edges.

4. **[contract_gap] The malicious file-server process has strained parent/token semantics.**  
   On `FILE-SRV-01`, the collection command

   `powershell.exe ... Compress-Archive ... -DestinationPath C:\ProgramData\Microsoft\cache_7f3a.zip`

   runs as domain account `svc_mhsync`, at medium integrity, while its parent is `svchost.exe -k netsvcs` running as `NT AUTHORITY\NETWORK SERVICE`. A service-hosted execution path can impersonate a user, but the visible evidence does not show the service/task or token transition that explains this specific parent/principal combination.

5. **[weak_signal] Attack actions are often represented by exceptionally explicit process command lines.**  
   Examples include:

   - `ms-index-service.exe "privilege::debug" "sekurlsa::logonpasswords" exit`
   - `net user svc_mhsync MhsSvc!2024 /add /domain`
   - `net group "Domain Admins" svc_mhsync /add /domain`
   - `Compress-Archive` over named Finance and Patients shares.
   - A Chrome launch directly containing the final upload URL.

   These are entirely possible telemetry records and are valuable for hunting, but their concentration around the attack path contributes weak synthetic evidence when combined with the stronger lifecycle and distribution indicators.

6. **[distribution_texture] Some background source families show narrowly repeated event recipes.**  
   Linux hosts repeatedly produce paired `/bin/sh -c 'command -v debian-sa1...'` and `debian-sa1 1 1` processes, periodic `php/sessionclean`, health checks, and short SSH sessions. Windows endpoints likewise share similar mixes of process, module-load, registry, DNS, and network events. There is variation, but the recurring family recipes remain visible at corpus scale.

## Evidence For Real

1. **[environment_or_collection_plausibility] The source-family mix is operationally coherent.**  
   The dataset contains endpoint ECAR on 18 hosts, Windows Security and Sysmon on Windows systems, Linux syslog and shell history, web and proxy access logs, Cisco ASA records, two Zeek sensor perspectives, and core/perimeter Snort. Host-specific collection is sensible: Windows hosts receive Windows event sources, Linux hosts receive syslog and bash histories, and dedicated appliances receive native access or network logs.

2. **[schema_or_format] Source-native formatting is generally strong.**  
   Windows records have credible providers, channels, event versions, EventRecordIDs, LogonIds, ProcessGuids, parentage, hashes, and source-specific fields. The Security log clear on `DC-01` is particularly convincing: `wevtutil cl Security` is followed by Event ID 1102 with EventRecordID 1. Zeek records use plausible conn states, histories, UID fan-out, packet accounting, certificate chains, TLS metadata, and protocol-specific logs. ASA build/teardown and translation messages are internally consistent.

3. **[contract_gap — positive finding] Process and session lifecycles are mostly well maintained.**  
   Process creates generally precede dependent module, file, process-access, and flow records, with corresponding termination events. No ECAR child/dependent event was found using a visibly terminated actor, and no process termination was found preceding its visible creation. SSH sessions generally include client process, transport, server-side privileged sshd, login shell, and logout evidence.

4. **[environment_or_collection_plausibility] Cross-sensor visibility behaves like routed enterprise collection.**  
   Internal client-to-proxy traffic appears in both core and DMZ Zeek data with separate UIDs and small timestamp differences, while proxy-to-origin traffic appears in the DMZ/perimeter path. This is more credible than copying one identical record to every sensor.

5. **[schema_or_format] Proxy exfiltration accounting agrees across sources.**  
   At approximately `17:25:13`, the upload from `10.10.1.35` through `10.10.3.20:8080` is represented as:

   - Endpoint ECAR flow from Chrome PID 7460 to the proxy.
   - Proxy CONNECT and inspected POST to `api.westbridge-services.net`.
   - Core and DMZ Zeek client-to-proxy connections with roughly 314.8 MB client bytes and a 4.564-second duration.
   - A proxy-to-`45.33.32.30:443` Zeek connection with about 315.4 MB outbound.
   - ASA build/teardown records reporting approximately 329.8 MB on the inside leg and 331.3 MB on the external leg.

   Differences reflect measurement layers and overhead rather than exact record duplication.

6. **[distribution_texture — positive finding] Benign activity provides genuine hunting friction.**  
   The six-hour window includes 6,218 core and 5,445 DMZ Zeek connections, 12,243 ASA lines, 1,916 proxy entries, hundreds of ordinary web requests, numerous failed inbound scans, DHCP, DNS, TLS/X.509, SMTP, OCSP, file, and PE telemetry, and substantial Windows authentication and filtering-platform noise. The attack is not simply the majority of the corpus.

7. **[environment_or_collection_plausibility] The main intrusion’s timing is operationally coherent.**  
   A malicious upload to `/ehr/admin/upload.php` at `13:19:43` precedes Apache-spawned `www-data` bash at `13:19:46`; the reverse-shell connection to `45.33.32.30:8443` follows immediately. Later discovery, credential access, WMI-executed SYSTEM commands on the DC, account and group changes, service/task persistence, data staging, workstation copy, proxy upload, encoded PowerShell, Security-log clearing, and account deletion occur in valid order.

8. **[weak_signal] Realistic imperfections remain.**  
   IDS visibility is incomplete, endpoint sources do not contain every sibling event, sensor timestamps are not bit-identical, network UIDs differ by sensor, some connections have missed bytes, and visible initiators or companions vary by source. Those are realistic collection properties.

## Detailed Analysis

### End-to-End Discovery

The externally visible intrusion begins with sustained web scanning from `185.70.41.45`, including Nikto-style probes and repeated access to PHP and WordPress paths. At `13:19:43`, that address successfully posts to `/ehr/admin/upload.php`. Roughly three seconds later, Apache spawns a `www-data` bash command that decodes and executes a reverse shell to `45.33.32.30:8443`. Zeek and ASA observe the outbound transport.

Post-compromise discovery includes `cat /etc/hosts`, `cat /etc/resolv.conf`, credential-oriented searches, `cat /var/www/html/config.php`, `cat /root/.ssh/id_rsa`, and `nmap` sweeps from `WEB-EXT-01`. The scan produces core and perimeter IDS evidence, supporting the web-server-to-internal pivot.

On `WS-AJOHNSON-01`, the actor performs `whoami /all`, domain-user and Domain Admin enumeration, and domain browsing. The renamed credential tool `ms-index-service.exe` runs with Mimikatz-style arguments, opens `winlogon.exe` and `lsass.exe`, obtains `0x1FFFFF` access to LSASS, and creates a remote thread.

### Operational Lifecycle Coherence

The main attack sequence is ordered credibly:

- Web upload precedes Apache-spawned shell execution.
- Shell process precedes the corresponding endpoint flow.
- Network-sensor transport opens before or around endpoint visibility and closes coherently.
- Credential-access process precedes its ProcessAccess and remote-thread evidence.
- SYSTEM execution on `DC-01` precedes creation of `svc_mhsync`.
- The account is added to Domain Admins before use on `FILE-SRV-01`.
- Archive creation precedes the SMB copy to the workstation.
- The workstation-side file creation at `17:22:47` precedes the proxy upload at `17:25:13`.
- Cleanup follows exfiltration: encoded PowerShell, `wevtutil cl Security`, Event ID 1102, and domain-account deletion.

The notable exception is the duplicated RDP shell bootstrap on `WS-AJOHNSON-01`. That is the clearest lifecycle-level authenticity defect.

### Pivots and Tradecraft

The dataset supports several distinct pivots:

- External scanner/upload source → `WEB-EXT-01`.
- `WEB-EXT-01` → internal discovery and scanning.
- Remote access into `WS-AJOHNSON-01` from `10.10.1.99`.
- Credential access on the workstation.
- WMI/SYSTEM execution on `DC-01`.
- Domain persistence through `svc_mhsync`, Domain Admin membership, `DeviceSyncSvc`, and an hourly scheduled task.
- Domain-account access to `FILE-SRV-01`.
- SMB staging to the workstation.
- Browser/proxy exfiltration to `api.westbridge-services.net`.
- Security-log clearing and account deletion.

The selected techniques are plausible and the chain spans Linux, Windows, identity, file, and network evidence. The visible use of Chrome for a 315 MB POST and an explicit upload URL is unusual but possible, especially in an interactive intrusion.

### Signal and Noise

Noise is substantial enough to require real pivots. External scanning comes from multiple unrelated addresses and ports, many Snort alerts are irrelevant, and ordinary enterprise DNS/TLS/proxy traffic dominates. Windows filtering-platform Event ID 5156 and Kerberos events create realistic high-volume identity/network background. Routine SSH activity complicates attribution of malicious remote access.

The main weakness is that parts of the noise are recognizable as pooled recipes: repeated root `wget` checks, broad synthetic-looking SaaS target selection, repeated short SSH lifecycles, and shared Windows activity-family composition. Thus the volume is convincing, but its generative texture is sometimes detectable.

### Source Volume and Source-Family Mix

The six-hour corpus is broad without being uniformly populated:

- Core Zeek: 6,218 connections, 2,146 DNS records, 974 HTTP records, plus DHCP, SMTP, SSL, X.509, files, OCSP, and PE.
- DMZ Zeek: 5,445 connections, 1,657 SSL, 1,158 HTTP, 773 DNS, 639 files, 506 X.509, and 45 OCSP.
- Cisco ASA: 12,243 records.
- Snort: 69 core and 136 perimeter alerts.
- Proxy: 1,916 access records.
- Web server: 839 access records.
- Endpoint ECAR ranges from 238 records on the laptop to 6,244 on the DC.
- Windows Security volume appropriately peaks on the DC and file server.

This distribution broadly matches host roles and network vantage points. It avoids the common synthetic error of giving every host every source. The main reservation is the conspicuous recipe reuse inside individual source families, not thinness or lack of source diversity.

## Synthetic Indicator Summary

| Indicator | Label | Weight |
|---|---|---:|
| Two `userinit.exe → explorer.exe` chains for one LogonGuid/session | contract_gap | High |
| Repeated one-shot root `wget`/health-check patterns across Linux servers | distribution_texture | Medium-High |
| Dense, broad SSH administration across many host roles in six hours | environment_or_collection_plausibility | Medium |
| `svc_mhsync` PowerShell spawned by NETWORK SERVICE `svchost.exe` without a visible token transition | contract_gap | Medium |
| Repeated host-family activity recipes | distribution_texture | Medium |
| Highly explicit malicious command lines concentrated on the attack path | weak_signal | Low |
| No confirmed impossible dependent-before-initiator ordering | hard_contradiction | None observed |
| Source formats and field structures generally valid | schema_or_format | Favors real |
| Cross-source byte, tuple, timing, and lifecycle agreement | contract_gap | Strongly favors real |

## Realism Score by Category

| Category | Score |
|---|---:|
| Temporal and Lifecycle Coherence | 8/10 |
| Cross-Source Correlation | 9/10 |
| Tradecraft and Investigative Realism | 8/10 |
| Environment and Collection Plausibility | 7/10 |
| Signal/Noise and Distribution Texture | 7/10 |

## Recommendations

1. Eliminate duplicate session bootstrap paths. Enforce one `userinit.exe` and one primary `explorer.exe` chain per LogonGuid and TerminalSessionId unless a second visible session or explicit restart explains it.

2. Diversify Linux operational activity by workload and host role. Replace broad, repeated bare-URL `wget` checks with stable application-owned services, realistic arguments, local configuration, persistent agents, and endpoint sets appropriate to each server.

3. Reduce repeated short SSH recipes. Model longer-lived administrative sessions, multiplexed commands within one shell, known maintenance windows, failed authentication, interrupted sessions, and user-specific server affinities.

4. Make remote execution token transitions explicit. For service-hosted or WMI-launched commands, expose the service, task, impersonation, logon, or remote-execution context that explains parent principal, child principal, integrity level, and session assignment.

5. Preserve the current network correlation model. The separate sensor UIDs, small timestamp offsets, proxy legs, and measurement-layer byte differences are among the corpus’s strongest authenticity features.

6. Continue adding source-local collection gaps and unrelated operational anomalies, while retaining lifecycle-group coherence. The dataset already avoids perfect one-to-one source mirroring; further variation should target repeated background recipes rather than reducing attack evidence arbitrarily.
