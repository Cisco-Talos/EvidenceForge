# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 86
**Synthetic-Confidence Score:** 68

## Executive Summary

This is a highly realistic dataset with credible host roles, source volumes, background activity, and unusually strong end-to-end correlation across Windows, Linux, Zeek, proxy, firewall, and eCAR telemetry. I nevertheless assess it as synthetic because the logs contain multiple concrete defects that production instrumentation should not produce: successful Samba `opendir` operations against apparent regular files, a network flow beginning after its owning process terminated, and repeated authentication-to-transport correlation gaps in remote-service activity.

## Evidence For Synthetic

- `[hard_contradiction]` FILE-LNX-01 records three successful Samba `opendir` operations against paths that are plainly modeled as regular documents rather than directories: `/srv/samba/ClinicalResearch/Studies/2024/model-validation.csv` at `2024-03-18T14:24:47.813311Z` and `2024-03-18T17:01:25.675107Z`, and `/srv/samba/Shared/Operations/2026/status-update-review.docx` at `2024-03-18T15:54:07.034767Z`. All three `opendir` records in `FILE-LNX-01.../syslog.log` have this defect. A successful directory-open operation on a CSV or DOCX regular file is a source-native semantic contradiction.
- `[hard_contradiction]` In `LOG-MON-01.../ecar.json`, actor `214686b0-acef-48ea-873a-f0539cc78d7f` (`/usr/bin/java -jar /opt/meridian/service-healthcheck.jar --target DC-01...`, PID 739650) terminates at `2024-03-18T17:47:39.136Z` but then owns a new FLOW `CONNECT` at `17:47:39.266Z`. `zeek-core/conn.log` places the corresponding TCP connection to `10.10.1.10:80` even later, at `17:47:39.789773Z`, followed by the OCSP HTTP request at `17:47:39.826773Z`. This is not merely reporting delay: the canonical connection begins after the attributed process is dead.
- `[contract_gap]` Both visible remote-service installations decouple the target Security 4624 source port from every observed transport. For WS-AJOHNSON to DC-01, the `15:59:54.578Z` logon uses source port 59428 and Logon ID `0x5553571`, while the visible SMB and RPC connections use ports 60230 and 60231; port 59428 is absent from the data. For DC-01 to DC-02, the `16:25:27.539Z` logon uses port 59728 and Logon ID `0xcd657aa`, while the visible SMB and RPC connections use 64910 and 64911; port 59728 is likewise absent. The same logon IDs are then used by the 4697 service-install events, making this a repeated activity-family ownership gap rather than a random unrelated logon.
- `[contract_gap]` WS-AJOHNSON records a Type 9 new-credentials logon at `2024-03-18T17:01:07.814Z`, with local user `aisha.johnson`, outbound user `marcus.chen`, and Logon ID `0x27cad98`, but no nearby Security 4648 explicit-credential event. This host's Security channel does collect 4648, and the two other Type 9 sessions in the dataset have 4648 records within 6 ms and 28 ms of their 4624 records. The selective omission occurs on the session used for subsequent SMB access and is inconsistent with the visible collection profile.
- `[distribution_texture]` The 333 Linux shell-history entries contain 60 exact command strings reused across multiple hosts. Common commands account for some overlap, but exact constructions such as `udevadm info --query=property --name=/dev/null | head`, `journalctl --since '10 min ago' --no-pager -n 20`, `iostat -x 1 3`, and `systemd-analyze blame | head` recur across unrelated workstation, application, file-server, and monitoring roles. This looks like a shared finite command pool, although it is a secondary indicator because common runbooks could explain part of the reuse.

## Evidence For Real

- The dataset has believable scale and source composition: approximately 117,000 logical records over six hours, spanning 20 endpoints, three Zeek sensors, perimeter firewall, two IDS sensors, proxy, and web access logs. Source volumes vary materially by role; they are not evenly apportioned among hosts or time buckets.
- The malicious activity remains a needle in substantial baseline traffic. The logs include Kerberos and LDAP chatter, service-account logons, failed authentication, DHCP renewals, DNS, web browsing, package and daemon activity, RDP and SSH, backup traffic, SMB use, proxy tunnels, and an external web scan burst. The 13:30 UTC network-volume spike is attributable to visible scan traffic rather than an unexplained regular generator pulse.
- The PsExec-style path from WS-AJOHNSON to DC-01 is operationally coherent. Zeek records SMB on source port 60230 at `15:59:53.673Z` and RPC on 60231 at `15:59:54.165Z`; DC-01 then records creation of `C:\Windows\PSEXESVC.exe` at `15:59:54.546Z`, a 4624 at `15:59:54.578Z`, service installation at `15:59:54.852Z`, and process execution at `15:59:57.213Z`, with matching eCAR activity.
- The account-persistence sequence on DC-01 has plausible Windows semantics and timing: `net user svc_dirsync ... /add /domain` begins at `16:15:06Z`, followed by 4720, 4724, 4738, and Domain Admins 4728 events from `16:15:10.325Z` through `16:15:14.478Z`. Later service and scheduled-task events use consistent identities and process ancestry.
- Data staging is deeply correlated. The WS-AJOHNSON Type 9 session is reused for access to FILE-SRV-01 and FILE-LNX-01; target logons, share access, object access, Zeek SMB mappings/files, and Samba audit entries agree on actors, targets, paths, and approximate timing. The archive `C:\ProgramData\Microsoft\cache_7f3a.zip` appears in Sysmon and eCAR shortly after collection.
- Exfiltration is technically credible across endpoint, proxy, and network sensors. `curl.exe` starts on WS-AJOHNSON at `17:25:21Z`, reads the staged archive at `17:25:25.074Z`, and opens an endpoint FLOW to proxy `10.10.3.20:8080` at `17:25:25.620Z`. Proxy CONNECT/POST records at `17:25:26Z` show 18,782,977 client bytes, while core/DMZ Zeek records show the client-to-proxy and proxy-to-origin legs with plausible vantage-specific timestamps.
- Proxy state is realistic: 458 tunnel IDs consistently begin with CONNECT and then contain one or more tunneled requests, with tunnel lengths varying from 2 to 11 records. There were no orphan non-CONNECT tunnel records in the examined set.
- Automated lifecycle checks found no Sysmon dependent event before process creation or after process termination. Zeek protocol companions have corresponding connection UIDs and fall inside their connection intervals. The isolated eCAR lifecycle failure therefore stands out against otherwise strong state handling.
- Windows Event 1102 at `17:41:47.818Z` follows `wevtutil` activity, uses the appropriate source-native UserData shape, and is followed by a record-ID reset. File hashes are stable for matching binaries and versions across hosts, while differing versions receive different hashes.
- Linux histories contain human-like typo variants such as `dmseg`, `lls`, `greo`, and `sss`, and activity timing includes bursts, quiet periods, and per-host differences rather than uniformly spaced loops.

## Detailed Analysis

### Environment and collection orientation

The visible period is approximately `2024-03-18T12:00:00Z` through `18:00:00Z`. The environment contains user workstations on `10.10.1.0/24`, Windows and Linux server roles on `10.10.2.0/24`, proxy/DMZ infrastructure on `10.10.3.0/24`, and a database host on `10.10.4.0/24`. Important systems include DC-01/DC-02, FILE-SRV-01, FILE-LNX-01, APP-INT-01, DB-PROD-01, WEB-EXT-01, LOG-MON-01, and multiple named-user workstations.

The source mix is believable for those roles. Zeek core has 10,794 connection records, Zeek DMZ 7,588, and Zeek DB 427. The proxy has 1,926 records, the web server 744, and the perimeter ASA 17,391. Endpoint eCAR volume ranges from a few hundred to several thousand records per host. Windows domain controllers contribute thousands of Security events, while Linux systems contribute syslog and shell history. The differences follow apparent roles and traffic placement rather than a fixed per-host quota.

### Hunt path and operational coherence

The principal chain begins with reconnaissance on WS-AJOHNSON around `15:19Z`, including `net user /domain`, `whoami /all`, and `net group "Domain Admins" /domain`. Around `15:59:53Z`, WS-AJOHNSON reaches DC-01 over SMB and RPC, and DC-01 records a PSEXESVC drop, network logon, service installation, service process, and child `cmd.exe /c whoami && hostname`. With the exception of the unexplained 4624 source port, the order and inter-source timing are mechanically plausible.

At `16:15Z`, WMI-hosted command activity on DC-01 creates `svc_dirsync`, resets its password, updates its account, and adds it to Domain Admins. DC-01 then installs `DeviceSyncSvc`, creates a scheduled task, and begins periodic proxy traffic to `api.westbridge-services.net`. DC-02 receives a similar `DirectoryCacheSvc` installation. This sequence uses plausible privileges, Windows event IDs, process ancestry, and service-control timing.

At `17:01Z`, WS-AJOHNSON creates a new-credentials session for `marcus.chen`, accesses Windows and Linux file shares, stages selected files, and produces `cache_7f3a.zip`. The archive is later uploaded through the explicit proxy at `17:25Z`. Separately, DB-PROD-01 runs `mysqldump`, compresses the export, transfers it to APP-INT-01 using SCP, and stages it onward to FILE-LNX-01 over SMB. These flows are viable given the visible host roles and network paths.

Cleanup at `17:41Z` includes encoded PowerShell activity and Security-log clearing, followed by account and service cleanup near `17:50Z`. The activity is narratively compact, but that compactness was not treated as an authenticity indicator. The verdict rests on source-native and lifecycle defects, not on the ease of reconstructing the chain.

### Cross-source pivot quality

Most pivots are unusually effective without becoming internally impossible. Process GUIDs and PIDs connect Sysmon and eCAR. Zeek UIDs connect `conn.log` to DNS, TLS, HTTP, SMB, and files records. SMB paths connect network telemetry to Windows 5140/5145/4663 records and Linux Samba audit lines. Proxy tunnel identifiers connect client CONNECT requests to tunneled methods, while separate Zeek observations represent proxy ingress and egress.

The two remote-service logon source-port mismatches are the primary cross-source exception. Dense Zeek visibility shows contiguous SMB/RPC transports for both installations, but neither 4624 source port appears. A separate earlier authentication socket is possible in principle, yet seeing the same disconnect in both modeled service installations weakens that explanation. Likewise, the missing 4648 on the attack's Type 9 session is notable because the same host and event family demonstrate that this event is otherwise collected.

### Timing and lifecycle analysis

The dataset generally handles lifecycles well. Process-create and termination records are ordered, network durations and byte fields are nonnegative, protocol records remain within their Zeek connection intervals, and DHCP leases renew near expected fractions of their lease periods with jitter. Cross-sensor copies have small, varying offsets and vantage-specific byte differences instead of bit-identical timestamps and counters.

The LOG-MON-01 health-check actor is a decisive exception. Its termination at `17:47:39.136Z` precedes an eCAR FLOW by 130 ms, the Zeek connection by about 654 ms, and the HTTP request by about 691 ms. Because the flow explicitly retains the terminated actor identity, this cannot be explained as a harmless collector timestamp skew without breaking process ownership.

### Behavioral and source-native texture

The baseline has a credible mix of human, service, maintenance, and network activity. Workstation users browse, authenticate, and launch varied applications; servers exhibit role-appropriate Kerberos, LDAP, database, web, SMB, health-check, and maintenance behavior. External scanning adds a plausible burst without dominating the full window.

Two texture issues remain. Samba reports `opendir|success` on file paths, which is stronger than a stylistic oddity because it violates the operation's semantics. Shell histories also reuse an identifiable collection of exact, moderately specialized commands across unrelated systems. The latter could reflect shared operational runbooks and is weighted lightly, especially because the histories also include typos and host-specific commands.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Impact on score |
|---|---|---|---|
| `hard_contradiction` | Linux Samba/syslog | 3 of 3 `opendir` records on FILE-LNX-01 | Successful directory opens target apparent CSV/DOCX regular files; direct source-native semantic impossibility. |
| `hard_contradiction` | eCAR + Zeek + HTTP | One LOG-MON-01 health-check actor | A new connection and HTTP request begin after the attributed process terminates. |
| `contract_gap` | Windows Security + Zeek/Sysmon | Both observed remote-service installations | 4624 source ports are absent and differ from the SMB/RPC transports whose activity uses the same logon IDs. |
| `contract_gap` | Windows Security | Attack Type 9 session on WS-AJOHNSON | Missing 4648 despite same-host collection and near-immediate 4648 companions for the other Type 9 sessions. |
| `distribution_texture` | Linux shell history | Multiple unrelated Linux roles; 60 shared exact commands | Repetition of several specialized command strings suggests a finite shared pool, but shared runbooks remain a plausible alternative. |

## Realism Score by Category

- **Field format accuracy:** 7/10 — Formats parse cleanly and most source-native fields are strong, but successful Samba `opendir` operations on regular-file paths are a material semantic defect.
- **Temporal patterns:** 7/10 — Volumes, bursts, lease renewals, and sensor offsets are credible, but one attributed flow begins only after its process has terminated.
- **Cross-source correlation:** 7/10 — Most attack and baseline pivots are excellent, while remote-service source-port ownership and the missing Type 9 companion event create repeated gaps.
- **Behavioral realism:** 8/10 — Host roles, tradecraft, noise, and data movement are operationally plausible; repeated Linux command constructions slightly reduce natural texture.
- **Environmental consistency:** 9/10 — Segmentation, role-driven volume, collection mix, and routine service activity fit a coherent mid-sized enterprise environment.

## Recommendations

- If this were synthetic, validate filesystem object type before selecting Samba operations: use `open`/`pread` for regular documents and reserve successful `opendir` for actual directories.
- If this were synthetic, make process termination a hard boundary for actor-owned network activity. OCSP/DNS/HTTP dependencies should complete before the final process-termination event, or the later flow should be attributed to the actual surviving process.
- If this were synthetic, have remote-service bundles preserve one canonical authentication/transport relationship. Either emit the 4624 session's actual TCP tuple and its sensor evidence or bind the logon to the observed SMB/RPC source ports according to Windows session semantics.
- If this were synthetic, emit the Security 4648 companion consistently for Type 9 explicit-credential sessions when that host's audit profile demonstrably collects the event, including the WS-AJOHNSON session used for `marcus.chen` share access.
- If this were synthetic, broaden shell-history generation by persona and host role and reduce exact reuse of specialized multi-argument commands across unrelated systems, while retaining the convincing typo and host-specific behavior already present.
