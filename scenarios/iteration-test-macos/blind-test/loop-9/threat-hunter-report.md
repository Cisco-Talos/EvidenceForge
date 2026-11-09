# Threat Hunter Blind Authenticity Review — Loop 9

## Verdict

**Likely synthetic log bundle.** The telemetry is detailed and cross-source-consistent, but the incident content reads like deliberately authored, highly legible training activity. This is an authenticity judgment, not a claim that the observed behaviors would be harmless in a real environment.

## Verdict Confidence (0–100)

**88**

## Synthetic-Confidence Score (0–100; lower is more production-like)

**82**

## Executive Summary

The bundle contains strong, actionable evidence of a probable compromise of **DC-01** and a separate sensitive-data staging event involving **DB-PROD-01**. On DC-01, WS-AJOHNSON-01 / `aisha.johnson` is tied to a PSEXESVC installation and a remote command; later, WMI-launched commands create `svc_dirsync`, add it to Domain Admins, install `DeviceSyncSvc`, and register an hourly SYSTEM task. An encoded PowerShell command subsequently retrieves a manifest from `api.westbridge-services.net`; the Security log is then cleared. Windows Security, Sysmon, eCAR, proxy, and Zeek records corroborate the main steps.

Separately, `root` on DB-PROD-01 dumps the `ehr` database's `patients` and `insurance_claims` tables, compresses the output, and copies it over SSH to APP-INT-01. APP-INT-01 then writes the same named archive to FILE-LNX-01's ClinicalResearch DB-Staging share under `svc_mhsync`. This is confirmed internal staging of sensitive data; the reviewed window does not establish onward external transfer.

The clear naming and unusually explicit progression of the two incident chains make an authored exercise more likely than routine production collection. The credible ambient activity, varied native formats, and coherent lifecycle evidence are meaningful production-like traits. Cross-source alignment is treated as evidence of technical quality, not as a synthetic indicator by itself.

## Evidence For Synthetic

- **Authored-looking incident vocabulary and payloads:** the new account `svc_dirsync` is created with a visible fixed password (`[redacted]`), placed in Domain Admins, followed by a service named `DeviceSyncSvc` and a matching `DeviceSync` scheduled task. This is a conspicuously readable set of names and actions for one incident chain.
- **Highly explicit teaching sequence:** PSEXESVC runs `whoami && hostname`; later commands create and elevate an account, add service and task persistence, make an encoded external manifest request, and clear the Security log. Each step is unusually easy to interpret from command lines and event fields.
- **Purpose-labeled data staging:** the archive `rpt_0318.sql.gz` is created from explicitly named patient and insurance tables, copied to a hidden-looking `.cache` path on APP-INT-01, then written to a `ClinicalResearch/Integration/DB-Staging` share. The sequence is plausible, but its naming makes the exercise intent unusually transparent.
- **Bounded capture envelope:** many host records fall within the same six-hour period. This is weak evidence because a deliberate collection window can have the same shape; it does not drive the verdict.

## Evidence For Real

- **Substantial ordinary background:** Windows service and endpoint activity, Linux service messages and shell histories, browser/proxy traffic, external web requests, DNS, SMB, mail, database flows, and perimeter alerts appear alongside the incident behavior.
- **Native source detail:** Windows Security and Sysmon retain different event schemas; Linux syslog and Samba audit lines carry service/session detail; proxy logs distinguish CONNECT from inspected requests; Zeek records retain connection and file metadata.
- **Plausible lifecycle ordering:** source-side process and transport, target authentication/session evidence, process execution, service/task creation, transfer, and termination are generally ordered coherently. Key identities and tuples are supported across sources.
- **Plausible incident tradecraft:** remote service execution, WMI-launched commands, domain persistence, proxy-routed HTTPS check-ins, and internal staging of a compressed database export could all occur in a real compromise. The capture contains no decisive source-format or timeline contradiction in the reviewed chain.

## Detailed Analysis

### DC-01 probable compromise

- At **16:59:56–17:00:00 UTC**, eCAR on WS-AJOHNSON-01 records `10.10.1.35` connecting to DC-01 on SMB and RPC. DC-01 eCAR records those inbound connections. DC-01 Security event **4624** records `aisha.johnson` logging on from `10.10.1.35`; event **4697** records installation of `PSEXESVC` by that account. Security event **4688** and Sysmon event **1** show `PSEXESVC.exe` followed by `cmd.exe /c whoami && hostname`.
- At **17:14:45–17:14:55 UTC**, DC-01 eCAR, Security events **4688**, **4720**, and **4728**, and Sysmon event **1** agree on creation of `svc_dirsync` and its addition to Domain Admins. The process chain is `WmiPrvSE.exe` → `cmd.exe` → `net.exe` and runs as SYSTEM. A clear-text password appears in the process command line.
- At **17:19:47–17:20:04 UTC**, DC-01 records `DeviceSyncSvc` creation as LocalSystem and creation of `\Microsoft\Windows\Maintenance\DeviceSync` as an hourly SYSTEM task. Sysmon later records the service binary starting at **17:30:05 UTC**.
- At **18:41:49 UTC**, DC-01 eCAR, Security event **4688**, and Sysmon event **1** record an encoded PowerShell `DownloadString` command for `https://api.westbridge-services.net/v2/manifest`. The proxy records the matching CONNECT and a successful **200** GET at **18:41:52 UTC** from `10.10.2.10`. DC-01 then records `wevtutil cl Security`; Security event **1102** follows at **18:41:53 UTC**. This is high-confidence malicious behavior and evidence of log tampering, not just an anomalous command.

### DB-PROD-01 sensitive-data staging

- At **18:14:30–18:14:43 UTC**, DB-PROD-01 records a root SSH session from APP-INT-01 (`10.10.2.30`). Its shell history then records queries for databases and tables followed by `mysqldump --single-transaction ehr patients insurance_claims`, `gzip`, and `scp` to `root@10.10.2.30:/tmp/.cache/rpt_0318.sql.gz`.
- DB-PROD-01 eCAR records the dump and archive creation, the archive read by `scp`, and an outbound TCP/22 flow from `10.10.4.10:35261` to `10.10.2.30`. APP-INT-01 records the corresponding inbound SSH flow, accepted root public key, session, and archive creation.
- About three minutes later, APP-INT-01 reads that archive and opens SMB to FILE-LNX-01 (`10.10.2.21`). Zeek SMB records a write of `Integration\\DB-Staging\\rpt_0318.sql.gz`; FILE-LNX-01 syslog and eCAR record a successful `svc_mhsync` write to `/srv/samba/ClinicalResearch/Integration/DB-Staging/rpt_0318.sql.gz`. This establishes transfer to an internal share. No later external transmission of this archive is demonstrated in the reviewed window.

## Synthetic Indicator Summary with Categories

| Category | Indicator | Weight |
|---|---|---|
| Scenario content and naming | Readable fixed account, password, service, task, C2 host, and staging path combine into unusually self-explanatory incident artifacts. | Strong |
| Behavior composition | The explicit probe → domain-admin account → service/task persistence → manifest fetch → Security-log clear chain is highly curated. | Strong |
| Data staging labels | Explicit PHI table names and a purpose-named internal staging directory make the second chain unusually legible. | Moderate |
| Capture distribution | A shared bounded six-hour window is present, but can result from capture scope and is not decisive. | Weak |
| Cross-source correlation | Corroboration is strong and helps validate event semantics; it is not counted as synthetic evidence on its own. | Neutral |

## Realism Score by Category

Scores assess how production-like the logs appear in each area (0 = poor, 100 = strong).

| Category | Score | Rationale |
|---|---:|---|
| Lifecycle coherence | 88 | Sessions, processes, services, scheduled task, and transfer activity are mostly ordered and correlated. |
| Signal-to-noise | 76 | Ordinary host, network, mail, web, and user activity surrounds the high-signal behavior. |
| Pivot quality | 92 | Host, user, IP, port, process, account, and file pivots connect endpoint, network, and storage evidence. |
| Tradecraft realism | 70 | Techniques are plausible, though the naming and step-by-step clarity feel exercise-authored. |
| Collection/environment realism | 82 | Multiple source families and native event details create credible environmental context. |
| Source-format realism | 89 | Sysmon, Windows Security, syslog, proxy, Zeek, and Samba records use distinct source-native forms. |
| Overall production likeness | 74 | Strong telemetry fidelity, reduced by conspicuously curated incident content. |

## Recommendations

1. Treat DC-01 as compromised for response purposes: isolate it, preserve remaining volatile and endpoint evidence, validate the `svc_dirsync` account and its group membership, and review/remediate `DeviceSyncSvc` and the hourly task.
2. Investigate WS-AJOHNSON-01 and the identity `aisha.johnson` as the initial observed source. Review authentication, admin-share/RPC use, credentials, and other hosts accessed from the workstation.
3. Investigate the repeated proxy activity to `api.westbridge-services.net`, including responses and TLS/DNS records, and search for the same domain, URI, service, task, and account on DC-02 and other systems.
4. Preserve the cleared Security-log evidence from endpoint, forwarded, and centralized records. Validate whether event 1102 and the encoded PowerShell command were received by independent collectors.
5. Treat the DB-PROD-01 export as a sensitive-data incident. Establish authorization and ownership for the root SSH session and `svc_mhsync` transfer, preserve the archive and share audit trail, and determine whether any downstream access or transfer occurred outside this window.
6. For authenticity assessment, retain the strong environmental background and native-source detail while reducing overly explanatory names and combining several attack steps into less pre-labeled, independently observable activity.
