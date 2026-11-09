# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 78  
**Synthetic-Confidence Score:** 68

## Executive Summary

The dataset contains usable, mutually corroborating incident trails, including a web-server reverse shell and a staged collection-and-upload sequence from WS-AJOHNSON-01. The strongest synthetic signal is a source-local process-visibility gap around the WEB-EXT-01 reverse-shell pipeline; repeated manual diagnostic commands across unrelated Linux hosts add a weaker distribution signal. Those defects support a synthetic verdict, while the observed cross-source agreement is substantial evidence of careful construction and is not itself a synthetic indicator.

## Evidence For Synthetic

- [contract_gap] On WEB-EXT-01, eCAR records PID 2702831 as `/bin/bash`, parent PID 23966, running `bash -c 'echo ... | base64 -d | bash'` at 2026-11-02 14:20:10.078Z. The same host's eCAR records its outbound connection to 45.33.32.30:8443 at 14:20:21.987Z, but no `echo`, `base64`, or nested `bash` process creation appears in the surrounding endpoint records. The same dataset records child processes for ordinary shell pipelines such as `ss -tanp | grep ESTAB | head` on PROXY-01 at 18:44:46Z, making the selective absence around this explicit multi-process pipeline a source-local visibility inconsistency.
- [distribution_texture] Human-attributed diagnostics repeat across otherwise distinct Linux servers. For example, Aisha Johnson runs `systemctl list-timers --all --no-pager`, `iptables -L -n -v`, `vmstat 1 5`, and `apt-cache policy openssl` on multiple hosts, including MAIL-EDGE-01, LOG-MON-01, PROXY-01, DB-PROD-01, and FILE-LNX-01. Priya Patel and Marcus Chen likewise perform repeated service-status, disk, and log checks across server roles. Each command is plausible in isolation; the repeated cross-host manual pattern weakens the variation in the visible admin activity.

## Evidence For Real

- The Linux web-shell event has a matching endpoint-to-network pivot: WEB-EXT-01 eCAR records the encoded reverse-shell command under `www-data` at 14:20:10.078Z, then a process-attributed flow from 10.10.3.10:46759 to 45.33.32.30:8443 at 14:20:21.987Z. The perimeter firewall logs build and teardown for the same tuple at 14:20:20 and 14:20:34, respectively.
- The Windows collection and outbound transfer sequence is cross-source coherent. WS-AJOHNSON-01 process records show `runas.exe /netonly`, creation of the VaultCache staging directories, copies from Finance, ClinicalExports, and ClinicalResearch shares, archive creation at 18:01:39Z, and curl upload at 18:24:58Z. eCAR ties the upload to `aisha.johnson`, PID 6716, the archive read, and the connection from 10.10.1.35:59155 to proxy 10.10.3.20:8080. PROXY-01 records the corresponding authenticated POST to `api.westbridge-services.net/upload/telemetry/7f3a2b19` at 18:25:01Z with `curl/8.4.0` and 18,783,258 client bytes; the firewall records a 19,733,300-byte outbound connection shortly after.
- On DC-01, Sysmon/eCAR process records show `net user svc_dirsync ... /add /domain` followed by adding the account to Domain Admins, and later deleting it. This is a coherent privileged account lifecycle with visible process lineage; the account action itself is suspicious, but the joins do not indicate a synthetic defect.
- The Linux database-to-file movement is also traceable: DB-PROD-01 root history shows `mysqldump`, gzip, and scp of `rpt_0318.sql.gz`; APP-INT-01 eCAR records creation/read of the received file; and FILE-LNX-01 Samba audit, eCAR, and Zeek SMB records show the same object written under `ClinicalResearch/Integration/DB-Staging` from 10.10.2.30.

## Detailed Analysis

### Scope and collection window

The visible fleet spans Windows domain controllers and workstations, Linux application, database, mail, proxy, file, and monitoring servers, two macOS endpoints, and core/DMZ/database Zeek sensors, perimeter firewall, proxy, and Snort logs. The principal Zeek/eCAR activity runs on 2026-11-02 across roughly 13:00–19:00 UTC. I assessed lifecycle relationships only within the visible window: a missing pre-window start or post-window close alone is not synthetic evidence, and complete cross-source joins alone are not synthetic evidence.

### Linux web host and outbound activity

At 14:20:10.078Z, WEB-EXT-01 eCAR attributes the encoded `bash -c` reverse-shell pipeline to `www-data` (PID 2702831; parent 23966). The attributed connection to 45.33.32.30:8443 follows at 14:20:21.987Z. Cisco ASA records the corresponding connection from 10.10.3.10:46759 to 45.33.32.30:8443, built at 14:20:20 and torn down at 14:20:34 after 13 seconds and 4,970 bytes. The process-to-flow timing and tuple are credible. The narrower authenticity defect is that the endpoint source records no pipeline child processes in the incident sequence even though eCAR on other Linux hosts does record constituent child processes for routine pipelines.

### Windows credential and data movement trail

On WS-AJOHNSON-01, a `runas.exe /netonly` process appears at 18:00:32.860Z, followed by PowerShell activity that stages files from Windows and Linux shares into `C:\ProgramData\Microsoft\VaultCache` and writes `cache_7f3a.zip` at 18:01:43Z. At 18:24:58Z, curl reads that archive and connects via the proxy. The proxy log records the matching authenticated POST at 18:25:01Z, with the same source port 59155 and high client-to-server byte count. The alignment is unusually easy to pivot through, but under the study rules that completeness is not a synthetic indicator on its own. The file/process sequence, identities, time ordering, and upload bytes agree across the visible sources.

### Domain account activity

DC-01 records the creation of `svc_dirsync` and addition to `Domain Admins` at 17:15:22Z and 17:15:29Z, with the corresponding `cmd.exe` → `net.exe` process lineage under SYSTEM. It later records account deletion around 18:49:57Z. These operations are high risk but technically plausible on a domain controller when executed in a SYSTEM context. I found no impossible visible ordering in these records.

### Repeated Linux diagnostics

Across MAIL-EDGE-01, LOG-MON-01, PROXY-01, DB-PROD-01, and FILE-LNX-01, the eCAR stream contains the same administrator names executing a recurring set of host inspection commands, including `systemctl list-timers --all --no-pager`, `iptables -L -n -v`, `vmstat 1 5`, and package-version checks. Admins can legitimately work across multiple servers, so this is a weak signal rather than a contradiction. Its repeated command set across mail, proxy, database, and file roles contributes to a synthetic texture concern.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `contract_gap` | Linux eCAR process telemetry | WEB-EXT-01 reverse-shell pipeline at 14:20:10Z | Strongest indicator: explicit shell pipeline produces a correlated network flow but lacks visible child process records, despite the same source recording children for routine pipelines elsewhere. |
| `distribution_texture` | Linux eCAR process telemetry | Repeated administrator diagnostics across at least five server roles | Weak supporting signal: the same interactive commands recur across unrelated operational roles with limited variation. |

## Realism Score by Category

- **Field format accuracy:** 8 — Host, user, process, and network fields support practical pivots; no decisive source-native error was established in this review.
- **Temporal patterns:** 8 — The selected attack sequences have plausible ordering and bounded durations; no isolated absent start/close was scored.
- **Cross-source correlation:** 9 — Endpoint, proxy, firewall, Zeek SMB, and Samba evidence agree on key tuples, identities, times, and objects.
- **Behavioral realism:** 6 — Multiple plausible behaviors appear, but repeated hand-run diagnostic commands reduce variation across Linux server roles.
- **Environmental consistency:** 7 — The mixed fleet and observed source families are coherent; the web-host process visibility gap remains unexplained by the visible records.

## Recommendations

- If this were synthetic, emit the child process records for the `echo`, `base64`, and nested `bash` stages of the WEB-EXT-01 reverse-shell command, or model the source visibility so this activity is consistently represented with other shell pipelines.
- If this were synthetic, vary the Linux administrator command mix and host targeting across mail, proxy, database, and file-server roles; retain the current cross-source transfer relationships where they are supported by matching records.
