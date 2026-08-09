# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 84  
**Synthetic-Confidence Score:** 68

## Executive Summary

The endpoint corpus is technically sophisticated: Windows process, logon, Sysmon, and eCAR lifecycles are mostly source-native and internally coherent, while Linux SSH/PAM sequences and shell histories contain convincing operational detail. The deciding defect is a repeated impossible caller-lifecycle relationship on `WS-DRAMIREZ-01`, where Security 4648 explicit-credential events identify PowerShell processes that Security 4689, Sysmon Event 5, and eCAR all agree had already terminated; broader workstation-role and Linux-session distributions add moderate synthetic texture.

## Evidence For Synthetic

- `[hard_contradiction]` On `WS-DRAMIREZ-01`, Security 4648 at `2024-03-18T13:05:10.1360714Z` says PID `0x1a74` (`6772`), `powershell.exe`, attempted explicit credentials for `MERIDIANHCS\svc_monitor` against `APP-INT-01`. Security 4689 records that PID terminating at `13:04:40.4957410Z`, and Sysmon Event 5 terminates ProcessGuid `{5af96291-3bb4-65f8-4c02-0000e477fc87}` / PID `6772` at `13:04:40.7268083Z`. The purported caller had been dead for about 29.4 seconds.
- `[hard_contradiction]` The same defect repeats on `WS-DRAMIREZ-01`: PID `0x1c94` (`7316`) is created for `C:\Scripts\backup-check.ps1` at `15:25:55.3157283Z`, terminated by Security 4689 at `15:26:16.4514040Z` and Sysmon Event 5 at `15:26:16.6347723Z`, yet Security 4648 at `15:26:33.8056581Z` attributes a `svc_backup` credential attempt to that PID approximately 17.2 seconds after termination. eCAR independently places that process's `TERMINATE` at `15:26:18.812Z`.
- `[environment_or_collection_plausibility]` Infrastructure credential activity is unusually widespread across ordinary employee workstations. In six hours, `WS-DRAMIREZ-01`, `WS-EBROOKS-01`, `WS-MCHEN-01`, `WS-PPATEL-01`, and `WS-SMARTINEZ-01` all generate SYSTEM-owned 4648 events using `svc_backup` or `svc_monitor` toward mail, database, proxy, web, application, file, and domain-controller hosts. Examples include `WS-PPATEL-01` running `C:\Scripts\backup-check.ps1` against `MAIL-EDGE-01` at `13:55:18Z`, and `WS-SMARTINEZ-01` using the same script against `APP-INT-01`, `WEB-EXT-01`, `MAIL-FIN-01`, and `MAIL-CLIN-01`. A fleet deployment is possible, but backup and monitoring callers placed across user endpoints with apparently arbitrary targets and service identities is weakly aligned with their host roles.
- `[distribution_texture]` The Linux desktop systems show an unusually dense pool of generic local PAM sessions. During the six-hour window, `WS-OHADDAD-01` has 12 `pam_unix(login:session)` opens, `WS-LNGUYEN-01` has 11, and `LT-MRIVERA-02` has 9. These are dominated by overlapping `root`, `admin`, and `ubuntu` sessions rather than the named workstation owners. For example, `WS-OHADDAD-01` opens root at `14:10:13Z`, ubuntu at `14:19:01Z`, admin at `14:25:31Z`, and later additional root/ubuntu sessions at `15:56:56Z`, `16:33:14Z`, `17:13:59Z`, `17:14:39Z`, and `17:33:31Z`. This resembles a generic session-noise pool more than normal single-user workstation activity.
- `[weak_signal]` Several generic administrative identities (`admin`, `ubuntu`, `ops`, `backup`, `deploy`, `svc_app`) perform interchangeable troubleshooting commands across unrelated Linux roles. The commands are individually valid, but the cross-host texture—repeated `systemctl`, `journalctl`, `ss`, `iostat`, `find`, and package-status activity from the same generic identity set—does not develop much durable host- or operator-specific behavior.

## Evidence For Real

- Windows source formatting is strong. Security events use appropriate provider GUIDs, versions, task/opcode values, named fields, hexadecimal PIDs and logon IDs, and source-specific structures. The DC's `1102` event at `17:42:29.6787301Z` correctly uses `Microsoft-Windows-Eventlog`, places the subject in the `LogFileCleared` `UserData` namespace, and is followed by the expected Security `EventRecordID` reset to `1` and then `3`.
- Security 4688 and Sysmon Event 1 correlate extremely well without obvious field corruption. Across the nine Windows systems, matching PID/image pairs generally differ by only a few milliseconds; all 171 creates on `DC-01`, all 101 on `FILE-SRV-01`, all 106 on `MAIL-FIN-01`, and all creates on most workstations matched. The small source-specific omissions on a few hosts are more believable than forced universal equality.
- Sysmon lifecycles are well maintained. Among all known ProcessGuid relationships, I found no Sysmon Event 3/7/8/10/11/13/22 record occurring before its process create or after its termination. ProcessGuid termination pairs also preserve positive lifetimes.
- eCAR identity ownership is convincing. Across all 18 hosts, no record whose `actorID` resolves to a process created in-window occurs before that process's creation or after its termination. Parent and source UUIDs, PIDs, principals, paths, and command lines remain coherent across process, file, registry, module, and flow records.
- Process trees are source-appropriate: `services.exe` launches service-hosted agents; `svchost.exe` launches `WmiPrvSE.exe`, `taskhostw.exe`, and `dllhost.exe`; `SearchIndexer.exe` launches SearchProtocolHost/FilterHost; `explorer.exe` launches user browsers, SSH clients, and `mstsc.exe`; and Linux `sshd` launches privileged monitor processes followed by user shells.
- Binary hashes are stable per image and software/OS cohort rather than being randomly regenerated per execution. For example, the workstation cohorts consistently share their respective `svchost.exe`, `conhost.exe`, `taskhostw.exe`, and PowerShell hash sets, while server and alternate workstation cohorts carry different but internally stable sets.
- Logon lifecycles have realistic type diversity. Windows systems contain service Type 5, network Type 3, interactive Type 2, remote-interactive Type 10, and unlock Type 7 activity. Matched Type 3 sessions are mostly short, while Type 2/10 sessions persist for hours. Unmatched service and interactive sessions at corpus boundaries are expected in a six-hour window and were not treated as defects.
- Linux SSH sequences are source-native and ordered. On `MAIL-CLIN-01`, the session beginning `12:04:36.651685Z` shows connection from `10.10.1.35:56966`, public-key acceptance at `12:04:38.931923Z`, PAM open at `12:04:39.064035Z`, logind session creation at `12:04:39.814292Z`, PAM close at `12:08:41.438627Z`, and logind removal at `12:08:42.252457Z`.
- Shell histories are meaningfully role-dependent. `lina.nguyen` uses Git, pytest, Docker, Kubernetes, and repeated SSH from her Linux workstation; `marcus.chen` performs service and network administration; and the database root history performs `mysqldump`, gzip, size checks, and SCP. The DB eCAR records preserve the same `/tmp/rpt_0318.sql.gz` object from gzip creation through SCP read.

## Detailed Analysis

### Windows process and Sysmon evidence

The Windows records contain 921 Sysmon Event 1 process creates distributed across nine systems. The Security/Sysmon matching behavior is very strong: matched process PIDs, paths, principals, command lines, parents, and timestamps agree, normally within roughly ±20 milliseconds. eCAR process-create observations have a separate, plausible collection delay, generally below about 1.4 seconds, with occasional source-specific omissions.

Parent-child relationships are mostly credible. User browsers and remote-access clients originate from `explorer.exe`; service processes originate from `services.exe` or the correct service host; console helpers originate from `csrss.exe`; and Search components originate from SearchIndexer. Within eCAR, all actor references that resolve to an in-window process stay inside that process's lifecycle.

The strongest contradiction is isolated to explicit-credential timing on `WS-DRAMIREZ-01`. For PID 6772, three sources place the lifetime around `13:03:48.6Z`–`13:04:40.7Z`, but Security 4648 claims credential use at `13:05:10.136Z`. PID 7316 similarly ends around `15:26:16.5Z`–`15:26:18.8Z`, before a 4648 at `15:26:33.806Z`. No intervening PID reuse or second process creation is visible. Because 4648 identifies the process that attempted the logon, these are source-native causal inversions, not mere collection completeness issues.

### Authentication and session lifecycle

Windows network logons generally pair correctly. Examples on workstations have Type 3 durations in the tens of seconds, while RDP and interactive sessions extend for hours. Lock/unlock records reuse the interactive logon ID as expected. Service Type 5 sessions commonly remain open beyond the bounded window, which is normal and was not penalized.

The eCAR USER_SESSION object lifecycle is also coherent: matched login/logout object IDs never invert. Orphan logouts near the beginning of the dataset on Linux mail/proxy systems and several Windows hosts are compatible with sessions begun before `12:00Z`.

The explicit-credential population is behaviorally less persuasive. DC and server-side Veeam, monitoring-agent, osquery, and Wazuh callers are reasonable. The same service-account pattern appearing repeatedly from employee workstations via generic `backup-check.ps1` and `service-health.ps1` calls is harder to reconcile with normal endpoint roles, especially where one process services multiple unrelated infrastructure targets over long intervals.

### Linux host evidence

RFC 5424 structure, priorities, process names, PIDs, PAM wording, and daemon messages are generally accurate. SSH activity shows appropriate connection, acceptance/failure, PAM, logind, shell, and close phases. PIDs advance coherently per host and remain within Linux limits, even on high-uptime systems such as `PROXY-01`.

The strongest Linux weakness is distributional rather than a hard schema fault. The three Linux workstations repeatedly create local `login` and `su` sessions for generic root/admin/ubuntu identities. Their frequency, overlap, and lack of strong association with the named workstation owners make the machines look populated by a reusable noise model. Server sudo messages show similar cross-role reuse of `ops`, `backup`, `deploy`, `svc_app`, and `ubuntu`, although individual command syntax and PAM open/close timing are valid.

Shell histories are substantially better. Commands are timestamped, vary by operator, and correlate with eCAR process/file/flow evidence. Concurrent shell history chunks can explain occasional non-monotonic timestamps, so those were not scored as defects.

### Higher-value endpoint correlations

The DC sequence at `16:00Z` contains convincing source-level evidence: PSEXESVC file creation by `services.exe`, Security 4697 service installation, PSEXESVC process start, and child `cmd.exe`. Later account creation/password change/group membership, service/task creation, audit-log clearing, record-ID reset, and account deletion are all represented with plausible native fields and ordering. This completeness was treated as positive/neutral, not as evidence of synthesis.

Likewise, the database archive lifecycle is coherent: `mysqldump` creates `/tmp/rpt_0318.sql`, gzip creates `/tmp/rpt_0318.sql.gz`, and SCP later reads that same eCAR file object before an outbound SSH flow. This is strong identity and ownership continuity.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected the synthetic-confidence score |
|---|---|---|---|
| `hard_contradiction` | Windows Security, Sysmon, eCAR | Two 4648 events on `WS-DRAMIREZ-01` | The named caller PIDs had already terminated 29.4 and 17.2 seconds earlier, confirmed independently by multiple endpoint sources. |
| `environment_or_collection_plausibility` | Windows Security/Sysmon | Five employee workstations | SYSTEM-owned backup/monitoring scripts and agents repeatedly use infrastructure service credentials toward unrelated server roles from ordinary endpoints. |
| `distribution_texture` | Linux syslog/PAM | Three Linux workstations | 9–12 local login opens per workstation in six hours, mostly overlapping root/admin/ubuntu sessions rather than owner sessions. |
| `weak_signal` | Linux syslog and eCAR | Multiple servers/workstations | A common set of generic accounts and interchangeable troubleshooting commands recurs broadly with limited durable operator/host specialization. |

## Realism Score by Category

- **Field format accuracy:** 9 — Windows XML, Sysmon, RFC 5424 syslog, and eCAR shapes are source-appropriate, including the native 1102 `UserData` structure and record-ID reset.
- **Temporal patterns:** 6 — Most process, SSH, and logon lifecycles are excellent, but the two post-termination 4648 events are decisive temporal faults and Linux local-session density is weak.
- **Cross-source correlation:** 8 — PID, image, GUID, object, hash, and file continuity are very strong; the explicit-credential caller inversion is the important exception.
- **Behavioral realism:** 6 — User shell histories and process trees are differentiated, but generic Linux sessions and fleetwide workstation backup/monitoring behavior look pooled.
- **Environmental consistency:** 6 — Server roles and service placement are generally coherent, while user workstations acting as broad infrastructure credential callers reduce plausibility.

## Recommendations

- If this were synthetic, generate Security 4648 at the actual credential-use instant while the caller process is alive. Enforce an invariant that the referenced PID/ProcessGuid exists at the 4648 timestamp and that any dependent network/auth activity precedes process termination.
- Tie explicit-credential patterns to declared endpoint roles. Backup, monitoring, and management service identities should normally originate from dedicated management servers or clearly configured administrative workstations, not be sprayed across employee endpoints without host-specific justification.
- Make the caller function agree with its command and target. Avoid cases where `backup-check.ps1` alternates between `svc_backup` and `svc_monitor` across unrelated mail, web, database, and application systems unless the logs expose a concrete operational reason.
- Reduce generic PAM `login`/`su` session generation on Linux workstations. Favor the named owner, desktop/session-manager behavior, realistic lock/unlock or suspend/resume activity, and a smaller number of durable administrative sessions.
- Diversify Linux administrative identities and command behavior by host ownership and role. Preserve the current source-native PAM formatting, but give operators stable specializations and reduce interchangeable use of `admin`, `ubuntu`, `ops`, `backup`, `deploy`, and `svc_app` across the fleet.
