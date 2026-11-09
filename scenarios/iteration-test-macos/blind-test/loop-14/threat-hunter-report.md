# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 66
**Synthetic-Confidence Score:** 53

## Executive Summary

This is a multi-source, mixed Windows, Linux, and macOS collection covering roughly 13:00–19:00 UTC on 2026-11-02. The suspicious operations on DC-01, the proxy, and Linux endpoints are technically coherent and cross-source timing is strong; that coherence supports operational realism but is not, by itself, evidence of synthetic data. A moderate synthetic score reflects the repeated generic Linux host-inspection command texture across many user histories, while the supplied records do not establish a hard source-native contradiction.

## Evidence For Synthetic

- [distribution_texture] Linux shell histories across otherwise distinct systems and users repeatedly use the same short host-inspection vocabulary—`ps aux`, `df -h`, `hostname`/`hostnamectl`, `systemctl`, `journalctl`, `uptime`, and `/proc` or `/etc` checks. Examples include `LOG-MON-01` histories for Marcus and Aisha, `APP-INT-01` for Lina and Aisha, and `DB-PROD-01` for Marcus and Maya. The commands are plausible individually, but the density and reuse of this generic checklist-like pool across many hosts makes the background activity feel templated.
- [weak_signal] Both Mac endpoints show a narrow, highly coordinated process-exit burst followed by user logout: `MAC-MROSS-01` exits multiple Chrome, Slack, login, and Terminal processes from 18:54:59.703–18:55:00.948 UTC, then logs Maya out at 18:55:01.020; `MAC-MROSS-02` exits Chrome, iTerm, Zoom, Word, and Outlook processes from 18:56:58.584–18:57:00.132, then logs her out at 18:57:03.134. A user logout can explain each local burst, so this is only a weak signal; the similar near-end timing on two machines is the part that looks staged.

## Evidence For Real

- The Windows attack activity has believable native companions. On DC-01, Security Event 4720 records creation of `svc_dirsync` at 17:14:36.236 UTC, Event 4724 follows at 17:14:37.616, and Event 4728 records its addition to Domain Admins at 17:14:40.683. Process creation records show `net user` and `net group` under `WmiPrvSE.exe`; the account is later deleted in Event 4726 at 18:50:06.782.
- DC-01 persistence is corroborated by Sysmon process creation and Security events: `sc.exe create DeviceSyncSvc` at 17:20:28, Event 4697 at 17:20:32, and Event 4698 for `\Microsoft\Windows\Maintenance\DeviceSync` at 17:20:41. The executable starts later as SYSTEM. Separately, DC-02 records a `DirectoryCacheSvc` installation by `marcus.chen` at 17:24:48 and a short service-process lifetime immediately afterward.
- At 18:41:51 UTC, DC-01 runs an encoded PowerShell command that decodes to an `IEX`/`WebClient.DownloadString` request for `https://api.westbridge-services.net/v2/manifest`. The same process opens a flow from 10.10.2.10 to the modeled proxy 10.10.3.20:8080; proxy logs at 18:41:55 record the corresponding HTTPS request, and the perimeter firewall and Zeek also show the proxy path. Security Event 1102 follows the visible `wevtutil cl Security` command at 18:41:57.
- Other suspicious transfer evidence is operationally plausible. `WS-LNGUYEN-01` history shows Lina packaging EHR connector logs and submitting them to a support endpoint at 16:39–16:40 UTC. Later, the proxy records a successful 18.7 MB POST from Aisha’s workstation to an upload path on the same API domain at 18:24:57. On `DB-PROD-01`, root history shows a database dump, compression, and SCP to an internal address. These are strong hunting leads, but the records do not make them synthetic indicators by themselves.
- There is substantial ordinary activity and protocol variety: Windows authentication and process telemetry, Linux service and shell activity, Mac Endpoint Security events, proxy browsing, Zeek DNS/HTTP/TLS/SMB/SMTP, firewall connection records, web access, and perimeter alerts. Source timestamps and network tuples generally make pivots feasible.

## Detailed Analysis

### Scope and source mix

The data covers about 23 named endpoint/server hosts across Windows, Linux, and macOS, plus network sensors. Most host and sensor records fall in the six-hour window beginning near 13:00 UTC on November 2. Endpoint records include Windows Security/Sysmon and eCAR, Linux syslog/history and eCAR, and two Mac Endpoint Security exports, Unified Log excerpts, histories, and eCAR. Network evidence includes core/DMZ Zeek, proxy, ASA, and Snort.

### Privilege and persistence trail

DC-01 provides a clear account and persistence sequence. At 17:14:32 UTC, its process records show `cmd.exe` running `net user svc_dirsync … /add /domain` under SYSTEM with `WmiPrvSE.exe` as parent; Security Events 4720, 4724, 4738, and 4728 document account creation, password handling, and Domain Admins membership. This is a strong privilege-escalation indicator. At 17:20:28, another SYSTEM command creates `DeviceSyncSvc` pointing into `C:\Windows\System32`; Event 4697 records the service and Event 4698 records a similarly named hourly scheduled task targeting that executable. The service process appears later at 17:29:10.

At 17:24:48 on DC-02, Event 4697 records `DirectoryCacheSvc` installed by `marcus.chen`, and eCAR shows the service process start at 17:24:50 and terminate about six seconds later. The short lifetime could represent a failed or one-shot service; the records do not prove that its executable was newly dropped during the visible window.

The initiating context for the DC-01 WMI-launched commands is not fully visible as a user action. I do not treat the absent initiator alone as a defect: collection can begin after an operation starts, and the WMI process could have been invoked locally. The visible order of the process and Security events is consistent.

### Command and network pivots

The later DC-01 PowerShell command is followed by network evidence at the expected destination. EDR reports the process flow to 10.10.3.20:8080 at 18:41:55; proxy access records the `/v2/manifest` request for `api.westbridge-services.net` on that connection; Zeek records the corresponding inside-to-proxy HTTP connection; and the ASA shows the client-to-proxy connection plus the proxy’s outbound HTTPS connection. The encoded command’s use of `IEX` is suspicious, but the successful flow and content retrieval fit the observed behavior.

The same host’s check-ins to `/api/v2/checkin` appear in the proxy log at variable intervals beginning 17:29:55, with changing response sizes. That pattern begins after the DeviceSyncSvc persistence event and continues through the visible window. At 18:41:53, Sysmon records the SYSTEM `wevtutil cl Security` command; Event 1102 is recorded at 18:41:57. The file still contains earlier Security events, which is compatible with a central event collection/archive and is not a contradiction without evidence that this is a post-clear local-only export.

Other transfer pivots include the Lina shell-history archive-and-upload commands at 16:39–16:40 and the Aisha workstation’s much larger successful upload at 18:24:56–18:24:57. The `DB-PROD-01` root history also shows a named EHR database dump and SCP to 10.10.2.30. The latter destination is internal, so the history alone does not establish external exfiltration.

### Background texture and limits

Many Linux histories contain plausible operations, but across distinct identities and roles they repeatedly lean on generic machine checks and service inspection. This is the strongest authenticity concern because it affects the baseline texture rather than the malicious narrative. Conversely, some records contain human-like variation, such as the `journapctl` typo in Marcus’s `LOG-MON-01` history and differing user workflows. I found no clear impossible source ordering or field value. The small number of Unified Log rows per Mac is not scored: the records do not establish that those files are full Unified Log exports, and sparse coverage alone is not a valid indicator.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `distribution_texture` | Linux bash histories | Repeated generic host-inspection and service-check commands across users and multiple unrelated hosts | Main reason for a moderate synthetic score; repeated vocabulary looks templated, though every command is individually plausible. |
| `weak_signal` | macOS eCAR process/session records | Two hosts | Similar near-end clusters of application exits and logout on both Macs look staged, but each cluster is locally explained by logout and is not a hard defect. |

## Realism Score by Category

- **Field format accuracy:** 8 — Windows, Zeek, proxy, Linux, and declared-version macOS ES records look source-native in the sampled events.
- **Temporal patterns:** 7 — The main Windows and proxy pivots line up; the repeated generic command texture and paired Mac logout timing are mild concerns.
- **Cross-source correlation:** 9 — Account, process, flow, proxy, firewall, and Zeek evidence support practical pivots; completeness itself is not counted as a synthetic tell.
- **Behavioral realism:** 7 — Suspicious actions are plausible, and there is background activity, but Linux operator histories reuse a narrow generic checklist.
- **Environmental consistency:** 8 — The mixed fleet and source roles are broadly coherent; the records do not prove a contradictory collection scope.

## Recommendations

- If this were synthetic, broaden and differentiate Linux command histories by user role and host purpose. The repeated generic checks across `APP-INT-01`, `LOG-MON-01`, `DB-PROD-01`, and other Linux systems are the clearest visible texture issue.
- If this were synthetic, make the paired Mac logout timing less similar across endpoints, or include naturally staggered user-session exits when the activity model calls for separate workstations.
