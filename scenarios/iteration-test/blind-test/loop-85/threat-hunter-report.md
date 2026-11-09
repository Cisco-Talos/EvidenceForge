# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive  
**Verdict Confidence:** 62  
**Synthetic-Confidence Score:** 52

## Executive Summary

The strongest cross-source pivots agree: Lina Nguyen’s support upload on WS-LNGUYEN-01 appears in shell history, endpoint events, and Zeek HTTP and file records; a root database dump from DB-PROD-01 is staged on APP-INT-01 and written to a file share. DC-01 also shows high-impact domain changes and an encoded PowerShell download, but the visible logs do not identify a remote user or host responsible for the initial SYSTEM activity.

## Evidence For Synthetic

- **[contract_gap]** On DC-01, Sysmon shows WmiPrvSE launching commands that create `svc_dirsync`, add it to Domain Admins, and create `DeviceSyncSvc`. Security logs show these actions as `SYSTEM`, but the nearby 4624 records do not identify a remote source for the activity. This leaves the origin unclear; it does not prove the events are fabricated.
- **[weak_signal]** The same host later runs encoded PowerShell that downloads `https://api.westbridge-services.net/v2/manifest` as SYSTEM. The proxy records the corresponding GET with no user agent, while ordinary Westbridge requests elsewhere use browser user agents. That variation could be operationally meaningful, but it is not by itself evidence of synthetic data.

## Evidence For Real

- **[weak_signal]** WS-LNGUYEN-01 shell history records Lina creating `/tmp/mhs-support-48217.tar.gz` and uploading it through the configured proxy. Endpoint events record the tar creation, archive read, and outbound flow; Zeek records a POST to `support.valeworks-health.net` returning HTTP 200 and identifies the same archive at 1,572,864 bytes.
- **[weak_signal]** DB-PROD-01 history and endpoint events agree on a root `mysqldump` of `ehr patients insurance_claims`, gzip compression, and SCP to APP-INT-01. On APP-INT-01, endpoint events record the received archive and an `smbclient` upload; Zeek records an SMB write to `\\FILE-LNX-01\ClinicalResearch\Integration\DB-Staging\rpt_0318.sql.gz`, size 191,097 bytes, with no missing bytes.
- **[distribution_texture]** The sampled data includes ordinary administration alongside suspicious activity: for example, APP-INT-01 shows SSH sessions, sudo maintenance commands, and DNS/system processes. The observed volume and mix do not reduce to only the conspicuous actions.
- **[environment_or_collection_plausibility]** The two macOS hosts show normal user activity and a corporate endpoint-inventory LaunchDaemon path. The visible shell histories do not show a download or execution that would establish malware activity, and plist creation alone does not establish activation.

## Detailed Analysis

- **2026-11-02 17:14:30–17:14:43 UTC, DC-01:** Sysmon process events show `WmiPrvSE.exe` launching commands to add `svc_dirsync` with the password `MhsSvc!2024`, then add the account to Domain Admins. Security events 4720, 4724, 4738, and 4728 corroborate the account and group changes. The visible Security log attributes them to `SYSTEM`; nearby logon events do not show a remote account or source address for this sequence.
- **2026-11-02 17:19:52–17:29 UTC, DC-01:** Security event 4697 records service `DeviceSyncSvc` pointing to `C:\Windows\System32\DeviceSyncSvc.exe`; event 4698 records an hourly task invoking the same path. Sysmon later records that executable starting. The logs establish installation and execution, but the initial service/task commands are attributed to SYSTEM.
- **2026-11-02 18:41:51–18:41:54 UTC, DC-01:** Sysmon and Security event 4688 record encoded PowerShell running as SYSTEM. The command decodes to an `IEX` invocation of `Net.WebClient.DownloadString` for the Westbridge manifest. The proxy records a matching GET at 18:41:54 with status 200 and 3,666 response bytes. The adjacent proxy record has no user agent.
- **2026-11-02 18:15–18:19 UTC, DB-PROD-01 to APP-INT-01 and FILE-LNX-01:** Root history records the database dump, gzip, and SCP. Endpoint events on DB-PROD-01 and APP-INT-01 match those operations. Zeek SMB records the subsequent write to the ClinicalResearch share. The transfer is concrete, but the logs alone do not establish whether it was authorized.
- **2026-11-02 18:12–18:13 UTC, WS-LNGUYEN-01:** Lina’s history records archive creation and a curl upload. Endpoint and Zeek records corroborate the command, archive name, destination, successful response, and byte count. This is a strong example of consistent source correlation.

## Synthetic Indicator Summary

The clearest authenticity concern is the unattributed SYSTEM activity on DC-01: high-impact domain changes, service/task installation, and a later encoded download are visible, but the initiating remote identity is not. The rest of the reviewed pivots are internally consistent across host and network records. These logs support an inconclusive assessment; they do not establish that the collection is synthetic.

## Realism Score by Category

- **Field format accuracy — 8/10:** Endpoint JSON, Windows XML, shell history, syslog, and Zeek records have plausible source-specific fields and usable values.
- **Temporal patterns — 8/10:** The sampled command and network sequences align in time, including both file transfers. DC-01’s SYSTEM activity lacks a visible remote source attribution.
- **Cross-source correlation — 9/10:** The support archive and database dump each correlate across host activity and network/file records, including matching names and transfer details.
- **Behavioral realism — 6/10:** Routine administration is present, but the DC-01 account, privilege, persistence, and download activity warrants investigation; visible logs do not identify who initiated it.
- **Environmental consistency — 7/10:** Proxy, SMB, domain, and host activity form a plausible enterprise environment. The supplied evidence does not establish whether Westbridge is an approved destination or service.

## Recommendations

- Attribute the DC-01 WMI activity to a source host and account using the relevant WMI, logon, or management-platform records.
- Confirm whether `svc_dirsync`, `DeviceSyncSvc`, and the `DeviceSync` scheduled task are approved. The logs show the account joined Domain Admins and the executable ran as SYSTEM.
- Verify whether the Westbridge manifest download and repeated Westbridge connections are authorized. The 18:41 SYSTEM request is corroborated by the proxy.
- Validate the root database export and SMB staging action against change or transfer records, since the logs show a production database dump written to a ClinicalResearch share.
