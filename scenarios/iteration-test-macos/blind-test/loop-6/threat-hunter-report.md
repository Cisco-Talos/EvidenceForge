# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 98  
**Synthetic-Confidence Score:** 87

## Executive Summary

The collection supports a technically coherent hunt across the exposed web host, internal servers, a domain controller, and a user workstation, with endpoint, authentication, proxy, and network evidence that often corroborates. I assess the data as synthetic with high confidence because Sysmon assigns the SHA-1, MD5, and SHA-256 empty-file digests to real executable images, and the eCAR stream repeatedly places failed SSH authentication before the corresponding TCP connection-open event.

## Evidence For Synthetic

- [hard_contradiction] `WS-AJOHNSON-01.meridianhcs.local/windows_event_sysmon.xml` records Sysmon Event ID 1 for `C:\Windows\System32\curl.exe` at `2026-11-02T18:24:53.305Z`, PID 6816, but its `Hashes` field is `SHA1=DA39A3EE5E6B4B0D3255BFEF95601890AFD80709,MD5=D41D8CD98F00B204E9800998ECF8427E,SHA256=E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855`—the empty-file digests. The image path identifies a Windows executable, not an empty file. `DC-01.meridianhcs.local/windows_event_sysmon.xml` repeats the same three digests for `C:\Windows\System32\DeviceSyncSvc.exe`, PID 5336, at `2026-11-02T17:30:05.723Z`. Reusing empty-file hashes for two executable images is a strong source-value defect.
- [contract_gap] In `PROXY-01.meridianhcs.local/ecar.json`, `USER_SESSION/LOGIN` for `svc_mgmt` from `10.10.2.30` is marked `failure` at `16:29:12.310Z`, before its matching `FLOW/CONNECT` (`10.10.2.30:37986` → `10.10.3.20:22`) at `16:29:12.598Z`. The same inversion appears on `DB-PROD-01` (`16:29:01.743Z` failure, then `16:29:02.303Z` flow for `10.10.2.40:35427` → `10.10.4.10:22`) and `APP-INT-01` (`16:29:07.770Z` failure, then `16:29:07.950Z` flow for `10.10.2.21:50902` → `10.10.2.30:22`). A TCP connection must be established before its SSH authentication can fail. The repeated same-stream inversion is more consistent with event timing/ownership drift than independent collection jitter.

## Evidence For Real

- Windows endpoint records carry useful process lineage and correlate: on `DC-01`, Sysmon Event ID 1 and Security Event ID 4688 both capture the `sc.exe create DeviceSyncSvc` and `schtasks.exe /Create ... DeviceSync` sequence at `17:19:47` and `17:19:51`; Security Event 4697 records service installation and Event 4698 contains the task definition at `17:20:04Z`. This gives an analyst actionable pivots across native Windows events.
- The apparent credential probing is corroborated by native Linux authentication logs. For example, `PROXY-01.meridianhcs.local/syslog.log` records `Failed password for svc_mgmt from 10.10.2.30 port 37986` at `16:29:16.402Z`; the eCAR process and flow records use the same account, source, port, and target. Similar failures appear on several distinct servers, giving a plausible distributed lateral-access trail.
- The user-workstation data has a coherent archive-to-egress chain. `WS-AJOHNSON-01` records PowerShell compressing Finance, Clinical, and Research `VaultCache` paths to `C:\ProgramData\Microsoft\cache_7f3a.zip` at `18:01:38Z`, then `curl.exe` reading that archive and connecting to proxy `10.10.3.20:8080` at `18:24:56–18:24:57Z`. `PROXY-01.meridianhcs.local/proxy_access.log` records the matching `POST https://api.westbridge-services.net/upload/telemetry/7f3a2b19` with status `200` and `tunnel_cs_bytes=18783008` at `18:24:57Z`.
- The Linux database staging activity is traceable across endpoint and file-server sources. `DB-PROD-01` eCAR records root creating `/tmp/rpt_0318.sql` with `mysqldump --single-transaction ehr patients insurance_claims` at `18:14:50Z`, compressing it, and SCPing it to `root@10.10.2.30:/tmp/.cache/rpt_0318.sql.gz` at `18:15:15Z`. The destination appears on `APP-INT-01`; shortly after, `FILE-LNX-01` syslog records `svc_mhsync` opening, writing, and closing `ClinicalResearch/Integration/DB-Staging/rpt_0318.sql.gz` from `10.10.2.30` at `18:18:32Z`, also visible in Zeek `smb_files.json` as a 16,211-byte write. The sources permit meaningful host, identity, and file pivots.
- Baseline telemetry includes service activity, DNS, Kerberos, syslog forwarding, failed inbound probes, and user/admin command histories across the visible Linux, Windows, and Mac hosts. The collection includes multiple source families; the verdict does not rely on its completeness or the attack activity being easy to narrate.

## Detailed Analysis

### Initial access and lateral movement

On `WEB-EXT-01`, eCAR shows `www-data` starting a base64-decoding shell pipeline at `14:19:59.940Z`; the decoded command opens a reverse shell to `45.33.32.30:8443`. `zeek-dmz/conn.json` records the matching `10.10.3.10:36170` → `45.33.32.30:8443` session at `14:20:03.077Z` as `SF`, with 620 originator and 1,840 responder bytes. Later, `WEB-EXT-01` eCAR records root reading `/root/.ssh/id_rsa` at `15:00:17.134Z`. These records show plausible progression, while the available logs do not establish how the root context was obtained.

At about `16:29Z`, `svc_mgmt` authentication failures and SSH connection attempts appear across several hosts. Native syslog confirms the failures and source ports, while eCAR adds host process and flow context. The eCAR ordering defect documented above affects the event chronology, but does not erase the broader activity trail.

### Domain-controller persistence and outbound contact

On `DC-01`, a SYSTEM-owned `WmiPrvSE.exe` parent launches `cmd.exe` to create `DeviceSyncSvc` at `17:19:47.058Z`; the child `sc.exe` command is visible in both Security 4688 and Sysmon Event 1. At `17:19:51Z`, SYSTEM creates the hourly `\\Microsoft\\Windows\\Maintenance\\DeviceSync` task and a service record naming `C:\\Windows\\System32\\DeviceSyncSvc.exe`. Security Event 4698 supplies the task XML. The service image executes under `services.exe` at `17:30:05.723Z`. Later, SYSTEM launches encoded PowerShell at `18:41:49.558Z`; its decoded intent is a `DownloadString` request to `api.westbridge-services.net/v2/manifest`, and eCAR records an outbound connection from `10.10.2.10` to `10.10.3.20:8080` at `18:41:54.009Z`. These are strong hunt leads. The empty-file hashes attached to executable images lower confidence in the fidelity of the Windows artifact values.

### Data staging and egress

The `rpt_0318.sql.gz` name and path connect the database dump, root SCP transfer, APP-INT receipt, and Samba staging write. The SMB activity is independently represented by `FILE-LNX-01` syslog and Zeek `smb_files.json`. Separately, Aisha Johnson’s archive and upload are backed by process/file events, native Windows Event 4688 and Sysmon Event 1, the proxy’s TLS-inspected POST, and a successful `200` response. The upload targets finance, clinical, and research cache paths and transfers about 18.8 MB, which is concrete evidence of potentially sensitive data egress rather than an inference from a suspicious domain name alone.

### Collection behavior and defects

The logs span approximately `13:00–19:00Z` on 2 November 2026 and cover Windows endpoints/domain controllers, Linux servers, two Mac endpoints, perimeter and core Zeek sensors, Snort, firewall, proxy, and web access logs. There is enough routine and adverse activity to make pivots useful. The strongest authenticity concern is a specific field-level defect, not source volume: Sysmon’s image hash triplets for the two named executable images are exactly the well-known empty-file digests. A second independent concern is repeated connection/authentication ordering inversion in eCAR for failed SSH attempts. These defects suggest synthetic or incorrectly materialized records even though many behaviors and cross-source links are credible.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected the score |
|---|---|---|---|
| `hard_contradiction` | Windows Sysmon Event 1 | At least `WS-AJOHNSON-01` PID 6816 at 18:24:53Z and `DC-01` PID 5336 at 17:30:05Z | Both nonempty executable images carry SHA-1/MD5/SHA-256 values for empty input; the repeated sentinel triplet is a direct field-level contradiction. |
| `contract_gap` | eCAR Linux SSH session/flow events | Multiple `svc_mgmt` failures around 16:29Z | On multiple hosts, authentication failure is timestamped before the same connection's FLOW/CONNECT, although TCP establishment precedes SSH authentication. |

## Realism Score by Category

- **Field format accuracy:** 5 — Most records are structured and usable, but empty-file digests on Windows executable images are a major field-value defect.
- **Temporal patterns:** 7 — Multi-hour background activity is varied, with a repeated SSH flow/authentication inversion lowering the score.
- **Cross-source correlation:** 8 — Process, file, SMB, proxy, and network pivots often align well; the SSH ordering inconsistency is localized but recurring.
- **Behavioral realism:** 8 — The logs include plausible administration, reconnaissance, persistence, and data staging actions with diverse background activity.
- **Environmental consistency:** 7 — Host roles and many flows fit the apparent mixed environment; sensitive archive/dump activity merits investigation but alone does not prove synthetic origin.

## Recommendations

- If synthetic, populate Sysmon `Hashes` from the actual executable image bytes or use the source-native unavailable representation. Do not emit empty-input digests for a known executable. Verify the `curl.exe` and `DeviceSyncSvc.exe` values against their Event ID 1 records and eCAR counterparts.
- If synthetic, timestamp the SSH FLOW/CONNECT at transport establishment before the associated failed authentication event. Preserve the same source tuple and event identity across eCAR and syslog so pivots have a valid causal order.
- If synthetic, retain the strong cross-source data-flow anchors seen here: archive creation/read and proxy upload, plus database dump/SCP receipt and Samba write. They make the hunt actionable; the quality fixes should preserve those relationships.
