# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 74
**Synthetic-Confidence Score:** 59

## Executive Summary

This is a broad, six-hour mixed-fleet collection with credible Linux, Windows, macOS, endpoint, proxy, firewall, Zeek, and IDS evidence. The high-impact activity is operationally plausible and unusually well corroborated, so I do not score its completeness or ease of narration as a synthetic clue. My main synthetic signal is the repeated, narrow Mac shell-survey routine across two hosts, with a few additional signs of templated operator texture; without a hard contradiction, the synthetic-confidence score stays in the inconclusive-to-likely-synthetic range.

## Evidence For Synthetic

- [distribution_texture] `MAC-MROSS-01` and `MAC-MROSS-02` histories repeatedly use the same small ordered set of host-survey commands (`sw_vers`, `uname -a`, `pwd`, `ls -la ~/Documents`, `du`, `df`, `ps`, `find ... '*.pdf'`, `ifconfig`, `dscl`). The sets recur across both machines during the 13:00–19:00 UTC window, separated by SSH hops. The repeated command-pool texture is more regular than varied day-to-day user work would usually be, though it could reflect a shared support checklist.
- [weak_signal] Both Mac histories contain recurring SSH hops among a small set of internal systems (`WEB-EXT-01`, `DB-PROD-01`, `APP-INT-01`, and the other Mac) interleaved with near-identical environment checks. This is possible for an administrator, but the repeated sequence contributes to the impression of templated user activity.
- [weak_signal] The Linux support upload and Windows archive upload both use compact task-like identifiers and explicit upload paths (`MHS-48217` and `7f3a2b19`). Each is plausible on its own and I do not treat shared identifiers as a defect; the authored-looking naming contributes only slightly to the score because the logs do not show a relationship between these two operations.

## Evidence For Real

- Source families and volumes fit a midsize enterprise with Windows directory services, workstations and file/mail servers; Linux application, database, file, monitoring, and mail systems; two Macs; and network sensors. The files cover roughly 13:00–19:00 UTC, and their event volumes vary by host and source rather than presenting a uniform count.
- Background evidence is present across platforms: Windows logons, process and allowed-connection events; Linux SSH, sudo, systemd/journald, cron and service activity; macOS Endpoint Security observations and routine shell work; Zeek DNS/HTTP/SMB/TLS; proxy, ASA, and Snort records. This provides useful signal-to-noise rather than making every record part of the suspicious activity.
- The Aisha Johnson trail on `WS-AJOHNSON-01` has plausible stages: domain enumeration around 16:20, PowerShell archive creation at 18:01:38, a file copy at 18:16:15, and a `curl.exe` upload at 18:24:53–18:24:58. The endpoint records show the file read and outbound proxy flow. Proxy access at 18:24:57 records a CONNECT and POST by `MERIDIANHCS\aisha.johnson` to the same host and path, returning HTTP 200 and reporting 18,783,008 client bytes. Zeek sees the client CONNECT to `api.westbridge-services.net:443` at 18:24:57, and the DMZ sensor records the proxy's outbound TLS connection at 18:24:58 with that SNI.
- On `DC-01`, the 17:14:45 `cmd.exe`/`net.exe` process chain creates `svc_dirsync`; Windows Security records Event 4720 at 17:14:49 and Event 4728 adding the account to `Domain Admins` at 17:14:54. The account is removed at 18:50. This is a plausible privilege-persistence lifecycle, not an impossible field or ordering.
- A separate database collection path is visible. `DB-PROD-01` records a root `mysqldump` of `ehr patients insurance_claims` at 18:14:49, gzip creation at 18:14:57, and SCP to `10.10.2.30` at 18:15:11. `APP-INT-01` resolves that SSH session from `10.10.4.10`, writes `/tmp/.cache/rpt_0318.sql.gz`, then opens an SMB session to `10.10.2.21` and reads the staged file. `FILE-LNX-01` records a matching write by `svc_mhsync` to `/srv/samba/ClinicalResearch/Integration/DB-Staging/rpt_0318.sql.gz` at 18:18:34. The destination address and file path align across endpoint and file-server evidence.
- `WS-LNGUYEN-01` separately shows Lina archiving EHR connector logs and submitting them as a multipart diagnostics attachment via the proxy at 16:32. It is possible this is legitimate support activity, but the host, ticket, archive, and remote upload are all inspectable in the logs and fit the apparent clinical environment.

## Detailed Analysis

### Scope and collection window

The Windows exports include Security and Sysmon from two domain controllers, several workstations, a Windows file server, and a finance mail server. The Linux hosts provide eCAR, Syslog, and selected bash histories; the Macs provide eCAR, Endpoint Security NDJSON, Unified Log NDJSON, and zsh histories. Network coverage includes core, database, and DMZ Zeek views, proxy access, Cisco ASA, and Snort. The observed timeline runs from about 13:00 to 19:00 UTC on 2026-11-02. It is a one-day slice, so longer-term baselines and out-of-window lifecycle records cannot be evaluated.

### Directory-service activity and discovery

At 16:20 on `WS-AJOHNSON-01`, Aisha's Security process records show `whoami /all`, `net user /domain`, `net group "Domain Admins" /domain`, and `net view /domain`. Roughly an hour later, `DC-01` records `WmiPrvSE.exe` launching `cmd.exe` and `net.exe` to add `svc_dirsync` with an exposed command-line password, then add it to `Domain Admins`. Security 4720 and 4728 records confirm the user and group changes. A deletion at 18:50 is visible. The commands, actor context, and event order form a credible directory-administration or intrusion sequence; command-line password exposure is a security concern but not an authenticity defect.

### File collection and outbound transfer

The `WS-AJOHNSON-01` System32 `curl.exe` command reads `C:\ProgramData\Microsoft\cache_7f3a.zip` and posts it to `api.westbridge-services.net/upload/telemetry/7f3a2b19` through proxy `10.10.3.20:8080`. EDR, Sysmon, and Security place the process and file activity at approximately 18:24:53–18:24:58. At the same second, proxy access records a CONNECT and subsequent POST with the same URL path and user agent, a 200 status, and about 18.8 MB of client data. Zeek observes the CONNECT and TLS session, while the ASA records outbound proxy traffic. This is a strong multi-source pivot with plausible source/proxy/perimeter semantics.

A separate Linux trail starts on `DB-PROD-01`: a root dump of two sensitive database tables, compression, and SCP to `10.10.2.30`. The SSH session arrives on `APP-INT-01` from `10.10.4.10`; the receiving host creates `/tmp/.cache/rpt_0318.sql.gz`. About three minutes later it reads that file over SMB to `FILE-LNX-01`, where the corresponding `svc_mhsync` write lands under `ClinicalResearch/Integration/DB-Staging`. The network and endpoint timing support each transition. `10.10.2.30` is resolved in Zeek DNS as `APP-INT-01` during the window.

Lina's earlier support archive is a separate transfer. `WS-LNGUYEN-01` creates `/tmp/mhs-support-48217.tar.gz` from EHR connector logs and runs a multipart `curl` through the corporate proxy to `support.valeworks-health.net`. Her shell history contains the archive and upload commands. The logs make this behavior worth investigating, but without additional evidence it could be an authorized diagnostics submission.

### Network activity and noise

Zeek DNS contains a concentrated run of TXT queries from `10.10.2.30` to changing subdomains under `ns1.westbridge-services.cloud`, with variable-looking labels and answers. The same host later resolves `api.westbridge-services.net`; proxy access also shows repeated GET/CONNECT activity to that host from other clients. This is consistent with suspicious beaconing or DNS transfer, but the aggregate can also include multiple host roles or collection activity. I treat it as malicious-looking behavior, not evidence of synthetic generation.

The surrounding Zeek and proxy traffic includes ordinary application, certificate-status, browsing, DNS, and SMB activity. Windows source counts are heavier on domain controllers and much smaller on endpoints; Linux/macOS eCAR volumes also vary. This is a plausible source-family distribution for the visible fleet, and I do not penalize it for not containing every possible event type.

### Distribution texture

The main weakness is in the Mac zsh histories. Both Mac hosts repeatedly show the same environment-check commands with similar ordering, mixed with SSH hops to the same internal systems. The commands are individually ordinary and may reflect support work, but their narrow repeated set makes the user activity look generated from a shared checklist. I found no proven impossible ordering or source-native contradiction in the high-impact Windows/Linux/network trails reviewed here.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected the score |
|---|---|---|---|
| `distribution_texture` | macOS zsh histories | `MAC-MROSS-01` and `MAC-MROSS-02`, several cycles | Repeated ordered host-survey commands across both hosts suggest a narrow replayed command pool. |
| `weak_signal` | macOS zsh histories | Maya Ross's internal SSH hops | Same small set of host-to-host hops repeatedly interleaved with the same survey commands adds templated texture. |
| `weak_signal` | Linux/Windows command and file labels | Separate support and archive transfers | Compact task IDs and upload names look authored, but no log evidence ties the operations together, so the score impact is small. |

## Realism Score by Category

- **Field format accuracy:** 8 — The reviewed Security, Sysmon, eCAR, Zeek, proxy, and firewall records contain usable source-native fields and values.
- **Temporal patterns:** 8 — The key process, file, authentication, proxy, and network steps are ordered plausibly; baseline timing is varied.
- **Cross-source correlation:** 9 — The Aisha proxy upload and the DB-to-APP-to-file-server transfer have detailed, timestamped pivots across endpoint and network sources.
- **Behavioral realism:** 7 — Privilege changes and sensitive collection are plausible; repeated Mac survey routines are the clearest unnatural behavior.
- **Environmental consistency:** 8 — The mixed enterprise/clinical fleet, identity use, network zones, and source volumes are broadly credible.

## Recommendations

If this were synthetic, vary the Mac shell histories with host-specific command choices and less repeated ordering. Give the separate support diagnostics and archive-upload activities distinct naming styles unless the logs establish a shared ticket or response workflow. Preserve the existing end-to-end source, proxy, DNS, Zeek, and perimeter correlation; those records are useful and the inspected pivots are technically coherent.
