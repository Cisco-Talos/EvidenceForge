# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 63  
**Synthetic-Confidence Score:** 64

## Executive Summary

The dataset has a broad mixed-platform footprint and multiple technically coherent pivots across endpoint, authentication, network, proxy, firewall, and file-audit sources. One material collection inconsistency is visible on APP-INT-01: eCAR records a successful root SSH session from WEB-EXT-01, but the host's syslog has no matching sshd acceptance or PAM session-open record during that visible interval. This lowers authenticity confidence, though a single missing authentication record does not establish that the dataset is synthetic.

## Evidence For Synthetic

- [contract_gap] On APP-INT-01, `ecar.json` lines 299–302 record an inbound TCP/22 flow from `10.10.3.10:59707`, an `sshd: root [priv]` process, a successful `USER_SESSION LOGIN` for `root` from the same tuple, and a `-bash` child at 2026-11-02 15:15:12–15:15:18 UTC. `ecar.json` lines 863–868 show a second successful root SSH session from `10.10.4.10:35261` at 18:15 UTC, with an SSHD process, file transfer, and logout. The corresponding `syslog.log` lines 110–150 cover the first interval and include ordinary host messages, but no `Connection from`, `Accepted password/publickey`, or `pam_unix(sshd:session): session opened` for that root session; lines 214–215 record only the close for the second root session, without a matching open or acceptance. The same syslog does record complete sshd/PAM sequences for other users. Both starts are visible in eCAR within the covered interval, so these are not absent pre-window initiators.

## Evidence For Real

- WEB-EXT-01's `ecar.json` line 827 records a `www-data` bash process at 14:19:59.940 UTC with a base64-decoded reverse-shell command; line 828 records its outbound tuple `10.10.3.10:36170 → 45.33.32.30:8443` at 14:20:03.041. `zeek-dmz/conn.json` line 1996 observes that tuple at 14:20:03.077 as an `SF` connection lasting 2.857 seconds, and `fw-perimeter/cisco_asa.log` lines 4831 and 4834 show the matching connection build and teardown. The web access record at 14:19:58 shows a successful `POST /ehr/admin/upload.php` immediately before the process event.
- Windows activity has source-native support across EDR, Sysmon and Security logs. On WS-AJOHNSON-01, Sysmon records the `ms-index-service.exe "privilege::debug" "sekurlsa::logonpasswords" exit` process at 16:44:49.945 UTC, Security 4688 records the same command at 16:44:50.298, and eCAR records the process plus LSASS access and a remote thread in `lsass.exe` (lines 734–744). This is a concrete host pivot; it is not inferred from the command string alone.
- The 18:24:53 UTC WS-AJOHNSON-01 `curl.exe` event is corroborated by its eCAR file-read and proxy flow, then by PROXY-01 lines 3518–3519: the same client tuple and `curl/8.4.0` upload a 18,783,008-byte archive to the API endpoint, with HTTP 200. The proxy's tunnel ID binds the CONNECT and POST records.
- The Linux transfer trail is similarly traceable: DB-PROD-01 eCAR records a database dump, gzip, and SCP of `rpt_0318.sql.gz` to APP-INT-01; the receiving SSH activity and later FILE-LNX-01 Samba audit records show the same filename staged by `svc_mhsync`. DB-PROD-01 `syslog.log` also records the root SSH authentication from APP-INT-01 and its PAM session lifecycle.
- Mac evidence is source-aware. MAC-MROSS-01 Unified Log records an Apple System Policy denial for `MeetingAssist` at 15:42:17 UTC. I found no corresponding successful execution or side effect in the supplied Mac eCAR or Endpoint Security records; the denial is not treated as proof of execution. MAC-MROSS-02 Unified Log records an accepted SSH authentication for maya.ross from `10.10.1.41`, while its Endpoint Security export declares version 11 and includes native process observations. The shell histories show Maya's SSH pivots among modeled hosts.
- The surrounding records include routine service, user, network, and file activity: Windows process and authentication events, Linux systemd/sshd/Samba messages, ordinary web requests, proxy traffic, and substantial Zeek connection/DNS/HTTP records. This provides a plausible background and source mix for the visible activity; matching records are treated as corroboration, not as a synthetic tell.

## Detailed Analysis

### Scope and collection window

The supplied directory contains Windows Security and Sysmon exports, eCAR endpoint records, Linux syslog and shell histories, macOS Endpoint Security and Unified Log exports, two Zeek network views plus a smaller database view, Snort alerts, perimeter ASA logs, proxy access records, and web access logs. The inspected event timestamps cluster on 2026-11-02, with visible activity spanning roughly 13:00–19:00 UTC. The environment includes Windows workstations and domain controllers, Linux application/database/file/web servers, two Macs, and internal network and security infrastructure.

### Operational and lateral-movement pivots

The web-facing sequence is technically coherent across layers: a successful upload request to WEB-EXT-01 is followed by a `www-data` child shell and an outbound TCP/8443 connection. The Zeek tuple and ASA build/teardown agree with the endpoint tuple and timing. Later, APP-INT-01 eCAR shows a successful root SSH session originating from WEB-EXT-01, followed by root shell commands including reads of `/etc/passwd` and `/etc/shadow`. That receiving host's native syslog omission for this session is the principal authenticity concern described above.

A later root session on APP-INT-01 connects to DB-PROD-01. DB-PROD-01 syslog records `Accepted password for root from 10.10.2.30` at 18:14:42 UTC and a PAM session open. The database host then creates and compresses `rpt_0318.sql`, and SCPs it to APP-INT-01. FILE-LNX-01 Samba audit and Zeek SMB file records show the same archive written into the `ClinicalResearch/Integration/DB-Staging` share a few minutes later. These are plausible pivots among the hosts and accounts shown, and the records preserve useful user, address, filename, and timing links.

### Windows activity

WS-AJOHNSON-01 shows a credential-access sequence under `aisha.johnson`: the process command line names `privilege::debug` and `sekurlsa::logonpasswords`, and eCAR records access to PID 4292 (`lsass.exe`) and a remote thread. DC-01 later shows SYSTEM-context WMI-launched process creation for a service and scheduled task named `DeviceSyncSvc`/`DeviceSync`, followed by service execution. At 18:41:49 UTC, DC-01 Sysmon and Security logs show an encoded PowerShell command that downloads a manifest from the same API endpoint used in later proxy observations. Separately, the workstation's curl upload at 18:24:53 UTC has matching proxy evidence. These high-risk events are explicit, but their clarity or coverage is not counted as evidence of synthetic generation by itself.

### Mac and SSH source semantics

The two Mac hosts provide distinct native sources: a small Unified Log export, Endpoint Security notifications with version 11, eCAR, and timestamped zsh history. On MAC-MROSS-01, Unified Log's policy-denial message establishes that a process launch was disallowed; it does not establish a child process or its effects. On MAC-MROSS-02, the Unified Log's SSH acceptance and endpoint process observations can be used as separate pivots, while the shell history provides operator context. The histories include ordinary inventory commands alongside SSH destinations; no missing shell command or absent Mac artifact was scored without a required companion relationship.

Linux SSH records also provide useful source-native lifecycle examples. DB-PROD-01 logs the root password acceptance, PAM session opening, and later session close. APP-INT-01 logs other successful password/public-key SSH and PAM sequences, which makes its missing native record for the earlier eCAR root session more salient than a generic collection limitation.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `contract_gap` | APP-INT-01 eCAR and Linux syslog/sshd | One visible successful root SSH session from WEB-EXT-01, 2026-11-02 15:15 UTC | Two successful root SSH sessions and their tuples are present in eCAR, but destination syslog shows no matching auth/session-open records and only one later close; other users have logged acceptance/PAM lifecycles. This repeated source-consistency defect is the main reason the verdict leans synthetic. |

## Realism Score by Category

- **Field format accuracy:** 8 — Sampled Windows, Zeek, Linux SSH, proxy, and Mac-native records use plausible source-specific fields and values.
- **Temporal patterns:** 7 — The sampled process, connection, auth, and file-transfer orderings are plausible; the APP-INT-01 authentication gap weakens one lifecycle.
- **Cross-source correlation:** 7 — Several independent pivots align on tuple, process, filename, or time; the APP-INT-01 root SSH session is a notable exception.
- **Behavioral realism:** 7 — Background activity and operational activity coexist with clear malicious behavior, and the visible host/account roles generally fit the actions.
- **Environmental consistency:** 7 — The mixed Windows/Linux/macOS fleet and network collection are coherent overall, with one source-family inconsistency on APP-INT-01.

## Recommendations

If this were synthetic, preserve matching APP-INT-01 sshd/PAM acceptance and session-open records for the visible 15:15 and 18:15 UTC root logins, or make the collection gap explicit in the host's observable coverage. No other improvement is recommended from the reviewed log-visible evidence.
