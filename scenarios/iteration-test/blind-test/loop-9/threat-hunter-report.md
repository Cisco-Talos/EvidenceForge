# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Real
**Verdict Confidence:** 61
**Synthetic-Confidence Score:** 29

## Executive Summary

The supplied telemetry is mostly production-like from a hunting perspective: the suspicious activity can be followed through technically plausible process, authentication, transport, and file lifecycles, with substantial and varied background traffic. I found no hard contradiction in the lifecycle checks or the principal attack pivots examined; a limited inconsistency in one host's curl User-Agent versions warrants caution but does not outweigh the coherent evidence. This is a modest lean toward real data, not a claim that a capable synthetic system could not produce these records.

## Evidence For Synthetic

- [weak_signal] On `WS-LNGUYEN-01`, two invocations explicitly name `/usr/bin/curl` without a User-Agent override, but their proxy records identify different versions. `ecar.json:294` records the support-tool download at 15:12:25.374 UTC; `PROXY-01.meridianhcs.local/proxy_access.log:1253` reports `curl/7.88.1` at 15:12:27. The later attachment upload in `WS-LNGUYEN-01.meridianhcs.local/ecar.json:510`, at 16:31:55.594, produces `curl/7.81.0` in proxy line 2234 at 16:32:15 and in both core and DMZ HTTP records. There is no visible curl package replacement in that host's supplied syslog. A binary replacement, wrapper, or application-specific proxy transformation remains possible; incomplete package auditing prevents elevating this to a hard contradiction. The concern is inconsistent software identity for a named executable, not the suspiciousness of the support workflow itself.

## Evidence For Real

- The web reverse-shell pivot has a plausible visible lifecycle. `WEB-EXT-01.meridianhcs.local/ecar.json:920-927` shows the Apache child, decoding pipeline, child shell, outbound flow, and termination. `zeek-dmz/conn.json:1929` observes the corresponding `10.10.3.10:39417 -> 45.33.32.30:8443` transport at 14:20:23.223066 UTC for 17.974253 seconds; the child shell ends at 14:20:42.075, after transport closure.
- Remote database access is supported by matching endpoint, SSH authentication, shell, and transport evidence. The `10.10.2.30:49601 -> 10.10.4.10:22` flow begins at 18:14:51.904006 in `zeek-core/conn.json:10852`; the DB host logs connection acceptance, password authentication, PAM opening, and session 549 before the dump process starts at 18:15:11.442.
- The subsequent SCP has a separate, correctly reversed connection tuple and distinct receiver session. Core connection `CCQCDjYS1t9j4BMGuB` starts at 18:15:37.899192, before APP-INT-01 accepts root's public key at 18:15:44.033638. The receiver's file creation, process termination, and PAM close occur around 18:16:09. The session is not confused with the long-lived shell in the other direction.
- Background data include failed local authentication, a disabled deployment identity, machine/directory traffic, cron execution, legitimate administration, and unsuccessful network connections. For example, MAIL-FIN-01 has repeated batch-logon failures for disabled `svc_deploy` at 14:43:18.7251930, 15:42:35.7361707, and 17:02:42.7585756; these are distinguishable from wrong-password user failures and the remote failures from `10.10.1.99`.
- The proxy upload distinguishes endpoint content from transport accounting. The 18:25 upload has a ZIP file read by the visible curl process, an inspected HTTPS POST in the proxy, and a large outbound encrypted connection from the proxy rather than an invented direct endpoint-to-Internet flow.
- Native Windows effects are source-appropriate. DC-01 includes account creation, group membership, service installation, task registration XML, and an audit-clear event using `UserData/LogFileCleared`. The task XML preserves its hourly trigger, SYSTEM principal, and executable path; those records are not flattened into generic process messages.

## Detailed Analysis

### Scope, collection, and signal-to-noise

The visible window is approximately 2026-11-02 13:00-19:00 UTC. There are 23 endpoint directories, including 10 Windows hosts with Security/Sysmon XML, Linux hosts with syslog and selected shell histories, and two macOS hosts with Endpoint Security notifications, Unified Log exports, shell history, and normalized eCAR. Network coverage includes core, DMZ, and DB Zeek sensors, a perimeter firewall, two IDS vantage points, a proxy, and a web access log.

I counted 37,413 eCAR rows, 17,689 Windows Security events, 11,624 Sysmon events, 4,007 syslog lines, 22,625 Zeek connection rows across the three sensors, 4,432 DNS rows, 5,320 HTTP rows, 3,582 TLS rows, 4,013 proxy access lines, 24,192 firewall lines, and 127 IDS alerts. Sensor observations can overlap and these numbers must not be interpreted as distinct underlying activities. The relative volumes make hunting necessary: ordinary DNS, Kerberos, LDAP, web, SMB, service, and scanning activity dominate many of the pivots.

The core connection set contains 12,313 rows, including 3,283 DNS, 2,041 Kerberos, 1,226 LDAP, 469 SMB, 50 SSH, and 15 RDP service labels. The DB sensor has 298 MySQL connections among 454 total; the DMZ sensor sees 9,858 connections with substantial HTTP/TLS and unsolicited traffic. This is a defensible distribution for the visible roles. I did not penalize low Unified Log volume, filtered Sysmon families, or unavailable endpoint telemetry for every network participant.

### Web execution pivot

At 14:20:19.996 UTC, WEB-EXT-01 records www-data PID 3044168, parent Apache PID 23966, executing a shell pipeline that decodes a reverse-shell payload. PID 3044169 runs `base64 -d` at 14:20:20.087, and PID 3044170 runs `bash` at 14:20:20.099. The outbound eCAR flow at 14:20:23.792 belongs to PID 3044170 and uses source port 39417, matching the DMZ connection tuple.

The network flow closes around 14:20:41.197; the child and parent shell terminations follow at 14:20:42.075 and 14:20:42.597. These relationships support the operational possibility of the observed command. The lack of a later long-lived interactive shell is not a defect: the visible connection itself is short-lived. The nearby Apache SQL error is a separate observable event; it does not by itself prove the exploit mechanism that launched the shell.

### Authentication, privilege, and Windows effects

The data contain both normal remote administration and more concerning activity. On DC-01, command processes at 17:15:01.957 and 17:15:06.424 request creation of `svc_dirsync` and its addition to Domain Admins. Security event 4720 at 17:15:06.0520314 and event 4728 at 17:15:10.2040334 use the same account SID ending `-4518`; the Domain Admins SID ends `-512`. The account deletion at 18:50:30.5467188 reuses the same target SID.

At 17:19:40.453 a child `sc.exe` requests creation of DeviceSyncSvc. Event 4697 follows at 17:19:44.0608844 with the corresponding binary and LocalSystem account. A separate `schtasks.exe` invocation at 17:19:43.632 is followed by event 4698 at 17:19:47.1406196 containing the matching task name, hourly interval, and action. Registration proves the service/task was created; I do not infer successful execution of the payload merely from registration.

The Security clear event at 18:42:26.0518531 uses the Microsoft-Windows-Eventlog provider, event 1102, a channel-specific record ID of 1, and a namespaced `LogFileCleared` UserData structure. Its absence from a simple EventData-only extractor would be a parser limitation, not missing actor information.

### Database collection and transfer

APP-INT-01 starts `ssh -o ServerAliveInterval=30 root@DB-PROD-01.meridianhcs.local` at 18:14:46.260. The connection is visible in the core and DB sensors with different sensor-local UIDs, matching tuple, and matching byte counts. DB-PROD-01 logs accepted password authentication at 18:15:03.503013, then session opening, then a shell at 18:15:05.267.

The shell launches `mysqldump --single-transaction ehr patients insurance_claims` at 18:15:11.442, creates `/tmp/rpt_0318.sql` at 18:15:14.113, and exits the dump at 18:15:27.312. Its shell history retains the output redirection absent from the process argument string. gzip runs from 18:15:28.982 through 18:15:34.550, creating the compressed artifact before SCP starts at 18:15:35.116.

The SCP connection uses `10.10.4.10:37396 -> 10.10.2.30:22`, not the original interactive tuple. APP-INT-01 records root's public-key acceptance at 18:15:44.033638, session 431, and the target artifact `/tmp/.cache/rpt_0318.sql.gz` at 18:16:09.067. Small timing differences between sensor transport closure, endpoint observation, and PAM close are plausible collection/source timing differences, not impossible ordering. I do not infer database size or stolen record count from the filename or command alone.

### Proxy and support-tool pivots

Three hosts download platform-specific support tools. I treat these downloads and their execution as separate facts: on MAC-MROSS-01, native ES records show curl execution at 13:48:41.201976 and `/bin/bash .../connector-check.sh --check-config` at 13:49:08.207155. The shell script's mere presence is not the basis for claiming it ran.

The Linux attachment upload at 16:31:55.594 is followed by HTTP POST observations at 16:32:15.397401 on the client-to-proxy leg and 16:32:15.457122 on the proxy-to-server leg. The client leg contains an absolute URI; the server leg contains an origin-form path. Both carry request-body length 1,573,258 and response-body length 96, supporting the proxy pivot. The software-version concern described above is limited to the inconsistent default curl identity.

On WS-AJOHNSON-01, PID 6760 starts the inspected HTTPS upload at 18:25:17.758 and reads `cache_7f3a.zip` at 18:25:20.645. Proxy line 3547 attributes the POST to that user and client source port 60912 at 18:25:21, with `cs_bytes=18783258`. The proxy's outbound TLS connection to `45.33.32.30:443`, UID `CcLdbyYpq9DECerxnCN`, starts at 18:25:21.624061 and has 18,808,705 originator bytes. HTTP application bytes and encrypted TCP payload need not be identical. This is an operationally plausible exfiltration lead, regardless of authenticity.

### Lifecycle and platform checks

Across the eCAR files, I compared visible process creation/termination with referenced source-process identities, allowing a two-second tolerance for observation timing. I found no references preceding a visible creation or following a visible termination beyond that tolerance. The 2,403 process lifecycles with both eCAR endpoints have varied durations; a check of exact duration values did not reveal a dominant fixed-duration pattern. These are bounded checks, not proof that every possible event relationship is correct.

I separately checked Sysmon process GUID relationships against its `UtcTime` fields and found no visible referenced process initiation/termination inversion in the inspected event families. The 1,037 populated process hash sets have correctly sized SHA1, MD5, and SHA256 values; 1,023 populated IMPHASH values also have the expected length.

I checked the Zeek protocol rows against same-sensor connection rows for established TLS or HTTP responses on S0/REJ connections, and DNS answers with zero responder packets; none of those specific contradictions appeared. TLS version/cipher combinations were plausible in the observed set.

For macOS I distinguished native ES fork/exec/exit notifications, Unified Log messages, history, and eCAR normalization. The supplied kernel policy message concerning MeetingAssist at 15:42:09.009673 does not establish execution of that application or any child effects; I found no corresponding MeetingAssist execution in the supplied ES/eCAR records and did not invent a successful launch. Pre-window processes and post-window survivors were not counted as lifecycle gaps.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| weak_signal | Linux eCAR, proxy access, Zeek HTTP | Two `/usr/bin/curl` operations on WS-LNGUYEN-01, 15:12-16:32 UTC | `curl/7.88.1` versus `curl/7.81.0` without an argument override or visible replacement is worth verifying; alternative software/collection explanations limit its weight. |

No demonstrated hard contradiction or high-impact contract gap was found in the checks described above. Complete matching, a compact intrusion sequence, filtered source coverage, sanitized names, and filesystem timestamps did not affect the synthetic-confidence score.

## Realism Score by Category

- **Field format accuracy:** 9 — Windows native event shapes, hash lengths, protocol fields, and distinct macOS source types are credible in the records examined.
- **Temporal patterns:** 9 — Process, transport, authentication, transfer, and closure orderings work in the examined pivots; ordinary source timing offsets remain plausible.
- **Cross-source correlation:** 9 — Connection tuples, separate proxy legs, sensor-local UIDs, file paths, and account SIDs support useful pivots without a demonstrated contradiction.
- **Behavioral realism:** 8 — Commands and visible effects support feasible operations amid substantial legitimate traffic; software-version attribution remains a limited concern.
- **Environmental consistency:** 8 — Source volumes and service distributions broadly fit the host roles; one named Linux executable has inconsistent reported versions.

## Recommendations

- If this were synthetic, preserve a consistent default User-Agent for each installed curl binary on a host. For WS-LNGUYEN-01, either retain one version across the two explicit `/usr/bin/curl` operations or, if a version transition is intentional and the collection captures it, represent the actual package/binary transition or explicit User-Agent override.
- Preserve the existing separation of transport, authentication, process execution, and registration effects. The observed SSH/SCP and proxy lifecycles already provide technically credible hunting pivots; I found no evidence-based reason to add arbitrary retries, extra failures, or additional sources solely to make them appear messier.
