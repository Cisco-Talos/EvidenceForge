# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 80
**Synthetic-Confidence Score:** 55

## Executive Summary

This is a technically convincing mixed-fleet collection with workable pivots through remote authentication, process ancestry, proxy traffic, database export and SMB staging. A multipart upload has an endpoint-process lifetime that ends unusually early relative to the observed HTTP transaction, and several interactive-looking command starts retain suspicious subsecond phase alignment; these raise synthetic suspicion, but the available records do not eliminate cancellation, buffering, clock differences or scripted execution as explanations.

## Evidence For Synthetic

- [contract_gap] The support upload's apparent client process ends before most of its corresponding HTTP file-transfer interval. In `WS-LNGUYEN-01.meridianhcs.local/ecar.json`, line 561 creates curl PID `3261860`, object `f2e382ea-2432-4a5f-96ba-2847685ef92d`, at `16:35:13.395`; line 565 reads `/tmp/mhs-support-48217.tar.gz` at `16:35:34.749`; line 566 terminates that same process at `16:35:34.950`. In `zeek-core/files.json`, line 430 starts the gzip part at `16:35:34.699640` with `duration=10.069288`, and line 431 starts the response body at `16:35:48.933566`. This is a substantial lifecycle tension, not a demonstrated impossibility: process exit status is unavailable, and buffered sends or cancellation could explain continued wire activity.
- [distribution_texture] The Windows connector-check sequence retains almost the same millisecond phase across distinct starts separated by tens of seconds. In `WS-MCHEN-01.meridianhcs.local/windows_event_sysmon.xml`, Event 1 records `525305`, `525313`, `525323` and `525325` give `UtcTime` values `14:45:35.733` (curl), `14:46:18.733` (connector-check), `14:46:54.733` (whoami), and `14:47:17.734` (ipconfig). Their normalized eCAR counterparts are lines 335, 376, 412 and 422. Integer-second scheduling is a plausible explanation, so this is supporting texture rather than proof of invented activity.
- [weak_signal] A small local permission change has a surprisingly long lifetime: `WS-LNGUYEN-01.meridianhcs.local/ecar.json` lines 311–312 show `/usr/bin/chmod 700 /tmp/connector-check` running from `15:12:49.378` to `15:12:58.605` (9.227 seconds). That is possible under blocking or host load, but it merits scrutiny alongside the upload's process timing. I do not infer a hard contradiction or a fleet-wide runtime defect from this one observation.

## Evidence For Real

- The database-export trail supports an actual investigation across independent formats. `DB-PROD-01` shell history records the dump, gzip and scp commands; its eCAR records show the resulting files and process identities; `APP-INT-01` syslog accepts root from `10.10.4.10:59215` at `18:15:39.382759`; and Zeek observes that same TCP/22 tuple. The receiver file appears before the subsequent SMB staging operation.
- The RDP pivot into Aisha's workstation has credible transport-before-authentication ordering. `zeek-core/conn.json` line 6699 opens `10.10.1.99:59465 -> 10.10.1.35:3389` at `16:01:16.007030`, with `service=rdp`, `conn_state=SF` and `duration=3154.510962`. The workstation's Security 4624 follows at `16:01:23.4749133`, identifying `LT-MRIVERA-02`, the same source port, Type 10 and logon ID `0x26db304`.
- Multipart upload semantics are substantially correct even though endpoint termination timing is questionable. The HTTP POST has separate JSON and gzip FUIds, the gzip part has a filename while the JSON metadata part does not, both travel in the originator direction, and the response travels in the opposite direction. Client-to-proxy and proxy-to-origin legs retain the same application request and body length while using different TCP tuples and request-target forms.
- The background mix includes role-appropriate diversity: domain-controller Kerberos and LDAP, SMB file activity, Linux SSH/PAM/logind, cron/sysstat, mail delivery queues, public-facing web noise and workstation browser/proxy traffic. Volumes differ materially between endpoints, domain controllers, proxy and exposed web host.
- Direct lifecycle checks found no visible Sysmon event referring to a process before its visible Event 1 or after its visible Event 5, using matching ProcessGuid/source/target/parent identifiers. Checks across the three Zeek sensors found no HTTP request/response body exceeding its connection's directional payload count and no HTTP timestamp more than 0.5 seconds beyond its connection interval.

## Detailed Analysis

### Scope and orientation

I examined only the supplied data directory. The endpoint collection contains 23 named hosts: ten with Windows Security/Sysmon XML, eleven with Linux-style syslog, and two Macs with Endpoint Security and Unified Log records. All 23 have normalized eCAR records. The apparent organization spans workstation addresses in `10.10.1.0/24`, infrastructure in `10.10.2.0/24`, a web/proxy segment in `10.10.3.0/24`, and a database segment including `10.10.4.10`.

The visible window is approximately `2026-11-02 13:00–19:00 UTC`. There are 38,411 eCAR records, 17,894 Security XML events, 11,689 Sysmon events, 4,304 Linux syslog lines, and 23,014 Zeek connection observations across core, DMZ and database sensors. The latter count includes overlapping observations and is not a count of distinct network conversations. I found 39 nonempty eCAR principal strings, including service and machine identities; that is not a human headcount.

The eCAR object mix is 27,732 FLOW, 6,309 PROCESS, 2,212 MODULE, 1,501 USER_SESSION, 378 FILE, 270 REGISTRY, six THREAD and three SERVICE records. These normalized counts cannot be equated directly with selected native audit-family coverage. The exposed web host and proxy are much busier than many individual workstations, while the two domain controllers carry most authentication traffic. This mix does not make the suspicious actions stand out merely through absent background traffic.

### Remote access and Windows hunting pivots

The `10.10.1.99 -> WS-AJOHNSON-01` RDP connection supports the Type 10 logon described above. The corresponding local process tree later contains PowerShell and `ms-index-service.exe "privilege::debug" "sekurlsa::logonpasswords" exit` at `16:50:59.564` in eCAR line 775. The executable's name alone is not benign; the command arguments are a credible credential-access lead. Conversely, those arguments alone do not prove successful credential extraction.

On `DC-01`, eCAR lines 3711 and 3718 show WMI-parented cmd/net execution to create `svc_dirsync` around `17:15:02`; lines 3730 and 3736 add it to Domain Admins around `17:15:07`. The Security file contains 4720 and 4728 account/group-management evidence as well as later deletion evidence. At `17:19:40–17:19:43`, sc.exe and schtasks.exe command trees provide concrete service/task persistence pivots. I do not score the breadth or organization of this intrusion sequence as an authenticity indicator.

A useful false-positive control is the preexisting Marcus desktop session. Processes using logon ID `0x6c29844` occur before the `14:33:57` Type 7 event, but the native source identifies that event as an unlock and also records a preceding 4800 lock. That is not a process-before-logon contradiction. Likewise, repeated SYSTEM session identifiers and SSH preauthentication privileged processes do not establish impossible session ordering.

### Database export and SMB staging

At `18:15:13.704`, `DB-PROD-01/ecar.json` line 553 records root running `mysqldump --single-transaction ehr patients insurance_claims`; line 554 creates `/tmp/rpt_0318.sql`. Gzip follows at `18:15:22.246`, with the compressed artifact at `18:15:26.193`. Scp starts at `18:15:30.778` and reads the compressed file at `18:15:40.337`.

`zeek-core/conn.json` line 10910 observes `10.10.4.10:59215 -> 10.10.2.30:22` starting `18:15:33.474312`, with a 29.826115-second successful connection. The database sensor independently observes that tuple with a different UID. `APP-INT-01/syslog.log` lines 244–247 show connection, accepted public key, PAM open and a logind session for the same source tuple. Its eCAR line 836 observes `/tmp/.cache/rpt_0318.sql.gz` at `18:16:03.972`.

The follow-on `smbclient` process starts at `18:18:51.980` on APP-INT and authenticates to `FILE-LNX-01/ClinicalResearch` as `svc_mhsync`, distinct from its local root identity. Zeek SMB UID `CApmzl6A60i7d2aJ0m` opens then writes `Integration\DB-Staging\rpt_0318.sql.gz`; `smb_files.json` lines 233–234 and `files.json` line 621 report 16,386 bytes in the client-to-server direction. `FILE-LNX-01/ecar.json` line 1451 records `svc_mhsync` writing the matching server-side path at `18:18:58.633`. This is a strong, usable chain without conflating local process identity and remote credentials.

### Support upload and client lifetime

The upload merits the closest review because it is the most concrete lifecycle concern I found. Curl PID `3261860` is tied by exact command line, account and archive path to the support attachment request. The archive is created by tar and read by curl. The only matching nearby HTTP attachment request uses client source port `35532`.

The core sensor starts the corresponding connection at `16:35:34.361911`; the DMZ sensor starts its copy at `16:35:34.247709`, a difference of about 114 milliseconds. The core HTTP row is line 1375, UID `CV1MUL2KILV0nz3bOeT`, `POST`, request body 1,573,258 bytes and response body 96 bytes. Core files lines 429–431 describe the 50-byte metadata, 1,572,864-byte gzip file and response. The connection remains visible until `16:35:52.904667`.

The apparent curl process ends at `16:35:34.950`, only 201 milliseconds after its archive read and almost 14 seconds before the first logged response-body observation. The normalized endpoint FLOW at `16:35:35.718` omits process identity. The same host's nearby diagnostic curl has a connection and process lifetime that overlap comfortably, so a blanket claim that every endpoint timestamp is offset by many seconds is not supported by that adjacent example.

Nevertheless, TCP can flush queued data after application exit, and a proxy can finish processing a request after client cancellation. There is no exit status here proving that curl successfully waited for and consumed the response. A file log's duration also reflects observation semantics, not necessarily application CPU or read time. I therefore classify this as a contract concern, not an impossible causal claim. It increases suspicion but cannot settle the verdict alone.

### macOS and collection limitations

The Mac records distinguish Endpoint Security fork/exec observations from normalized process events and from Unified Log messages. The `MeetingAssist` policy message on MAC-MROSS-01 at `15:42:09.009673` says policy “would not allow” the process; that wording does not establish a completed denial, nor does a download alone establish execution. I did not infer successful effects or a denial/child-execution contradiction from that message.

The Mac zsh histories also provide practical SSH pivot leads between the two Macs and Linux servers. I did not apply Windows account or LogonID expectations to native macOS audit tokens, or treat the small Unified Log selection as proof of an implausible fleet. Missing pre-window starts, selected Sysmon families, sanitized domains and source completeness were excluded from scoring.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on synthetic-confidence score |
|---|---|---|---|
| contract_gap | Linux eCAR plus Zeek HTTP/files/conn | One multipart attachment transaction on WS-LNGUYEN-01 | Main upward influence: apparent client exits before most file-transfer observation and response; buffering/cancellation remain viable alternatives. |
| distribution_texture | Windows Sysmon Event 1 and corresponding eCAR | Four connector-check/discovery starts over 102 seconds | Modest upward influence: repeated millisecond phase suggests scheduled timestamps; actual scripted execution could explain it. |
| weak_signal | Linux eCAR process lifecycle | One chmod invocation | Small upward influence: 9.227-second lifetime for a simple local operation, without enough evidence to call it impossible. |

No demonstrated hard contradiction or generator identity leak was established. The score remains in the mixed/inconclusive band because the operationally coherent pivots are substantial and the suspicious timing has plausible production explanations.

## Realism Score by Category

- **Field format accuracy:** 9 — Native XML/JSON records are usable and internally consistent in the examined fields; no demonstrated parser or schema defect drove the verdict.
- **Temporal patterns:** 6 — Most sequencing works, but the upload lifetime and repeated subsecond command phase deserve review.
- **Cross-source correlation:** 8 — RDP, SSH, export and SMB pivots agree on useful identities and tuples; the upload completion interval is the notable concern.
- **Behavioral realism:** 8 — Credential access, account persistence, remote sessions and data staging are technically intelligible amid varied ordinary activity.
- **Environmental consistency:** 8 — Host roles, segment placement, account scopes and unequal source volumes form a plausible mixed enterprise.

## Recommendations

- If this were synthetic, derive curl termination from the complete client-side request/response lifecycle. If the intended behavior is cancellation or failure, expose the corresponding exit/failure evidence and model buffered transmission or proxy continuation explicitly.
- If this were synthetic, vary execution starts through actual per-command scheduling overhead rather than retaining a nearly identical millisecond phase across human-facing commands. Preserve regular timing when a real script or scheduler owns the action.
- If this were synthetic, calibrate simple utility lifetimes separately from network and long-running commands; investigate the 9.227-second chmod example before using it as a general runtime pattern.
