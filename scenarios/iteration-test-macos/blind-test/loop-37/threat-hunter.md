# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 77
**Synthetic-Confidence Score:** 43

## Executive Summary

The supplied six-hour collection is operationally convincing across a mixed fleet, with usable pivots from endpoint execution to remote authentication, network transport, and destination file activity. I found a narrow cluster of questionable Linux process/file ownership assignments, but their interpretation depends on the normalized endpoint collector's attribution semantics; I did not establish a hard contradiction sufficient to confidently classify the whole dataset.

## Evidence For Synthetic

- [contract_gap] The database-to-application SCP transfer assigns the TCP/22 connection directly to the `scp` process. `DB-PROD-01.meridianhcs.local/ecar.json:502` creates `/usr/bin/scp`, PID `1089153`, at `18:15:57.555Z`; line 504 attributes the outbound `10.10.4.10:53008 → 10.10.2.30:22` FLOW at `18:16:01.199Z` to that same PID and process UUID. No process CREATE in that host file has PPID `1089153`. Standard OpenSSH SCP uses an SSH subprocess for the transport. This suggests application-level intent being substituted for the socket-owning process. It is an attribution concern rather than an established native-source contradiction, because eCAR here is normalized telemetry and its collector semantics are unspecified.
- [contract_gap] The SQL dump's file creation appears attributed to the payload executable rather than its redirecting shell. `DB-PROD-01.meridianhcs.local/bash_history/root.bash_history:2` records `mysqldump --single-transaction ehr patients insurance_claims > /tmp/rpt_0318.sql`. The endpoint record at `ecar.json:495` starts the actual executable without shell redirection at `18:15:17.553Z`, while line 496 assigns `FILE/CREATE /tmp/rpt_0318.sql` to the mysqldump PID at `18:15:20.385Z`. In an ordinary shell redirection the shell opens/creates the output before executing the program; writes by mysqldump are expected. This is a second instance of questionable source-process attribution, subject to the same normalization caveat.
- [weak_signal] Both Mac histories reuse a small diagnostic vocabulary: `id`, `sw_vers`, `uname`, `pwd`, `ls`, `du`, `df`, `ps`, and a fixed PDF `find` command. `MAC-MROSS-01.../zsh_history/maya.ross.zsh_history:1-6` and `MAC-MROSS-02.../zsh_history/maya.ross.zsh_history:1-6` illustrate this. The repeated account and administration role provide a plausible explanation, so this has only a small effect on the score and does not independently support a synthetic verdict.

## Evidence For Real

- The source mix fits distinct roles rather than assigning the same volume to every host. DC-01 and DC-02 have 6,875 and 6,066 Security events respectively, including substantial Kerberos and filtering-platform activity; WS-EBROOKS-01 has 508. The three network sensors have 12,279 core, 9,287 DMZ, and 464 database connection records, with 307 MySQL records visible at the database sensor. Those are plausible differentiated workloads, not evidence of authenticity on their own.
- The SCP/SMB staging sequence preserves both temporal order and account boundaries. The root local shell, root SSH credentials, and later directory account `svc_mhsync` are distinct and are not collapsed into one identity. The destination file audit and Zeek SMB file record agree on the actual share-relative path.
- Mac-to-Mac SSH has the expected order across independent source families. MAC-MROSS-02's Endpoint Security record 99 shows execution of `/usr/bin/ssh -tt maya.ross@MAC-MROSS-01.meridianhcs.local` at `16:01:12.772982Z`; MAC-MROSS-01 eCAR line 304 observes the inbound `54015 → 22` flow at `16:01:25.772Z`; its Unified Log line 3 reports accepted publickey authentication at `16:01:31.465667Z`; eCAR line 310 reports LOGIN at `16:01:33.025Z`.
- The Mac policy observation is not falsely followed by visible successful execution. `MAC-MROSS-01.../macos_unified_log.ndjson:2` names a policy problem for MeetingAssist, but neither Mac's supplied Endpoint Security exec records establish a successful execution of that image. This preserves the distinction between an attempted/assessed launch and its effects.
- The network records have failed connections, varied protocols, packet accounting, and separately observed sensor timestamps. For example, the SCP flow has distinct core and database UIDs and slightly different sensor times, while its tuple and byte totals agree. This is a plausible observation arrangement, not a penalty for complete alignment.

## Detailed Analysis

### Orientation and collection scope

The endpoint directories cover 23 systems: ten Windows systems, eleven systems with Linux-style syslog/endpoint evidence, and two Macs. The visible time window is approximately `2026-11-02 13:00–19:00Z`. Sources include Windows Security and selected Sysmon XML, normalized eCAR endpoint events, Linux syslog and bash histories, Mac Endpoint Security and Unified Log records, zsh histories, three Zeek sensor locations, perimeter ASA records, Snort alerts, proxy records, and external web access logs.

The addressing supports workstation, server, DMZ, and database segments (`10.10.1.*` through `10.10.4.*`). I treated these as observed topology rather than assuming connectivity from names alone. I counted records by parsing the XML and JSON; the physical XML line count is not an event count. Across the endpoint eCAR files there are 35,814 records; Zeek has 22,030 connection records across its sensors. I did not require every process or session to start and end inside this bounded collection.

### Intrusion pivots and prerequisite plausibility

An external web request provides an initial hunting pivot: `WEB-EXT-01.../web_access.log:482` records `185.70.41.45` posting to `/ehr/admin/upload.php` at `14:20:04Z`, returning HTTP 200 and 912 bytes. `WEB-EXT-01.../ecar.json:811` then records a `www-data` bash process under Apache at `14:20:06.215Z`, with a base64-decoding shell pipeline. The encoded command resolves to a reverse-shell invocation toward `45.33.32.30:8443`. The HTTP status alone does not establish execution, but the endpoint process supplies that independent evidence.

Later root sessions are visible. For example, WEB-EXT endpoint lines 903–915 show a root SSH context, a child login shell, host/network discovery, and an nmap command. The root authentication is a separate observed fact; I did not infer that the earlier www-data shell itself escalated to root just because those events are on the same host. Similarly, APP-INT syslog lines 115–118 give a transport tuple, accepted root password, PAM session opening, and logind session creation at `15:15:01–11Z` from `10.10.3.10:60950`.

DC-01 later supplies service execution and account changes. Its eCAR lines 3547 and 3555 show PSEXESVC under SYSTEM followed by a child command shell at `16:59:46–49Z`. Lines 3754 and 3761 show the command wrapper and `net user` child used to create `svc_dirsync`; the Security XML has 4720, 4724, and 4738 events at `17:14:52.0809664Z`, `17:14:53.0902796Z`, and `17:14:55.2539325Z`, followed by group membership event 4728 at `17:14:56.4041055Z`. These visible steps preserve the account creation/change ordering. I did not score the compactness or comprehensibility of this activity as an authenticity indicator.

### Database collection and file staging

The most useful end-to-end pivot is the database export:

1. `APP-INT-01.../ecar.json:747` starts `ssh root@DB-PROD-01.meridianhcs.local` at `18:14:40.582Z`; line 750 observes `10.10.2.30:46416 → 10.10.4.10:22` at `18:14:58.780Z`.
2. `DB-PROD-01.../ecar.json:492–495` observes inbound transport, successful root login, shell creation, then mysqldump. The login is at `18:15:11.496Z`, before the shell at `18:15:13.260Z` and command at `18:15:17.553Z`.
3. mysqldump terminates at line 497 (`18:15:43.874Z`). Gzip starts at line 499 (`18:15:45.617Z`) and terminates at line 501 (`18:15:55.916Z`). SCP starts at line 502 (`18:15:57.555Z`). This is a technically usable order for producing and then transferring the archive.
4. `zeek-core/conn.json:11001` records `CsIZtbwpQYGENvKOB4`, the `10.10.4.10:53008 → 10.10.2.30:22` connection, starting `18:16:00.366168Z`, with duration `19.17837`, state `SF`, 25,675 origin bytes and 28,876 response bytes. APP-INT syslog lines 220–223 show the matching root publickey acceptance, PAM opening and close.
5. `APP-INT-01.../ecar.json:761` creates the received archive at `18:16:20.287Z`. Its `smbclient` starts at line 774, using root locally and `svc_mhsync` for remote authentication.
6. `zeek-core/smb_files.json:187–188` opens/writes `Integration\DB-Staging\rpt_0318.sql.gz` on `\\FILE-LNX-01\ClinicalResearch`. `zeek-core/files.json:613` reports the extracted SMB file at 10,464 bytes. The matching core connection is line 11117 with 12,490 origin application bytes, which can accommodate that file and SMB overhead. FILE-LNX syslog lines 535–537 show successful open/write/close under `svc_mhsync`; its eCAR lines 1445–1447 carry the same directory-account session reference.

I found no visible requirement for an enormous archive: the logs give a small 10,464-byte transfer, and the supplied records do not establish the actual table populations. I therefore did not invent a size contradiction based only on the organization appearing clinical.

The two attribution concerns above remain localized to the process that owns the file-open/transport operation. They do not invalidate the observed tuple, transfer direction, destination path, or account separation. They could reflect a collector that deliberately attributes actions to the initiating application; without its documentation that explanation cannot be excluded.

### Lifecycle and collection checks

I checked the parsed eCAR records for dependent actions more than one second before a visible actor PROCESS/CREATE or after its PROCESS/TERMINATE using the same host-local UUID. That check found no examples. This does not validate every source-native lifecycle, but it removes a common, directly testable ownership contradiction.

I also avoided treating the slight differences between endpoint and network timestamps as impossible ordering. The SMB endpoint file WRITE timestamp trails its native Samba audit and Zeek observation, which can reflect endpoint observation/collection timing. The native Samba open, write and close remain ordered. Source gaps, selected Sysmon types, absent full Mac Unified Log volume, sanitized domains, and the lack of visible post-window termination were not independently penalized.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| contract_gap | Linux normalized endpoint process/network | One SCP transfer, DB-PROD eCAR 502/504 | Moderate: SSH transport attributed directly to scp; normalization remains a plausible alternative. |
| contract_gap | Linux normalized endpoint process/file | One redirected database dump, DB-PROD eCAR 495/496 and root history 2 | Moderate but related to the same attribution issue: FILE/CREATE owner and timing differ from ordinary shell redirection semantics. |
| weak_signal | Mac shell histories | Two endpoints of the same account | Small: repeated diagnostic vocabulary, readily explainable by shared operator habits. |

No demonstrated hard contradiction or verified native Mac schema defect was used in the score. The two ownership concerns are related and were not treated as independent dataset-wide failures.

## Realism Score by Category

- **Field format accuracy:** 8 — Structured records parse, native and normalized source families are distinguishable; the unresolved issue is attribution semantics.
- **Temporal patterns:** 8 — Sampled SSH and export lifecycles have feasible order; no same-UUID dependent-event lifecycle reversal found in eCAR beyond the stated threshold.
- **Cross-source correlation:** 8 — Network tuples, remote identities and destination file paths support effective pivots; normalized process attribution is the main reservation.
- **Behavioral realism:** 8 — Visible command prerequisites and effects work together; repeated Mac diagnostic commands provide a mild texture concern.
- **Environmental consistency:** 8 — Source volumes and protocols vary plausibly with DC, endpoint, DMZ and database roles.

## Recommendations

- If this were synthetic, model the SCP application's SSH subprocess and assign the socket FLOW to the process that actually opens the connection. Preserve any higher-level SCP attribution separately so analysts can still pivot to transfer intent.
- If this were synthetic, distinguish a shell's redirected output-file open/create from the child's subsequent writes. If the normalization intentionally reports the initiating payload instead, make that collector convention explicit and consistent.
- If this were synthetic, expand ordinary Mac user command diversity beyond the repeated diagnostic vocabulary where the modeled user's actual work warrants it. Keep repetition that is explained by the same operator or automation; random novelty is not a substitute for realistic activity.
