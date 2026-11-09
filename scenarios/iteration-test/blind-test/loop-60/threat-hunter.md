# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 82
**Synthetic-Confidence Score:** 29

## Executive Summary

The supplied slice is mostly production-like: the investigated remote sessions, privilege boundaries, file staging, network paths, and source-specific collection loss fit together without a demonstrated impossible lifecycle. Two small behavioral texture concerns remain, but they are explainable human or administrative behavior and do not establish synthetic origin; the evidence supports a low synthetic-appearance score and an inconclusive provenance verdict.

## Evidence For Synthetic

- [weak_signal] On MAC-MROSS-02, four separate document reads use `/bin/cat` on binary document formats: `project-plan.pdf`, `service-review.xlsx`, `project-plan.docx`, and `onboarding.docx`. The execution observations are in `MAC-MROSS-02.meridianhcs.local/ecar.json` lines 67, 384, 482, and 488 at 13:37:14.425, 16:05:38.929, 17:10:44.223, and 17:12:28.114 UTC. Corresponding file reads appear at lines 75, 387, 485, and 490. Repeatedly using the same text-output utility across PDF and Office documents is an odd usage texture. It remains technically possible, including scripted checks, and has only a small effect on the score.
- [weak_signal] `WS-LNGUYEN-01.meridianhcs.local/syslog.log` line 56 records `sudo ... COMMAND=/bin/systemctl is-active smbclient` at 13:42:20.177063 UTC; eCAR lines 48–49 show the sudo wrapper and root child. The service-name choice resembles substitution of a client program into a service-health command. A custom unit or a mistaken operator command remains possible, and the logs do not claim that the check succeeded. This is not a contradiction or a required missing-service finding.

## Evidence For Real

- The apparent fleet has differentiated roles and traffic: 23 endpoint directories include domain controllers, Windows workstations and a file server, Linux application/database/mail/proxy systems, and two Macs. The 35,885 normalized eCAR rows coexist with 19,003 Windows Security events, 11,995 Sysmon events, and 21,936 Zeek connection rows across three observation locations. Those counts do not resemble an attack-only extract.
- The root database-transfer sequence has usable causal pivots. `DB-PROD-01.meridianhcs.local/bash_history/root.bash_history` lines 1–6 shows a redirected dump, gzip, and scp. eCAR lines 455–464 preserves the matching child processes, produced archive, file read, and sender lifecycle. The target SSH authentication, target file receipt, and successful TCP interval agree with that activity.
- Sensor disagreement is intelligible rather than arbitrary. For the support upload, `zeek-core/http.json` line 1330 reports a 95-byte response while `zeek-dmz/http.json` line 1510 reports 96. Core `files.json` line 414 explicitly accounts for the absent byte with `seen_bytes=95`, `total_bytes=96`, and `missing_bytes=1`; core `conn.json` line 7601 also reports loss. The DMZ equivalents show no loss. This is a coherent collection difference, not a response-size contradiction.
- Local and remote credentials remain distinct in the staging sequence. On WS-AJOHNSON-01, the process account remains `aisha.johnson` after `runas /netonly /user:marcus.chen`, while Security 4648 records the supplied remote identity. Local identity retention is appropriate for net-only credentials.
- Routine DHCP evidence carries concrete lease timing. `WS-LNGUYEN-01.meridianhcs.local/syslog.log` lines 1–3 records a lease bound at 13:01:20 with renewal in 1,886 seconds; lines 40–42 shows the next request around 13:32:45. Later requests continue with changing renewal intervals. This is more informative than disconnected DHCP filler.
- The Mac policy message does not become a successful-execution claim. `MAC-MROSS-01.meridianhcs.local/macos_unified_log.ndjson` line 2 records an AppleSystemPolicy message concerning MeetingAssist, while the supplied Endpoint Security execution observations do not show MeetingAssist executing. I found no basis for attributing child activity or effects to that message.

## Detailed Analysis

### Scope, method, and input provenance

I examined only the neutral reviewer instructions and files under `/private/tmp/log-study-boe6lty3/data`, using system `python3` from `/private/tmp`. No project files, scenario, prior assessments, or other reviewer reports were accessed. The inherited operating context was not used as evidence about origin. Paths below are relative to the supplied data directory; timestamps are UTC unless otherwise stated.

The endpoint slice is approximately 2026-11-02 13:00–19:00. There are ten Windows endpoint directories with Security/Sysmon XML, eleven Linux endpoint directories with syslog, and two Mac directories with Endpoint Security and Unified Log observations. Normalized eCAR accompanies all 23. Network evidence includes core, DMZ, and database Zeek views, perimeter ASA records, two IDS views, proxy access, web access, SMTP, and SMB evidence. Source counts are a description of scope, not proof that every possible event is collected.

I parsed the normalized endpoint records and Windows XML, sampled native operating-system records, and followed suspicious activity through endpoint, authentication, network, application, and file observations. An automated same-object check across the eCAR files found no actor use after a visible same-identity process termination, no actor action before its visible creation, and no same-process non-create occurrence before its visible creation. That check does not prove complete correctness, but it guards against a common false narrative assembled from unrelated PIDs.

### Windows access and credential boundaries

WS-AJOHNSON-01 shows failed authentication from `10.10.1.99`, followed by a remote interactive session. eCAR line 524 records a successful Type 10 login at 16:00:07.040, source port 58594, LogonID `0x26d8d1c`. Userinit and Explorer then appear at lines 526 and 529, with the same LogonID and session 3. Discovery commands around 16:19 are suspicious, but their compactness is not an authenticity indicator.

On DC-01, Security 4697 at XML line 177183 records creation of `PSEXESVC` at 17:00:17.3065527 under the remote `aisha.johnson` identity. DC eCAR line 3529 records `C:\Windows\PSEXESVC.exe` at 17:00:19.674, followed by `cmd.exe /c whoami && hostname` at line 3537. The service-install-to-service-process ordering is plausible.

At 18:00:37.323, WS-AJOHNSON eCAR line 1070 records `runas.exe /netonly /user:marcus.chen "cmd.exe /d /q"`. Security 4648 at XML line 26028 follows at 18:00:40.5488061 and identifies subject `aisha.johnson`, target credentials `marcus.chen`, and ProcessId `0x194c` (6476), matching the runas PID. The child command process at eCAR line 1085 keeps local principal `aisha.johnson` and has a new LogonID, `0x27c9769`. Subsequent PowerShell activity uses that local process context. I do not misclassify the difference between supplied network credentials and local execution identity as inconsistent attribution.

### Directory changes and persistence

DC-01 eCAR lines 3724/3731 show the account-creation shell and `net user` child at 17:15:19. Security 4720 at XML line 186510 records `svc_dirsync` at 17:15:30.3831973, with SID ending `9594`. Security 4728 at line 187119 adds that same SID to the group whose SID ends `512`, after the group command at eCAR lines 3745/3752. Security 4726 at line 276501 deletes the same account at 18:50:16.4296709. These durable identities make the pivot meaningful.

The service and scheduled task are separate observations. Security 4697 at line 191583 records `DeviceSyncSvc`, while 4698 at line 191703 records `\Microsoft\Windows\Maintenance\DeviceSync` with a one-hour repetition and the same executable path. Their command processes precede the registration records. I do not assume the task itself caused the later service execution merely because the executable matches.

The 1102 at line 267884 follows the visible `wevtutil cl Security` execution. Subsequent retained Security events are compatible with forwarded collection or a continued export and are not evidence that the clearing failed.

### Database staging and transport coherence

DB-PROD-01 syslog lines 189–192 shows SSH from `10.10.2.30:44872`, password authentication for root, PAM session opening, and logind session creation. The database command appears after that session is available. Bash history preserves the shell redirection to `/tmp/rpt_0318.sql`; its absence from the external program's process command line is ordinary shell behavior, not a missing-output contradiction.

The database dump process starts at eCAR line 455, 18:15:29.410. The gzip process starts at line 458, 18:15:56.953, and its output `/tmp/rpt_0318.sql.gz` appears at line 459. Scp starts at line 461, 18:16:03.646, and reads that artifact at line 463. Zeek database `conn.json` line 344 observes the sender tuple `10.10.4.10:54707 -> 10.10.2.30:22`, successful state `SF`, duration 30.211086 seconds, and 978,623 originator bytes.

APP-INT-01 syslog lines 214–217 records that exact source tuple and successful public-key authentication before the transfer finishes. APP eCAR line 762 records the received `/tmp/.cache/rpt_0318.sql.gz` at 18:16:37.204. Later, APP eCAR lines 769–771 shows smbclient reading and uploading that file to FILE-LNX-01. Core SMB rows 223–224 and files row 604 agree on the destination relative path and a 951,368-byte object. Encrypted SSH overhead and subsequent SMB file size need not be identical.

The visible archive upload also has an appropriate explicit-proxy path: WS-AJOHNSON eCAR line 1235 runs curl with `--proxy http://10.10.3.20:8080`; proxy access line 3263 records the matching POST path, tunnel identifier, and client source port 55554. Core connection line 11154 observes `10.10.1.35:55554 -> 10.10.3.20:8080` with about 18.8 MB sent. A direct workstation-to-external HTTPS connection is not required for that command.

### Collection differences and baseline texture

The support diagnostic upload is an especially useful control. WS-LNGUYEN eCAR lines 314–318 contains archive construction and a multipart curl invocation. Core HTTP line 1330 and DMZ HTTP lines 1510–1511 preserve the multipart JSON/gzip types and the proxy's outbound request. The one-byte core response deficit is explicitly represented by the file and connection loss fields. Across 2,167 HTTP transaction groups observed by multiple sensors, 19 have differing response-body lengths and none has differing request-body lengths; the examined response differences were accompanied by observation-loss evidence. I did not count those differences as defects.

Network states also have a long tail: core has SF, S0, OTH, RSTO, RSTR, REJ, S1, S2, and S3 records. Database traffic is dominated by TCP/3306, while proxy and DNS traffic have larger shares in the other views. This is consistent with the apparent roles. The source mix does not make every alert an attack, and the suspicious-looking support attachment has a separate ticket-oriented operational context.

The Mac binary-document `cat` commands and the Linux `smbclient` service check are the only behavioral oddities I would carry forward from this review. Neither establishes an impossible effect, and both could be explained by operator intent or custom configuration. I did not find a hard contradiction that justifies moving the score into the likely-synthetic range.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `weak_signal` | Mac normalized endpoint process/file observations | Four binary-document reads on MAC-MROSS-02 | Small increase: repeated utility choice is unusual but executable and explainable |
| `weak_signal` | Linux syslog and normalized endpoint process observations | One service-health command on WS-LNGUYEN-01 | Small increase: client-program name used as a service target; no successful-result claim |

No demonstrated `hard_contradiction`, source-required `contract_gap`, or verified native `schema_or_format` defect was identified in this threat-hunting review. Complete matching and thin optional source coverage were not scored.

## Realism Score by Category

- **Field format accuracy:** 9 — The investigated records support practical parsing and pivots; no verified source-native format contradiction was established.
- **Temporal patterns:** 9 — Investigated session, service, transfer, and registration phases occur in workable order; periodic cron and lease timers have operational explanations.
- **Cross-source correlation:** 9 — Session tuples, supplied credentials, artifact paths, remote receipt, and sensor-specific byte loss agree in the tested pivots.
- **Behavioral realism:** 8 — Attack and administrative behavior are operationally usable; binary-document cat commands and one service-name choice are minor concerns.
- **Environmental consistency:** 9 — Database, proxy, directory, workstation, and mixed-platform activity fit the visible roles without requiring absent optional telemetry.

## Recommendations

- If this were synthetic, review the four MAC-MROSS-02 document-reading command choices. Use behavior appropriate to the intended operation, or make a scripted binary-validation purpose evident in the actual command context. Do not simply substitute a GUI opener if the intended activity is a noninteractive read.
- If this were synthetic, ensure service-health command targets represent the intended service. For the `systemctl is-active smbclient` case, use the relevant actual service name when a health check is intended, or retain an erroneous command only with an appropriate unsuccessful outcome when that outcome is within collection scope.
- Preserve the existing distinction between canonical activity and source observation. In particular, keep the interpretable core/DMZ byte-loss accounting, net-only local/network identity distinction, and SSH transport/authentication/file-receipt ordering demonstrated by these records.
