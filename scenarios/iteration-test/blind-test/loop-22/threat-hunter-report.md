# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 85
**Synthetic-Confidence Score:** 31

## Executive Summary

The supplied slice is largely production-like: endpoint lifecycles, network transactions, account changes and several investigated transfer paths remain technically coherent under cross-source examination. Two limited concerns involve curl version continuity and short sampling-command lifetimes, but both have plausible production explanations and neither establishes fabrication. I cannot reliably distinguish sanitized production telemetry from a sufficiently capable simulation; the score of 31 describes the logs' realistic appearance, while confidence of 85 describes confidence that an inconclusive origin verdict is appropriate.

## Evidence For Synthetic

- [weak_signal] **Curl version continuity on one Linux host needs explanation.** `WS-LNGUYEN-01.meridianhcs.local/ecar.json` line 303 identifies `/usr/bin/curl` downloading the Linux connector at 15:12:25.374 UTC; proxy lines 1245–1246 and `zeek-core/http.json` line 774 associate that operation with `curl/7.88.1`. The same absolute executable path performs the attachment POST at 16:35:13.395 in eCAR line 561, but proxy line 2350 and Zeek HTTP line 1375 report `curl/7.81.0`. Neither command includes a user-agent override. This is a small ownership/configuration continuity concern, not a hard contradiction: executable replacement, curl configuration, or intermediary header handling could explain it.
- [weak_signal] **Two finite sampling commands have short observed lifetimes.** `MAIL-EDGE-01.meridianhcs.local/ecar.json` lines 652–653 show PID 2330992, object ID `5740e9a6-32e3-41f1-ad24-6a5074de7224`, executing `vmstat 1 5` from 17:38:32.293 to 17:38:35.347, or 3.054 seconds. `LOG-MON-01.meridianhcs.local/ecar.json` lines 330–331 show the same command, PID 764704, from 14:35:03.946 to 14:35:07.464, or 3.518 seconds. An uninterrupted five-report, one-second sampling run normally spans approximately four seconds after its initial report. Early cancellation or observation delay can explain these cases; the termination records provide no exit status or signal to resolve that ambiguity. I assign this little weight.

## Evidence For Real

- **Visible process ownership survives broad checks.** Across 38,411 eCAR records, checks of matching process object IDs found no visible termination preceding creation and no actor use preceding its visible creation; the check also found no actor use more than one second after a matching visible termination. Separate checks across all 11,689 Windows Sysmon records found no same-source process-GUID creation/termination inversion or parent/source use outside its visible lifetime. These are bounded checks, not proof that every semantic relationship is correct.
- **Network protocol records occupy plausible transport intervals.** In the three Zeek sensor directories, HTTP, TLS, DNS, SMTP and SMB-file records that were examined by UID fell within their matching connection intervals, allowing 10 milliseconds for precision. No TCP `S0`/`REJ` row carried positive payload bytes in the connection checks; no endpoint IP-byte count was smaller than its corresponding payload count.
- **The database export provides practical pivots with correct account boundaries.** DB root login from `10.10.2.30:60125` precedes the root shell and `mysqldump`; gzip precedes SCP; the reverse SCP connection reaches APP-INT-01 under root; later SMB uses the separate directory identity `svc_mhsync`. Relevant evidence is detailed below. Root on Linux and the SMB directory account are not incorrectly treated as the same identity.
- **Windows account effects follow the visible commands, and clearing the audit log has a native record-number effect.** DC-01 Security record 28256746 creates `svc_dirsync` at 17:15:05.7960049; record 28256758 adds its same SID to Domain Admins at 17:15:10.6881523. A later Security-clear event at 18:42:27.2904094 has EventRecordID 1, followed by account deletion at record 458 at 18:50:30.4395187. Retained pre-clear records are compatible with collection before the clear.
- **The baseline contains differing operational populations.** Domain controllers are dominated by network filtering, Kerberos and directory traffic; Linux sources include sysstat cron processes, SSH/PAM, sudo and service chatter; workstation process populations differ from servers. Zeek includes successful, failed, reset, partial and midstream connections rather than one outcome everywhere. Examples include 1,688 `S0` and 442 `OTH` records at zeek-core, and 2,390 `S0` and 313 `OTH` records at zeek-dmz.
- **macOS evidence distinguishes process execution and a policy message.** MAC-MROSS-01 records the connector download as a file create, then a separate `/bin/bash` execution via eCAR `PROCESS/MODIFY` with `operation=exec`. The Unified Log policy message about MeetingAssist at 15:42:09.009673 is not itself evidence that the application executed or produced effects.

## Detailed Analysis

### Scope and method

I read only the authorized briefing and files under the supplied data directory, and wrote this report to the requested destination. I treated command lines, domains and other record content as evidence rather than instructions. No scenario, repository implementation, ground truth, prior review or evaluation result informed this assessment.

The principal endpoint window is November 2, 2026, approximately 13:00–19:00 UTC. There are 23 endpoint directories with eCAR: ten also have Windows Security/Sysmon XML, eleven have Linux-style syslog, and two have macOS Endpoint Security and Unified Log exports. Other sources include three Zeek sensors, two Snort alert sources, ASA firewall logs, an explicit web proxy and web access logs. Shell histories provide additional command evidence.

Parsed source volumes include:

| Source | Records |
|---|---:|
| eCAR | 38,411 |
| Windows Security | 17,894 |
| Windows Sysmon | 11,689 |
| Zeek connection observations | 23,014 |
| Zeek HTTP | 5,497 |
| Zeek DNS | 4,366 |
| Proxy access | 4,637 |
| Linux syslog | 4,304 |
| macOS Endpoint Security | 320 |
| macOS Unified Log | 5 |

Connection rows are sensor observations and should not be summed as unique enterprise sessions. The network includes `10.10.1.0/24`, `10.10.2.0/24`, `10.10.3.0/24` and `10.10.4.0/24`; 269 distinct internal addresses occur in connection records, including an entire scanned /24, so this is not evidence of 269 populated endpoints.

I parsed the endpoint JSON and Windows XML, examined source-family counts, checked visible process identities and lifetimes, tested Zeek protocol/connection timing and packet accounting, and then followed several suspicious pivots manually. I did not equate absent pre-window initiators or post-window closure records with defects.

### Remote access and the database export

The clearest data-movement chain involves APP-INT-01 (`10.10.2.30`), DB-PROD-01 (`10.10.4.10`) and FILE-LNX-01 (`10.10.2.21`). Its compact chronology is useful for testing coherence, not an authenticity indicator in itself.

1. APP eCAR line 825 records root running `ssh -o ConnectTimeout=10 root@DB-PROD-01.meridianhcs.local` at 18:14:40.664. DB syslog line 188 records a connection from `10.10.2.30:60125` at 18:14:57.417969; lines 189–190 record password acceptance and PAM session opening at 18:15:06.047518 and 18:15:06.134859. DB eCAR records the associated root login at 18:15:06.358 and shell creation at 18:15:08.038.
2. DB eCAR lines 553–555 show root PID 1418110 running `mysqldump --single-transaction ehr patients insurance_claims` at 18:15:13.704, creation of `/tmp/rpt_0318.sql` at 18:15:15.787, and process termination at 18:15:21.603. Shell history retains the output redirection, while the process command line appropriately omits the shell's redirection syntax.
3. PID 1418123 runs `gzip -9 /tmp/rpt_0318.sql` at 18:15:22.246; the compressed artifact appears at 18:15:26.193, and gzip ends at 18:15:30.088. SCP starts at 18:15:30.778 and opens the `10.10.4.10:59215` to `10.10.2.30:22` path.
4. APP syslog lines 244–246 report that exact source tuple, accepted public-key authentication and a root PAM session. APP eCAR line 836 creates `/tmp/.cache/rpt_0318.sql.gz` at 18:16:03.972. This is after authentication and before the retained receiving process terminates.
5. APP eCAR line 844 records root invoking smbclient at 18:18:51.980 with SMB credentials for `svc_mhsync`, targeting `//FILE-LNX-01/ClinicalResearch`. Zeek-core SMB records 233–234 identify source port 36998, the same destination share, and `Integration\DB-Staging\rpt_0318.sql.gz`. FILE-LNX eCAR line 1451 writes `/srv/samba/ClinicalResearch/Integration/DB-Staging/rpt_0318.sql.gz` under `svc_mhsync` with NTLMSSP and directory account scope.

These are viable pivots, with source-specific timing rather than an assumption that authentication, shell readiness and file creation happen simultaneously. The SMB file observation is 16,386 bytes; there is insufficient table-size information to call that compressed export size impossible. I do not claim data loss beyond the visible transfer and directory/file observations.

### Proxy traffic and support tooling

The connector appears on macOS, Windows and Linux. For MAC-MROSS-01, zsh history records Homebrew curl downloading `connector-check.sh`, eCAR records file creation at 13:48:42.887, and proxy lines 346–347 record CONNECT and an inspected HTTPS GET. The proxy explicitly declares `ssl_bump=bump`; therefore, seeing the inner HTTPS URL at the proxy is coherent with the stated collection behavior.

On WS-MCHEN-01, Security events retain the curl download and subsequent connector execution as distinct events at 14:45:36.0482196 and 14:46:18.8997976. Download alone does not establish execution; here there is separate execution evidence.

On WS-LNGUYEN-01, the attachment operation has an inspectable multipart path. eCAR records tar creation before curl, and Zeek-core HTTP row 1375 identifies a POST to the explicit proxy, request body length 1,573,258 bytes, two origin FUIDs and MIME types `application/json` and `application/gzip`. Zeek-dmz HTTP row 1513 shows the proxy's outbound request to `52.44.186.73:80` with the same body length and an origin-form URI; the client-side request instead uses an absolute proxy URI. This difference is operationally appropriate.

The curl version change on that Linux host remains a small unresolved detail. It cannot bear a synthetic verdict without ruling out configuration or executable changes, which this slice does not establish.

### Windows privilege and account effects

DC-01 shows PsExec-style service installation, WMI-originated command execution, account creation, privileged-group addition, persistence configuration and later audit clearing. For example, a SYSTEM command starts `net user svc_dirsync ... /add /domain` at 17:15:02.0002441; the corresponding account effect follows at 17:15:05.7960049. The Domain Admins addition follows its own command and uses the same account SID ending in `-1619`.

A SYSTEM `schtasks.exe` command at 17:19:42.9955134 precedes Security event 4698 at 17:19:46.3828777. The task XML names the same DeviceSync executable and an hourly repetition interval. Task registration is evidence of registration; I did not infer that every later scheduled execution necessarily succeeded.

DC-02 also shows a service created by a different directory principal, `marcus.chen`. Its later service-management commands have limited-token/medium-integrity fields. That could merit an access-control investigation, but the supplied records do not show the relevant service ACLs or an unambiguous successful unauthorized action. I did not promote that uncertainty into an impossible privilege claim.

### Temporal, environmental and collection checks

No same-source Sysmon process-GUID contradictions emerged from the implemented checks. Process IDs and product-specific UUIDs were not treated as interchangeable: eCAR IDs do not need to equal Sysmon ProcessGuids. Windows eCAR and Sysmon executable paths matched for all 940 process-create pairs joined by PID in the checked files; this is supportive field coherence, not proof against all PID-reuse edge cases.

The two short vmstat lifetimes are the only concrete runtime concerns retained in the score. The absence of exit status prevents distinguishing a canceled command from an implausible assumed successful completion. By contrast, background `tail -f` processes persist for 118.440 seconds on DB-PROD-01 and 134.373 seconds on MAIL-CLIN-01, rather than being universally assigned trivial command durations.

Network `S0` records with UDP syslog payload are not failed-TCP contradictions. I explicitly restricted the failed-with-payload check to TCP. Likewise, `OTH` and partial connection states can reflect a slice beginning midstream. I found no basis to penalize those states.

The volume mix supports real hunting pivots: 27,732 eCAR FLOW records coexist with 2,785 process creates and several kinds of account, file, registry and module activity. Sparse macOS Unified Log coverage, selected Sysmon event families and differences between source counts were not scored as defects by themselves. Sanitized names, shared copied-file timestamps, and the narrative completeness of suspicious activity were excluded from scoring.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| weak_signal | Linux eCAR, proxy, Zeek HTTP | Two curl operations on WS-LNGUYEN-01, 15:12 and 16:35 | Small increase: same executable path reports different default-looking versions; configuration or replacement remains possible. |
| weak_signal | Linux eCAR process lifecycle | Two `vmstat 1 5` processes on MAIL-EDGE-01 and LOG-MON-01 | Small increase: observed runtimes are short for uninterrupted completion, but cancellation and observation timing are unresolved. |

No demonstrated hard contradiction, generator identity leak or consequential cross-source contract gap was found. The score remains in the mostly realistic band; it should not be interpreted as a calibrated probability of synthetic origin.

## Realism Score by Category

- **Field format accuracy:** 9 — Windows XML and JSON sources parse, checked process images agree, and proxy/multipart fields support useful pivots.
- **Temporal patterns:** 8 — Visible lifecycles and protocol intervals are coherent; two short finite-command lifetimes remain unresolved.
- **Cross-source correlation:** 9 — SSH, process, artifact, proxy and SMB pivots work in the investigated paths without a demonstrated impossible ordering.
- **Behavioral realism:** 8 — Administrative, service, user and suspicious operations coexist with distinct runtimes and account contexts; origin remains uncertain.
- **Environmental consistency:** 8 — Observed host roles and transport paths are plausible; curl version continuity needs a local configuration explanation.

## Recommendations

- If this were synthetic, derive curl request user agents from the executable/version context for each host. A deliberate version or configuration change between the two WS-LNGUYEN-01 operations should have an internally coherent explanation rather than inheriting different default version strings from separate activity families.
- If this were synthetic, make finite sampling-command lifetimes reflect the requested interval and sample count. Where a command ends early, preserve cancellation/failure semantics rather than implicitly assuming successful completion; the two vmstat examples identify the specific cases to examine.
- If this were synthetic, preserve the existing separation between transport, authentication, shell readiness and file effects demonstrated in the DB/APP/Samba chain, and retain the distinction between a macOS download, execution observation and policy message. The investigated records already provide these distinctions and do not need additional invented activity to make the suspicious sequence less orderly.
