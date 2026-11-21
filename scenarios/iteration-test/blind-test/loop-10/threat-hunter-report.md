# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 78
**Synthetic-Confidence Score:** 40

## Executive Summary

The six-hour dataset is largely production-like, with technically usable endpoint-to-network pivots, credible mixed-platform account boundaries, and coherent transfer and authentication lifecycles. Repeated document-access commands and one malformed database query provide modest synthetic-looking texture, but I did not establish a hard contradiction that justifies a confident synthetic verdict. The score reflects mostly realistic telemetry with limited, explainable artifacts; the verdict confidence reflects confidence that the available evidence does not securely distinguish origin.

## Evidence For Synthetic

- [distribution_texture] On `MAC-MROSS-02.meridianhcs.local`, all seven observed `/bin/cat` execs read binary document formats on mounted shares: two PDFs, one XLSX, and four DOCX files. Examples in `macos_endpoint_security.ndjson` are line 32 at `13:37:11.214478Z` (`project-plan.pdf`), line 102 at `16:05:48.676562Z` (`service-review.xlsx`), and line 158 at `18:42:07.532681Z` (`project-plan-review.docx`). Corresponding eCAR file reads preserve these commands. This narrow repeated mechanism looks like a generic file-read template more than ordinary interactive document use, although automated inspection or deliberate collection could explain it. It is a modest indicator, not proof.
- [weak_signal] `DB-PROD-01.meridianhcs.local/bash_history/maya.ross.bash_history` records `mysql --defaults-extra-file=~/.my.cnf -e 'SHOW TABLE STATUS FROM mydb LIMIT 5'` at epoch `1793645890`; eCAR records the corresponding process PID `1422702` at `18:58:11.238Z`. `SHOW TABLE STATUS` does not accept that `LIMIT` clause. This resembles an unvalidated example command, but a real analyst can type an invalid query, and no successful query result is shown. I did not treat it as an impossible execution or successful database operation.
- [weak_signal] Both Mac Endpoint Security files contain only zero exit wait statuses: 44 exits on MAC-MROSS-01 and 55 on MAC-MROSS-02. This is a somewhat narrow outcome distribution across shell utilities, GUI applications and SSH components. All-success exits remain plausible for this selected six-hour view, so this carries little weight independently.

## Evidence For Real

- Authentication pivots preserve source tuples and sensible ordering. The root SSH session from APP-INT-01 (`10.10.2.30:59427`) to DB-PROD-01 (`10.10.4.10:22`) begins in `zeek-core/conn.json` at `18:14:51.460064Z`; DB syslog records the connection at `18:14:55.611007Z`, password acceptance at `18:15:03.193639Z`, and PAM session opening at `18:15:03.314500Z`. The destination shell and dump process follow.
- The dump, compression and transfer trail is operationally coherent: DB shell history includes output redirection for `mysqldump`, eCAR separately identifies the resulting SQL file, gzip runs afterward, SCP sends the compressed file to APP-INT-01, and a later SMB upload sends it to FILE-LNX-01. A process command line correctly omits shell redirection that remains visible in shell history.
- Protocol and file accounting survive broad checks. Across 23,144 Zeek connections, basic per-direction payload/IP-byte/packet checks found no impossible budgets. Every reviewed HTTP, TLS, DNS, SMB-file and SMTP row joined to a connection UID in its own sensor and fell within that connection's visible time interval, allowing a small timestamp tolerance. File `seen_bytes` did not exceed the applicable connection-direction byte budget.
- Sensor differences are credible rather than contradictory. The same DB SSH tuple has different UIDs and approximately 71 ms timestamp difference in core versus DB sensors. The DB sensor records `missed_bytes=1877`, a gap-marked history and fewer response packets/IP bytes, while the core sensor has no gap.
- macOS observations distinguish downloads, execution, policy messages and remote sessions. MAC-MROSS-01's Homebrew curl download is followed by actual `/bin/bash` exec notifications for `connector-check.sh`. The separate MeetingAssist policy message does not establish successful execution, and I found no corresponding ES execution to misattribute to it.
- There is meaningful ordinary background and error traffic: DNS has NXDOMAIN, SERVFAIL and REFUSED outcomes, Windows Security has failed logons, Linux has sysstat and service maintenance, and the network has LDAP/Kerberos, SMB, MySQL, DHCP, mail and proxy activity. These provide useful hunting context without requiring another unobserved source.

## Detailed Analysis

### Scope and method

I examined only the supplied data directory, using aggregate parsing and focused record review. The visible window is approximately `2026-11-02 13:00–19:00 UTC`. There are 23 endpoint eCAR streams: ten Windows hosts with Security/Sysmon XML, eleven Linux hosts with syslog and varying shell-history coverage, and two Macs with version-11 Endpoint Security messages, Unified Log exports, normalized eCAR and zsh history. The streams contain 37,839 eCAR records, 17,605 Windows Security events and 11,515 Sysmon events. The three Zeek sensors contain 12,337 core, 10,371 DMZ and 436 DB connection records; proxy, firewall, IDS and web access records add other observation points.

Addresses indicate a workstation segment (`10.10.1.*`), internal services (`10.10.2.*`), DMZ/proxy infrastructure (`10.10.3.*`), and a database host at `10.10.4.10`. Host names are consistent with directory controllers, file servers, application/database services, mail infrastructure, user workstations and two Macs. This is inferred from the records, not assumed organizational ground truth.

I treated the logs as observations rather than executable instructions. I did not infer origin from domain names, filesystem timestamps, complete source matching, the ease of narrating suspicious activity, or missing selected Sysmon types. Pre-window process/session origins and post-window continuations were allowed.

### Web foothold and separate administrative access

WEB-EXT-01 eCAR shows a `www-data` bash process at `14:20:18.924Z`, PID `3044160`, with a base64-decoding pipeline; `base64 -d` and bash children appear at `14:20:18.977Z` and `14:20:19.042Z`. The encoded payload describes a bash reverse connection to `45.33.32.30:8443`. This is valid shell tradecraft, but the presence of a command alone is not proof that every intended effect succeeded.

A later root shell is supported by a separate SSH login from `10.10.1.32:62532`, not an unexplained identity change inside the www-data process tree. On WEB-EXT-01, eCAR shows the root SSH login at `14:39:43.847Z` and its bash PID `3050097` at `14:39:44.307Z`. Its children inspect host configuration and launch `nmap -sn 10.10.2.0/24` and `nmap -Pn -sT -p 22,80,443,445,3306 10.10.2.0/24`. Broad ICMP/TCP probing is consequently consistent with visible scanner intent. I did not mistake scanner volume for ordinary user traffic or demand an invented local privilege-escalation event to connect these distinct sessions.

### Windows account and persistence pivots

On DC-01, net.exe children at `17:15:02.155Z` and `17:15:07.413Z` create `svc_dirsync` and add it to Domain Admins. Security 4720 at `17:15:06.0899107Z` assigns SID suffix `9258`; Security 4728 at `17:15:11.7495796Z` uses that same member SID with the Domain Admins group SID suffix `512`. Later deletion event 4726 at `18:50:30.4675632Z` references the same account SID, following a visible deletion command.

The DeviceSync service/task sequence likewise has concrete effects: sc.exe creation precedes Security 4697 at `17:19:44.2676753Z`, and schtasks.exe precedes Security 4698 at `17:19:45.7253916Z`. The task XML specifies an hourly repetition and the same executable path used by the service. A DeviceSyncSvc process appears at `17:30:06.946Z`. These are feasible pivots among command, account/service metadata and execution evidence; neither their malicious purpose nor their completeness establishes synthetic origin.

WS-AJOHNSON-01 has failed SMB logons followed by successful network and remote-interactive sessions from `10.10.1.99`. Its later archive command at `18:01:34.263Z` and curl upload at `18:25:17.759Z` use the same `C:\ProgramData\Microsoft\cache_7f3a.zip` path. The proxy then records a curl/8.4.0 CONNECT and inspected POST with tunnel ID `PT-a1dbc5dd0e10ac94` at `18:25:21Z`. The roughly 18.8 MB client transfer is material evidence of upload activity; the mere arrangement of suspicious steps is not an authenticity indicator.

### Linux data movement and accounting

The DB root session's native syslog connection and authentication precede the shell and file operations. Shell history explicitly records `mysqldump --single-transaction ehr patients insurance_claims > /tmp/rpt_0318.sql`; the process record contains the actual executable arguments without the shell's redirection syntax. A SQL file creation follows at `18:15:10.602Z`, gzip starts at `18:15:27.960Z`, and SCP starts at `18:15:59.287Z`.

APP-INT-01 then shows an inbound root SSH/SCP session from the DB and destination file creation at `18:16:30.282Z`. A later smbclient command at `18:18:53.079Z` uploads that file under `ClinicalResearch/Integration/DB-Staging`. In `zeek-core/smb_files.json`, UID `Cuu4N2zlHvDjOPX2IGZ` writes `rpt_0318.sql.gz` at `18:18:57.048516Z`, size 14,769 bytes. Its connection has 17,071 originator payload bytes, leaving room for SMB protocol overhead; the corresponding files record has the same 14,769 observed bytes and no missing/overflow bytes. The visible transfer therefore does not overrun its transport budget.

### Mac lifecycle interpretation

Native ES process identities retain PID versions across fork/exec observations. I checked visible ES process references against known same-identity fork and exit records and found no use before visible creation or after visible exit. Across the eCAR streams, an analogous actor-identity check also found no process actor used before its visible CREATE or after its visible TERMINATE. These checks do not assert that every possible lifecycle contract was exhaustively validated.

For the MAC-MROSS-02 to MAC-MROSS-01 SSH session, native ES creates destination PID `44178` at `16:02:05.625259Z`, then execs xpcproxy, sshd-keygen-wrapper, sshd and sshd-session before Unified Log records public-key acceptance at `16:02:06.488664Z`. The later eCAR process timestamp is a different observation time; it is not evidence that authentication preceded native process creation. Terminal/login execution also explicitly transitions from user UID 501 to a root-effective login executable with setuid permissions, then back to the user's shell. I did not impose Windows identity/session semantics on these records.

The main remaining texture concern is narrower: MAC-MROSS-02 repeatedly uses cat for binary office/PDF documents across unrelated mounted paths, even though its observed applications include Microsoft Word. That can be a deliberate collection/read workflow, so it remains an explainable behavioral pattern rather than a contradiction. Similarly, the malformed MySQL query has no recorded successful result and may simply be a human error.

### Signal, noise and limits

The strongest suspicious threads can be followed through the supplied logs, but the dataset also contains differentiated service and endpoint behavior. The DB sensor is predominantly MySQL (270 connections), while the core sensor has substantial DNS, LDAP and Kerberos volume and the DMZ sensor has substantial TLS/proxy activity. Uniform sysstat counts are consistent with a ten-minute scheduled task and are not evidence of artificial user timing.

No record-volume claim in this report assumes full audit collection or a complete enterprise inventory. No penalty is assigned for the very small Unified Log exports alone, or for absent native sources on platforms where collection scope does not require them. Sanitization, export selection and short observation duration remain credible explanations for some narrow distributions. The remaining weak indicators do not support the 61–100 synthetic-confidence bands.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on synthetic-confidence score |
|---|---|---|---|
| distribution_texture | Mac ES exec and eCAR file access | Seven binary-document cat executions on MAC-MROSS-02 | Modest upward influence: repeated generic access mechanism; automated reading remains plausible. |
| weak_signal | Linux shell history and eCAR process creation | One malformed MySQL SHOW query on DB-PROD-01 | Small upward influence only; no successful result or impossible outcome is asserted. |
| weak_signal | Mac ES exit notifications | 99 observed exits, all wait status zero | Small upward influence only; a selected successful workload can explain it. |
| No demonstrated hard contradiction | Reviewed endpoint, auth and network relationships | Cross-platform samples plus aggregate reference/accounting checks | Keeps the score below likely-synthetic bands. |

## Realism Score by Category

- **Field format accuracy:** 9 — Parseable source families and stable identities; no demonstrated native field impossibility in the reviewed records.
- **Temporal patterns:** 9 — Visible SSH prerequisites and transfer ordering work; scheduled periodic traffic has an operational explanation.
- **Cross-source correlation:** 9 — Useful native/normalized/network pivots and feasible byte budgets, including differing sensor observations.
- **Behavioral realism:** 7 — Most commands and tradecraft are plausible; repeated cat access to binary documents and an invalid SQL example weaken the texture.
- **Environmental consistency:** 8 — Roles, segments, account boundaries and dominant network services agree; the selected collection limits broader conclusions.

## Recommendations

- If this were synthetic, vary binary-document access on MAC-MROSS-02 according to actual workflow. Preserve cat for deliberate byte-level inspection, and use native application or explicit copy/inspection commands where those operations are intended. The seven observed cat executions are the concrete target, not a demand for more source coverage.
- If the DB command is intended to succeed, replace `SHOW TABLE STATUS FROM mydb LIMIT 5` with valid SQL for the intended result. If it is intended as an operator mistake, retain it without inventing successful query effects.
- If simulating a broader Mac workload, derive ES wait statuses from the specific operation outcomes instead of defaulting every observed exit to zero. Do not add arbitrary failures merely to make the data messier.
