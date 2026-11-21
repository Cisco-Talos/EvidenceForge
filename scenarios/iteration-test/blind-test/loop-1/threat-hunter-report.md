# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 85
**Synthetic-Confidence Score:** 43

## Executive Summary

The supplied six-hour slice supports practical hunting across Windows, Linux, macOS, network, proxy, firewall, and IDS telemetry, with coherent process identities and useful remote-session and file-transfer pivots. I found limited behavioral and timing texture that could reflect simulation, but no demonstrated impossible lifecycle or source-native contradiction in the checks performed; those reservations are insufficient to confidently distinguish a carefully constructed dataset from selected production telemetry.

## Evidence For Synthetic

- [distribution_texture] On `MAC-MROSS-02.meridianhcs.local/ecar.json`, all nine visible FILE/READ records are attributed to `/bin/cat` (seven) or `/bin/ls` (two). All seven `cat` targets are PDF or Office documents, including `project-plan.pdf` at 13:37:29.812, `service-review.xlsx` at 16:05:58.012, and `onboarding.docx` at 17:12:31.889. Repeatedly treating binary office documents as shell-display targets is an unusual texture for routine desktop document activity. This is possible, and a narrow collection selection could explain it; it is not an execution impossibility.
- [weak_signal] Some support-tool execution timing is unusually aligned to a common fractional second. In `WS-MCHEN-01.meridianhcs.local/windows_event_sysmon.xml`, the curl downloader starts at `UtcTime=2026-11-02 14:45:35.733` (PID 7508), followed by the downloaded executable at `14:46:18.733` (PID 7520). On `WS-LNGUYEN-01.meridianhcs.local/ecar.json`, the corresponding download/chmod/execute/inspect starts are 15:12:25.373, 15:12:49.378, 15:13:06.383, and 15:13:43.387. These short runs of nearly integer-second spacing suggest scheduled or constructed timing, but scripts, timestamp precision, and observation effects remain reasonable alternatives. I give this little weight and do not generalize it to the entire slice.

## Evidence For Real

- Visible process lifecycles withstand direct checks. Across all 39,336 eCAR records and all 12,197 Sysmon events, identifier-based checks found no matched process use before its visible creation or after its visible termination, with a 5 ms comparison tolerance. This includes eCAR actor relationships and Sysmon source, target, parent, and process GUID relationships; missing pre-window creations were excluded from those tests.
- The database export and staging pivot is technically connected across independent-looking sources. DB-PROD-01 shows root SSH authentication, `mysqldump`, gzip, and scp. APP-INT-01 records the matching inbound SSH source tuple, creates the received file, and later sends it to FILE-LNX-01 over SMB. The network and endpoint evidence agrees on the participating hosts, file names, and transfer direction.
- The support attachment upload has appropriately different proxy legs. `zeek-core/http.json` line 1540 and `zeek-dmz/http.json` lines 1679–1680 show the client-to-proxy and proxy-to-server POST, with absolute-form versus origin-form request URIs, distinct connection identities, and the same 1,573,258-byte request body. The command explicitly requests a proxy and two multipart fields, consistent with the observed JSON and gzip MIME types.
- macOS records distinguish fork, exec image replacement, and exit. For example, MAC-MROSS-02 PID 18998 moves through launchd/xpcproxy into iTerm2, followed by login and shell processes. Mac-to-Mac SSH has distinct transport, authentication, and shell events. I did not mistake a native exec transition for a new PID or demand that all sources render it as a new process creation.
- The slice contains substantial ordinary activity and varied transport outcomes. The 23 endpoint/host directories include directory controllers, file services, mail, application, database, proxy, monitoring, and user systems; 23,842 Zeek connection records span DNS, Kerberos, LDAP, SMB, HTTP, TLS, MySQL, SSH, and other traffic. Reset, failed, partial, and successful connection states coexist rather than every connection succeeding.
- Within each host and image/version grouping, visible Sysmon process-start hashes were stable. Checks also found no identical full hash string associated with conflicting file versions across hosts.

## Detailed Analysis

### Scope and method

I examined only the assigned instruction file and data directory. The directory contains 118 files under 29 immediate source directories: 23 host directories and six sensor/firewall/IDS directories. The eCAR slice runs approximately 2026-11-02 13:00–19:00 UTC. Apparent internal segments include user systems in 10.10.1.0/24, infrastructure in 10.10.2.0/24, DMZ systems in 10.10.3.0/24, and the database host at 10.10.4.10. These are inferences from addresses and observed services, not external environment documentation.

The principal record counts are 39,336 eCAR records, 19,405 Security events, 12,197 Sysmon events, 23,842 Zeek connections, 25,938 firewall lines, 4,732 proxy lines, and 197 IDS alerts. Native macOS Endpoint Security contains 319 records across two hosts; the Unified Log export contains five selected records. That small Unified Log set is not a defect by itself because the export predicate is unknown. Likewise, I did not score the selected Sysmon event-family coverage or an absence of unprovided sources.

I parsed XML and JSON records, inventoried source and host distributions, reconstructed selected process/session/file pivots, and checked visible process lifecycle boundaries. The automated checks are bounded to fields present in these exports; they are not proof that every protocol or lifecycle detail is correct.

### Support activity and diagnostic upload

The history on MAC-MROSS-01 shows a download of `connector-check.sh` from the support site, followed by explicit bash invocation with `--check-config` and later `--check-network`. Native Endpoint Security distinguishes curl execution from script execution: the download runs at 14:07:25.660378 and `/bin/bash ... --check-config` at 14:07:42.819492. The eCAR file creation is at 14:07:28.247. This is a usable download-before-execution chain, rather than attribution of execution from a GET alone.

WS-MCHEN-01 has a Windows executable variant at 14:45–14:46, and WS-LNGUYEN-01 has a Linux variant at 15:12–15:13. These share a support destination but use platform-appropriate executable paths and command forms. That common destination is investigatively relevant, but its name and real-world resolution are not authenticity evidence because domains may be sanitized.

At 16:31:34.994, WS-LNGUYEN-01 starts tar to build `/tmp/mhs-support-48217.tar.gz` from two connector logs. At 16:31:44.035 it starts curl with an explicit HTTP proxy, a JSON metadata form field, and a gzip attachment field. The corresponding Zeek HTTP transactions at approximately 16:31:58 show the two-part upload and a 200 response. The proxy access log line 2780 records the same ticket URI and response body length of 96. This supports a transfer, while the actual attachment content and authorization cannot be determined from the supplied metadata alone.

### Credential access and Windows administration pivots

On WS-AJOHNSON-01, PID 5796 executes `ms-index-service.exe "privilege::debug" "sekurlsa::logonpasswords" exit` at approximately 16:45:03. Its command line is strongly suspicious for credential dumping. Sysmon records a High integrity process under aisha.johnson, parented by Edge PID 5792; eCAR subsequently records access to lsass PID 4292 with `granted_access=0x1FFFFF` at 16:45:11.949, followed by process termination at 16:45:12.023.

That is observable credential-access behavior, not proof that usable credentials were extracted. The browser parent is unusual and merits an incident pivot, but malware execution, parent manipulation, and browser compromise are plausible; I do not label the parent relationship impossible or use the lack of an explanatory exploit event as an authenticity defect.

Later, aisha.johnson starts `runas.exe /netonly /user:marcus.chen "cmd.exe /d /q"` at approximately 18:00:42. The child remains locally attributed to aisha.johnson while using a distinct logon identifier, consistent with the distinction between a local token and outbound network credentials. The subsequent PowerShell commands reference both Windows and Linux SMB shares and stage files under `C:\ProgramData\Microsoft\VaultCache`. This is a useful account-boundary pivot; treating every local child as marcus.chen would be an analytical error.

DC-01 separately exposes account, privilege, service, task, and cleanup activity: `net user svc_dirsync ... /add /domain` at 17:15:01.957, Domain Admins group modification at 17:15:15.935, service/task creation around 17:19:40–17:19:46, encoded PowerShell at 18:42:16.127, and Security-log clearing at 18:42:16.646. These are suspicious observed commands and corroborating event families. Their narrative completeness contributes nothing to my authenticity score.

### Database export, SSH transfer, and SMB staging

`DB-PROD-01.meridianhcs.local/syslog.log` lines 193–196 show an inbound root session from APP-INT-01 address 10.10.2.30, source port 56918: connection at 18:14:56.573720, password acceptance at 18:15:04.114267, PAM opening at 18:15:04.290351, and logind session 385 at 18:15:04.802947.

DB endpoint process events then show:

- 18:15:09.965: `mysqldump --single-transaction ehr patients insurance_claims`, PID 1088982.
- 18:15:11.059: creation of `/tmp/rpt_0318.sql`.
- 18:15:30.378: `gzip -9 /tmp/rpt_0318.sql`, PID 1089057.
- 18:15:34.325: creation of `/tmp/rpt_0318.sql.gz`.
- 18:15:56.525: scp to `root@10.10.2.30:/tmp/.cache/rpt_0318.sql.gz`, PID 1089150.

The outbound eCAR FLOW uses source 10.10.4.10:54886 and destination 10.10.2.30:22 at 18:15:59.615. APP-INT-01 syslog lines 220–223 show that exact tuple, acceptance, PAM, and logind opening around 18:16:04–18:16:05. The sender file read at 18:16:05.917 precedes the receiver file creation at 18:16:23.957; target session closure follows at 18:16:24.319340. Observation times differ by seconds, but no visible dependency is reversed by these records.

APP-INT-01 later starts smbclient at 18:18:52.933, authenticated as `svc_mhsync`, to upload the received gzip file into ClinicalResearch. `zeek-core/smb_mapping.json` line 135 and `smb_files.json` lines 230–231 show source 10.10.2.30:33409, target 10.10.2.21:445, UID `CH9L6pukWIL9Ifj7oH`, and `Integration\DB-Staging\rpt_0318.sql.gz`; the SMB write reports size 34,063. The application host, database host, and SMB destination have distinct roles and accounts, which is operationally plausible.

### macOS semantics and background behavior

The Mac native records preserve audit-token fields and PID-version changes across exec transitions. Short commands have varied lifetimes: examples on MAC-MROSS-02 include `uname -a` at about 140 ms and `pwd` at about 61 ms; the visible `sw_vers` inventory executions last approximately 466, 515, and 724 ms. This does not resemble one universal process lifetime applied across all activity.

MAC-MROSS-01 Unified Log contains a policy message concerning MeetingAssist at 15:42:09.009673. I found no MeetingAssist eCAR process record. The wording alone does not establish the ultimate authorization outcome, and I do not infer successful execution, children, or effects from it. LaunchDaemon plist placement/deletion and observed inventory process launches are also separate observations; I do not infer a registration failure merely because a particular management command is absent.

The modest behavioral reservation is the second Mac's seven `cat` reads of Office/PDF content. This repeated source-visible program/file pairing deserves scrutiny, but it does not by itself prove synthesis: a collector predicate, a troubleshooting script, or a user's terminal workflow could select just such events. The first Mac's `cat` of a JSON manifest is entirely reasonable and is not included in that reservation.

### Limits and balance

The process checks returned no visible boundary inversions, and simple Zeek consistency checks returned no negative durations, payload exceeding corresponding IP-byte counters, zero-packet/nonzero-origin-payload combinations, or S0 records with response packets. These are positive bounded results, not a complete protocol certification.

Source alignment is useful for hunting and technically credible. It is not evidence of synthesis simply because many pivots work. Conversely, successful correlation cannot prove production origin: a sufficiently capable simulator could produce it. The remaining weak textures therefore support an inconclusive verdict, with a score below the midpoint reflecting the greater weight of observed coherence over limited anomalies.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on synthetic-confidence score |
|---|---|---|---|
| distribution_texture | macOS eCAR file/process activity | MAC-MROSS-02: seven binary-document reads via cat, among nine total FILE/READ records | Modest upward influence: repeated program/file pairing is unusual for routine document use, but selection and scripting can explain it. |
| weak_signal | Windows Sysmon and Linux eCAR process timing | Two support-tool sequences; exact .733 pairing on Windows and .373/.378/.383/.387 starts on Linux | Small upward influence only: restricted timing regularity has plausible scripted/measurement explanations. |
| No demonstrated hard_contradiction or contract_gap | eCAR, Sysmon, selected SSH/SMB/proxy pivots | All visible process-boundary checks and the investigated transfer chains | Keeps the score below the midpoint; no impossible ordering was established. |

## Realism Score by Category

- **Field format accuracy:** 9 — Parsed native and normalized records provide credible identities, paths, timestamps, and protocol fields; no demonstrated native schema defect in the checked records.
- **Temporal patterns:** 8 — Process boundaries and selected network/authentication/transfer ordering hold; two short support-tool sequences show weak timing alignment.
- **Cross-source correlation:** 9 — SSH, SMB, multipart proxy legs, and Windows process/account pivots are feasible and preserve distinct identities.
- **Behavioral realism:** 7 — Support/admin and suspicious activity is technically plausible; the concentration of binary-document reads through cat is unusual.
- **Environmental consistency:** 8 — Observed services and network segments support the apparent host roles; unknown collection predicates limit claims about desktop behavior and source volume.

## Recommendations

- If this were synthetic, make routine Mac document-access activity reflect the actual programs performing it. The seven PDF/Office reads via cat on MAC-MROSS-02 could be replaced or balanced with application-owned access where the intended activity is document viewing, while retaining shell reads for legitimate troubleshooting. Do not invent application access if the modeled activity really is a script.
- If this were synthetic, derive support-tool command start times from their execution or interaction mechanism. Preserve exact scheduling when a script actually owns it; vary human interaction delays when the sequence represents manually entered commands. The Windows .733 pairing and Linux near-fixed fractional progression warrant checking at that owning layer.
- Preserve the existing distinction among download, execution, policy messages, file placement, and activation; preserve local versus outbound credentials and the matched SSH/SMB transfer identities. The investigated records already make these distinctions usable for hunting.
