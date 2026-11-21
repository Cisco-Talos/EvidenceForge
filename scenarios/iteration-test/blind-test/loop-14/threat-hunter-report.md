# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 78
**Synthetic-Confidence Score:** 66

## Executive Summary

This is a technically strong, huntable mixed-fleet dataset, with credible transport, authentication, process, and file-transfer pivots. I lean synthetic because routine share activity repeatedly combines generic document/policy names with interchangeable folders and extensions, and one Mac repeatedly reads Office/PDF documents through an interactive `cat` process. These are behavioral and distribution concerns, not proof of impossible execution; the coherent major lifecycles keep the score well below the highest synthetic-confidence band.

## Evidence For Synthetic

- [distribution_texture] In `zeek-core/smb_files.json`, 52 of 122 `SMB::FILE_OPEN` rows concern SYSVOL or NETLOGON. The paths repeatedly combine a small vocabulary of `Policies`, `Preferences`, `Scripts`, `User`, and `Machine` with names such as `logon-review.ini`, `groups-v2.pol`, `registry-approved.bat`, `gpt-draft.ps1`, and `startup-final.ps1`, sometimes with year directories. Examples include line 2 at 13:05:20.192421 (`\\DC-02\SYSVOL`, `Policies\logon-review.ini`), line 18 at 14:27:36.082106 (`\\DC-02\NETLOGON`, `Scripts\gpt-draft.ps1`), and line 29 at 14:56:09.465160 (`\\DC-01\SYSVOL`, `Preferences\registry-approved.bat`). All times are UTC on 2026-11-02. This repeated recombination across users, operating systems, and both DCs is the strongest template-like texture I found. Custom administrative share contents are possible, so these paths are not individually impossible.
- [environment_or_collection_plausibility] `MAC-MROSS-02.../macos_endpoint_security.ndjson` contains seven explicit `/bin/cat` executions against `.pdf`, `.xlsx`, or `.docx` share files: lines 32, 108, 118, 121, 149, 155, and 161. Examples are `project-plan.pdf` at 13:37:11.214478, `service-review.xlsx` at 16:05:48.676562, and `onboarding.docx` at 17:12:27.402087. These are actual exec argument arrays, with a terminal and iTerm environment, rather than filenames inferred from network traffic. Repeated terminal reads of binary office documents are possible but unusual as routine document-consumption behavior; their recurrence across unrelated shares makes the background activity less production-like.
- [distribution_texture] The same Mac's share-document texture includes `/Volumes/Users/Reports/draft-draft.pdf` at 18:37:47.000074, `/Volumes/ClinicalResearch/Team/project-plan-review.docx` at 18:42:07.532681, and `/Volumes/ResearchShared/Reference/2024/meeting-notes.docx` at 18:44:51.352962. At 18:42:09.887846, `/usr/bin/tee` targets `/Volumes/Users/Downloads/draft.docx`. Together with the policy-share vocabulary above, this looks like generalized file-access templates applied across content types. I treat this as supporting texture, not a separate hard contradiction or proof that `tee` could not receive binary input.

## Evidence For Real

- The available volume is a plausible hunting haystack: 36,715 normalized endpoint rows, 17,375 Windows Security events, 11,315 Sysmon events, 22,408 Zeek connections, 4,171 Linux syslog lines, and 3,992 proxy records. Visible activity spans approximately 13:00–19:00 UTC over 23 endpoint host directories, with Windows, Linux, and two Macs; network addresses expose several internal segments and external clients.
- The Linux root SSH pivot works across sources. APP-INT-01 to DB-PROD-01 uses source port 37538; Zeek transport begins at 18:14:56.820573 on the core sensor, DB syslog accepts root at 18:15:10.483450, and the DB shell appears at 18:15:13.241. The reverse file-transfer transport uses a different port, 56898, and APP syslog accepts that session before the destination file creation.
- File staging and upload have useful concrete pivots. The DB history records a dump, `gzip -9`, and `scp`; endpoint events and SMB logs then follow the staged archive. The Aisha endpoint's upload command corresponds to a proxy POST with the same destination path and `curl/8.4.0`, rather than an unrelated generic browser request.
- Background activity includes actual pipeline children, sudo privilege transitions and PAM opens/closes, scheduled sysstat processes, SSH failures, multiple web/proxy outcomes, and variable network observations. I do not treat scheduled task regularity or a coordinated service-account password failure as synthetic by themselves.
- The Macs distinguish fork from exec, preserve execution identities, model Terminal versus iTerm launch paths, and provide separate local and SSH session evidence. A Unified Log policy warning concerning MeetingAssist does not by itself establish successful execution or downstream effects, and I found no basis to attribute such effects from that warning.

## Detailed Analysis

### Orientation and method

I examined only the supplied data directory. I enumerated the sources, parsed endpoint JSON and Windows XML, sampled native text logs and shell histories, and cross-referenced several operational trails. The environment appears to contain two domain controllers, Windows and Linux file services, application/database systems, mail hosts, a proxy, a public web host, workstations, and two Macs. Endpoint names and observed IPs place user systems mainly in `10.10.1.0/24`, internal services in `10.10.2.0/24`, a DMZ/proxy in `10.10.3.0/24`, and the database at `10.10.4.10`.

I evaluated the visible window rather than demanding boot-to-shutdown completeness. Early process/session terminations are not defects merely because their creation is outside the slice. I also did not penalize intentionally selected Sysmon event coverage, domains that may have been sanitized, or complete cross-source matching.

### Windows hunting trail and privilege boundaries

WS-AJOHNSON-01 records domain discovery at approximately 16:20:25, followed by PID 6048 running `ms-index-service.exe "privilege::debug" "sekurlsa::logonpasswords" exit` at 16:45:04.641 in normalized telemetry. Sysmon independently records the creation at 16:45:04.5798829, with High integrity, LogonId `0x26db315`, and the same parent cmd process. Subsequent Sysmon Event 10 rows target LSASS PID 4292 with `GrantedAccess=0x1FFFFF` and winlogon PID 4772 with `0x1010`; Event 8 records a remote thread into LSASS. These are credible hunting leads, although process access and thread creation do not alone prove that credentials were recovered.

DC-01 then contains PSEXESVC creation around 17:00:17 and `cmd.exe /c whoami && hostname` at 17:00:26.185. At 17:15, WMI-parented command processes add `svc_dirsync` and place it in Domain Admins; Security telemetry includes account creation and group-membership events. Service and task creation around 17:19 have corresponding source event families. This sequence is technically usable; its narratability is not an authenticity indicator.

At 18:00:42.319 the Aisha endpoint launches `runas.exe /netonly /user:marcus.chen "cmd.exe /d /q"`. Subsequent local child processes retaining Aisha's principal are compatible with `/netonly`; I did not mistake this for a requirement that every local process switch to Marcus. The PowerShell collection commands reference specific Finance, ClinicalExports, and ClinicalResearch paths, followed by archive creation.

At 18:25:17.758, PID 6868 launches curl with the archive and explicit proxy. `PROXY-01.../proxy_access.log` line 3512 at 18:25:21 records `POST https://api.westbridge-services.net/upload/telemetry/7f3a2b19`, HTTP 200, `cs_bytes=18783258`, and `proxy_action=ssl-inspect`. Its `ssl_bump=bump` field explains why the proxy can report the HTTPS request path. This is a feasible endpoint-to-proxy pivot.

### Linux dump, SSH, and archive staging

`zeek-core/conn.json` line 10672 records APP-INT-01 (`10.10.2.30`) to DB-PROD-01 (`10.10.4.10`), port 22, source port 37538, with an established `SF` interval lasting 133.633606 seconds. DB syslog lines 219–220 record password acceptance and PAM opening for root at 18:15:10; endpoint PID 1418108 is the root bash shell. PID 1418113 then runs mysqldump.

The root bash history supplies the shell redirection and the intermediate `gzip -9 /tmp/rpt_0318.sql`. Thus the apparent omission of redirection from the process command line, and the later use of a `.gz` file, are not evidence of a broken operation. Shell history and executable arguments need not have identical text.

The scp client PID 1418198 starts at 18:16:07.525. Core Zeek line 10721 and database-sensor line 433 agree on the reverse transport tuple `10.10.4.10:56898 -> 10.10.2.30:22`, with approximately 2.15 MB of client payload. APP syslog accepts the public key at 18:16:16.109611; its endpoint row 856 creates `/tmp/.cache/rpt_0318.sql.gz` at 18:16:41.209. Later, SMB rows 205–206 at about 18:18:57 carry `Integration\DB-Staging\rpt_0318.sql.gz` to FILE-LNX-01, size 2,127,953. The direction, approximate byte volume, identities, and ordering support the pivot.

### Mac remote sessions and file activity

For MAC-MROSS-02 to MAC-MROSS-01, core Zeek line 6759 observes `10.10.1.42:53621 -> 10.10.1.41:22` at 16:02:01.697763. MAC-MROSS-01 Endpoint Security then shows the sshd launch sequence, Unified Log records public-key acceptance at 16:02:08.147068, and Endpoint Security records the target zsh exec at 16:02:08.299168. This is credible transport-before-auth-before-shell ordering.

The concern is the routine file-consumption distribution described above, rather than these SSH semantics. The seven binary-document `cat` executions share Maya's interactive environment, and corresponding normalized rows attribute reads to those processes. This makes the observation stronger than a guess from a file extension in an isolated network record, but it remains possible administrative or scripted activity.

### Negative checks and limits

I checked normalized source-process references for dependencies more than two seconds before a visible creation or after a visible termination; that check produced no findings. I also checked protocol-row timestamps against associated Zeek connection intervals: no SMB row or HTTP row exceeded the connection end by more than 0.2 seconds. These checks are bounded and do not prove every lifecycle correct.

Some packet accounting looked unusual initially, but the affected examples also had reported capture gaps; I did not turn those into impossible-byte-count findings. I found no demonstrated hard contradiction sufficient to justify an 81–100 score. The verdict rests on repeated background behavior and vocabulary, with meaningful room for a real environment using unusual administrative workflows.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on synthetic-confidence score |
|---|---|---|---|
| distribution_texture | Zeek SMB and corroborating endpoint commands | 52 DC-share opens, multiple hosts/users and both DCs | Highest weight: repeated folder/name/extension recombination looks more like generalized file-access vocabulary than a stable enterprise policy tree. Custom content remains possible. |
| environment_or_collection_plausibility | macOS Endpoint Security, eCAR, SMB | Seven binary-document `cat` executions on MAC-MROSS-02 | Moderate weight: repeated interactive binary document reads are unusual routine work. No claim of impossible execution. |
| distribution_texture | macOS Endpoint Security and share paths | Generic repeated document names and `tee` to `.docx` | Supporting weight only; overlaps the preceding finding and is not counted as an independent hard defect. |

## Realism Score by Category

- **Field format accuracy:** 8 — Structured records parse and expose usable source fields; I established no decisive native schema error.
- **Temporal patterns:** 8 — The inspected transport/authentication/shell and file-transfer intervals are coherent, with source-specific timing differences.
- **Cross-source correlation:** 9 — Concrete ports, principals, process identities, archive paths, and proxy requests make major pivots feasible.
- **Behavioral realism:** 6 — Credible suspicious activity and Linux pipelines coexist with repetitive binary-document reads and templated share access.
- **Environmental consistency:** 7 — Roles and network segments are broadly credible; the DC-share path distribution is less convincing than the transport/session modeling.

## Recommendations

- If this were synthetic, define persistent, role-specific SYSVOL/NETLOGON trees and reuse actual objects rather than freely recombining policy names, extensions, year folders, and administrative directory labels. Where ordinary Group Policy processing is intended, represent its actual domain/GPO hierarchy; custom script repositories can remain custom.
- If this were synthetic, make routine document access reflect the content and purpose: application opens for normal Office/PDF consumption, and explicit command-line inspection/copy workflows when `cat`, `head`, or `tee` is intended. Preserve the existing process, SMB, and file-identity correlations while varying the behavior.
