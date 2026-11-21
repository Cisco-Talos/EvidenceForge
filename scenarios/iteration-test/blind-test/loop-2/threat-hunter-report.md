# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 86
**Synthetic-Confidence Score:** 45

## Executive Summary

The logs provide technically usable hunting pivots across a mixed fleet, including coherent SSH sessions, a web-shell attempt, domain account manipulation, and database staging and transfer. A repeated macOS command pattern raises a limited behavioral-texture concern, but the reviewed evidence does not demonstrate an impossible lifecycle or source-native contradiction strong enough to distinguish a carefully generated dataset from sanitized production telemetry.

## Evidence For Synthetic

- [distribution_texture] `MAC-MROSS-02.meridianhcs.local/ecar.json` repeatedly represents access to binary documents as shell `cat` commands: `/Volumes/ClinicalResearch/Team/2026/project-plan.pdf` at 13:37:11.489, `/Volumes/ClinicalResearch/Archive/2025/service-review.xlsx` at 16:05:48.991, `/Volumes/Shared/Reference/project-plan.docx` at 17:10:44.223, `/Volumes/Shared/Reference/onboarding.docx` at 17:12:28.114, `/Volumes/Users/Reports/draft-draft.pdf` at 18:37:47.236, and two more DOCX paths at 18:42:07.755 and 18:44:51.566. These seven executions take approximately 9–27 seconds each before their matching process termination. This recurring choice of a text-stream utility for several unrelated binary document formats resembles a generic file-access activity pool. It is a modest indicator: deliberate binary inspection, scripted access testing, or a selective export remain plausible, and remote filesystem latency could explain the durations. I do not treat the absence of an Office application alone as evidence.

## Evidence For Real

- SSH pivots preserve actual transport tuples and meaningful authentication order. For the Mac-to-Mac connection, `zeek-core/conn.json` records `10.10.1.41:54176 -> 10.10.1.42:22` at 14:24:28.138878, followed by target Unified Log authentication at 14:24:36.236187 and a target eCAR login at 14:24:37.155. The transport lasts 631.354674 seconds rather than appearing as a tiny placeholder connection.
- Database staging has a workable sequence. On `DB-PROD-01`, `mysqldump` starts at 18:15:13.120 and terminates at 18:15:36.422; `gzip` follows at 18:15:37.904 and terminates at 18:15:51.542; `scp` begins at 18:15:52.802. The corresponding SSH flow carries 2,877,433 originator bytes and the receiver records the destination archive.
- The web-shell attempt joins process execution to actual network activity: Apache's child launches a base64-decoding Bash pipeline at 14:20:18.144; the Bash descendant opens `10.10.3.10:56400 -> 45.33.32.30:8443` around 14:20:21.8. The network flow closes within the visible lifetime of the shell processes.
- Domain account creation and group membership changes have source-native effects, matching SIDs, and surviving process lifetimes. `DC-01/windows_event_security.xml` records account creation at 17:15:05.6389464 and addition to Domain Admins at 17:15:11.0147277, while the corresponding `net.exe` processes are still alive.
- Background evidence is substantial and heterogeneous: 37,734 eCAR records across 23 endpoint directories, three Zeek sensors with 23,091 connection records in total, successful and failed connection states, perimeter scanning, DHCP records, SMTP, SMB, proxy traffic, scheduled activity, sudo records, authentication failures and operating-system maintenance messages. Malicious-looking commands are embedded in useful competing activity.

## Detailed Analysis

### Scope and method

I examined only the assigned data directory and instruction file. The apparent collection spans 2026-11-02 approximately 13:00–19:00 UTC, with endpoints in `10.10.1.0/24`, infrastructure in `10.10.2.0/24`, DMZ services in `10.10.3.0/24`, and a database host at `10.10.4.10`. Hostnames and visible applications suggest a healthcare organization, but names and domains may be sanitized.

There are 23 endpoint directories: Windows workstations and servers, Linux workstations and servers, and two Macs. Available evidence includes Windows Security and Sysmon XML, normalized eCAR, Linux syslog and Bash histories, macOS Endpoint Security and Unified Log NDJSON, zsh histories, three Zeek sensor families, Snort alerts, an ASA firewall log, web access and proxy access logs. XML physical line counts are not event counts; I parsed Windows events before interpreting their volumes.

I parsed all eCAR records and the Windows XML families for selected lifecycle and identity checks, inventoried network families, and followed specific suspicious and ordinary transactions across formats. This was not an exhaustive validation of every native event schema or every transaction in the dataset.

### Web entry and command execution

At 14:20:18.144, `WEB-EXT-01/ecar.json` records PID 2702844, principal `www-data`, parent `/usr/sbin/apache2`, executing a Bash command that decodes a base64 payload and pipes it into Bash. It is followed by PID 2702845 (`base64 -d`) at 14:20:18.219 and PID 2702846 (`bash`) at 14:20:18.269. The payload expresses a Bash reverse-shell connection to `45.33.32.30:8443`.

The descendant's eCAR FLOW occurs at 14:20:21.792. `zeek-dmz/conn.json` supplies UID `CHUDe4Hfq9iF7hFGT77`, source port 56400, duration 11.576779 seconds, state `SF`, and 620/1,840 application bytes. The Bash descendant terminates at 14:20:44.339 and its parent at 14:20:44.723, after the network interval. This is a feasible attempted command channel. The logs do not prove the execution of additional unseen commands through that channel.

The nearby Apache SQL error is separately useful evidence of suspicious web requests. I do not assume that every request from the same external address has the same TCP connection or directly causes every observed subprocess.

### Remote access, identities and lifecycle

The Mac-to-Mac SSH pivot can be followed from `MAC-MROSS-01` shell history and native Endpoint Security execution of `/usr/bin/ssh maya.ross@MAC-MROSS-02.meridianhcs.local` at 14:24:12.692695, to the source eCAR FLOW at 14:24:29.424, to the target authentication record at 14:24:36.236187. The source port is consistently 54176. Native execution, source observation and authentication are separate events; their timestamps need not be identical.

The reverse direction is similarly distinguishable. `MAC-MROSS-02` executes `/usr/bin/ssh -tt maya.ross@MAC-MROSS-01.meridianhcs.local` at native time 16:01:51.843341; its source eCAR FLOW uses port 54873 at 16:02:01.344. The target Unified Log reports accepted public-key authentication at 16:02:05.723657. Native target Endpoint Security shows the launchd/xpcproxy/sshd chain and then `/usr/libexec/sshd-session` before that accepted-authentication message. This avoids mistaking the later normalized process observation for the native process's actual start.

Across eCAR, I checked visible process-create and process-terminate records against events referencing their process identities. With small observation tolerances, I found no referenced process visibly created after its dependent event or terminated before a later dependent event in this check. Root-owned pre-authentication SSH processes preceding a user login are expected. Windows Type 7 unlock events can reuse an existing session's logon identifier, so earlier processes sharing that identifier are also expected and were not scored as causality defects.

### Domain changes and data movement

`DC-01` has `cmd.exe -> net.exe` execution for creating `svc_dirsync` and adding it to Domain Admins. Security events 4720 and 4728 use the same account SID ending in 4921; the group's SID ends in 512. The creation operation's `net.exe` lifetime extends through 17:15:07.225 in Sysmon, after account creation at 17:15:05.6389464. The group-change process extends through 17:15:11.356, after event 4728 at 17:15:11.0147277. A scheduled-task creation and later account deletion provide further hunting leads. Their visibility alone does not prove that the scheduled payload subsequently ran.

On the database host, the root export session is preceded by `10.10.2.30:41435 -> 10.10.4.10:22`, observed by both core and database sensors around 18:14:52.9. Target syslog accepts root at 18:15:05.214877 and opens its session before the export commands. The subsequent transfer goes in the opposite direction, from `10.10.4.10:40671` to `10.10.2.30:22`, around 18:15:55.8. Its core UID is `CoKEZobejRi5ctVT5w`; the database sensor independently records UID `CfctRVJJYQEr2e9HME`, with the same tuple and byte counts. Different sensor-local UIDs are appropriate.

`APP-INT-01` accepts the receiver session and records `/tmp/.cache/rpt_0318.sql.gz` creation at 18:16:17.722. The archive later receives a read observation at 18:18:59.005. I would investigate authorization for this export, but its suspicious purpose is separate from whether the telemetry is authentic.

### Support-tool activity and competing explanations

The support domain appears in Windows, Linux and macOS download commands. On `WS-LNGUYEN-01`, a Linux binary is downloaded at 15:12:25.373, chmodded at 15:12:51.631 and executed at 15:13:06.383. On `MAC-MROSS-01`, native fork/exec observations distinguish the downloaded script from its later Bash execution. These are useful hunting leads, not proof that all support activity is malicious.

A separate Linux support upload is explicitly scoped to two connector logs. eCAR records `tar` creating `/tmp/mhs-support-48217.tar.gz` at 16:31:38.921, then `curl` posting multipart metadata and that archive at 16:32:00.736. The proxy records the same attachment URL, user `lina.nguyen@meridianhcs.local`, HTTP 200 and a 96-byte response. Core and DMZ HTTP observations preserve a 1,573,258-byte request body and the two multipart MIME types. This is a workable pivot and a plausible legitimate explanation requiring content and authorization review.

On the Macs, the visible launch-daemon plist operations, xpcproxy launches and `sw_vers` executions should be interpreted separately. Likewise, the `MeetingAssist` policy message at 15:42:09.009673 is not by itself proof of successful application execution. I found no basis to attribute unseen child activity to that policy message.

### Noise and behavioral texture

The core sensor has 12,307 connection records, the DMZ sensor 10,391, and the database sensor 393. Core connection states include 9,885 `SF`, 1,650 `S0`, 438 `OTH`, resets, rejections and partial states. The DMZ has 2,460 `S0` records as well as substantial successful activity. This is sufficient competing traffic to require filtering and attribution rather than merely reading an isolated attack list.

The narrow concern is repeated binary-document `cat` activity on `MAC-MROSS-02`, including seven unrelated PDF/XLSX/DOCX reads. It reduces confidence in the naturalness of that workflow, but it cannot establish origin. I did not penalize complete joins, source coverage choices, sanitized domains, attacks fitting inside the window, missing Sysmon families, or processes and sessions extending beyond the window.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | macOS normalized endpoint process/file evidence | Seven binary-document `cat` executions on MAC-MROSS-02, 13:37–18:45 UTC | Modest concern about a generic file-access behavior pool; alternative scripted inspection and remote-filesystem explanations prevent a strong verdict. |

No hard contradiction was established in the reviewed operational paths. The score remains in the mixed/inconclusive range because this behavioral concern coexists with substantial plausible lifecycle and cross-source evidence.

## Realism Score by Category

- **Field format accuracy:** 9 — Parsed sources and reviewed Windows/native Mac identity fields support usable pivots; this was not a complete native-schema audit.
- **Temporal patterns:** 8 — Checked command, authentication and transport lifetimes work together; repeated binary-document utility lifetimes deserve scrutiny.
- **Cross-source correlation:** 9 — SSH, database transfer, account effects and support upload preserve useful identities and source-specific observation differences.
- **Behavioral realism:** 7 — Tool execution and staging are feasible, with a recurring macOS binary-document shell-access pattern as the main reservation.
- **Environmental consistency:** 8 — Mixed platforms, segments, infrastructure roles and competing background activity are plausible within the visible collection scope.

## Recommendations

- If this were synthetic, review the seven `MAC-MROSS-02` binary-document `cat` executions. If the intended action is human document reading, generate the application and file-access behavior appropriate to that action; if it is scripted inspection, preserve the actual inspection purpose and command arguments instead of repeatedly using a generic stream utility.
- If this were synthetic, ground those file-access durations in the operation and file/network behavior being represented. Investigate the repeated 9–27 second `cat` lifetimes using the associated SMB transaction and file-size evidence before changing them; remote storage and blocked terminal output can legitimately lengthen an execution.
