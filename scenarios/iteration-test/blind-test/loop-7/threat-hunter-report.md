# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 74
**Synthetic-Confidence Score:** 62

## Executive Summary

The data supports practical hunting across endpoint, authentication, file-sharing, proxy and network evidence, and the remote-session examples I examined have credible lifecycle ordering. My lean toward synthetic rests on two narrower behavioral distribution artifacts: a substantial population of very large policy/script files on domain-controller shares, and repeated use of `cat` to access binary office documents on a Mac. These are plausibility findings rather than demonstrated impossibilities, so they support a moderate verdict rather than certainty.

## Evidence For Synthetic

- [distribution_texture] In `zeek-core/smb_files.json`, 15 of the 51 size-bearing SYSVOL/NETLOGON file records exceed 1 MiB. Examples include `\\DC-01\NETLOGON` / `User\registry.ini`, 8,700,366 bytes at 14:06:57.335802 UTC (line 15); `\\DC-02\SYSVOL` / `Preferences\2026\policy.ps1`, 9,890,978 bytes at 15:04:27.399360 (line 55); and `\\DC-02\NETLOGON` / `Scripts\2026\startup.bat`, 2,803,606 bytes at 16:09:08.273444 (line 116). A large registry policy or embedded-payload script is possible, but this frequency across INI, XML, BAT and PS1 names gives the background share corpus a generic file-size texture rather than convincing policy-file semantics. These are record counts, including repeated accesses, not counts of unique files.
- [environment_or_collection_plausibility] On `MAC-MROSS-02`, seven visible office/PDF file reads are performed by `/bin/cat`: two PDF files, four DOCX files and one XLSX file. This is independently present in native Endpoint Security exec argument arrays, rather than merely a normalized display: `macos_endpoint_security.ndjson` lines 32, 102, 112, 115, 143, 149 and 155. Examples include `/bin/cat /Volumes/ClinicalResearch/Archive/2025/service-review.xlsx` at 16:05:48.670374 UTC and `/bin/cat /Volumes/Shared/Reference/onboarding.docx` at 17:12:27.399937. The corresponding eCAR FILE/READ records occur at 16:05:58.468 and 17:12:31.889. One such command could be inspection, automation or a mistake; seven binary-document accesses through this same tool, across multiple shares and hours, weakens the behavioral realism of this host's background file use. It does not prove the commands could not execute.

## Evidence For Real

- Remote SSH transport, authentication, process lineage and close evidence agree in the examples examined. For `10.10.1.41:62697 -> 10.10.1.42:22`, `zeek-core/conn.json` has UID `CmiOrLqysTzHRCJtC6`, start 14:24:25.125871 UTC, duration 634.401310 seconds and state `SF`. The destination Mac records SSH LOGIN at 14:24:36.136 and LOGOUT at 14:35:12.865; its SSH processes and commands fall within the session. The authentication follows transport establishment, and session close is near the transport end without being artificially identical.
- A second SSH pivot reverses the direction coherently: `10.10.1.42:60489 -> 10.10.1.41:22`, UID `CFpznllhyYCHV7rhfqm`, starts at 16:01:58.262360 with duration 961.346177 seconds. `MAC-MROSS-01/ecar.json` records inbound FLOW at 16:01:59.543, LOGIN at 16:02:08.705 and LOGOUT at 16:18:12.794, with SSH daemon/session/shell transitions and subsequent commands in between.
- The macOS download uses an explicit proxy path, not an invented direct client-to-Internet connection: curl PID 46134 on `MAC-MROSS-01` connects from `10.10.1.41:53992` to `10.10.3.20:8080`. `zeek-core/http.json` line 276 records CONNECT to `support.valeworks-health.net:443`; the endpoint separately records creation of `/Users/maya.ross/Downloads/connector-check.sh` and later `/bin/bash` execution of that path.
- The Mac process telemetry differentiates fork, exec and credential/session transitions. `MAC-MROSS-02/ecar.json` shows iTerm2, iTermServer, login, ShellLauncher and zsh rather than substituting a Linux terminal/session chain. Native ES records retain argument arrays and audit-token identities, allowing the normalized view to be checked against a separate representation.
- The 15:42:09.009673 AppleSystemPolicy message about `MeetingAssist` in `MAC-MROSS-01/macos_unified_log.ndjson` is not accompanied by an observed successful ES exec of that application in the supplied ES file. I did not treat the policy wording as proof of either successful execution or a subsequent compromise.
- There is a meaningful mix of ordinary activity: periodic sysstat jobs on Linux, sudo maintenance and package inspection, SMB access, browser helper processes, mail-server activity, machine-account authentication, service logons, failed authentication and unrelated network alerts. The visible source population is sufficient to require pivots rather than treating every alert as an intrusion.

## Detailed Analysis

### Scope and method

I examined only the supplied data directory and assigned briefing. The directory contains 118 files and 23 endpoint host directories with eCAR telemetry. Available sources include Windows Security and Sysmon XML, Linux syslog and Bash histories, two Macs' Endpoint Security and Unified Log exports plus zsh histories, three Zeek sensor collections, a proxy log, an ASA firewall log, Snort alerts and web access logs.

The eCAR window runs from 2026-11-02 13:00:02.083 through 18:59:55.782 UTC. It contains 37,747 records: 27,304 FLOW/CONNECT, 2,717 PROCESS/CREATE, 2,550 PROCESS/TERMINATE, 2,170 MODULE/LOAD, 929 USER_SESSION/LOGIN and 515 USER_SESSION/LOGOUT, plus other process, file, registry, thread and service observations. LOGIN includes failed attempts, so those two session counts are not a pairing test. Process/session observations at either boundary may refer to state outside this slice.

The apparent environment spans user workstations in `10.10.1.x`, domain/file/application infrastructure in `10.10.2.x`, web/proxy infrastructure in `10.10.3.x` and a database host in `10.10.4.x`. These roles are inferred from filenames, process names, destination services and traffic; I did not use external organizational context.

### Following the Mac activity

The first Mac provides a feasible pivot chain. At 13:48:42.695, the normalized process record shows Homebrew curl retrieving `connector-check.sh`. Endpoint file creation follows at 13:48:44.714. The proxy CONNECT observation names the requested remote hostname while the endpoint FLOW correctly names the internal proxy. `/bin/bash .../connector-check.sh --check-config` follows at 13:49:09.693, and a later invocation uses `--check-network` at 14:37:51.521. This supports download and script execution without requiring knowledge of the script's contents or intent.

SSH from the first Mac to the second Mac, web host, database and application host is visible. For the Mac-to-Mac connection, the client exec is at 14:24:12.699, transport begins at 14:24:25.125871, destination SSH authentication is at 14:24:36.136 and the shell's `id`, `sw_vers` and `find` executions occur later. The delay before authentication is technically plausible; I found no reason to label this ordering impossible. The second Mac later connects back, with destination inbound transport preceding its SSH login.

At 15:10–15:13, the first Mac lists, reads and writes `/Volumes/ClinicalResearch/Integration/Manifests/pipeline-manifest.json`, alongside SMB transport observations. This is a useful hunting pivot, but the logs alone do not establish whether this manifest change is authorized. I did not equate complete visibility of these steps with synthetic origin.

The second Mac's recurring binary-document `cat` activity is a separate concern from that activity chain. I counted seven corresponding native ES execs; the arguments explicitly name the binary document paths, so shell quoting or eCAR command-line reconstruction does not explain the repeated tool choice. Direct byte reads of DOCX/XLSX/PDF data can be legitimate, including scripted testing or exfiltration, but the repeated pattern across unrelated document paths looks like a generic file-access behavior substituted for application-specific use. The evidence does not establish impossibility or maliciousness.

### Linux and Windows intrusion pivots

There is additional attack-relevant Linux activity independent of the Mac script. `WEB-EXT-01/ecar.json` shows root reading host/network configuration at 14:39:37–14:39:48, running `nmap -sn 10.10.2.0/24` at 14:39:56.881 and a TCP-connect port scan at 14:40:09.523. Later root commands read the web configuration and SSH private-key path. These are operationally meaningful discovery/credential-access pivots, not authenticity indicators by themselves.

On the database host, root runs `mysqldump --single-transaction ehr patients insurance_claims` at 18:15:14.094, gzip at 18:15:38.081 and scp toward `10.10.2.30` at 18:16:05.122. The Bash history preserves the dump's output redirection to `/tmp/rpt_0318.sql`, which is absent from the child program's argument rendering as expected for shell redirection. Destination `APP-INT-01/syslog.log` lines 211–216 show the corresponding SSH connection from `10.10.4.10:40951`, public-key acceptance for root, PAM session open and close. This is a coherent path for moving the compressed dump to the application host.

Windows evidence supports account/persistence pivots as well. On DC-01, `net user svc_dirsync ... /add /domain` executes at 17:15:02.155; Security event 4720 for that account follows at 17:15:11.1682565. The `net group "Domain Admins" svc_dirsync /add /domain` command at 17:15:12.516 is followed by event 4728 at 17:15:16.1040262, with the account SID matching the member SID. Scheduled-task creation at 17:19:44.430 is followed by event 4698 at 17:19:48.9411133 for the named DeviceSync task. Account deletion later has both a command and a 4726 observation. These checks support pivot feasibility and do not expose a causal contradiction.

### Baseline file-share plausibility

The stronger synthetic indicator lies in the background corpus rather than an intrusion's narrative shape. Across the size-bearing SYSVOL/NETLOGON records, the median is 65,275 bytes, maximum 9,890,978 and 15/51 exceed 1 MiB. In comparison, other shares have 19/62 size-bearing records above 1 MiB, with a 411,404-byte median. The policy/script population consequently has a surprisingly substantial large-file tail spanning file types generally associated with compact configuration or login scripts.

The concern is not that a large script or registry policy is forbidden. It is the combination of many such files, generic policy/registry/startup/drives names and large sizes across several text-oriented extensions. `User/registry.ini` at 8.7 MB and a 2.8 MB startup BAT file are especially awkward as routine background artifacts. A customized deployment system or embedded content could account for them; file contents are unavailable, so this remains a distribution finding with limited confidence.

### Contradiction checks and limits

I compared visible eCAR actor references against visible PROCESS/CREATE and PROCESS/TERMINATE records. This scan found no actor action preceding its visible creation, and no actor action more than three seconds after its visible termination. This was an identifier-based screen, not proof that every process or source lifecycle is perfect.

For Zeek HTTP, SSL, DNS, SMTP and SMB companion records with matching local conn UIDs, I found no timestamps more than one second outside the corresponding connection interval. File records with matched conn UIDs did not claim more `seen_bytes` than the sum of connection payload byte counts. I also checked Sysmon process-create SHA256 mappings and did not find a hash shared across different executable basenames. These are useful negative results that prevent overstatement of the synthetic verdict.

The study's selected Sysmon coverage, clock differences among sensors, pre-window processes, post-window closes, privacy-altered domains and completeness of matching evidence were not counted against authenticity. Periodic sysstat scheduling was also not counted as artificial uniformity: it has a visible scheduler-based explanation.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
| --- | --- | --- | --- |
| distribution_texture | Zeek SMB, corroborated by SMB client commands | 51 size-bearing SYSVOL/NETLOGON observations; 15 above 1 MiB, across multiple text/config/script extensions | Main reason for leaning synthetic; plausible individually, less convincing as the background corpus's distribution |
| environment_or_collection_plausibility | macOS ES and normalized eCAR file activity | Seven `/bin/cat` accesses to PDF/DOCX/XLSX paths on MAC-MROSS-02 across several hours | Moderate evidence of a generic file-access template; executable actions, not an impossible operation |

Neither finding is a hard contradiction. Stronger lifecycle and source-correlation performance holds the score near the lower end of the “likely synthetic” band.

## Realism Score by Category

- **Field format accuracy:** 9 — The sampled XML, JSON, native ES argument arrays and normalized records are usable; I found no demonstrated source-native schema contradiction.
- **Temporal patterns:** 8 — Examined session and transport orderings are feasible, with source timing differences and no decisive visible inversion.
- **Cross-source correlation:** 9 — SSH, proxy, account administration and dump-transfer pivots work across the available sources.
- **Behavioral realism:** 6 — Repeated binary-document `cat` use weakens the Mac's background behavior despite technically executable commands.
- **Environmental consistency:** 6 — The role/topology mix is credible, but policy-share file sizes and names form an unconvincing background corpus.

## Recommendations

- If this were synthetic, condition policy-share file sizes on their actual formats and purpose. Retain occasional large scripts or policies when their contents justify them, while revisiting the population represented by the 8.7 MB INI, 9.9 MB PS1 and 2.8 MB BAT examples.
- If this were synthetic, give binary office-document accesses a concrete workflow. The seven native `/bin/cat` execs should represent a justified byte-oriented task, or use the actual document application/preview/conversion process appropriate to the intended behavior.
- If this were synthetic, preserve the existing proxy routing, SSH transport-before-authentication ordering, process exec/credential transitions and independently timed session closes while adjusting those background patterns. Those are successful aspects of the observed evidence.
