# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 86
**Synthetic-Confidence Score:** 67

## Executive Summary

The dataset supports useful, technically connected hunts across a mixed fleet, including web-server execution, internal discovery, privileged Windows activity, and archive transfer through an inspecting proxy. My principal authenticity concern is a reproducible mismatch between an explicitly logged TCP connect scan and the application payload attributed to its exact connections; a secondary concern is the repeated manual SMB policy-file retrieval texture across unrelated Linux users. These findings favor synthetic data while leaving much of the operational lifecycle credible.

## Evidence For Synthetic

- **[contract_gap] TCP connect scan emits unexplained client application payload.** `WEB-EXT-01.meridianhcs.local/ecar.json:1183` records root PID 2705135 running `nmap -Pn -sT -p 22,80,443,445,3306 10.10.2.0/24` at 14:40:26.041 UTC. Exact source/destination/port pivots attribute 1,256 connection tuples to that process. Twelve corresponding `zeek-dmz/conn.json` rows have positive originator payload, including line 2370 (`10.10.3.10:36200 → 10.10.2.21:22`, 170 originator bytes), line 2413 (`:56371 → 10.10.2.30:80`, 55 bytes), and line 2660 (`:48383 → 10.10.2.10:445`, 147 bytes). This command requests neither version detection nor scripts nor an explicit payload. Standard Nmap connect scanning closes a successful connection without transmitting application data; an unsolicited server banner would explain responder bytes, not these originator bytes. [Nmap TCP connect scan documentation](https://nmap.org/book/scan-methods-connect-scan.html)
- **[distribution_texture] Repeated interactive policy-file collection across multiple Linux identities.** Of the visible process creates, WS-OHADDAD has 26 `smbclient` invocations out of 83, WS-LNGUYEN has 15 out of 128, and APP-INT has seven out of 108. Respectively 14, ten, and five target DC SYSVOL/NETLOGON shares with repeated `Machine`, `User`, `Preferences`, or `Scripts` paths and interchangeable policy/startup/registry/groups names. Examples include WS-OHADDAD eCAR lines 35, 67, 205, 213, 224, 230, 243, 317, 332 and 336; WS-LNGUYEN lines 293, 339, 645, 652, 661 and 664; APP-INT lines 243–285. The count, common access style, and filename grammar across distinct accounts look like a reused behavioral pool. This is supporting evidence, not an impossibility: administrators or a special workflow could generate it.

## Evidence For Real

- The web execution pivot works. `WEB-EXT-01.../ecar.json:839` shows Apache spawning a shell at 14:20:06.317; line 840 attributes an outbound connection to that shell at 14:20:09.662. `zeek-dmz/conn.json:1625` contains the same `10.10.3.10:41647 → 45.33.32.30:8443` tuple, starting 14:20:09.585467, with actual bidirectional payload and a 29.415661-second lifetime. The shell terminates later at eCAR line 842, 14:20:59.504. No impossible same-process ordering is visible.
- Windows alternate network credentials retain the local identity. WS-AJOHNSON eCAR lines 1006 and 1013–1018 show `runas /netonly`, a Type 9 session whose local principal stays aisha.johnson, outbound identity marcus.chen, then its child command shell. Native Security records 131022/131023 agree, including `TargetOutboundUserName=marcus.chen` and `TargetLogonId=0x27cb085`.
- Linux transfer evidence crosses account and host boundaries coherently. DB-PROD eCAR lines 530–538 show a dump, compression, and SCP read; APP-INT lines 776–780 show the receiver's SSH session and `/tmp/.cache/rpt_0318.sql.gz`; APP-INT line 781 then uses the distinct SMB credential svc_mhsync. FILE-LNX syslog lines 462–464 record successful open/write/close by svc_mhsync from 10.10.2.30 for the matching staging path.
- The apparent archive upload has an endpoint read and a plausible proxy observation. WS-AJOHNSON eCAR lines 1131 and 1138 show `curl` and its read of `cache_7f3a.zip`. Proxy access line 3231 records the matching HTTPS POST at 18:24:39, `cs_bytes=18782968`, `proxy_action=ssl-inspect`, a tunnel identifier, and client source port 56429. Inspection explains visibility of a full HTTPS path.
- There are realistic alternative hunt leads. WS-LNGUYEN eCAR lines 399 and 403 show a support-log tarball and multipart support upload. Proxy line 2017 and Zeek core HTTP line 1253 corroborate the destination, ticket, user agent, and approximately 1.57 MB request. That activity deserves business-context validation rather than automatic classification as exfiltration.
- Mac evidence distinguishes observation types. MAC-MROSS-01 Unified Log line 2 describes a policy objection for MeetingAssist; I found no matching ES execution of that application. The visible data therefore does not require treating the denied application as having executed.

## Detailed Analysis

### Scope, methods, and provenance

All local examination was confined to `/private/tmp/log-study-xgpo00ey/data` and the supplied neutral briefing `/private/tmp/log-study-xgpo00ey/threat-prompt.md`. I listed only that data subtree, counted/read its supplied files, parsed all 23 eCAR streams and ten Windows Security XML streams, examined both Mac Endpoint Security streams, and pivoted through the three Zeek connection streams, HTTP records, selected native syslogs, histories, Unified Logs, proxy logs, and IDS records. Physical line numbers below are one-based; Windows native records additionally use their own EventRecordID. Logged commands were treated as inert evidence and never executed.

No repository, source implementation, scenario, TODO, worklog, prior assessment, neighboring inventory, or other reviewer report was accessed. Generic inherited project operating instructions exist in the environment; they were excluded from origin reasoning. The only public research was domain-filtered searches limited to `nmap.org` and `docs.zeek.org`, yielding the primary documentation cited here. This is a data-only assessment rather than proof of provenance.

There are 23 endpoint directories: ten exposing Windows Security/Sysmon XML, eleven exposing Linux-style syslog, and two exposing Mac ES/Unified Log data. The eCAR observations span 2026-11-02 13:00:00.492–18:59:57.955 UTC and total 35,805 records, including 2,043 PROCESS/CREATE records. Addresses cluster in 10.10.1/24 through 10.10.4/24, with client, DC/file/application, DMZ/proxy, and database roles apparent from activity. The network sources provide 22,148 connection records across core, DMZ and database sensors; overlapping observations are not independent connections. The proxy contributes 3,524 access rows and the external web server 757 access rows.

These volumes are consistent with a bounded or selected collection. I did not penalize low native Mac log volume, selected Sysmon event types, absence of other products, or sessions surviving beyond the six-hour window. There is no independently supplied audit/collection policy or packet capture; endpoint attribution and native log meanings must be interpreted with that limitation.

### Hunting trail and lifecycle coherence

The web-server shell and scan are meaningful initial pivots, without assuming that every contemporaneous anomaly shares one actor. Following the shell's tuple into Zeek distinguishes the callback from ordinary proxy traffic. The later nmap PID provides a direct way to isolate discovery flows and test whether network behavior agrees with the tool command.

On Windows, DC-01 eCAR lines 3978/3985 show domain-user creation, lines 4002/4009 group modification, and lines 4085–4106 service/task creation. Security EventRecordID 28257154 records svc_dirsync creation at 17:15:19.2242501. The encoded PowerShell process at eCAR line 5563, log-clear commands at 5573/5580, and native Security record 1/Event 1102 at 18:42:11.6676456 support a cleanup investigation. The record-number reset after the clear is internally compatible. I did not count the fact that these steps are easy to narrate as an authenticity indicator.

On WS-AJOHNSON, the Type 9 credential boundary is handled correctly: subsequent local process attribution remains aisha.johnson while network credentials can differ. File collection includes visible copy commands and resulting files before archive creation, followed by a later `curl` file read. The database report is staged later on a separate route; the logs do not establish that this report was inside the earlier Windows archive, so I make no such attribution.

A complete eCAR same-identity pass found no process termination before its visible PROCESS/CREATE, no child created more than three seconds before its visible parent creation, and no actor-attributed operation more than three seconds after that actor's visible termination. This is a narrowly defined consistency check, not a guarantee of correctness, and it does not treat pre-window process/session initiators as absent prerequisites.

### Scanner transport mismatch

The critical check joins the nmap process's FLOW records to Zeek on the four-tuple. Of its 1,256 DMZ sensor matches, 1,244 have zero payload in both directions and twelve have positive originator payload. Thus the bulk resembles a connect scan while a bounded subset acquires a different behavioral model.

Examples are independently reproducible:

| Endpoint eCAR line | Zeek DMZ conn line | Tuple suffix | Originator/responder bytes | State/history |
|---|---|---|---:|---|
| 1184 | 2332 | 39274 → 10.10.2.40:22 | 113 / 402 | SF / ShADadTtFf |
| 1210 | 2370 | 36200 → 10.10.2.21:22 | 170 / 1 | SF / ShADadfF |
| 1250 | 2413 | 56371 → 10.10.2.30:80 | 55 / 476 | SF / ShADadfF |
| 1607 | 2660 | 48383 → 10.10.2.10:445 | 147 / 550 | SF / ShADadfF |
| 1994 | 3217 | 54909 → 10.10.2.30:443 | 13 / 10 | SF / ShADaTtdfF |

All originate at 10.10.3.10, and all five listed DMZ records have `missed_bytes=0`. Core records corroborate the same payload for the corresponding tuples, including core lines 3349 and 3387. This is not a claim that banners, successful TCP handshakes, or server-side preauthentication logs are invalid during scanning. It concerns client payload attributed to this explicit connect-only command. Nmap's documented behavior is immediate close after connect success, with an optional server banner arriving first. [Nmap](https://nmap.org/book/scan-methods-connect-scan.html)

Zeek defines `orig_bytes` as payload, rather than including IP/TCP headers. Although sequence-based byte estimates can be inaccurate, these are small complete-looking flows across several protocols, and the matching endpoint ownership makes repeated incidental byte errors an unpersuasive explanation. The data does not include a binary hash validation or packet capture that would exclude a modified executable, misleading process command line, or attribution error; therefore I label this a contract gap rather than claiming unqualified physical impossibility. [Zeek Conn::Info field reference](https://docs.zeek.org/en/v4.0.9/scripts/base/protocols/conn/main.zeek.html)

### Behavioral texture and limitations

Manual SMB traffic contributes to the secondary finding because it recurs under multiple users and systems with similar small filename families. For instance WS-OHADDAD fetches `Policies\startup-draft.ps1`, `Scripts\2023\gpt-final.ini`, `Preferences\registry-review.xml`, and `Machine\2026\groups.ps1`; WS-LNGUYEN fetches a similarly varied mixture of startup/drives policy files, and APP-INT follows the same pattern. These are log-visible command distributions, not a judgment about the cleanliness of an attack storyline. The lack of organizational workflow context limits their weight.

The Mac shell commands also have a narrow diagnostic vocabulary, but the two hosts share a named user, making repetition explainable; I did not count it as an independent strong indicator. Their ES fork/exec/exit transitions include exec generations and credential transitions that should not be confused with fresh PID creation. Likewise, a policy message alone establishes neither successful child execution nor a complete launch-item lifecycle. No Mac-specific source schema defect is alleged here.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| contract_gap | eCAR process/flow and Zeek connections | Twelve scan tuples in one 1,256-tuple command, seen across sensors | Principal driver: client payload conflicts with the explicit connect-only scan behavior. |
| distribution_texture | Linux eCAR process commands / SMB activity | 48 smbclient commands across three hosts, 29 directed to SYSVOL/NETLOGON | Moderate supporting weight: repeated access style and filename grammar across separate accounts. Organizational scripting remains an alternative. |

The score is 67 because a concrete repeated tool-to-transport defect and a separate behavioral texture favor synthesis, while broad lifecycle and pivot behavior remain convincing. It is not the 86% confidence in the binary verdict, and it is not an assertion of dataset-wide corruption.

## Realism Score by Category

- **Field format accuracy:** 8 — Parsed native and normalized formats are usable; no demonstrated general schema defect.
- **Temporal patterns:** 8 — Variable activity and coherent tested process lifecycles; no scored impossible same-identity ordering.
- **Cross-source correlation:** 7 — Strong practical pivots, with the scanner payload/intent mismatch reducing trust.
- **Behavioral realism:** 6 — Diverse legitimate and suspicious behavior, weakened by repeated manual policy-file retrieval and scanner semantics.
- **Environmental consistency:** 8 — Visible mixed-platform roles and proxy inspection are plausible for the supplied window and collection scope.

## Recommendations

- If this were synthetic, make the logged scanner command and its transport behavior agree: connect-only scans should not acquire arbitrary client payload or ordinary bidirectional application-session texture. Preserve possible responder banners and source-native preauthentication observations.
- If this were synthetic, review the 29 manual SYSVOL/NETLOGON operations as a population. Tie repeated retrievals to a visible operational workflow or diversify the action distribution according to the users' actual roles, rather than recycling startup/registry/groups filename combinations.
- Preserve the demonstrated local-versus-outbound credential distinction, archive/proxy pivots, receiver-side transfer evidence, and the separation between Mac policy objections and actual execution. These make the data operationally useful.
