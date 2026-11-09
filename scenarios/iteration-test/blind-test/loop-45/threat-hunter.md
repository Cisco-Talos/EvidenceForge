# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 78
**Synthetic-Confidence Score:** 35

## Executive Summary

The supplied six-hour mixed-platform slice is mostly production-like and supports technically coherent hunts across endpoint, authentication, network, proxy, and file evidence. A narrow, repeatedly reused macOS interactive command vocabulary supplies a limited behavioral texture concern, but I did not establish a hard contradiction or a sufficiently strong independent set of defects to decide synthetic versus real reliably.

## Evidence For Synthetic

- [distribution_texture] The two macOS shell histories have a conspicuously narrow, overlapping interactive vocabulary across almost six hours: `MAC-MROSS-01.meridianhcs.local/zsh_history/maya.ross.zsh_history` contains 20 entries and 13 distinct full commands; the corresponding `MAC-MROSS-02` file contains 19 entries and 12 distinct full commands. Both repeatedly cycle through system identification, disk/process checks, and the same Documents search rather than showing much task-specific variation. For example, MAC-MROSS-01 lines 10 and 18 repeat `/usr/bin/find /Users/maya.ross/Documents -maxdepth 2 -type f -name '*.pdf'`; MAC-MROSS-02 lines 7 and 17 repeat that command. This is a weak-to-moderate distribution concern, not evidence that reconnaissance itself is artificial. The same user working on two machines and selective collection are substantial alternative explanations.
- [weak_signal] Repeated macOS identity/version checks are confirmed as executions rather than only duplicated history text: MAC-MROSS-01 Endpoint Security lines 9/12 execute `id`/`sw_vers`, lines 93/96 execute `sw_vers`/`id` again, and MAC-MROSS-02 lines 12, 89 repeat interactive `sw_vers -productVersion`. I count this as corroboration of the preceding texture observation, not a second independent defect. Inventory-service `sw_vers` launches were excluded from this concern because their periodic execution has a clear operational explanation.

No hard contradiction, demonstrated native schema error, or confirmed required-companion gap was established in the checks below. The concerns above receive limited weight.

## Evidence For Real

- The collection contains substantial, varied background traffic: 22,148 Zeek connection records, 4,313 DNS records, 4,610 HTTP records, 3,142 TLS records, 3,861 Linux syslog lines, 19,030 Windows Security events, 11,785 Sysmon events, and 35,807 normalized eCAR records. The endpoint records cover 23 named hosts. These counts fit a small enterprise slice without relying on attack activity to supply all volume.
- Authentication pivots preserve local versus remote identities. On WS-AJOHNSON-01, eCAR line 1006 runs `runas.exe /netonly /user:marcus.chen`; line 1013 records Type 9 credentials with local principal `aisha.johnson`, outbound principal `marcus.chen`, and a new logon ID `0x27cb085`; line 1017 starts the resulting local command interpreter as Aisha. That is a meaningful distinction for hunting, not simply a username copied everywhere.
- The database-to-application-server transfer has a coherent transport/authentication/file/termination chain. DB-PROD-01 eCAR lines 536–539, APP-INT-01 eCAR lines 775–780, APP-INT-01 syslog lines 200–201, and zeek-core `conn.json` line 11098 agree on the SSH tuple `10.10.4.10:58586 -> 10.10.2.30:22` and its successful transfer interval.
- macOS native process evidence distinguishes fork from exec and records real terminal/application ancestry. MAC-MROSS-02 Endpoint Security lines 1–10 show launchd, xpcproxy, iTerm2, iTermServer, login, ShellLauncher, and zsh rather than pretending every executable is a newly forked independent process. The separate Unified Log SSH acceptance at 14:24:44.399410Z does not precede its network transport.
- Network data include failures, resets, partial observations, and gaps. Zeek-core connection states include 1,897 `S0`, 150 `RSTO`, 116 `RSTR`, and smaller `OTH`, `REJ`, `S1`, `S2`, `S3` populations. This is more credible than a universal successful-flow population.
- Operational ambiguity survives the available evidence. Lina's support upload has a ticket-bearing command and multipart attachments, while the separate archive upload and credential/account activity require different investigative interpretations. Source-visible technical detail supports those distinctions without requiring a privileged narrative.

## Detailed Analysis

### Input provenance, scope, and method

I read the supplied neutral study briefing and files under `/private/tmp/log-study-rm6iexyd/data`. I did not access repository code, TODO/worklog files, scenario definitions, previous results, or other reviewers' reports. The input actually examined is the copied data directory identified by the briefing; I have no independently established production or synthetic origin for it. Generic inherited agent instructions were not used as evidence of origin. No public-documentation lookup was needed, and no unverified platform-schema claim affects the score.

All references below are relative to `data/`. NDJSON, syslog, and history references use physical one-based lines. Windows examples use native EventID, EventRecordID, timestamp, and host because the XML expands each event over many lines.

The eCAR time bounds are 2026-11-02 13:00:00.492Z through 18:59:57.955Z. The 23 endpoint host directories imply workstation, directory, file, application, database, proxy, web, monitoring, and mail roles. Addressing visibly spans `10.10.1.*` workstations, `10.10.2.*` internal infrastructure, `10.10.3.*` web/proxy infrastructure, and `10.10.4.10` database service. Names and addressing are descriptive inferences, not proof of actual segmentation policy.

I parsed all eCAR records, all supplied Windows Security/Sysmon XML files, all Zeek connection/HTTP/TLS/DNS records, and sampled relevant protocol/file histories and alerts. I followed both suspicious and plausible administrative activity across formats. The total XML record counts above count Event elements, not physical XML lines.

### Operational hunt: web activity and remote administration

WEB-EXT-01 eCAR line 840 records a www-data-owned bash child of apache2 at 14:20:06.317Z with an encoded shell command. That deserves investigation. The later root recon/scanning sequence is a distinct SSH session: line 915 accepts source `10.10.1.34:57673` at 14:39:54.177Z, line 916 creates its shell, and lines 917, 920, 923, 926, 928, 1184 run address/host/resolver/file checks and nmap commands under logon ID `0x13665f17`.

WS-DRAMIREZ-01 eCAR line 364 supplies the matching outbound SSH tuple and `ssh.exe root@WEB-EXT-01.meridianhcs.local`. I therefore did not infer that the web shell magically became root, or that every later root command must descend from the apache2 child. The visible remote-session evidence supplies a different operational path. Linearity or a compact sequence was not scored.

On DC-01, eCAR lines 3978/3985 show cmd/net creating `svc_dirsync`, then lines 4002/4009 add it to Domain Admins. The Security source records account creation as Event 4720, EventRecordID 28257154 at 17:15:19.2242501Z, with target SID ending `-2456`, followed by group membership Event 4728, EventRecordID 28257173 at 17:15:31.4047722Z using that same member SID and the Domain Admins SID ending `-512`. These effects follow the command launches and preserve the affected identity. The scheduled task's Event 4698, EventRecordID 28257394 at 17:19:48.9866198Z, includes actual task XML with the DeviceSync executable and hourly repetition. This is useful operational evidence, not merely a prose claim that persistence succeeded.

I did not interpret later Security Event 1102, EventRecordID 1 at 18:42:11.6676456Z, as proof that previously forwarded records should vanish from this collected export. The source uses the Windows Eventlog provider and native UserData/LogFileCleared shape. A forwarded slice can retain earlier records across a local log clear.

### Operational hunt: database staging and collection

DB-PROD-01 syslog lines 180–181 record an SSH connection and accepted root password from `10.10.2.30:44990` at 18:15:09.390728Z and 18:15:17.263527Z. Its eCAR line 528 records the resulting successful session at 18:15:17.553Z. The shell precedes mysqldump at line 530 (18:15:22.996Z), the SQL file creation at line 531, gzip at line 533, and the compressed-file creation at line 534.

For the return transfer, DB-PROD-01 line 536 launches scp at 18:16:05.208Z; line 537 records the outbound tuple with source port 58586. Zeek-core `conn.json` line 11098 starts that transport at 18:16:07.938634Z, reports 34.180338 seconds, `service=ssh`, `conn_state=SF`, and no missed bytes. APP-INT-01 syslog lines 200–201 show connection then accepted public key at 18:16:13.458417Z and 18:16:14.267546Z. Its eCAR line 777 opens the session, line 778 observes the received file at 18:16:42.816Z, line 779 terminates the receiver at 18:16:43.325Z, and line 780 closes the session at 18:16:50.841Z. Source scp terminates at 18:16:43.464Z. Small sensor/endpoint timing differences are compatible with these source observations; this is not a demonstrated transfer-after-process-death case.

APP-INT-01 line 781 subsequently launches smbclient with the staged archive and a ClinicalResearch destination; line 783 reads the local archive. That supplies a feasible pivot to SMB evidence without assuming that every database access necessarily represents theft.

WS-AJOHNSON-01 provides a separate collection path. Its Type 9 session is used for collection commands and file creates, and line 1082 creates `C:\ProgramData\Microsoft\cache_7f3a.zip` at 18:02:10.215Z. Line 1131 launches curl through the proxy at 18:24:36.004Z; line 1138 reads that same local archive at 18:24:38.879Z. Those visible actions are ordered plausibly.

### Benign comparison and pivot feasibility

WS-LNGUYEN-01 eCAR line 403 launches the support upload with ticket `MHS-48217`, a metadata JSON part, a gzip diagnostic part, and an explicit proxy. Zeek-core `http.json` line 1253 observes the client-to-proxy POST at 16:32:37.931574Z, with absolute-form URI, 1,573,258 request-body bytes, and MIME types `application/json` and `application/gzip`. Zeek-dmz `http.json` lines 1416–1417 provide the client-side view and proxy-to-server view; the upstream request uses origin-form URI and source `10.10.3.20`. This distinction is operationally credible for an explicit HTTP proxy. Matching fields are counted positively for hunt feasibility, not negatively as excessive completeness.

The Mac-to-Mac SSH pivot is similarly workable. MAC-MROSS-01 Endpoint Security line 45 executes SSH toward MAC-MROSS-02 at 14:24:27.438759Z. Zeek-core `conn.json` line 2497 observes `10.10.1.41:49252 -> 10.10.1.42:22` at 14:24:37.445446Z. MAC-MROSS-02 Unified Log line 2 accepts keyboard-interactive/PAM at 14:24:44.399410Z; Endpoint Security line 61 executes the target shell at 14:24:44.513340Z. These are distinct phases with a believable ordering.

### Broad consistency checks and limitations

Across all eCAR files, joins by stable process object identity found no actor references more than one second before an observed create or more than one second after an observed terminate. This does not prove every principal or process association correct, but it avoids conflating PID reuse with a same-identity lifecycle contradiction.

For eCAR flows with both observed actor termination and matching near-time Zeek tuples, I found no transport extending more than 30 seconds beyond process termination. SSH session checks found no successful eCAR SSH authentication before the matching near-time Zeek transport open.

Across the Zeek sensors, HTTP, TLS and DNS rows with UIDs had matching connection references within their own sensor files. No tested protocol timestamp was more than 100 milliseconds before its connection timestamp or more than one second beyond its recorded interval. This is bounded consistency evidence; it is not a claim that every possible protocol semantic was exhaustively verified.

A naive packet-overhead check initially produced apparent exceptions, but the inspected examples had explicit `missed_bytes` and `G/g` history markers. For example zeek-core `conn.json` line 147 reports 387 missed bytes. Sequence-derived payload totals and captured packet-byte totals need not agree under capture loss, so these were excluded from synthetic evidence.

Within each Windows host, observed Sysmon process-create records did not assign multiple different hash strings to the same image path. This supports stable binary identity but does not establish that every hash is authentic to a public binary; I did not compare hashes against external malware or software databases.

Source volume is uneven in sensible ways. Zeek-core hourly counts are 1,849, 3,233, 1,757, 1,698, 2,068, 1,709 for hours 13–18; the scan period contributes to the larger hour. Directory servers and proxy/web infrastructure dominate many counts. I found no volume contradiction strong enough to penalize. Source selection, pre-window process creation, post-window closure, domain sanitization, and absence of unprovided audit families were kept neutral.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | macOS zsh histories, corroborated by Endpoint Security execs | Two hosts belonging to one user; 39 history commands total, 13/12 distinct full commands per host | Limited upward pressure: repeated diagnostic vocabulary is noticeable, but same-user workflow and selective collection remain plausible. |
| weak_signal | macOS Endpoint Security | Repeated interactive id/version-check executions | Corroborates the same texture concern; not counted as a second independent finding. |

There is no confirmed high-impact contradiction in this assessment. A score of 35 reflects mostly realistic telemetry with a limited explainable texture concern; it is not a 35% confidence in the verdict.

## Realism Score by Category

- **Field format accuracy:** 9 — XML and NDJSON parse, native event shapes are differentiated, and inspected protocol fields are credible; no exhaustive vendor schema certification was attempted.
- **Temporal patterns:** 8 — Variable traffic and coherent observed lifecycles; macOS interactive command repetition slightly weakens the behavioral timing texture.
- **Cross-source correlation:** 9 — SSH, netonly credentials, proxy routing, archive staging and transport pivots work in the inspected examples, with broad reference/timing checks supporting them.
- **Behavioral realism:** 7 — The attacks and administration are technically workable; the two Mac shell histories have a limited repetitive diagnostic vocabulary.
- **Environmental consistency:** 9 — Host/service roles, source volumes, network paths and account namespaces are mostly coherent within the supplied window.

## Recommendations

- If this were synthetic, broaden the macOS interactive command vocabulary around concrete work tasks, particularly the repeated Documents searches and identity/version checks in the two Maya histories. Preserve the observed terminal ancestry and the distinction between interactive checks and the legitimate periodic inventory service.
- If this were synthetic, keep the existing transport-before-authentication, local-versus-outbound-principal, explicit proxy request-form, and file/process lifecycle relationships while varying that command texture. I found no evidence-based reason to add arbitrary missing sources or increase background volume merely to make the data busier.
