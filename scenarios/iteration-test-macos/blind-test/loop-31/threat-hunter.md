# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 86
**Synthetic-Confidence Score:** 66

## Executive Summary

The collection supports credible multi-source hunting across Windows, Linux, macOS and several network zones, with notably coherent process, credential and transfer relationships. My synthetic verdict rests primarily on repeated, measurable patterns in ordinary macOS activity—especially identical arithmetic command-spacing patterns on two separate interactive shells and document access represented exclusively by simple command-line utilities—rather than on the completeness or narrative shape of suspicious activity. I did not establish a decisive impossible lifecycle or source-native schema contradiction, which limits the score.

## Evidence For Synthetic

- [distribution_texture] Two macOS shell histories share a distinctive progression of within-burst delays despite different commands and widely separated wall-clock times. In `MAC-MROSS-01.meridianhcs.local/zsh_history/maya.ross.zsh_history`, lines 4–6 have a 30-second then 50-second gap, lines 8–10 have 37 then 52 seconds, lines 11–12 have 44 seconds, lines 14–15 have 51 seconds, and lines 19–20 have 65 seconds. On `MAC-MROSS-02.../zsh_history/maya.ross.zsh_history`, lines 4–5, 6–7, 9–10, 12–13 and 18–19 repeat **30, 37, 44, 51, 65 seconds**, respectively. The first gap in successive command groups advances by exactly seven seconds across both machines. These are individual history entries, not one visibly invoked script. This shared cadence is substantially more diagnostic than ordinary command repetition.
- [distribution_texture] Across both Mac endpoint streams, all eight visible ordinary shared-document reads are attributed to `/bin/cat`, including `.xlsx` and `.pdf` documents; both visible shared-document writes are attributed to `/usr/bin/tee`, targeting `.pptx` and `.xlsx` documents. Examples: `MAC-MROSS-01.../ecar.json:80,122,165,200,261` and `MAC-MROSS-02.../ecar.json:99,359,401,506,604`. This is an unusually homogeneous implementation of document activity for workstations also showing Chrome, Slack, Outlook and Word. It could be deliberate diagnostic activity, so I score the distribution rather than claiming these operations are impossible.
- [distribution_texture] Initial Chrome launches on both Macs have almost the same staged helper-start schedule. `MAC-MROSS-01.../macos_endpoint_security.ndjson:19,21,23,25` shows browser exec at `13:13:31.656549Z`, then renderer, GPU and network helper execs at approximately **+2.003, +3.002 and +5.008 seconds**. `MAC-MROSS-02.../macos_endpoint_security.ndjson:24,26,28,30` shows browser exec at `13:27:10.354352Z`, with the same helper classes at **+2.005, +2.996 and +4.997 seconds**. Software startup can be repeatable, but the close reproduction of this schedule reinforces the separate shell-history evidence. This carries less weight than the arithmetic history cadence.

## Evidence For Real

- The data contains substantial operational background rather than only suspicious actions: 21,473 Zeek connection records, 35,583 normalized endpoint records, 18,945 Windows Security events, 11,789 Sysmon events, 4,249 syslog lines and 3,387 proxy records. Network states include successful sessions, unanswered probes, rejects, resets and partial connections. The observed population is 23 endpoint directories plus network/security infrastructure.
- SSH pivots have usable transport, source-tuple, authentication and endpoint identities. For example, `zeek-core/conn.json:8103` records `10.10.1.41:58137 → 10.10.2.30:22` at `17:02:18.740383Z`; `MAC-MROSS-01.../ecar.json:325` records the matching outbound SSH process flow, and `APP-INT-01.../ecar.json:348` records successful `maya.ross` SSH login at `17:02:31.877Z`. Transport precedes authentication.
- Credential cloning distinguishes local execution identity from outbound identity: `WS-AJOHNSON-01.../ecar.json:1096,1103,1107` shows `runas /netonly`, a Type 9 session retaining `aisha.johnson` locally with `outbound_principal=marcus.chen`, and a child command interpreter using the new logon ID. The Security 4624 event at `18:00:40.6779064Z` likewise retains Aisha as target/local identity while naming Marcus in `TargetOutboundUserName`.
- The database staging pivot preserves file provenance and ordering across distinct hosts and sources. `DB-PROD-01.../ecar.json:503–514` shows dump, gzip and SCP; `APP-INT-01.../syslog.log:219–220` records matching root public-key authentication from the database host and source port; the receiver then records `/tmp/.cache/rpt_0318.sql.gz` in `APP-INT-01.../ecar.json:731`.
- macOS evidence separates policy messages from successful execution. `MAC-MROSS-01.../macos_unified_log.ndjson:2` reports AppleSystemPolicy would not allow `MeetingAssist`; I found no successful MeetingAssist exec in that host's supplied ES stream and did not infer execution or effects from this policy message.

## Detailed Analysis

### Collection orientation and hunt feasibility

The principal window is approximately `2026-11-02 13:00–19:00 UTC`. Hostnames and traffic suggest user endpoints in `10.10.1.0/24`, internal services in `10.10.2.0/24`, web/proxy infrastructure in `10.10.3.0/24` and a database segment at `10.10.4.10`. These are inferences from visible tuples and names, not external organization information.

The source mix is broadly plausible: ten Windows hosts have Security/Sysmon XML, eleven hosts have syslog, two Macs have native ES and Unified Log records, and all 23 endpoints have normalized eCAR data. Three Zeek viewpoints provide different network visibility. A six-hour bounded collection explains sessions inherited from earlier activity and sessions continuing after the window; I did not score absent outside-window initiators or closures.

I parsed the normalized endpoint records and checked every visible actor reference against same-host process create/terminate times where the matching process lifecycle was available. This check found no actor observation before its visible creation or after its visible termination. I also checked Zeek byte/packet relationships for payload bytes exceeding IP bytes or nonzero bytes with zero packets; those checks produced no defects. These checks do not prove every semantic relationship correct, but materially weaken a verdict based on broken elementary lifecycles.

### Suspicious activity and corroborating pivots

The web server supplies a credible initial investigation lead. `WEB-EXT-01.../web_access.log:501` records a successful upload request from `185.70.41.45` at `14:19:57 UTC`. `WEB-EXT-01.../ecar.json:923` records an Apache child `/bin/bash` as `www-data` at `14:19:57.838Z`, carrying an encoded reverse-shell command; line 924 then records its connection to `45.33.32.30:8443` at `14:20:01.832Z`. The parent identity, account and direction agree with the observed server role. I treat this as suspicious evidence and a feasible pivot; the fact that it can be narrated is not an authenticity indicator.

Later, root accesses the integration and database systems. On the database server, `ecar.json:501` records root SSH login from `10.10.2.30:34468` at `18:15:09.103Z`; native syslog lines 194–195 record the same source and accepted password. The shell starts before `mysqldump` at `18:15:13.240Z` (`ecar.json:502–503`). The dump creates `/tmp/rpt_0318.sql`, gzip follows the dump's visible termination, and SCP begins after gzip terminates (`:504,507–511`). This is coherent operational ordering.

The SCP connection is visible in `zeek-core/conn.json:10512` as `10.10.4.10:51478 → 10.10.2.30:22`, beginning `18:15:37.642972Z`, duration `30.262984`, with `orig_bytes=633847` and `resp_bytes=15330`. The integration server's SSH log explicitly uses port 51478 (`syslog.log:219–220`), and its endpoint stream creates the receiver file (`ecar.json:731`). Later `zeek-core/smb_files.json:172–173` shows the same basename written to `ClinicalResearch\Integration\DB-Staging\rpt_0318.sql.gz`, size 613,435. Wire byte totals need not equal file size because of SSH/SMB framing, so I did not score that difference as a defect.

Windows collection/staging also has technical substance. Aisha's local Type 9 token is preserved through PowerShell commands accessing UNC paths and writing local staging files (`WS-AJOHNSON-01.../ecar.json:1128–1183`), followed by `Compress-Archive` and a resulting ZIP (`:1185,1192`). The use of different local and outbound principals is appropriate to `/netonly`; simply equating local username with the supplied network credential would yield a false finding.

### Why ordinary Mac activity changes the verdict

The Mac shell histories are my highest-impact evidence because their timing signature is independent of the intrusion timeline. The paired machines do not merely repeat common administrative commands: the gaps between groups reproduce an arithmetic series, while the commands rotate. For example, one host uses `df → ps` with 37 seconds while the other uses `ps → find` with 37 seconds; the next groups use different commands but each gap becomes 44 seconds, then 51 seconds. The recurrence is directly reproducible from the integer history timestamps and also has native ES executions nearby.

An administrator could intentionally pace diagnostics, and shell history can be manipulated. However, neither explanation is visibly established. Combined with shared document traffic uniformly implemented through `cat`/`tee` and nearly copied first-launch browser-helper schedules, this is more consistent with procedural activity templates than ordinary interactive workstation usage.

I kept this finding bounded. I did not penalize sparse Unified Log coverage, missing optional audit sources, the selected Sysmon event families, sanitized domain names, coherent pivots, or the apparent completeness of the intrusion. I also did not allege unfamiliar macOS ES fields were invalid without a source-native contradiction.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | macOS zsh history, corroborated by ES executions | Two hosts, multiple separate command groups over several hours | Strongest indicator: repeated 30/37/44/51/65-second spacing across changing commands suggests shared procedural timing. |
| distribution_texture | macOS normalized file/process telemetry | Eight shared-file reads and two writes across both Macs | Moderate: Office/PDF document activity has a homogeneous cat/tee implementation despite visible GUI business applications. |
| distribution_texture | macOS native ES process execution | Initial Chrome launch on each Mac | Supporting: helper classes recur at almost identical +2/+3/+5-second offsets; weaker independently because application startup is partly deterministic. |

No hard contradiction is needed or claimed for this verdict. The score remains in the lower part of “likely synthetic” because operational cross-source coherence is strong and alternate explanations exist for the activity texture.

## Realism Score by Category

- **Field format accuracy:** 9 — Native and normalized fields were parseable and supported practical pivots; no demonstrated source-native schema contradiction.
- **Temporal patterns:** 6 — Transport/auth and process lifecycles generally work, but repeated Mac diagnostic cadence and browser helper offsets look procedural.
- **Cross-source correlation:** 9 — SSH tuples, credential cloning and staged-file transfers support detailed, technically useful investigations.
- **Behavioral realism:** 6 — Suspicious actions are workable, while ordinary Mac document and shell activity has a narrow, repeated texture.
- **Environmental consistency:** 8 — Hosts, zones and services largely agree; the business-workstation document access pattern is the principal concern.

## Recommendations

- If this were synthetic, replace the shared arithmetic spacing between interactive command groups with behavior derived from distinct user tasks and separate per-session timing. Preserve the actual shell-command/process relationship while allowing variable pauses and interruptions.
- If this were synthetic, represent ordinary spreadsheet, presentation and PDF use through the applications actually shown on the Macs, reserving `cat`/`tee` for explicit diagnostics or scripted file manipulation. Maintain file/process/share identity consistency.
- If this were synthetic, vary Chrome helper startup timing with actual launch context, session reuse and workload rather than reproducing the same initial +2/+3/+5-second sequence across hosts.
- Preserve the existing transport-before-auth relationships, local-versus-outbound credential semantics and transfer provenance while changing activity texture; those parts already make the dataset useful for hunting.
