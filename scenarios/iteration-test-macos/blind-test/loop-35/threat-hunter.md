# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 78
**Synthetic-Confidence Score:** 48

## Executive Summary

The collection supports useful hunting across a mixed fleet, and the major process, authentication, and transfer chains I tested work together technically. Several baseline command patterns look templated, especially shell manipulation of binary business documents on both Macs, but I did not establish an impossible same-identity lifecycle or source-native contradiction strong enough to distinguish synthetic data confidently from a selected, sanitized production collection.

## Evidence For Synthetic

- [distribution_texture] Both Macs repeatedly use raw shell utilities for shared business documents. `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson` lines 50, 64, 66, 78, and 95 show `tee` writing `.pptx`/`.xlsx` and `cat` reading `.xlsx`/`.pdf`; `MAC-MROSS-02.../macos_endpoint_security.ndjson` lines 109 and 128 repeat the `cat` pattern for a PDF and spreadsheet. The normalized file observations corroborate this: Mac 01 `ecar.json` lines 132, 171, 180, 233, 262; Mac 02 lines 326, 424. These utilities can handle arbitrary bytes, so this is a behavioral distribution concern, not an impossible operation. Its recurrence across both hosts is more suggestive than one unusual command.
- [distribution_texture] User shell histories on both Macs draw heavily from the same small diagnostic vocabulary. Mac 01 `zsh_history/maya.ross.zsh_history` lines 1–22 and Mac 02 lines 1–19 repeatedly cycle through `id`, `sw_vers -productVersion`, `uname -a`, `pwd`, `df -h`, `ps aux`, and the same `find ... -name '*.pdf'` command over six hours. For example, Mac 01 issues that identical `find` at epochs 1793630383 and 1793640422, while Mac 02 uses it at 1793631127 and 1793643844. This could be an administrative procedure, but the shared limited vocabulary weakens the organic-user impression.
- [weak_signal] Linux maintenance commands also reuse a recognizable diagnostic pool across different roles. `MAIL-CLIN-01.../ecar.json` lines 17–41 and 91–118 contain dense runs of `journalctl`, `apt-cache policy openssl`, `find /tmp`, `apt-get -s upgrade`, `ss`, and service-status commands; `LOG-MON-01.../ecar.json` lines 2–21 and `PROXY-01.../ecar.json` lines 597–657 contain many of the same utilities. An administrator's standard checklist is an adequate alternative explanation, so this contributes little independently.

## Evidence For Real

- SSH evidence preserves useful tuple and timing relationships. DB-PROD-01 `ecar.json` lines 481–485 show the server process, inbound `10.10.2.30:35206 -> 10.10.4.10:22`, accepted root session, shell, then `mysqldump`. Its `syslog.log` lines 184–187 independently show connection, password acceptance, PAM opening, and logind session 279044.
- The subsequent SCP transfer has coherent source, receiver, and network evidence: DB-PROD-01 `ecar.json` lines 492–497; APP-INT-01 `syslog.log` lines 192–197; and `zeek-core/conn.json` line 10766. The transfer port remains 43693, and receiver authentication and close evidence fit the visible transport interval.
- Proxy semantics distinguish plaintext forwarding from encrypted tunnels. `zeek-core/http.json` line 1215 records an absolute-form HTTP POST through the proxy, whereas line 1939 records CONNECT for the later HTTPS upload. `PROXY-01.../proxy_access.log` lines 3045–3046 explicitly label the CONNECT setup and SSL-inspected POST with the same tunnel ID and client port, explaining otherwise surprising HTTPS application visibility.
- Windows persistence and account activity contain actionable identities rather than isolated command strings. DC-01 has PSEXESVC installation, SYSTEM process execution, creation of `svc_dirsync`, addition to Domain Admins, and later deletion with matching account SID. This is evidence of technical coherence, not proof of production origin.
- Across all supplied normalized endpoint files, my bounded identity checks found no child created before its visible parent, child created after its parent's visible exit, or non-process action preceding its visible actor's creation or following its exit. Pre-window actors and still-running processes were treated as neutral.

## Detailed Analysis

### Scope and method

I examined only the supplied data directory. There are 23 host directories with normalized endpoint records: ten Windows, eleven Linux-like hosts with syslog, and two Macs with Endpoint Security and Unified Log exports. The endpoint timestamps span 2026-11-02 13:00:01.011–18:59:52.375 UTC. The visible address space includes workstation addresses in `10.10.1.0/24`, servers in `10.10.2.0/24`, web/proxy hosts in `10.10.3.0/24`, and database traffic to `10.10.4.10`.

I counted 35,078 normalized eCAR records, 18,797 Windows Security events, 11,651 Sysmon events, 3,849 syslog lines, 302 Mac Endpoint Security notifications, five Unified Log records, 21,549 Zeek connection rows across three sensors, 3,425 proxy access lines, and 153 IDS alerts. Zeek counts include observations of shared traffic at multiple sensors and should not be interpreted as unique enterprise connection counts. XML line counts are not event counts.

The normalized events contain 26,482 FLOW/CONNECT records, 2,012 process creations, 1,890 process terminations, and 932 login observations. These volumes and their uneven distribution are compatible with a selected six-hour collection; I do not infer missing sources from the small Unified Log export or selected Sysmon families.

### Intrusion-relevant pivots

WEB-EXT-01 `ecar.json` line 872 at 14:19:32.245 shows `www-data` launching a base64-decoding bash command. Its decoded command invokes an interactive shell using `/dev/tcp/45.33.32.30/8443`. The process context makes this a strong hunting lead on an externally serving host. I do not treat the comprehensibility of the attack as an authenticity indicator.

On WS-AJOHNSON-01, `ecar.json` lines 658–677 show a shell followed by `whoami /all`, domain-user/group enumeration and `net view /domain` at 16:20:21–22. DC-01 lines 3499 and 3507 later show `PSEXESVC.exe` and a SYSTEM command shell at 17:00:03–05. The native DC Security records include 4697 at 17:00:02.0223028 with `ServiceName=PSEXESVC` and subject `aisha.johnson`, followed by 4720/4728 at 17:15:02.5591152 and 17:15:08.0890444 for `svc_dirsync`. The account SID ends `-5643` at creation, group addition, and deletion at 18:49:55.4722966. Those pivots are operationally meaningful even though causal attribution between every stage would require further investigation.

WS-AJOHNSON-01 lines 1001–1076 show collection from finance, clinical, and research shares into `VaultCache` and archive creation. Line 1154 launches curl at 18:25:19.535 using the explicit proxy and `cache_7f3a.zip`. Proxy lines 3045–3046 at 18:25:23 show client `10.10.1.35`, port 53467, tunnel `PT-52b4371b2066e215`, and approximately 18.8 MB of client bytes for the corresponding POST. Zeek-core HTTP line 1939 observes the matching CONNECT. I do not require the passive sensor to expose the encrypted POST itself.

### Database staging and transport coherence

DB-PROD-01 lines 485–489 show `mysqldump`, creation of `/tmp/rpt_0318.sql`, and gzip creation of `/tmp/rpt_0318.sql.gz`. Shell redirection is normally absent from the executed program's argv, so the lack of `>` in the dump process command does not disprove file output.

At 18:16:02.173 line 492 launches SCP toward APP-INT-01. Zeek-core connection line 10766 starts at epoch 1793643364.619031 and lasts 13.069763 seconds, with 100,850 origin bytes and `conn_state=SF`. APP-INT-01 syslog line 193 accepts root public-key authentication at 18:16:10.191193 and line 196 closes PAM at 18:16:18.653669. A slight source timestamp offset at close is plausible and does not establish an impossible lifecycle.

APP-INT-01 `ecar.json` line 738 subsequently runs SMB upload of that archive to FILE-LNX-01. `zeek-core/smb_files.json` lines 191–192 identify the same destination path and a 74,865-byte write; `zeek-core/files.json` line 629 retains the same FUID and complete byte count. The SCP transport volume can contain a file of that size plus protocol overhead. I found no byte-volume impossibility in this chain.

### Baseline texture and limits

The two-Mac document behavior is the most concerning authenticity feature. Text-based inspection of PDF/Office bytes and direct `tee` writes are possible but poorly represent routine interactive document use when they repeatedly dominate the visible shared-document operations. The diagnostic shell loops reinforce that impression. These observations justify a mixed score, but could also result from scripted tests, a specialized administrative workflow, or deliberate selection of shell telemetry.

I also checked HTTP request/response body sizes against each sensor's matching connection byte counts, and checked application observations for failed `S0`/`REJ` transports. Those checks found no contradiction. I did not infer execution from the MeetingAssist policy warning in Mac 01 Unified Log line 2: its wording alone does not establish denial or subsequent execution. I did not treat plist creation as proof of launch activation.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | Mac ES and normalized file/process telemetry | Repeated `cat`/`tee` operations on binary business documents across both Macs | Main reason the score rises above mostly production-like |
| distribution_texture | Mac zsh histories and matching process telemetry | Repeated identical diagnostic vocabulary on both endpoints | Moderate supporting texture signal; scripted workflow remains plausible |
| weak_signal | Linux normalized process telemetry | Reused maintenance vocabulary across mail, proxy, and monitoring roles | Small contribution; shared administrator procedures could explain it |

No established hard contradiction is included in this assessment. The synthetic indicators overlap and should not be counted as three independent proofs.

## Realism Score by Category

- **Field format accuracy:** 9 — Readable native XML/JSON and coherent source-specific fields; no verified schema defect established.
- **Temporal patterns:** 8 — Tested attack lifecycles have plausible ordering; repeated diagnostic routines reduce natural texture.
- **Cross-source correlation:** 9 — SSH/SCP, SMB, and proxy pivots retain useful identities, tuples, and volume relationships.
- **Behavioral realism:** 6 — Intrusion actions are technically plausible, but repeated raw shell manipulation of business documents is conspicuous.
- **Environmental consistency:** 8 — Mixed host roles, directory identities, proxy paths, and database segmentation fit together; selection limits conclusions.

## Recommendations

- If this were synthetic, diversify shared-document activity around the actual reader/writer applications and preserve their process ownership. Keep raw `cat` and `tee` for workflows that plausibly use binary streams; the repeated Mac examples above should not be the dominant pattern for PDF and Office documents.
- If this were synthetic, give the two Mac shell histories distinct, task-driven command distributions. Retain occasional repeated diagnostics, while reducing identical cycles of version checks, user enumeration, and PDF searches.
- If this were synthetic, distinguish Linux maintenance routines by host role and operator task, using the mail/proxy/monitoring command sequences cited above as the bounded review targets. A standard administrator checklist may repeat, but its observed scheduling and task purpose should remain plausible.
