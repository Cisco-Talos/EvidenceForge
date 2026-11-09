# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 85
**Synthetic-Confidence Score:** 35

## Executive Summary

The supplied slice is mostly production-like in the operational relationships I tested: exploitation, privileged Windows execution, Linux remote administration, proxy uploads, and cross-platform SSH pivots have usable identities and plausible visible ordering. The strongest origin concern is a narrow, repeatedly reused interactive command vocabulary on the two Macs; I found no demonstrated impossible same-identity lifecycle or source-native contradiction sufficient to classify the data as synthetic. The score measures the observed data's relatively realistic appearance, while the higher verdict confidence expresses confidence that its origin remains unresolved.

## Evidence For Synthetic

- [weak_signal] The two `maya.ross.zsh_history` files contain 38 entries but only 14 distinct complete command strings collectively; 35 entries come from 11 diagnostic/listing command strings, with the other three being SSH launches. For example, MAC-MROSS-01 history lines 1–3 contain `id`, `sw_vers -productVersion`, and `uname -a`; lines 8–10 contain `df -h`, `ps aux`, and a PDF `find`; lines 15–16 repeat `sw_vers` and `id`; lines 17–20 revisit listing, finding, process listing, and disk space. MAC-MROSS-02 history lines 1–9 and 11–18 reuse almost the same vocabulary. This is a concrete small-vocabulary texture, but the same person may be checking two machines, so it receives limited weight.
- [weak_signal] Some Mac document activity uses a conspicuously generic terminal pattern: MAC-MROSS-02 `macos_endpoint_security.ndjson` line 109 executes `/bin/cat /Volumes/ClinicalResearch/Archive/2025/service-review.xlsx`; lines 122 and 125 execute `cat` against `project-plan.docx` and `onboarding.docx`; line 153 does the same for `draft-draft.pdf`. These are executable commands and valid file reads, not impossible behavior, but the repeated use of `cat` for office documents is an unusual interactive work texture. A shell-based scanner or diagnostic workflow could explain it. I do not assume that a read proves the document was viewed meaningfully.

No hard contradiction, contract gap, or verified schema defect was established by this review. These weak observations should not be treated as independent proof of fabrication.

## Evidence For Real

- The network data contains varied outcomes and imperfect observation rather than only successful traffic. Across all three Zeek connection files, examples include successful connections, resets, refusals, unanswered SYNs, partial connections, and `OTH`; `zeek-core/conn.json` has 10,107 `SF`, 1,709 `S0`, and 438 `OTH` rows among 12,556 connections. This is a plausible collection texture, although a simulation can reproduce it.
- A concrete SSH pivot joins endpoint process identity, source tuple, network interval, remote native authentication, and normalized session evidence. MAC-MROSS-02 ES line 107 starts SSH PID 45500 at `16:01:45.997331Z`; its eCAR line 269 observes `10.10.1.42:57354 -> 10.10.1.41:22`; `zeek-core/conn.json` line 6835 identifies the same tuple as UID `C7906aMHFsw8UVipEM`, opening at epoch `1793635318.312099`; MAC-MROSS-01 Unified Log line 3 accepts that public key at `16:02:03.740308Z`; its eCAR line 297 records the SSH login at `16:02:05.439Z`.
- The credential-access process has appropriate visible privilege, rather than being assigned implausible standard-user access. WS-AJOHNSON-01 Sysmon PID 5896 has `IntegrityLevel=High` at XML line 11776, followed by the same GUID/PID accessing LSASS with `GrantedAccess=0x1FFFFF` at approximately `16:44:54.215Z`. Windows Security 4688 also assigns high mandatory integrity to this process.
- Windows remote service execution includes target-side file placement, service installation, service process, and child process evidence: DC-01 Sysmon records `PSEXESVC.exe` placement at `17:00:28.392Z`, Security records service installation at `17:00:28.6998168Z`, then the service starts at `17:00:34.531Z` and creates `cmd.exe` at `17:00:41.148Z`. Those relationships are technically useful hunting pivots.
- Proxy evidence distinguishes tunnel control traffic from inspected application traffic. PROXY-01 `proxy_access.log` lines 3280–3281 associate a CONNECT and an inspected upload with `tunnel_id=PT-f74d626f47bff8b1` and client port 52745, and explicitly describe different byte scopes. I do not count their complete matching as suspicious.
- Platform identities remain local where appropriate. MAC-MROSS-01 ES represents Maya as UID 501, while APP-INT-01 `syslog.log` line 166 opens Maya's SSH session as UID 2176; different local numeric identities do not invalidate the successful named-account pivot.

## Detailed Analysis

### Inputs, provenance, and limits

I read the supplied neutral briefing at `/private/tmp/log-study-wxj1n2j_/threat-prompt.md` and examined only files beneath `/private/tmp/log-study-wxj1n2j_/data`. The coordinator's delegation and generic inherited operating context were available; no repository files, scenario, TODO, worklog, prior assessment, other review, or neighboring directory inventory was accessed. Logged commands were treated as inert text. The report destination is outside the data directory only because the briefing explicitly names it.

I enumerated supplied data files, counted their records, parsed all eCAR rows and Windows XML event envelopes, and examined selected native and network rows around hunting pivots. The quantitative identity checks described below covered the entire supplied eCAR corpus; behavioral interpretation and protocol review were selective rather than an exhaustive field audit or packet reconstruction.

Public documentation actually accessed: the direct upstream [Apple `find` manual source](https://raw.githubusercontent.com/apple-oss-distributions/shell_cmds/main/find/find.1) and [Microsoft Sysmon documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon). Microsoft documents GUID-based process correlation and distinguishes process access from remote thread events. Apple documents `-maxdepth`, so its appearance in Mac commands was not scored as an unsupported-command defect.

Source-selection qualification: an initial search mistakenly included `manpagez.com` alongside Apple-specific domains in its actual domain filter, and returned third-party manual-page snippets. I did not rely on those snippets for a finding or score, and subsequently opened Apple's upstream source directly. This was a primary-source-only workflow deviation; no task-project or previous-assessment information was returned or exposed. All scored observations above come from the supplied logs.

### Environment and collection scope

The endpoint inventory inferred from eCAR contains 23 host directories: ten with Windows Security/Sysmon exports, eleven with Linux-style syslog, and two with Mac Endpoint Security/Unified Log exports. The eCAR corpus contains 37,046 records and 39 distinct principal strings, including service, machine, and anonymous identities; that is not a count of human users. Network records show several internal networks, particularly `10.10.1.x` clients, `10.10.2.x` servers, and `10.10.3.x` web/proxy infrastructure, with DB access also using `10.10.4.10`.

The visible interval is approximately `2026-11-02 13:00–19:00 UTC`. Native source volumes include 12,119 Sysmon events, 19,553 Security events, 4,191 syslog lines, 304 Mac ES rows, five Mac Unified Log rows, 22,650 Zeek connection rows, 3,551 proxy lines, and 781 web access lines. The network sources have different observation scopes, so these totals should not be added and interpreted as unique real-world actions. Thin Mac Unified Log coverage and missing pre-window process starts are neutral under the briefing's collection assumptions.

### Hunt reconstruction and effect attribution

The web entry point is visible in WEB-EXT-01 `web_access.log` line 396: an external `185.70.41.45` client submits a successful POST to `/ehr/admin/upload.php` at `14:20:00 UTC`. WEB-EXT-01 eCAR line 898 then creates an Apache-child `www-data` bash process at `14:20:01.393Z`, with an encoded shell command naming `45.33.32.30:8443`. Zeek DMZ connection line 1818 observes `10.10.3.10:33642 -> 45.33.32.30:8443` at `14:20:04.587847Z`, lasting 20.968882 seconds. HTTP success alone would not prove code execution; the process and outbound connection supply additional evidence here. I do not infer a particular server vulnerability or an unlogged privilege-escalation mechanism.

Later root sessions on WEB-EXT-01 and APP-INT-01 are supported by their own authentication/process records. APP-INT-01 syslog line 99 accepts root from `10.10.3.10:55174` at `15:15:32.464091Z`; its eCAR line 196 starts the root shell at `15:15:34.912Z`. At `18:14:31.950Z`, APP-INT-01 eCAR line 771 launches `ssh root@DB-PROD-01.meridianhcs.local`. DB-PROD-01 syslog line 194 accepts root from `10.10.2.30:51026` at `18:14:50.634655Z`; eCAR lines 496–503 then show shell readiness, a database dump command, compression, and SCP back to `10.10.2.30`. These are compatible operational steps. Neither the dump command string alone nor SCP launch alone proves complete transfer of a specific file's contents.

On Windows, the high-integrity credential-access process at `16:44:45Z` has explicit LSASS access and a remote-thread observation before termination. Those rows substantiate invasive process interaction, but they do not independently reveal recovered credentials. At DC-01, the subsequent service-execution sequence has separate service-install, service-start, and child-process times. Security account-management records further show `svc_dirsync` account creation, password-related changes, and Domain Admins membership; examples are XML line 198513 for the account name and line 198893 for the membership distinguished name. I distinguish the commands from their later account-management effects.

The Windows upload is also distinguishable from a benign support upload. WS-AJOHNSON-01 eCAR line 1291 launches curl with an explicit proxy and an archive multipart form at `18:24:35.361Z`. Proxy lines 3280–3281 record its CONNECT and POST at `18:24:39 UTC`, carrying 18,783,084 client bytes under one tunnel ID. By contrast, proxy line 2187 records Lina's `MHS-48217` support attachment at `16:40:39 UTC`, tied to the ticket-specific curl command at WS-LNGUYEN-01 eCAR line 357. Similar tools and upload methods do not make both operations malicious.

### Mac execution and session boundaries

MAC-MROSS-01 Unified Log line 2 says policy would not allow PID 62464 to execute `/Applications/MeetingAssist.app/Contents/MacOS/MeetingAssist` at `15:41:46.254163Z`. I found no corresponding successful ES execution for that program in the supplied Mac file. I therefore do not attribute a successful child process, persistence activation, or later effects to this policy message. Similarly, an eCAR plist creation for the endpoint inventory service is file placement evidence; its existence alone is not proof of launch-item activation.

For the two-Mac SSH pivot, the network interval opens before accepted authentication and ends at approximately `16:17:59.356314Z`. The client normalized process termination is `16:18:01.120Z` and the server normalized logout is `16:18:08.388Z`. These are different source observations within seconds of shutdown rather than a demonstrated impossible lifecycle. Native ES distinguishes fork and exec: a process can retain its PID while its execution image and pidversion change, so I did not miscount exec transitions as necessarily new process creation.

### Corpus checks and weighting

Across all 37,046 eCAR records, I joined `actorID` and `properties.source_process_uuid` to visible process CREATE and TERMINATE object IDs. With a one-second tolerance, I found zero referenced activities before a visible creation or after a visible termination. This checks only relationships explicitly represented by those identities; it does not establish complete coverage or certify every timestamp.

I also checked all 22,650 Zeek connection rows for `S0` records with response packets and for payload-byte counts exceeding the corresponding IP-byte counts. No such basic contradictions were found. Across Sysmon process-creation rows, no identical complete hash string was associated with conflicting `FileVersion` values. These narrow negative checks support coherence but cannot prove real provenance.

The repetitive Mac diagnostic vocabulary receives limited weight because it is observed interactive behavior repeated across two hosts, rather than a claim that the attack is too orderly. Ordinary cron repetition, configured audit selection, sanitized domains, complete cross-source joins, source thinness, and the absence of out-of-window lifecycle endpoints did not increase the synthetic-confidence score.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `weak_signal` | Mac shell history, corroborated by ES execs | 38 history entries on two hosts; 35 entries from 11 diagnostic/listing strings | Small increase: concentrated interactive vocabulary, explainable by one operator checking both hosts |
| `weak_signal` | Mac ES process activity | Repeated `cat` reads of PDF/DOCX/XLSX paths on MAC-MROSS-02 | Small increase: unusual document-access texture, explainable by a shell scanner or diagnostics |
| No verified high-impact indicator | Tested eCAR process relationships and selected native/network pivots | Whole-corpus identity checks plus targeted investigations | Prevents a likely-synthetic verdict; no hard contradiction or material required-companion failure demonstrated |

## Realism Score by Category

- **Field format accuracy:** 9 — Parsed sources support usable native identifiers and fields; no verified format defect was established, but this was not an exhaustive native-schema audit.
- **Temporal patterns:** 8 — Tested pivots preserve feasible ordering and show variable timing; repeated diagnostic activity has somewhat narrow texture.
- **Cross-source correlation:** 9 — SSH, remote service execution, and proxy uploads support concrete pivots with plausible source-dependent timing.
- **Behavioral realism:** 7 — Administrative, service, scanning, support, and suspicious activity coexist; interactive Mac command/document patterns remain the weakest observed area.
- **Environmental consistency:** 8 — Mixed host roles, local UID differences, proxy routing, and source volumes are plausible within a filtered six-hour slice.

## Recommendations

- If this were synthetic, broaden the demonstrated purposes of interactive Mac terminal work beyond the 11 heavily reused diagnostic/listing commands, with commands tied to each visible application's actual work. Preserve the technically coherent SSH relationships.
- If this were synthetic, make the repeated office-document `cat` workflow explicit in the telemetry when it represents a scanner or diagnostic script, or use process/file evidence consistent with the intended document interaction. The issue is the observed repeated access pattern, not a requirement to add an arbitrary product or source.
- Preserve the successful distinction between policy messages and successful execution, between tunnel control bytes and application bytes, and between command invocation and independently observed effects. No additional audit source is required solely to make the narrative easier to investigate.
