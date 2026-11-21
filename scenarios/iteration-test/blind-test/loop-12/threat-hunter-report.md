# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 76
**Synthetic-Confidence Score:** 47

## Executive Summary

The visible attack and administration trails are operationally coherent across endpoint, authentication, network, and proxy records, and I did not establish an impossible visible lifecycle. A concentrated pattern of shell-based reads of binary office documents on one Mac is suggestive of an activity template, but remains explainable by unusual user or scripted behavior. That localized concern does not outweigh the credible correlations sufficiently to identify either production or synthetic origin reliably.

## Evidence For Synthetic

- [distribution_texture] On `MAC-MROSS-02.meridianhcs.local/ecar.json`, seven of nine `FILE/READ` observations are `/bin/cat` operations against binary document formats: two PDFs, one XLSX, and four DOCX files. Examples include line 64 at `13:37:29.955Z`, `/bin/cat /Volumes/ClinicalResearch/Team/2026/project-plan.pdf`; line 294 at `16:05:57.353Z`, `/bin/cat /Volumes/ClinicalResearch/Archive/2025/service-review.xlsx`; and lines 374/380 at `17:10:47.996Z`/`17:12:32.454Z`, reading `project-plan.docx` and `onboarding.docx`. Native Endpoint Security confirms actual `cat` executions, so this is not simply an EDR labeling a GUI document open as a generic read. Reusing a text-stream utility for every observed binary-document read is a localized behavioral texture concern, not an impossible action or proof of fabrication.

## Evidence For Real

- The web-server reverse-shell sequence has viable command ancestry and network timing. `WEB-EXT-01.../ecar.json` lines 930–932 show Apache-owned `www-data` launching a Bash decoding pipeline at `14:20:17Z`. `zeek-dmz/conn.json` line 2003 records `10.10.3.10:52175 → 45.33.32.30:8443` opening at `14:20:20.568885Z`, completing an `SF` connection before the visible shell processes terminate around `14:20:50–51Z`.
- The database dump and SCP transfer follow credible host and account boundaries. `DB-PROD-01.../ecar.json` lines 620–629 tie root SSH session `0x1185ef26` to `mysqldump`, a dump file, and SCP to `10.10.2.30`. The receiving application's syslog identifies the reverse-direction SSH transport from `10.10.4.10:56898`, authenticates root, and closes its PAM session after the transfer.
- The support upload is represented as a multipart POST rather than an unrelated generic web request. `WS-LNGUYEN-01.../ecar.json` line 484 includes separate JSON metadata and a gzip diagnostics attachment. `zeek-core/http.json` line 1354 records the matching case URI, POST method, request body of `1,573,258` bytes, and separate JSON/gzip file observations; proxy line 2064 agrees on the user, URI, method, and response.
- The Mac-to-Mac SSH pivot has appropriate transport-before-authentication ordering and differentiated native evidence. `MAC-MROSS-01.../macos_unified_log.ndjson` line 3 reports public-key acceptance at `16:02:08.147068Z` from `10.10.1.42:53621`; the corresponding `zeek-core` connection begins earlier, and normalized endpoint login follows authentication. The opposite-direction session uses keyboard-interactive/PAM instead of repeating the same authentication mechanism.
- Background activity is substantial and heterogeneous. The dataset includes successful, refused, reset, unanswered, and partial network connections; Kerberos and account validation activity; scheduled Linux sysstat work; service activity; application browsing; and unsuccessful Windows logons. These provide realistic alternative explanations and investigative pivots around suspicious actions.

## Detailed Analysis

### Scope and method

I examined only the supplied data directory. It contains 23 endpoint directories with 36,715 normalized eCAR records, ten Windows Security/Sysmon pairs totaling 17,375 Security events and 11,315 Sysmon events, Linux syslog and shell histories, two Mac Endpoint Security exports and small Unified Log extracts, three Zeek observation points, firewall records, IDS alerts, web access logs, and proxy logs. The apparent window is approximately `2026-11-02 13:00–19:00 UTC`; visible internal addresses span `10.10.1.x` through `10.10.4.x`.

I inventoried source volumes, parsed native Windows XML and JSON sources, inspected shell histories and suspicious commands, tested endpoint process references against visible creation/termination times, checked authentication ordering against corresponding remote transports, and compared HTTP body sizes with connection byte counters. No repository, scenario, ground truth, external source, or other reviewer report was used.

### Operational lifecycle and lateral movement

The web-facing server's Bash command decodes a reverse-shell command directed to TCP/8443. Its parent is `/usr/sbin/apache2`, the account is `www-data`, and the decoded destination agrees with the observed network tuple. The connection closes at `14:20:45.341211Z`, preceding the Bash process terminations. This is credible execution evidence, rather than an inference based on an IDS label alone.

At `18:15:10.697Z`, the database endpoint records root SSH login from application host `10.10.2.30:37538`. Its shell starts before `mysqldump --single-transaction ehr patients insurance_claims` at `18:15:15.997Z`; the SQL file appears at `18:15:18.198Z`, and the dump process terminates at `18:15:39Z`. SCP subsequently reads `/tmp/rpt_0318.sql.gz` and sends it back to the application host.

The transfer transport is observed independently by `zeek-db` and `zeek-core`. In `zeek-db/conn.json` line 433, UID `C0KQnyxRDxDDy3Kh8` opens at `18:16:10.546520Z`, carries `2,150,225` originator bytes, and closes at `18:16:40.482412Z` with state `SF`. Application syslog lines 240–245 show the same source address and port, public-key acceptance at `18:16:16.109611Z`, PAM session opening, and closure at `18:16:42.891310Z`. The target file creation appears near transfer completion at `18:16:41.209Z`. Small differences between sensor and endpoint timestamps are compatible with the observed collection layers; they do not establish an impossible dependency.

The database shell history includes a gzip command between dump and SCP, while the normalized process records inspected do not show a corresponding gzip creation. I did not score that absence: the supplied evidence does not establish exhaustive process collection, and the history itself provides a plausible compression action.

### Upload and pivot feasibility

The Linux support command uses `--form` with a JSON metadata part and a gzip diagnostics file, explicit proxy configuration, and a case-specific attachment URI. Zeek records the same method and URI on both the client-to-proxy and proxy-to-origin legs. The client-facing connection has `1,573,700` originator bytes, accommodating its `1,573,258`-byte HTTP body. It remains open until approximately `16:32:50Z`, after the endpoint file read at `16:32:30.014Z`; there is no read-after-transfer contradiction.

The reconstructed remote logins with matching visible TCP/22 or TCP/3389 tuples occur inside successful transport intervals. Some late-window logins have no corresponding completed Zeek row in this slice. I did not count those as defects because ongoing connections may be logged outside the visible window. Likewise, a Windows unlock event reusing an existing logon ID is not a new initiating session; processes preceding that unlock are not an authentication-order violation.

### Mac behavior and evidence boundaries

The strongest concern is how document access is performed on `MAC-MROSS-02`. Seven observed reads of PDF/XLSX/DOCX content all use `cat`, distributed across several mounted shares and several hours. Endpoint Security line 32 confirms `/bin/cat` execution for the first PDF at `13:37:11.214478Z`; analogous executions precede the later document reads. This concentration suggests a generic file-read behavior template, although byte inspection, streaming, troubleshooting, or scripting could produce such commands in production. It is insufficient to support a hard-contradiction finding.

By comparison, `MAC-MROSS-01` uses `cat` on a JSON manifest and system text files, which is behaviorally natural. The distinction makes the binary-document pattern more specific than a general objection to shell usage on Macs.

I treated the `MeetingAssist` AppleSystemPolicy message at `15:42:09.009673Z` as a policy observation. I did not infer successful execution or downstream effects from it. Similarly, visible LaunchDaemon plist placement and later deletion establish file operations, not registration or activation. The narrow Unified Log and Endpoint Security event selections were not themselves penalized.

### Broader consistency checks

Across the eCAR records, checks of visible process identities against their creation and termination boundaries found no referenced process action clearly preceding its creation or following its termination beyond a 100 ms comparison margin. HTTP request and response body sizes did not exceed the corresponding connection-direction payload counters in any of the three Zeek datasets. No Windows logon ID was observed assigned to different target accounts on the same host in the parsed 4624 events.

These checks support internal consistency but cannot prove production origin. Complete cross-source alignment is not treated as suspicious. I also did not score sanitized names, filesystem modification times, intrusion narrative shape, selected Sysmon event omissions, or absent out-of-window state.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | Mac normalized endpoint file/process telemetry, corroborated by native Endpoint Security | Seven of nine visible file reads on MAC-MROSS-02 use `cat` against PDF/XLSX/DOCX files across multiple shares | Raises doubt about activity selection and command diversity; localized and technically possible, so it supports uncertainty rather than a synthetic verdict |

No demonstrated hard contradiction was found. The score of 47 reflects mixed but slightly production-leaning evidence, not a 47% confidence in the assessment. Verdict confidence of 76 expresses confidence that the supplied observations are insufficient for a reliable binary attribution.

## Realism Score by Category

- **Field format accuracy:** 9 — Parsed Windows XML and structured network/endpoint records support useful native-field pivots; no decisive field impossibility was established.
- **Temporal patterns:** 8 — Tested transports, authentication, file reads, and process exits generally maintain viable ordering and varied durations.
- **Cross-source correlation:** 9 — Independent endpoint, syslog, Zeek, and proxy views agree on tested operations without a demonstrated causal contradiction.
- **Behavioral realism:** 6 — Tradecraft and administration are credible, but repeated `cat` reads of binary documents create a localized command-selection concern.
- **Environmental consistency:** 8 — Host roles, network segments, remote identities, and source volumes are broadly compatible with the visible activity.

## Recommendations

- If this were synthetic, make the document-access behavior on `MAC-MROSS-02` depend on the intended activity and file format. Ordinary document viewing should produce evidence attributable to a suitable application or launch mechanism; shell-based streaming or inspection should retain its actual command behavior when that is the intended action.
- If this were synthetic, avoid routing every observed PDF/XLSX/DOCX read on one endpoint through the same generic `cat` pattern. Preserve legitimate shell use, but give the observed mix a concrete operational explanation or a broader set of activity-appropriate access methods.
