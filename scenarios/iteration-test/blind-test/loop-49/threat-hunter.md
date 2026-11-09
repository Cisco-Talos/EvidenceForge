# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 82
**Synthetic-Confidence Score:** 46

## Executive Summary

The data supports useful, technically coherent hunts across Windows, Linux, macOS, network sensors, and an explicit proxy. Two independently identifiable Chrome network processes nevertheless carry Safari or Edge identities on their exact network tuples; these are concrete correlation discrepancies, but user-agent overrides provide a real-world alternative explanation. I found no demonstrated impossible same-identity lifecycle ordering, so the evidence supports a mixed assessment rather than a confident synthetic verdict.

## Evidence For Synthetic

- [contract_gap] **Chrome process, Safari request identity on MAC-MROSS-01.** `MAC-MROSS-01.meridianhcs.local/ecar.json:36` assigns `10.10.1.41:65241 -> 10.10.3.20:8080` to PID `42890`, a Google Chrome NetworkService helper. `zeek-core/conn.json:472` supplies UID `CzGkkmDBo7E5CDmYjR`; `zeek-core/http.json:69` records that same tuple/UID at `13:15:58.760352Z` with `AppleWebKit/605.1.15 ... Version/26.0 Safari/605.1.15`, without a Chrome token. The proxy independently records the Safari string at `proxy_access.log:115`. Native ES confirms the helper's executable and arguments at `macos_endpoint_security.ndjson:25`. This is not an inference from a host name or an arbitrary other request from that IP.
- [contract_gap] **Chrome process, Edge request identity on MAC-MROSS-02.** `MAC-MROSS-02.meridianhcs.local/ecar.json:59` assigns `10.10.1.42:63949 -> 10.10.3.20:8080` to PID `20423`, another Google Chrome NetworkService helper. `zeek-core/conn.json:965` and `zeek-core/http.json:184` identify UID `CR90Q5PxqndDaKTSHj`; the latter has `Chrome/155.0.0.0 ... Edg/155.0.0.0` at `13:28:51.448030Z`. The same Edge string occurs in `proxy_access.log:282`, and native ES establishes the Google Chrome helper at `macos_endpoint_security.ndjson:30`. This repeats the browser-ownership discrepancy on a second host. These are two activities, not four findings merely because two sensors observe each activity.
- [weak_signal] **One very long identity lookup relative to the same host's other observations.** On MAC-MROSS-01, native ES lines `82–83` show PID `64542` executing `/usr/bin/id` at `16:03:58.660391Z` and exiting successfully at `16:05:26.788371Z`, an elapsed `88.128` seconds. Other visible `/usr/bin/id` executions on this host take approximately `0.150` and `0.296` seconds. Directory-service delays can explain this; it has little independent weight and is not an impossible-duration claim.

## Evidence For Real

- **Credential boundaries survive the pivots.** In `WS-AJOHNSON-01.meridianhcs.local/windows_event_security.xml`, EventRecordID `131022` near line `24284` records Event `4648`: local subject `aisha.johnson`, alternate credentials `marcus.chen`, and `runas.exe` PID `0x1838`. Record `131023` near line `24326` then records Type `9` with local `TargetUserName=aisha.johnson`, `TargetOutboundUserName=marcus.chen`, and new logon ID `0x27cb085`. The subsequent command process and file-access activity retain the local identity. Treating those two names as a contradiction would misread network-only credentials.
- **The database-to-application-to-file-server trail has usable ownership and transport pivots.** DB-PROD creates a dump, compresses it, and reads the compressed artifact through the SCP process. The receiving host opens an SSH session for the matching source tuple, observes the destination file, and later reads it using an SMB client with a separately specified remote account. Relevant rows are detailed below.
- **Denied traffic behaves as denied traffic in the examined joins.** An exact tuple/time join of ASA `106023` deny messages to supplied Zeek connections found `324` sensor observations within five seconds, all in `S0`; none had the successful bidirectional `SF` transfer that would contradict the deny. This is positive consistency evidence, not a demand that every deny have a sensor companion.
- **HTTP volume fits its transport accounting in the examined records.** Across the three supplied Zeek sensors, no individual logged HTTP request or response body exceeded its associated connection's directional payload-byte total. No HTTP transaction timestamp lay more than `0.1` seconds outside the connection interval. This check has limits, but it avoids obvious impossible upload accounting.
- **Native macOS process identity is internally coherent.** Across the two ES files, observed snapshots sharing a PID and pidversion did not disagree about executable identity, and a PID's recorded process start time remained consistent. The launchd/xpcproxy/application, login/shell, and SSH process chains carry distinct fork/exec identities rather than collapsing all phases into a single process creation.
- **The environment has meaningful background variation.** There are substantial DNS, Kerberos, LDAP, proxy, database, SMTP, SMB, failed-connect, and routine endpoint records. For example, the core sensor has `12,314` connections, including `1,897 S0`, `150 RSTO`, and `116 RSTR` observations. This is not a dataset composed solely of successful suspicious transfers.

## Detailed Analysis

**Input provenance and scope.** I read `/private/tmp/log-study-pdlkpnp9/threat-prompt.md` and examined only its supplied data directory for dataset evidence. The inventory contains `117` files and `23` endpoint directories with eCAR data, including ten Windows endpoint families, eleven Linux/syslog endpoint families, and two macOS endpoint families; there are also three Zeek sensors, two Snort collections, and one ASA collection. The `35,805` eCAR records cover approximately `2026-11-02 13:00:00Z–18:59:58Z`. They include `40` distinct principal strings, a count that mixes users and service/system identities rather than counting human users. The visible address ranges include client `10.10.1.0/24`, internal/server `10.10.2.0/24`, DMZ `10.10.3.0/24`, and database `10.10.4.0/24` activity.

All supplied files were loaded for inventory/line counts. My substantive checks included full eCAR scans, Windows Sysmon XML parsing, selected Windows Security event inspection, Zeek connection/HTTP joins, ASA deny joins, shell histories, and selected syslog, SMTP, IDS, proxy, and native macOS records. I did not inspect repository files, authored scenarios, implementation code, project worklogs, prior assessments, or another reviewer's output. Inherited operating instructions and project-related task metadata are an unavoidable blinding limitation; I did not use them as evidence of origin. External consultation used actual domain-filtered searches restricted to Microsoft, Chrome, and Samba primary documentation. No logged command was executed.

**High-interest Windows trail.** At `18:01:10.062Z`, `WS-AJOHNSON-01/ecar.json:1006` records the alternate-credential launcher. Rows `1017`, `1025`, `1036`, `1053`, `1062`, and `1075` then expose the new command process, directory preparation, share enumeration, research-file copying, and archive process. The distinction between metadata enumeration and copying matters: a `Get-ChildItem` invocation alone does not prove a file's contents were staged. The visible copying operation is stronger evidence than enumeration, and local process identity need not equal the outbound SMB account.

At `18:24:36.004Z`, row `1131` starts the proxy-aware upload process; row `1138` reads `C:\ProgramData\Microsoft\cache_7f3a.zip`. The explicit proxy records the HTTPS POST at `PROXY-01/proxy_access.log:3231`, including `ssl-inspect`, `ssl_bump=bump`, client source port `56429`, request bytes `18,782,968`, and response status `200`. This supports a feasible investigation pivot into a large outbound transfer. It does not, by itself, establish the sensitivity or authorization status of its contents.

**High-interest Linux trail.** `DB-PROD-01/ecar.json:528–539` shows a root SSH login from `10.10.2.30`, the root shell, dump process, dump artifact, compression, SCP process, compressed-file read, and process exits. The dump starts at `18:15:22.996Z`; the compressed artifact appears at `18:15:57.196Z`; SCP begins at `18:16:05.208Z`. The source file is read at `18:16:15.092Z`.

The SCP transport is `10.10.4.10:58586 -> 10.10.2.30:22`: `zeek-core/conn.json:11098` records UID `CdGaeB9qSEac4wswIt`, a `34.180338` second successful connection with `77,785` originator payload bytes. `zeek-db/conn.json:385` observes the same tuple with its own sensor UID and close timing. `APP-INT-01/ecar.json:776–780` records the target-side process, root login using source port `58586`, receiving-file evidence, termination, and logout. Different source-observation timestamps around transport close are not automatically proof that data was written after a physical connection ceased.

`APP-INT-01/ecar.json:781–784` subsequently associates the received file with an SMB client whose local principal is root and whose requested SMB identity is `svc_mhsync`. `zeek-core/smb_files.json:215–216` records the corresponding destination `Integration\DB-Staging\rpt_0318.sql.gz` on `FILE-LNX-01\ClinicalResearch`, including a `57,275` byte write. Local root and a remote service-account identity are compatible. This chain is suspicious and huntable, while remaining technically feasible on the evidence inspected.

**Distinguishing a support upload from the other trails.** The Lina Nguyen history and `WS-LNGUYEN-01/ecar.json:399,403` show creation of a diagnostics archive and a multipart support submission. `zeek-core/http.json:1253` records a plaintext-proxy POST with `1,573,258` request-body bytes and both JSON and gzip MIME components; `PROXY-01/proxy_access.log:2017` records the same ticket path and a `200` response. This is a separate transfer whose visible arguments are compatible with support diagnostics. Its presence contributes meaningful competing activity; I have not classified it as malicious merely because it uploads an archive.

**Browser attribution finding and its limits.** The two browser findings use the endpoint's process-bound FLOW tuple, matching Zeek connection and HTTP records, and corroborating native ES executable snapshots. The comparison therefore survives the obvious alternative that a different browser on the same host sent an unrelated request. Microsoft's documentation identifies the desktop `Edg` token with Edge, supporting the second classification. [Microsoft user-agent guidance](https://learn.microsoft.com/en-us/microsoft-edge/web-platform/user-agent-guidance).

However, Chrome explicitly supports overriding its user agent to represent other browsers. A website test or compatibility workaround could explain both records without any impossible OS behavior. I therefore classify these as moderate contract gaps rather than hard contradictions. [Chrome user-agent overrides](https://developer.chrome.com/docs/devtools/device-mode/override-user-agent). A broader join found `1,658` browser-process/HTTP sensor matches, with four mismatching sensor observations representing these two activities; most examined browser associations were consistent. That denominator limits how far the discrepancy should move the score.

**Lifecycle and collection checks.** A scan of all eCAR records found no actor-linked occurrence more than one second before its visible actor process creation or more than one second after its visible actor termination. This is a bounded check of the available actor links, not proof of every process relationship. Missing pre-window initiators, surviving post-window sessions, selected Sysmon coverage, and thin native macOS Unified Log coverage were not scored as defects.

The `MeetingAssist` policy message in `MAC-MROSS-01/macos_unified_log.ndjson:2` at `15:42:11.450696Z` was not treated as proof of execution, child execution, or successful installation. Likewise, similar copied-file timestamps, sanitized destinations, comprehensible activity sequences, and complete correlations contributed nothing to the synthetic score.

**Other observations that did not earn strong authenticity weight.** Several Linux commands ask about `smb-client`/`smbclient`/`cifs-utils` as service-unit names, including `APP-INT-01/syslog.log:15` and `WS-OHADDAD-01/syslog.log:32`. Samba documents smbclient as a command-line SMB client. [Samba smbclient manual](https://www.samba.org/samba/docs/current/man-html/smbclient.1.html). But a user can legitimately issue an unsuccessful status query, and custom units can exist; no supplied successful service-status result establishes an environmental contradiction. I did not treat these attempted commands as hard software-placement errors.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on synthetic-confidence score |
|---|---|---|---|
| contract_gap | macOS ES/eCAR, Zeek HTTP/connection, proxy | One MAC-MROSS-01 Chrome-owned connection identifies as Safari | Moderate: exact tuple disagrees with ordinary browser identity; override remains possible |
| contract_gap | macOS ES/eCAR, Zeek HTTP/connection, proxy | One MAC-MROSS-02 Chrome-owned connection identifies as Edge | Moderate: recurrence on a second host; same failure class, not an independent impossible behavior |
| weak_signal | Native macOS ES process lifecycle | One `/usr/bin/id` run lasts 88.128 seconds | Small: anomalous relative to peer executions, but directory-service blocking is plausible |

No hard contradiction or generator identity leak was established. The score remains in the mixed/inconclusive band because the strongest issues have credible production explanations and occur amid predominantly coherent inspected relationships.

## Realism Score by Category

- **Field format accuracy:** 9 — Structured records parse and support native and normalized pivots; no demonstrated native schema violation.
- **Temporal patterns:** 8 — Visible lifecycles largely work; one identity-command runtime is a substantial outlier.
- **Cross-source correlation:** 8 — Strong account, file, transport, and proxy pivots, with two browser-identity gaps.
- **Behavioral realism:** 8 — Administrative and support activity competes with suspicious activity; the examined sensitive workflows technically fit together.
- **Environmental consistency:** 8 — Host roles, protocols, and account namespaces generally agree; browser attribution remains an unresolved exception.

## Recommendations

- If this were synthetic, preserve a common browser identity across executable ownership and HTTP user-agent generation for the two cited tuples. If user-agent spoofing is intentional, retain it as a deliberate exceptional behavior with coherent surrounding evidence rather than allowing an independent browser choice on each source.
- If this were synthetic, give an 88-second identity lookup an environmental cause when such a delay is intended; otherwise use the short-duration behavior already visible for the same binary on that host. Do not indiscriminately shorten genuine directory-service timeouts.
- Preserve the working distinctions among local credentials, outbound network credentials, transfer processes, received-file artifacts, and sensor-specific observations. The inspected hunt paths benefit from those distinctions; adding unrelated log sources or making every correlation exact would not address the identified issues.
