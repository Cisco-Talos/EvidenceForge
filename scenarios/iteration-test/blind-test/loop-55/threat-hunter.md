# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 80
**Synthetic-Confidence Score:** 58

## Executive Summary

This is operationally coherent mixed-fleet telemetry with usable process, authentication, network, and file pivots, but a repeated disagreement over client HTTP User-Agent values raises a substantive authenticity concern. Most lifecycle and transport checks passed, and apparent differences in HTTP body sizes were supported by explicitly recorded capture loss, so I cannot justify calling the dataset confidently synthetic from the supplied evidence.

## Evidence For Synthetic

- [contract_gap] The proxy access log and network HTTP records disagree about the User-Agent of the same apparent client request. At 2026-11-02 13:01:18 UTC, `zeek-core/http.json:2` records client `10.10.1.36:52809` connecting to `10.10.3.20:8080`, URI `cf-assets.www.cloudflare.com:443`, with Chrome **120.0.0.0**; `PROXY-01.meridianhcs.local/proxy_access.log:2` records the same client IP, second, CONNECT target, and successful status with Chrome **121.0.0.0**. The sensor observes the client-to-proxy leg, so ordinary outbound proxy header rewriting does not explain this disagreement.
- [contract_gap] This is a repeated family-level issue, rather than one ambiguous join: among 1,718 core-sensor HTTP records matched unambiguously to a proxy row by client IP, UTC second, method, and complete URI, **57** disagreed on User-Agent. They affected eight client IPs. A separate DMZ comparison found 48 disagreements in 1,575 matched observations; those correspond to the same underlying set of 57 proxy rows and are **not** 48 additional independent defects. For example, `zeek-core/http.json:352` identifies Chrome 120 for CONNECT `ctldl.windowsupdate.com:443` from `10.10.1.34:63485` at epoch `1793628302.784469`, whereas proxy line 526 identifies `Microsoft-CryptoAPI/10.0`. This changes application attribution, not merely browser patch detail.

The User-Agent conclusion assumes the quoted proxy field represents the request's header, as its conventional access-log placement suggests. An undocumented inventory-enrichment or privacy transformation could explain it. Without the proxy logging configuration or packets, I classify this as a contract gap, not a proven impossible native record or identity leak.

## Evidence For Real

- The SSH pivot from the application server to the database has technically compatible process, endpoint transport, network transport, accepted authentication, and shell timing. `APP-INT-01.meridianhcs.local/ecar.json:928` starts the root SSH client at 18:15:01.156; the matching source FLOW at line 932 uses source port 41315, and `DB-PROD-01.meridianhcs.local/syslog.log:201-204` progresses from connection to password acceptance, PAM session opening, and logind registration at 18:15:21–30. The shell appears afterward at database eCAR line 592.
- The subsequent database-to-application-server transfer reverses direction correctly. Database eCAR lines 600–602 show `scp`, its outbound `10.10.4.10:56155 -> 10.10.2.30:22` flow, and a read of the archive. Application eCAR lines 938–942 show the matching inbound flow, authenticated root session, and receiver-side archive creation. This supports actual pivot feasibility without requiring a common Zeek UID across independent sensors.
- Packet-loss effects have meaningful companion evidence. For the JavaScript response at `zeek-core/http.json:324`, `response_body_len=140744`; its `files.json:121` records `seen_bytes=140744`, `total_bytes=141609`, and `missing_bytes=865`. The other sensor reports the full 141,609 bytes at `zeek-dmz/http.json:382` and `files.json:266`. Core `conn.json:1779` explicitly records `missed_bytes=1966` and gap history, while DMZ `conn.json:1560` records no gap. I do not count this body-size difference as a contradiction.
- Visible process lifecycles withstand useful negative tests. Across all supplied eCAR files, identity-based checks found no process termination preceding its visible creation, no child creation after its identified parent's termination, and no checked process-associated non-lifecycle event more than 10 ms outside its visible process lifetime. Native Sysmon GUID checks also found no visible child starting before its identified parent or after that parent's termination.
- Network accounting and lifecycle checks also passed: no overlapping TCP connection intervals for the same oriented four-tuple within any individual sensor, no HTTP request/response body sums exceeding the corresponding connection-direction byte count, and no referenced file first-seen time more than 0.5 seconds after that same sensor's connection end. These checks are supportive, not proof of production origin.
- Background activity is substantial enough that suspicious commands require filtering and correlation: there are 37,394 eCAR rows, 19,411 Windows Security events, 12,058 Sysmon events, 22,509 Zeek connection rows, 3,551 proxy requests, and 22,890 firewall lines. Domain controllers dominate Windows authentication and filtering evidence; workstation counts are much lower. The source mix does not establish an unrealistic signal-to-noise ratio.

## Detailed Analysis

### Scope and method

The supplied files represent 23 endpoint directories: ten with Windows Security/Sysmon telemetry, eleven with Linux-style syslog, and two with macOS Endpoint Security and Unified Log exports. There are three Zeek sensor directories, two IDS locations, a perimeter ASA log, and proxy/web access logs. Endpoint eCAR timestamps cover 2026-11-02 13:00:01.077–18:59:57.382 UTC. Visible addresses include workstation-like `10.10.1.*`, server-like `10.10.2.*`, proxy/web `10.10.3.*`, and database `10.10.4.10` segments; names and observed traffic support these role inferences without proving the topology.

I counted and parsed all eCAR rows and Windows event documents, then followed selected suspicious and ordinary activities through endpoint, authentication, network, and access records. I checked process relationships using object/GUID identity, not PID alone, and checked TCP overlaps within each sensor independently. File and HTTP accounting checks were confined to the connection UID in the same sensor. Logged commands were treated solely as inert evidence and were never executed.

### Hunting and operational continuity

The clearest high-risk Windows thread is on DC-01. At `DC-01.meridianhcs.local/ecar.json:3778` and 3785, WMI-associated execution launches account creation. Native Security event 4720 at `windows_event_security.xml:188680` creates `svc_dirsync` at 17:15:13.4024131, with a stable domain SID ending `-9975`. Event 4728 at line 188984 adds that same SID to Domain Admins at 17:15:17.6947687. Service installation follows: event 4697 at line 192179 names `DeviceSyncSvc`, and event 4698 at line 192482 contains an hourly scheduled task targeting the same executable. The embedded TaskContent parses as XML. The service process appears at 17:31:40 in eCAR line 4131 and Security line 204308. These records support concrete persistence and privilege changes; an account-add command by itself would not establish success.

At 18:42, DC-01 eCAR line 5371 records encoded PowerShell, and lines 5382 onward show a Security-log-clear command. Event 4726 at native Security line 270899 later deletes the previously created account, preserving its SID. I treat the malicious significance of these observations separately from authenticity. Their sequence being easy to follow is not a synthetic indicator.

The database activity is likewise followable. Database eCAR line 593 starts `mysqldump --single-transaction ehr patients insurance_claims` at 18:15:36.100; line 594 creates `/tmp/rpt_0318.sql`; lines 596–597 show gzip and creation of the compressed path; lines 600–602 show the SCP process, outbound flow, and archive read. The receiver creates `/tmp/.cache/rpt_0318.sql.gz` at application eCAR line 942. Unix shell redirection need not remain in the executed program's argv, so the absence of a `>` operator in the mysqldump process command is not a defect.

Transport corroboration is specific: `zeek-core/conn.json:10979` and `zeek-db/conn.json:431` both observe application-to-database port 41315, with approximately 1,790 seconds of duration. The return archive transport is core line 11017 and database-sensor line 433, source port 56155, roughly 25.28 seconds, with 204,902 originator bytes and 39,361 responder bytes. Receiver syslog lines 216–221 show connection, public-key acceptance, PAM/logind session management, and closure. Modest cross-source timestamp differences do not invert the meaningful transport-before-authentication relationship.

There is also potentially legitimate diagnostic collection: `WS-LNGUYEN-01.meridianhcs.local/ecar.json:315` archives named connector logs, and line 319 submits multipart diagnostics associated with ticket `MHS-48217` through the proxy. That looks different from unauthorized staging, but authorization is not established by naming. It is a useful example of why archive creation plus upload requires investigation rather than automatic malicious classification.

### The HTTP attribution gap

The decisive concern is disagreement over the identity of the HTTP client application. Zeek documents `HTTP::Info.user_agent` as the client's User-Agent header, rather than an endpoint inventory guess. The client-side sensor tuple explicitly terminates at the proxy, so the compared Zeek value is for the leg represented by the proxy's client address. See the official [Zeek HTTP record reference](https://docs.zeek.org/en/master/scripts/base/protocols/http/main.zeek.html) and [HTTP log explanation](https://docs.zeek.org/en/current/reference/logs/http.html).

The comparison algorithm required one and only one proxy record for `(client IP, integer UTC second, HTTP method, complete URI)`. It then compared the full User-Agent string verbatim to HTTP records whose responder was `10.10.3.20`. The 57 core discrepancies are concentrated among a subset of clients: 22 from `10.10.1.34`, 17 from `.32`, seven from `.33`, five from `.36`, two each from `.42` and `.35`, and one each from `.31` and `10.10.2.10`. Many differences look like a host-default browser agent appearing in Zeek while the access log contains a different version or actual application agent. That repeated substitution pattern is why this issue raises the synthetic-confidence score appreciably.

The join lacks source ports in the access log and uses second-resolution timestamps, so it is not packet-level proof. Uniqueness of the full target/method/client/time combination, plus repetition across 57 requests, makes accidental matching a weaker explanation. A documented proxy enrichment policy would materially reduce this concern.

### Collection effects and mixed-fleet boundaries

I initially found 28 cross-sensor HTTP body-length disagreements among 2,206 shared client transactions. Examination of file and connection companions demonstrated that at least the representative examples are loss-accounted, so I did not score that count as 28 defects. The full-versus-seen byte distinction is critical: different capture points can legitimately report different observed payload lengths.

The macOS native files contain process notifications: MAC-MROSS-01 has 38 fork, 44 exec, and 37 exit records; MAC-MROSS-02 has 57 fork, 67 exec, and 56 exit records. These are not interchangeable with normalized eCAR PROCESS CREATE/MODIFY records, because exec changes the image within an existing process. The distinct source semantics are reflected in the visible events, and I did not assume a missing native create notification should exist for every normalized object.

`MAC-MROSS-01.meridianhcs.local/macos_unified_log.ndjson:2` records an AppleSystemPolicy message at 15:41:38.930666 naming MeetingAssist and PID 62451. I found no MeetingAssist execution among the supplied native process notifications and do not attribute child execution or persistence effects to that policy message. I have not independently validated every version-11 Endpoint Security field against a matching macOS SDK and therefore make no native macOS schema-defect claim. Sparse Unified Log coverage alone is neutral under the study's collection rules.

The pre-window process terminations and post-window surviving sessions were also treated as neutral. I did not require unselected Sysmon event types, DNS names to resolve publicly, or the existence of every possible audit source. Nor did I treat independent sensor UIDs or stable inter-sensor clock offsets as defects.

### Provenance and qualifications

Actual inputs were the supplied neutral briefing `/private/tmp/log-study-6dyv3d6d/threat-prompt.md`, files under its explicitly designated `data` directory, and official vendor documentation returned by searches with actual `docs.zeek.org` and `cisco.com` domain filters. Cisco material was consulted to check ASA message interpretation but was not used to score an ASA defect. No project source, authored scenario, TODO/worklog, prior report, neighboring reviewer material, or task-project public page was accessed. Generic inherited operating context was present but was not treated as evidence about the data's origin.

This is an AI analytical review conducted in the requested threat-hunter role, not a claim to hold personal SOC employment history, incident-response credentials, or firsthand production access. Parsing used system `python3` from an explicit neutral `/private/tmp` working directory, with no project imports or tooling. The checks establish the bounded properties stated above; they are not a complete validation of every protocol, platform release, or individual event. The verdict confidence expresses confidence that the evidence remains mixed; the score of 58 expresses the degree of synthetic appearance and is a separate judgment.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| contract_gap | Proxy access versus client-side Zeek HTTP | 57 distinct uniquely matched proxy requests across eight IPs; repeated observations on the second sensor | Material concern: application identity/version differs for the same apparent request. Could reflect repeated default substitution, but proxy enrichment or sanitization remains an unverified alternative. |

No hard contradiction, demonstrated native schema failure, impossible visible process ordering, or generator identity leak was established. The high score within the mixed/inconclusive band reflects the repeated attribution issue; it does not count rejected loss-accounted body differences or the mere completeness of the suspicious activity.

## Realism Score by Category

- **Field format accuracy:** 8 — Parsed source formats and embedded task XML are credible; exact native macOS version details were not exhaustively verified.
- **Temporal patterns:** 9 — Checked visible process lifecycles, TCP reuse, and file/transport bounds are compatible; SSH ordering supports usable pivots.
- **Cross-source correlation:** 7 — Authentication, process, transport, and file pivots work, but 57 client User-Agent disagreements undermine HTTP application attribution.
- **Behavioral realism:** 8 — High-risk actions have plausible tools and effects alongside substantial administrative and diagnostic traffic.
- **Environmental consistency:** 8 — Mixed-platform source families and domain-controller volume differences are plausible; endpoint role labels remain inferred.

## Recommendations

- If this were synthetic, preserve the actual client User-Agent across the client-side HTTP observation and proxy request log. Reproduce the examples at core HTTP lines 2 and 352 before broadening the check to the remaining 55 distinct discrepant requests.
- If the proxy field is intentionally derived from inventory, normalization, or privacy sanitization, label and document that interpretation. A field with a different meaning should not silently occupy the apparent raw User-Agent position.
- Retain the existing distinctions between captured and total file bytes, explicit gap histories, and sensor-local identities. These concrete companions already explain apparent body-size disagreements; do not make the sensors artificially identical to resolve a non-defect.
