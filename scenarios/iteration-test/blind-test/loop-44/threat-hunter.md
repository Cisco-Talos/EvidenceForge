# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 78
**Synthetic-Confidence Score:** 54

## Executive Summary

The records support practical hunts across Windows, Linux, macOS, network sensors and an explicit web proxy, with substantial baseline traffic and generally coherent visible process lifecycles. A multipart upload has two notable timing problems: its curl process exits before the observed response and upload completion, and the proxy's outbound file finishes before the corresponding inbound file on the same sensor. Those findings make the data appear mixed, but they are concentrated in one transaction and do not justify calling the entire collection confidently synthetic.

## Evidence For Synthetic

- [contract_gap] **The multipart upload's client lifecycle ends prematurely.** In `WS-LNGUYEN-01.meridianhcs.local/ecar.json`, line 403 creates curl PID `2977788`, process UUID `d1ec5f45-2064-41ea-80ab-d7f9a5ae634c`, at `16:32:15.474Z`, with an explicit multipart POST for `mhs-support-48217.tar.gz` to the ticket attachment API. Line 407 reads that artifact at `16:32:38.200Z`; line 408 terminates the same process at `16:32:38.417Z`. The matched client-to-proxy transaction in `zeek-core/http.json:1253`, UID `CkMEGqZpKuNZYlIGep`, has gzip FUID `FG9lzWRMGtshLu2GRt`; `zeek-core/files.json:378` places that file's last observation at `16:32:42.881755Z` (`ts + duration`), while its HTTP response file starts at `16:32:42.719877Z` in line 379. A normal foreground curl transfer waits for the HTTP response. Kernel transmission after process exit can explain some remaining TCP activity, so the connection's later close alone is not the finding; the combination of process exit, extended upload observation and response availability is the discrepancy. No exit reason or documented clock correction is supplied, so this is a timing contract concern, not a proved impossible process execution.
- [contract_gap] **The corresponding proxy relay has inverted file-completion timing within one Zeek sensor.** `zeek-dmz/http.json:1416-1417` joins the client request (`10.10.1.21:40107 -> 10.10.3.20:8080`, UID `CBC8jpjlK5VDBsA5gA`) and its upstream request (`10.10.3.20:51963 -> 52.44.186.73:80`, UID `Cs9x3O9B2Lq3RpJiCih`) by host, attachment URI, method, body length and multipart filenames. `zeek-dmz/files.json:1013` observes the incoming gzip from `16:32:38.005741Z` for `4.999294` seconds, ending `16:32:43.005035Z`. Line 1012 observes the outgoing gzip from `16:32:37.976055Z` for `4.138482` seconds, ending `16:32:42.114537Z`. Both identify `mhs-support-48217.tar.gz`, `seen_bytes=1572864`, `missing_bytes=0`. The outgoing copy therefore finishes **0.890498 seconds before** the incoming copy. Streaming can overlap the two transfers, but cannot normally forward the final byte before receiving it. The absence of a content hash and possible unusual multi-interface timestamp behavior limit certainty; this remains a strong, localized relay-timing concern.

## Evidence For Real

- **Substantial, varied background traffic.** There are 23 endpoint exports, 35,807 normalized endpoint rows, 19,030 Windows Security events, 11,785 Sysmon events, 3,861 Linux syslog rows and 22,148 Zeek connections across three sensors. Endpoint volumes vary substantially: `DC-01` has 5,859 normalized rows, `PROXY-01` 5,568, `WEB-EXT-01` 3,960 and `LT-MRIVERA-02` 258. This is a credible role-dependent distribution, not a common fixed event budget on every host.
- **A usable SSH pivot across actual platform boundaries.** `MAC-MROSS-01.meridianhcs.local/ecar.json:428-429` shows PID `69947` fork and then exec `/usr/bin/ssh maya.ross@APP-INT-01.meridianhcs.local` at `17:01:26.762-26.763Z`. Line 432 shows outbound TCP `10.10.1.41:56813 -> 10.10.2.30:22` at `17:01:35.859Z`. `APP-INT-01.meridianhcs.local/ecar.json:406` shows the inbound tuple at `17:01:36.190Z`, before its session login at line 409 (`17:01:46.263Z`) and shell creation at line 410 (`17:01:47.702Z`). Native syslog lines 171-174 independently show connection, accepted password, PAM session opening and logind session `378050` in the correct order.
- **Windows directory-account effects have meaningful state transitions.** In `DC-01.meridianhcs.local/windows_event_security.xml`, the account-create event at `17:15:19.2242501Z` (timestamp line 195850) gives `svc_dirsync` SID ending `2456` and `NewUacValue=0x15`. Password reset follows at `17:15:20.5654052Z` (line 195948); account change at `17:15:22.3256574Z` (line 196025) changes `0x15 -> 0x10`; group membership addition at `17:15:31.4047722Z` (line 196416) links the same member SID to the Domain Admins SID ending `512`. Deletion at `18:49:53.4619920Z` (line 279094) retains the same target SID. The initial account-state flags are therefore not an unexplained disabled-account contradiction.
- **Process identities hold up under visible-window checks.** Across the ten Sysmon exports, grouping `ProcessGuid` with `ProcessId` and `Image` found no identity conflicts. Comparing visible Event 5 `UtcTime` with later same-GUID activity found no post-exit events or children created after their same-GUID parent exited. A corresponding normalized-endpoint check found no actor-UUID activity more than one second after its visible termination. This is positive lifecycle evidence, not proof of production origin.
- **Loss is represented in internally interpretable terms.** For example, the upstream attachment response in `zeek-dmz/files.json:1014` has `seen_bytes=95`, `total_bytes=96`, `missing_bytes=1`, consistent with the upstream HTTP row's 95 observed response-body bytes and the corresponding downstream observation of 96 bytes. Different byte counts here need not mean the proxy changed the payload.
- **The macOS records distinguish kinds of evidence.** The exports expose fork/exec identities, audit tokens and native-looking notification structures separately from normalized endpoint rows and shell history. `MAC-MROSS-01.meridianhcs.local/macos_unified_log.ndjson:2` is an AppleSystemPolicy message about `MeetingAssist` at `15:42:11.450696Z`; I did not find a matching successful exec of that application in the supplied ES records. Treating this as a policy-related observation without inventing successful execution avoids a false attack trail.

## Detailed Analysis

### Scope, collection and method

I examined only the supplied data directory and the provided reviewer briefing. The directory contains 117 files, with ten Windows endpoints exporting Security/Sysmon XML, eleven Linux endpoints exporting syslog, two Macs exporting Endpoint Security and Unified Log records, normalized endpoint telemetry on all 23 systems, shell histories, Zeek at core/database/DMZ locations, proxy and web access logs, firewall records and IDS alerts.

The observed working window is approximately `2026-11-02 13:00-19:00 UTC`. The visible network distinguishes workstation addresses in `10.10.1.0/24`, server addresses in `10.10.2.0/24` and DMZ/proxy addresses in `10.10.3.0/24`. These are inferred scopes, not claims that the export contains every host or account in the organization. I did not infer an absent auditing facility from an absent file.

The examination combined source inventory, record counts, complete JSON/XML parsing for selected invariants, process-identity/lifetime checks, network-accounting checks and detailed manual pivots through selected operational sequences. All line references are one-based in the supplied files. Windows XML references identify the event's `TimeCreated` line; the event ID and named fields are in its enclosing `<Event>`.

### Hunting sequence: public-facing web execution

`WEB-EXT-01.meridianhcs.local/ecar.json:840` shows a `www-data` bash process, PID `2702825`, parent `/usr/sbin/apache2` PID `23966`, at `14:20:06.317Z`. The command decodes a shell instruction containing `/dev/tcp/45.33.32.30/8443`. `zeek-dmz/conn.json:1625` observes `10.10.3.10:41647 -> 45.33.32.30:8443` at `14:20:09.585467Z`, with a successful TCP session lasting `29.415661` seconds and bidirectional bytes. The process terminates at `14:20:59.504Z` in endpoint line 843, after the observed transport interval.

This is suspicious execution with a feasible network effect. I would investigate it, but the fact that it is easy to recognize is not an authenticity indicator. The command, parent ownership, flow direction and visible lifetime do not produce a concrete contradiction in this example. I also do not require every shell pipeline stage to be present in a filtered normalized endpoint export.

### Hunting sequence: Windows privilege and persistence effects

The `svc_dirsync` sequence permits useful pivots from process command lines to account-state events and persistent SID identity. Endpoint `DC-01/ecar.json:3978` shows the SYSTEM `cmd.exe` command that creates the account; line 3985 shows its `net.exe` child. Native Security records then show creation, password reset, account enabling and membership modification, rather than simply substituting one generic success event.

The collection also contains a `PSEXESVC` service-install event at `17:00:21.9994534Z` in the same host's Security XML (timestamp line 183755), with `aisha.johnson` as the subject, domain-account SID and a Type 3 session identifier. I treat this as evidence of suspicious remote administration. I do not infer that every later SYSTEM process was launched by that service solely because both are suspicious; provenance must come from the process/session identities.

The directory-account sequence's compactness and eventual account deletion are neutral for authenticity. The meaningful positive evidence is the consistent SID and intervening state changes, while the meaningful limitation is that logs show actions and effects, not the operator's intent.

### Hunting sequence: multipart support upload

The upload is where the strongest authenticity concerns arise. `WS-LNGUYEN-01/ecar.json:399-402` shows tar creation, archive artifact creation and tar termination before the curl action. This is a plausible support workflow; ticket names and domains may be sanitized, and I do not classify a support upload as exfiltration simply because it moves an archive externally.

The transfer can be followed through the explicit proxy using all of these pivots:

| Evidence | Identity and visible fact |
|---|---|
| Endpoint line 403 | curl PID `2977788`, UUID `d1ec5f45-2064-41ea-80ab-d7f9a5ae634c`; exact multipart command and archive path |
| Endpoint line 407 | Same process reads the archive at `16:32:38.200Z` |
| Endpoint line 408 | Same process terminates at `16:32:38.417Z` |
| Core connection line 7723 | Client-to-proxy UID `CkMEGqZpKuNZYlIGep`, tuple `10.10.1.21:40107 -> 10.10.3.20:8080` |
| Core HTTP line 1253 | POST, ticket attachment URI, `request_body_len=1573258`, metadata and gzip FUIds, status 200 |
| Proxy access line 2017 | Same client/user/URI, status 200, `cs_bytes=1573516`, `wire_sc_bytes=338`, `proxy_action=forward` |
| DMZ HTTP lines 1416-1417 | Client-side absolute URI becomes upstream origin-form URI, with separate transport UIDs |
| DMZ files lines 1012-1013 | Matching named gzip object and byte count, but inverted completion times |

The archive byte count is smaller than the multipart body, which is smaller than the wire request accounting. Those differences are sensible: they are not byte-equality defects. The response-loss accounting is also interpretable. The problems are temporal ownership and relay ordering.

For reproducibility, the key calculations are:

- Incoming gzip completion: `1793637158.005741 + 4.999294 = 1793637163.005035`.
- Outgoing gzip completion: `1793637157.976055 + 4.138482 = 1793637162.114537`.
- Incoming completion minus outgoing completion: `0.890498` seconds.
- Core gzip completion minus endpoint curl termination: `(1793637158.137174 + 4.744581) - 1793637158.417 = 4.464755` seconds.
- Core response-file start minus curl termination: `1793637162.719877 - 1793637158.417 = 4.302877` seconds.

I checked other identifiable POST relay pairs on the DMZ sensor by matching method, host, body length and timestamps within two seconds, then matching original-direction files by MIME and observed byte count. Eight file-part pairs matched, including this transaction's two parts. This archive was the only matched pair whose outgoing completion preceded incoming completion by more than 0.1 seconds. Thus this is localized evidence, not a demonstrated fleet-wide timing fingerprint.

A process can be killed after sending a request, and TCP can drain buffered bytes after process exit; a server can also issue an early response. These alternatives prevent treating the endpoint timing alone as an absolute impossibility. However, they do not naturally explain the same-sensor full-file forwarding inversion. Packet-level capture, exit status and capture-interface timing details would help distinguish an export/collection artifact from synthetic scheduling.

### Baseline and lifetime checks

The source mixture has credible operational variety: machines and service identities contacting domain controllers, routine SSH, cron/sysstat, service startup noise, endpoint process/module evidence, web/proxy traffic, SMB activity and network loss. I did not penalize selected Sysmon coverage, missing out-of-window initiators, surviving sessions, or complete cross-source matches.

All 22,148 Zeek connection rows passed simple accounting checks that payload bytes did not exceed corresponding IP bytes, and positive packet counts had at least a minimum IPv4-header byte budget. No TCP `SF` row had zero responder packets. These are limited checks: they rule out easy accounting mistakes but do not certify packet-level realism.

The visible Windows process checks were deliberately identity-based, not based on a PID alone, to avoid conflating PID reuse with activity after exit. Likewise, I did not flag session openings or closings outside this six-hour slice. The notable upload finding survives those restrictions because its initiating process, archive read, termination, request, file transfer and response all occur inside the window.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on synthetic-confidence score |
|---|---|---|---|
| `contract_gap` | Endpoint process/file telemetry versus Zeek HTTP/files | One multipart attachment upload on `WS-LNGUYEN-01` | Normal foreground curl exits about 4.3 seconds before the observed response starts; moderate concern after allowing for termination and clock alternatives. |
| `contract_gap` | Zeek DMZ files across explicit proxy ingress/egress | The same named 1,572,864-byte gzip part, two linked HTTP transactions | Outgoing file completes 0.890498 seconds before incoming completion on one sensor; strongest localized synthetic/collection-timing indicator. |

These are related findings in one activity, not two independent dataset-wide fingerprints. I found no defensible hard contradiction in the visible process identity checks and no basis for scoring narrative linearity, matching completeness or thin source coverage.

## Realism Score by Category

- **Field format accuracy:** 9 — Parsed source structures and identity fields support useful pivots; byte-loss accounting is interpretable.
- **Temporal patterns:** 6 — Broad visible lifetimes are coherent, but the attachment relay and client completion have meaningful timing defects.
- **Cross-source correlation:** 7 — Tuples, archive identities, process UUIDs, account SIDs and SSH session details join well; the upload's correlated timestamps weaken causal trust.
- **Behavioral realism:** 8 — Commands and observed effects generally fit the respective platforms and workflows; suspicious and routine activities both exist.
- **Environmental consistency:** 8 — Role-dependent volume and segmented network observations are plausible for the exported fleet and six-hour window.

## Recommendations

- If this were synthetic, coordinate multipart client execution, input-file reading, upload completion and response reception before scheduling successful foreground curl termination. If premature termination is intended, retain its cause and model resulting transport/response behavior coherently.
- If this were synthetic, derive both proxy-side file intervals from one shared byte-transfer chronology. Allow streaming overlap while ensuring corresponding outbound final bytes cannot precede their inbound availability; apply collection timing consistently afterward.
- If this were synthetic, preserve the existing role-dependent baseline volumes, separate proxy-hop UIDs, multipart overhead, loss accounting, identity-stable Windows account changes and ordered SSH session evidence. The demonstrated issue calls for focused timing correction, not for adding unrelated telemetry or artificial mistakes.
