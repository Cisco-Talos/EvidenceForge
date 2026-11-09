# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 82
**Synthetic-Confidence Score:** 72

## Executive Summary

The clearest detection-engineering defect is in both macOS Endpoint Security exports: records for `fork` (event type 11) and `exit` (event type 15) carry `action_type: 1` and an authorization-result payload (`action.result.result.auth: 0`). Those event families are notifications, so this appears to serialize the wrong action union and would mislead or break a parser that distinguishes authorization decisions from notifications. Windows event samples and Zeek UID/reference joins were otherwise coherent; I found no comparably strong cross-source contradiction in the inspected records.

## Evidence For Synthetic

- [hard_contradiction] In `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson`, event records with `event_type: 11` contain `event.fork` but set `action_type` to `1` and `action.result.result.auth` to `0`; records with `event_type: 15` contain `event.exit` with the same authorization action and result. `MAC-MROSS-02.meridianhcs.local/macos_endpoint_security.ndjson` repeats this pattern. Fork and exit are notification event families, not authorization decisions. The event payload and action type therefore disagree at the source schema/semantics level.
- [weak_signal] Both endpoint-security exports use the same `version: 11`, `schema_version: 1`, and `action_type: 1` across the represented exec, fork, and exit event families. The repeated action-union mismatch across separate hosts makes a shared serialization artifact more likely than isolated malformed messages.

## Evidence For Real

- Windows Security XML samples use the `Microsoft-Windows-Security-Auditing` provider and source-appropriate event fields. For example, DC-01 event 4769 at `2026-11-02T13:01:58.2786829Z` has ticket, service, status, and client-address fields; event 4688 has hexadecimal process IDs and parent/process names; and event 5156 includes direction, protocol, addresses, ports, and filter-layer fields.
- Windows Sysmon samples use event-specific shapes: Event 1 has process creation fields, Event 3 has network tuple fields, Event 10 has source/target process fields, Event 13 has registry value fields, and Event 22 has DNS query fields. A DC-01 taskhostw process creation is represented in both Sysmon and Security/eCAR at closely aligned times with matching PID and image.
- Zeek subordinate records reference observed connection UIDs. In `zeek-core`, all 3,132 DNS, 2,435 HTTP, and 378 SSL rows point to connection UIDs present in `conn.json`; all 716 file rows' `conn_uids` references also resolve. Certificate-chain file UIDs in sampled SSL records resolve to `x509.json` IDs.
- eCAR process creates on the Windows hosts I checked align with native 4688/Sysmon Event 1 records by PID, image, and timestamp. For example, all 167 DC-01 eCAR process-create rows and all 123 DC-02 rows had an exact PID/image native counterpart within two seconds.
- The bounded collection window explains some unmatched Windows 4634/4689 lifecycle records: I did not count absent pre-window starts or post-window closings as synthetic evidence. Nor did I treat complete joins by themselves as synthetic.

## Detailed Analysis

### macOS Endpoint Security action semantics

The two files `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson` (128 rows) and `MAC-MROSS-02.meridianhcs.local/macos_endpoint_security.ndjson` (182 rows) contain event types 9/exec, 11/fork, and 15/exit. In each, the records use `action_type: 1` and an action object ending in `result.auth: 0`. This shape represents an authorization result, while fork and exit are notification events. For example, MAC-MROSS-01 has a fork at `2026-11-02T13:07:54.822488000Z` (seq 0) carrying that authorization action, and an exit at `2026-11-02T13:07:57.813235000Z` also carrying it. MAC-MROSS-02 shows the same pattern, including exit rows near `2026-11-02T18:56:58Z`.

The records otherwise contain detailed process audit tokens, PID versions, executable metadata, event-specific `fork.child` / `exec.target` / `exit` payloads, and increasing global sequence numbers. The defect is specifically the action type/result union attached to notification events. A SIEM parser could misclassify these notifications as authorization decisions or reject the payload shape. I did not infer a problem from a particular event's presence or from the absence of other macOS event families.

### Windows Security and Sysmon

I sampled different event types across domain controllers, servers, and workstations. The Security XML consistently identifies the Security-Auditing provider and uses familiar source-specific fields. Selected examples include 4624/4634 logon identifiers and types, 4768/4769 Kerberos fields, 4688/4689 process IDs and names, 5140 share access, and 5156 filtering-platform network tuples. The source's timestamp carries subsecond precision; Sysmon's `UtcTime` is millisecond precision, with expected small differences from the outer event timestamp.

Sysmon Event IDs 1, 3, 5, 7, 8, 10, 11, 13, and 22 in the inspected hosts have event-appropriate field sets. PID/image/time joins between Security, Sysmon, and eCAR were coherent in sampled cases. I did not flag the few event lifecycle rows without a matching record inside the visible window: the collection starts and ends at different points in ongoing host activity, so absence alone does not establish a broken lifecycle.

### Zeek and network references

The sampled Zeek core, DB, and DMZ files use the expected JSON field families (`uid` for connection-aware protocol records, five-tuple fields on connection rows, and `fuid`/`conn_uids` for file records). Every tested DNS/HTTP/SSL UID resolved to a connection row. File `conn_uids` and SSL certificate-chain references resolved to their corresponding connection/file or X.509 records. HTTP's repeated UID values are consistent with multiple transactions over one connection and were not treated as broken joins.

### Scope and window limits

The records cluster on 2026-11-02, with the Zeek connection samples spanning roughly 13:00–19:00 UTC. I treated this as the visible collection interval. Unmatched session or process starts/closings at its edges are not synthetic indicators by themselves. High cross-source matching is reported only as positive evidence of working joins; completeness alone is not evidence of synthetic generation.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected the score |
|---|---|---|---|
| `hard_contradiction` | macOS Endpoint Security | Both Mac hosts; fork (type 11) and exit (type 15) records | Notification event families carry an authorization action type and authorization-result payload, creating a source-semantic mismatch likely to affect SIEM parsing and rule logic. |
| `weak_signal` | macOS Endpoint Security | Both Mac hosts; all represented event families | The identical `action_type: 1`/auth-result serialization across hosts and event families suggests a shared systematic mapping error; this reinforces the primary finding but is not scored as a separate hard defect. |

## Realism Score by Category

- **Field format accuracy:** 6 — Windows and Zeek structures sampled cleanly; macOS Endpoint Security action/result semantics conflict with fork and exit event types.
- **Temporal patterns:** 8 — sampled timestamps are well-formed and causal; no impossible ordering was established.
- **Cross-source correlation:** 9 — tested Windows PID/image joins and Zeek UID/file/certificate references resolved consistently.
- **Behavioral realism:** 7 — the inspected Windows and network telemetry has plausible event-specific fields and variability; the macOS parser-semantic defect remains material.
- **Environmental consistency:** 8 — the visible host/source families are coherent; no source-coverage gap alone was counted against authenticity.

## Recommendations

- If this were synthetic, serialize the correct Endpoint Security action type and matching action union for notification events such as fork and exit. Keep authorization-result payloads only on authorization events; for notifications, emit the notification action representation expected by the declared message version.
- If the data is used to validate SIEM parsing, add a parser check that rejects or quarantines event-type/action-type combinations that cannot occur together, and report them with the host, event type, action type, and message version.
