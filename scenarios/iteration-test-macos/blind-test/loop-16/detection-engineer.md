# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 86  
**Synthetic-Confidence Score:** 74

## Executive Summary

Most inspected Windows, eCAR, and Zeek records have coherent schemas and useful cross-source correlation. The decisive issue is in both macOS Endpoint Security exports: process identity changes across successive `exec` notifications for the same PID, with `pidversion` increasing systematically. That breaks process-lifetime correlation in a source used for detection and supports a synthetic verdict.

## Evidence For Synthetic

- [hard_contradiction] In both macOS Endpoint Security files, fork-child and subsequent exec-target audit tokens retain the same PID but change `pidversion`. For example, in `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson`, PID `42198` has `pidversion` `2147492864` at `2026-11-02T13:08:00.998589Z` (`fork.child.audit_token`) and `2147493888` at `13:08:01.005156Z` (`exec.target.audit_token`). PID `42199` similarly changes from `2147495936` to `2147496960` between `13:08:01.033042Z` and `13:08:01.053648Z`. The same pattern occurs for all 52 fork-to-exec PID matches in this file and all 60 in `MAC-MROSS-02.meridianhcs.local/macos_endpoint_security.ndjson`. Since these records describe successive executable images within a process lifetime, changing the process-version identity prevents reliable PID-incarnation correlation.

## Evidence For Real

- The Windows Security XML uses the expected event envelope and named `EventData` fields in sampled 4624, 4625, 4648, 4688, 4768, 4769, 4776, and 4697 records. Examples include `WS-MCHEN-01.meridianhcs.local/windows_event_security.xml` 4624 service logons with `LogonType=5` and local `IpAddress=-`, and `DC-01.meridianhcs.local/windows_event_security.xml` 4769 records with mapped IPv4 addresses such as `::ffff:10.10.2.21`.
- Zeek JSON records parsed cleanly in the inspected core, DB, and DMZ sets. Every DNS, HTTP, and SSL UID checked had a matching connection UID in its sensor’s `conn.json`; the checked DNS answer and TTL arrays also had no mismatches.
- Mac shell-history entries have corresponding Endpoint Security executions. For example, `MAC-MROSS-01.meridianhcs.local/zsh_history/maya.ross.zsh_history` records `/usr/bin/id` at epoch `1793624887`; its Endpoint Security file shows `/usr/bin/id` executing at `2026-11-02T13:08:07.241854Z` and exiting successfully at `13:08:07.509010Z`.
- eCAR records use consistent top-level fields such as integer `timestamp_ms`, UUID-shaped `id` and `objectID`, and object-specific properties across the sampled Mac and Windows hosts.

## Detailed Analysis

### macOS Endpoint Security identity and event shape

The two `macos_endpoint_security.ndjson` files contain `version=11` records with event types 9, 11, and 15, corresponding in the observed data to exec, fork, and exit shapes. The event-specific fields are present: fork records include a child process, exec records include a target, and exit records include an exit status.

The identity relationship is the significant defect. In `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson`, the fork at `13:08:00.998589Z` gives child PID `42198` version `2147492864`; the exec at `13:08:01.005156Z` gives its target the same PID with version `2147493888`. The following exec at `13:08:01.022371Z` again uses PID `42198`, now with version `2147494912`. This pattern is systematic across both Mac files, rather than an isolated mismatch.

### Windows event fields and process evidence

Sampled Windows Security records use plausible event-specific fields and values. `WS-MCHEN-01.meridianhcs.local/windows_event_security.xml` includes 4688 process creation records with `NewProcessId`, `NewProcessName`, `ProcessId`, `ParentProcessName`, and `CommandLine`; a 4625 record has status `0xc000006d` and substatus `0xc000006a`; and a 4648 record identifies `runas.exe`. DC records include Kerberos ticket fields and mapped IPv4 client addresses. These samples did not reveal a comparable schema or value contradiction.

### eCAR and Zeek correlation

The Mac eCAR files contain `USER_SESSION`, `PROCESS`, `FLOW`, and `FILE` records, with properties that vary by object type. In the inspected Zeek core set, 11,956 connection records had plausible state values and the companion DNS, HTTP, and SSL records referenced existing connection UIDs. DB and DMZ companion UID checks also found no missing connections. This correlation supports operationally useful pivots; it is not itself evidence of synthetic origin.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `hard_contradiction` | macOS Endpoint Security audit tokens | Both Mac hosts; all 112 observed fork-to-exec PID matches changed `pidversion` while retaining PID | Strong source-native process identity defect that undermines lifetime and PID-incarnation correlation |

## Realism Score by Category

- **Field format accuracy:** 7 — Windows and Zeek samples were structurally coherent; the Mac audit-token identity inconsistency is material.
- **Temporal patterns:** 8 — Sampled event sequences and timestamps were coherent.
- **Cross-source correlation:** 8 — eCAR, shell history, and Zeek companion references support useful pivots, subject to the Mac PID-version issue.
- **Behavioral realism:** 7 — Sampled process and session behavior is plausible, but the Mac process identity lifecycle is not.
- **Environmental consistency:** 8 — The inspected source families and host types do not show a clear collection-profile contradiction.

## Recommendations

- If this were synthetic, preserve a process’s `pidversion` across fork-to-exec image transitions for the same process lifetime. Add a consistency check across fork, exec, and exit notifications on both Mac hosts.
