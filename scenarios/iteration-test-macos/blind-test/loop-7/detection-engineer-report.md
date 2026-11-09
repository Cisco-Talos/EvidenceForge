# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 78
**Synthetic-Confidence Score:** 62

## Executive Summary

The Windows event records and Zeek JSON examined are broadly parseable and their core field relationships look credible. The clearest synthetic indicator is a macOS endpoint export that assigns one eCAR timestamp to multiple distinct native Endpoint Security transitions, obscuring their observed order; repeated opaque Unified Log trace identifiers across two Macs add a weaker template signal. I assess the bundle as likely synthetic, with moderate synthetic evidence rather than a demonstrated impossible schema value.

## Evidence For Synthetic

- [contract_gap] On `MAC-MROSS-01`, `macos_endpoint_security.ndjson` records distinct transitions for PID 42171 at `2026-11-02T13:07:43.411700Z` (fork), `.420283Z` (exec to `xpcproxy`), `.439181Z` (exec to Terminal), and `.470817Z` (fork of PID 42172). The corresponding early process rows in `ecar.json` (records 6–9) all carry `timestamp_ms: 1793624864584` (`13:07:44.584Z`). This batches several lifecycle transitions to one timestamp about 1.1 seconds later, losing the native event ordering that a time-based SIEM rule would otherwise see. A common ingest delay may explain the offset, but does not explain away the collapsed sequence.
- [weak_signal] The first Unified Log entry in each Mac export uses the same opaque `traceID` (`562950054215684`) and the same `-[Login1 launchWorkspace] | enter` message, despite belonging to separate hosts and boot UUIDs. A trace identifier is not established here as globally unique, so this is only a repeated-template signal, not a hard contradiction.
- [distribution_texture] The two Maya Ross zsh histories repeat a narrow inventory-command vocabulary in similar work sessions (`id`, `sw_vers`, `uname`, `ps`, `df`, `du`, and `find`); for example, both host histories include `sw_vers`, `uname`, then document-directory inspection. This is compatible with a shared operator workflow, but the repeated, compact command sequence contributes a small amount of synthetic texture evidence.

## Evidence For Real

- The sampled Windows Security records have recognizable Event ID-specific shapes and values. A workstation 4624 v2 record on `WS-MCHEN-01` has `LogonType=5`, `services.exe`, and local `-` address fields; a 4625 v0 record has `Status=0xc000006d`, `SubStatus=0xc000006a`, and `LogonType=2`; a 4688 v2 record has separate `NewProcessId`, creator `ProcessId`, `ParentProcessName`, and `MandatoryLabel` fields.
- Domain-controller authentication records use plausible Kerberos field sets. A `DC-01` 4768 record has `ServiceName=krbtgt`, a successful `Status=0x0`, and an IPv4-mapped client address; a 4769 record has service/ticket fields and a client address. The sampled 4624/4634 records use matching session field conventions and plausible logon types.
- The three Zeek connection files contain native-style JSON field names and values (`ts`, `uid`, `id.orig_h`, `conn_state`, packet/byte counters). In each sensor, all sampled DNS, HTTP, and SSL UIDs resolved to a `conn.json` UID; this completeness is positive correlation evidence, not a synthetic clue by itself.
- Mac Endpoint Security records distinguish the actor process from the `exec.target`, and preserve audit-token PID, parent PID, PID version, signing ID, executable path, and event time. The Terminal launch sequence changes process images and credentials in a plausible order; later shell commands have corresponding `exec` and `exit` notifications.
- Mac native and normalized evidence agrees on an SSH session: the `MAC-MROSS-01` Unified Log reports an accepted public key from `10.10.1.42:57317` at `16:02:03.635545Z`, while the other Mac's endpoint records show an SSH client exec to `MAC-MROSS-01` at `16:01:46.697479Z`. The client activity precedes the server acceptance as expected.
- Linux syslog uses RFC 5424-style records and shows varied operational messages alongside PAM and sudo session events. For example, the `MAIL-EDGE-01` sudo command at `13:04:44.803718Z` is followed by a root session open and close, while routine `snapd`, `unattended-upgr`, and cron records coexist in the same time window.

## Detailed Analysis

### Windows event schema and correlation

I sampled Security events from a domain controller and multiple workstations. `DC-01` includes 4624/4625/4634, 4648, 4688, 4672, 4768, and 4769 records. The sampled 4624 is Version 2 with the expected subject/target, LogonType, process, and address fields; the sampled 4688 is Version 2 and includes the newer token and parent fields. On `WS-MCHEN-01`, the 4688 record at `13:01:13.0225089Z` reports a PowerShell process created by `explorer.exe`, with `NewProcessId=0x1c24` and creator `ProcessId=0x19cc`. A later 4648 record contains a `runas.exe` process path and target DC, which are structurally plausible for explicit credential use. The examined records show no definite SID, GUID, timestamp-format, or Event ID/field contradiction.

The Security XML uses the Microsoft event namespace, source-native Event IDs, versions, levels, task/opcode values, keywords, event record IDs, and `SystemTime` attributes. On the workstation samples, 4624 and 4634 use the same `TargetLogonId` field convention; the examples are different sessions, so I do not infer a mismatch from those samples. DC event record IDs are much larger than workstation IDs but progress within each source, which is not itself anomalous.

### macOS Unified Log and Endpoint Security

The Unified Log exports contain two to three JSON records each. Their timestamps, timezone, boot UUID, process and sender image paths/UUIDs, subsystem/category, format string, and event message are distinct Unified Log-style fields. The `MAC-MROSS-01` records include a loginwindow message, an AppleSystemPolicy message that says policy would not allow a process, and an sshd-session accepted-key message. I treat the policy message as a policy observation, not proof of a denied execution's effects.

The Endpoint Security files contain version 11 records with event types 9, 11, and 15 (exec, fork, and exit). In the sampled Terminal chain, `launchd` forks a process; successive exec notifications identify `xpcproxy` and Terminal as targets; Terminal then forks the `login` process. The process PID remains associated with image changes while PID version and audit credentials change, which is consistent with the actor/target distinction in an exec notification. SSH sessions show client `ssh` exec and server `sshd-session`/shell lifecycles. I found no basis to reinterpret these ES notifications as authorization decisions.

The material timestamp defect is in the normalized eCAR view, not in the raw ES timestamps: four separate events in a roughly 59 ms native sequence become same-millisecond eCAR process records. That can collapse causal order in downstream time-window queries. It is more consequential for detection processing than the repeated trace identifier, but it remains a moderate rather than impossible contradiction because the eCAR feed could be batched.

### Zeek, eCAR, and Linux records

`zeek-core/conn.json` has 12,532 rows, `zeek-dmz/conn.json` has 9,830, and `zeek-db/conn.json` has 449. The inspected connections use plausible state and protocol fields; examples include an internal UDP Kerberos exchange and an inbound TCP SYN-only (`S0`, history `S`) observation. DNS rows contain query type/class, response code, answers, TTLs, and connection UIDs. A sampled LDAP SRV answer names two DCs, and an `isatap` query returns NXDOMAIN. HTTP proxy CONNECT examples and TLS rows have the expected Zeek-style host/SNI and UID fields. The associated UID joins checked across conn/dns/http/ssl had no unmatched references; that consistency is beneficial for SIEM pivots and is not scored against authenticity.

The eCAR files use a consistent JSON-lines record shape for `PROCESS`, `FLOW`, and `USER_SESSION` objects, including timestamps, IDs, principals, and source/destination properties where applicable. Windows Security, Sysmon, and eCAR samples use recognizable event families and process/session fields. The Linux syslog and command-history samples show source-native text patterns and useful activity context. I did not find an independently demonstrated Linux or Zeek parser-breaking field error in the records sampled.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected the score |
|---|---|---|---|
| `contract_gap` | macOS Endpoint Security / eCAR | One observed PID 42171 image/fork sequence on `MAC-MROSS-01` | Four native events at `13:07:43.411700Z` through `.470817Z` are represented at the same eCAR `timestamp_ms` (`1793624864584`), reducing lifecycle ordering fidelity for SIEM time-based detections. |
| `weak_signal` | macOS Unified Log | First loginwindow record on each of two Macs | Same opaque `traceID` and exact message recur across distinct hosts/boot UUIDs; uniqueness semantics are not established, so the signal is low weight. |
| `distribution_texture` | macOS zsh history | Two user histories | A compact inventory-command set recurs in similar sequences. Shared operator behavior remains a plausible explanation, so this is low weight. |

## Realism Score by Category

- **Field format accuracy:** 8 — Sampled Windows XML, Zeek JSON, Linux syslog, and macOS record shapes are largely source-appropriate; no hard schema contradiction was established.
- **Temporal patterns:** 6 — Native Mac event ordering is plausible, but eCAR collapses several distinct transitions to a single timestamp.
- **Cross-source correlation:** 8 — The sampled Mac SSH activity and Zeek UID joins are coherent; the Mac normalized timestamp issue weakens sequence fidelity.
- **Behavioral realism:** 7 — Process and session lifecycles are plausible, with some repeated inventory-command texture in the two Mac histories.
- **Environmental consistency:** 8 — The mixed Windows, Linux, macOS, and network sources show plausible host and service relationships in the records reviewed.

## Recommendations

- If this were synthetic, preserve distinct native event timestamps or encode an explicit ingest-time field separately in eCAR so the PID 42171 fork/exec sequence remains chronologically visible to time-based rules.
- If this were synthetic, scope opaque Unified Log trace IDs to their host/boot/activity context and vary the Mac shell-history inventory routines enough that separate sessions do not repeatedly expose the same compact command set.
