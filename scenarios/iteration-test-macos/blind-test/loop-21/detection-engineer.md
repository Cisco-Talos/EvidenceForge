# Detection Engineer Assessment

## Verdict

**Plausible; no hard contradiction found in the reviewed records.** The macOS SSH connection, authentication, and shell-start evidence is ordered and correlated coherently across eCAR, Endpoint Security, and Unified Log. The reviewed window has some collection sparsity, but it does not establish an unrealistic collection pattern.

## Verdict Confidence

**84/100.** Confidence is high for the concrete cross-source SSH checks below; this is a bounded review of emitted records, not proof that every record in the bundle is defect-free.

## Synthetic-Confidence Score

**28/100** (lower is more production-like). The inspected records have few concrete synthetic tells. This score reflects the lack of visible contradictions and does not assert that the records are real telemetry.

## Executive Summary

Two macOS SSH sessions show the expected source tuple, inbound transport, accepted authentication, and post-authentication shell execution. Endpoint Security records are internally ordered, with nanosecond-formatted UTC timestamps, audit-token identity, executable paths, and lifecycle events. Unified Log rows add plausible login and policy messages. Representative Windows, Sysmon, Zeek, and eCAR records also use source-appropriate field shapes and timestamp precision. No hard contradiction, source-format error, or demonstrably implausible distribution was established.

## Evidence for Synthetic

- **No confirmed synthetic indicator.** The small number of Unified Log records (3 on `MAC-MROSS-01`, 2 on `MAC-MROSS-02`) is sparse beside 137/154 Endpoint Security records, but missing companion volume is neutral under the bounded-window and thin-coverage rules. It does not by itself show unrealistic collection or an orphaned required event.
- The Endpoint Security files contain only event types 9, 11, and 15 (exec, fork, exit in the observed payloads). That may reflect source selection or event filtering; it is not evidence that a process was authorized or that other event classes could not occur.

## Evidence for Real

- On `MAC-MROSS-02`, eCAR reports inbound SSH from `10.10.1.41:59129` to `10.10.1.42:22` at 14:24:48.418Z, then Maya Ross's SSH login at 14:24:54.383Z (`ecar.json:138,146`). Unified Log records accepted keyboard-interactive/PAM authentication for the same user, source, and port at 14:24:53.650676Z (`macos_unified_log.ndjson:2`). Endpoint Security records the sshd/session/auth process chain followed by the user shell (`macos_endpoint_security.ndjson:51-65`, 14:24:51.715940Z–14:24:53.750785Z). The transport precedes authentication; the shell follows it.
- The reciprocal session is similarly consistent. `MAC-MROSS-01` records an eCAR inbound flow from `10.10.1.42:62470` to `10.10.1.41:22` at 16:02:12.565Z and login at 16:02:19.207Z (`ecar.json:242,248`). Unified Log records accepted public-key authentication for Maya Ross from that tuple at 16:02:17.562108Z (`macos_unified_log.ndjson:3`); Endpoint Security shows sshd startup and `/bin/zsh` execution at 16:02:16.141810Z–16:02:17.723014Z (`macos_endpoint_security.ndjson:74-88`). The authentication message falls between transport and shell start.
- The Endpoint Security records inspected have plausible event-specific payloads: numeric event/version fields, nanosecond UTC `time`, `mach_time`, sequence numbers, audit tokens, executable paths, and fork/exec/exit payloads. For example, `MAC-MROSS-01/macos_endpoint_security.ndjson:1-16` shows Terminal startup followed by login, zsh, and short-lived `id`, `sw_vers`, and `uname` processes (13:08:00.998589Z–13:09:14.679907Z).
- A representative Windows Security record uses `EventID 5156`, named network fields, and a UTC `SystemTime` with seven fractional digits (`WS-AJOHNSON-01/windows_event_security.xml:8,14,19,27-40`, 13:06:37.3451593Z). The corresponding Sysmon DNS record is represented with Event ID 22, `UtcTime`, `QueryName`, `QueryStatus`, and `QueryResults` (`WS-AJOHNSON-01/windows_event_sysmon.xml:6,12,23-30`, 13:06:37.4120778Z). These are source-native field shapes; no contradiction is inferred between the firewall destination and DNS answer because they describe different facts.
- Zeek records use fractional epoch `ts`, per-connection `uid`, tuple fields, protocol, duration, and state in `zeek-core/conn.json:1-2`; DNS records carry query and qtype in `zeek-core/dns.json:1-2`. eCAR rows use normalized `timestamp_ms`, object/action, stable object IDs, and properties. The formats are distinguishable and coherent in the inspected samples.

## Detailed Analysis

### macOS session and process ordering

- `MAC-MROSS-02.meridianhcs.local/ecar.json:138` — 2026-11-02 14:24:48.418Z, inbound TCP/22 from `10.10.1.41:59129` to `10.10.1.42`.
- `MAC-MROSS-02.meridianhcs.local/macos_endpoint_security.ndjson:51-65` — 14:24:51.715940Z–14:24:53.750785Z, launchd → xpcproxy → sshd → sshd-session/auth, then `/bin/zsh` under UID 501.
- `MAC-MROSS-02.meridianhcs.local/macos_unified_log.ndjson:2` — 14:24:53.650676Z, accepted keyboard-interactive/PAM for `maya.ross` from `10.10.1.41` port `59129`.
- `MAC-MROSS-02.meridianhcs.local/ecar.json:146` — 14:24:54.383Z, successful SSH login for the same principal and source tuple. Its logout is later recorded against the same session object and logon ID at `ecar.json:176` (14:35:08.357Z).
- `MAC-MROSS-01.meridianhcs.local/ecar.json:242,248` — 16:02:12.565Z inbound SSH transport, then 16:02:19.207Z successful login from `10.10.1.42:62470`.
- `MAC-MROSS-01.meridianhcs.local/macos_unified_log.ndjson:3` — 16:02:17.562108Z accepted public-key authentication for the same user and tuple. `macos_endpoint_security.ndjson:74-88` shows the server process chain and user shell at 16:02:16.141810Z–16:02:17.723014Z. The later eCAR login normalization is consistent with the native message and shell-start ordering.

### Source formats and bounded coverage

- Endpoint Security rows expose `schema_version`, `version`, `event_type`, `action_type`, `time`, `mach_time`, sequence values, and nested process/audit-token data. The observed exec/fork/exit payloads agree with their corresponding path and PID changes. Sequence gaps occur in the files, but with partial observation and no same-ID dependent-before-initiator inversion they are not a contradiction.
- Unified Log messages have source-specific timestamps with microseconds and process/sender metadata. The sparse count is a coverage observation only; it is not scored as an unrealistic volume pattern.
- Windows Event XML preserves `System/Provider`, `EventID`, `TimeCreated`, `Computer`, and named `EventData` fields. Sysmon uses its own event IDs and `UtcTime` alongside the XML event timestamp. Zeek JSON uses fractional epoch timestamps and connection UIDs. eCAR is normalized and uses millisecond epoch timestamps. No mixed precision or malformed sample was observed in the reviewed records.
- The Unified Log policy message on `MAC-MROSS-01/macos_unified_log.ndjson:2` (15:42:29.972020Z) says policy denied `MeetingAssist` PID 62521. There is no same-PID Endpoint Security exec row in the inspected process stream. This is not scored as a contradiction: Endpoint Security here contains notification-style exec/fork/exit records, and its absence is not an authorization result.

## Categorized Indicator Summary

| Category | Findings |
|---|---|
| `hard_contradiction` | None established. |
| `contract_gap` | None established. The observed SSH flow/auth/session ordering is coherent. |
| `distribution_texture` | No positive finding. Unified Log volume is sparse, but thin coverage alone is neutral. |
| `schema_or_format` | None established in inspected Windows XML, Sysmon, Zeek, eCAR, macOS Endpoint Security, or Unified Log samples. |
| `environment_or_collection_plausibility` | None established. The policy-denial message is not treated as an Endpoint Security authorization decision. |
| `weak_signal` | Endpoint Security contains only three observed event types and the Unified Log samples are sparse; this may be collection scope and is not evidence of synthetic output on its own. |

## Realism Scores

| Dimension | Score (1–10) |
|---|---:|
| Source schema and format fidelity | 8 |
| Timestamp precision and event ordering | 9 |
| Identity, process, and session correlation | 9 |
| Network and authentication correlation | 9 |
| Distribution texture and collection plausibility | 7 |

## Recommendations

- No root-cause fix is justified by the reviewed records; avoid changing generation based on the sparse Unified Log count alone.
- Preserve the demonstrated ordering contract for SSH: transport before accepted-auth evidence, and accepted-auth evidence before the authenticated shell. Keep source-specific timestamps and IDs in each renderer while correlating on the actual endpoint/tuple/session evidence.
- If broader macOS collection realism is a target, assess it using an explicitly declared Unified Log collection profile and additional source-specific messages; do not infer authorization from Endpoint Security notification rows.
