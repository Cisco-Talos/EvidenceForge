# Detection Engineer Blind Authenticity Review — Loop 11

## Verdict

Likely synthetic.

## Verdict Confidence (0-100)

82

## Synthetic-Confidence Score (0-100; lower is more production-like)

78

## Executive Summary

The reviewed logs have strong production-like structure: macOS Endpoint Security process sequences are ordered, process IDs and execution transitions line up with normalized eCAR process events, and two SSH sessions have plausible cross-host tuple and authentication timing. The broader dataset also contains source-specific Windows XML, Linux syslog, Zeek JSON, proxy/web, firewall, and Snort artifacts.

The main authenticity concern is macOS Endpoint Security action serialization. All 303 captured events are notification types (`event_type` 9, 11, or 15) with `action_type: 1`, yet every row also carries an authorization result (`result.auth: 0`). A notify event does not represent an authorization decision. This looks like a generic result object attached regardless of event semantics. It shifts the verdict toward synthetic, though the evidence is not conclusive by itself.

## Evidence For Synthetic

- **Endpoint Security semantics:** Every record in both `macos_endpoint_security.ndjson` files has `action.result.result.auth: 0`, while event types 9/11/15 and `action_type: 1` denote exec/fork/exit notifications. An authorization result is not meaningful for these notify events. This is the clearest source-semantic defect.
- **Uniform lifecycle representation:** The Endpoint Security streams contain only fork, exec, and exit events. The normalized eCAR streams represent almost every observed process with a create, one or more modify events, and a terminate. This is coherent, but more curated than a broadly collected raw Endpoint Security feed.
- **Global sequence gaps:** `global_seq_num` is monotonic and unique but has seven gaps on MAC-MROSS-01 and six on MAC-MROSS-02. Drops or filters could explain them, so this is weak evidence; no sequence reversal or duplicate was observed.
- **Sparse Unified Log coverage:** Only two or three Unified Log records appear per Mac over roughly five to six hours, despite hundreds of normalized flow events and many process events. Thin coverage alone is not counted as a defect; it limits corroboration of routine macOS activity.

## Evidence For Real

- **Coherent time behavior:** Endpoint Security timestamps are ordered with no backward steps. `mach_time` advances in step with wall-clock time. Unified Log uses timezone-qualified timestamps with microsecond precision, Endpoint Security uses nanosecond-formatted UTC timestamps, and eCAR uses millisecond epoch timestamps.
- **Correlated process identity and transitions:** Endpoint Security PIDs overlap eCAR process PIDs on both Macs. Fork child PIDs, parent PIDs, executable transitions, and exit events correspond to eCAR `PROCESS CREATE`, `MODIFY`, and `TERMINATE` records. The transition from launchd through XPC proxy, Terminal/iTerm, login, shell, and command execution is internally plausible.
- **Cross-source SSH evidence:** MAC-MROSS-01 eCAR records an outbound SSH flow from `10.10.1.41:50952` to `10.10.1.42:22`; its process event and Endpoint Security exec identify the same SSH client and PID. MAC-MROSS-02 Unified Log records a successful keyboard-interactive authentication from that source and port shortly after transport begins. A later inbound session from `10.10.1.42:57317` to MAC-MROSS-01 is followed by a public-key acceptance message. These are specific tuple and timing relationships, not just broad cross-source alignment.
- **Rich source-native records:** Unified Log entries include process and sender image paths/UUIDs, subsystem/category, trace identifiers, and mach timestamps. Endpoint Security rows include audit tokens, PID versions, ancestry, code-signing metadata, executable stats, and event-specific fork/exec/exit payloads.
- **eCAR integrity:** Mac eCAR rows are timestamp-sorted, use unique event IDs, and retain stable process object IDs across lifecycle events. FLOW records have explicit source/destination tuples and direction.

## Detailed Analysis

### macOS Unified Log

The Unified Log files contain structured records with timestamps, timezone names, mach timestamps, boot UUIDs, process IDs, image paths and UUIDs, and event messages. The SSH authentication messages agree with host direction, source IP, source port, and nearby endpoint/network evidence. The loginwindow message is plausible but provides little coverage. The low row count limits analysis but is not, by itself, evidence of fabrication.

### macOS Endpoint Security

The streams use stable top-level fields (`schema_version`, `version`, event and action types, time, mach time, sequence numbers, thread, process, and event payload). Payload keys align with event types: fork records have a child object, exec records have a target, and exit records have an exit status. Global sequence numbers increase without duplication; per-event times are ordered. Process identity changes are represented with PID version and audit-token fields.

The main defect is that all events include `action.result.result.auth: 0` while the event/action combination denotes notifications. That communicates an authorization result even though the rows are not authorization events. If this is an enriched export rather than direct Endpoint Security message serialization, the export contract should label or remove that field so consumers do not mistake it for an ES decision.

### Normalized eCAR and cross-source timing

Both Mac eCAR streams are sorted by `timestamp_ms`, with unique IDs. Process lifecycle rows use stable `objectID` values and consistent PID/PPID lineage. Millisecond precision is coarser than native Endpoint Security precision, as expected for a normalized source. The strongest examples are the outbound and inbound SSH sessions, where PID/command, network tuple, direction, source port, and target authentication message fit together in time.

The eCAR feed has hundreds of flows per host while native Unified Log is sparse. Without collection configuration, this is an observability gap rather than a contradiction. No impossible process ordering or reversed transport/auth sequence was found in the examined Mac examples.

### Other source formats

The dataset includes native-style Windows Event XML, Linux syslog and shell histories, Zeek JSON, proxy/web logs, firewall records, and Snort alerts. Their formats and volume are consistent with multi-sensor collection. This review did not treat absent event types, bounded-window initiator gaps, story completeness, or cross-source alignment alone as evidence of synthetic data.

## Synthetic Indicator Summary

| Category | Finding | Weight |
|---|---|---:|
| Source schema and semantics | Notify-type Endpoint Security events carry an auth result on every row | High |
| Event coverage | Endpoint Security contains fork/exec/exit only; Unified Log is sparse | Low; coverage alone is not a contradiction |
| Timestamp/order | Monotonic sequences and source-appropriate precision; only sequence gaps | Low |
| Process identity | PID, ancestry, exec transitions, and lifecycle records correlate | Evidence for real |
| Network/auth causality | SSH tuples and authentication timing align across hosts | Evidence for real |
| Record identifiers | Unique eCAR IDs and stable process object IDs | Evidence for real |
| Volume/distribution | Large mixed-source dataset; no specific volume contradiction established | Neutral |

## Realism Score by Category

Scores are realism-oriented: 100 means highly production-like.

| Category | Score | Notes |
|---|---:|---|
| Native schema and field semantics | 63 | Good record structure, with the Endpoint Security notification/auth-result mismatch |
| Timestamp precision and ordering | 94 | Ordered streams; precision differs plausibly by source |
| Process lifecycle and identity | 91 | PID, parent, execution, and termination relationships are coherent |
| Network and authentication causality | 93 | Two Mac SSH flows are specifically corroborated by authentication logs |
| Cross-source correlation | 92 | Correlation uses matching tuples, ports, PIDs, and nearby times |
| Collection coverage | 68 | Unified Log is sparse; treat as a collection limitation |
| Record identifiers and stability | 94 | Unique event IDs and stable lifecycle object IDs |
| Overall | 82 | Mostly coherent evidence with one meaningful Endpoint Security semantic anomaly |

## Recommendations

1. Correct the Endpoint Security action serialization: omit authorization-result data for notification events, or label the export as a normalized representation and document what `auth: 0` means.
2. Preserve the existing native-to-eCAR PID, parent, timestamp, and SSH tuple correlations; these are strong and detection-useful.
3. If fuller macOS observability is intended, include representative Unified Log events around process launch, SSH authentication/session setup, and routine service activity. Current sparsity is a coverage limit, not an independent authenticity finding.
4. Keep global sequence gaps only when they correspond to an explicit drop/filter model; otherwise make sequence accounting and collection gaps explainable in the export contract.
