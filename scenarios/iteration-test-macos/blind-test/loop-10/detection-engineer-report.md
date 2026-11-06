# Detection Engineer Authenticity Review

## Verdict

Likely synthetic, with a substantial amount of technically coherent host and network telemetry.

## Verdict Confidence (0-100)

78

## Synthetic-Confidence Score (0-100; lower is more production-like)

76

## Executive Summary

The strongest production-like evidence is the consistency among the macOS process, shell-history, endpoint-flow, Zeek, proxy, and SSH-session records. Commands in both user histories line up closely with process execution records, and host flow tuples line up with Zeek and many proxy client ports. The time precision and process lifecycles are generally credible.

The main synthetic indicator is in both `macos_endpoint_security.ndjson` files: records use event types 9, 11, and 15 (the exec, fork, and exit notification families) and set `action_type` to 1, but every record carries an authorization-result-shaped `action.result.result_type/result.auth` value. A notification record's action is not an authorization decision. This is a source-schema/union mismatch repeated across the complete Endpoint Security sample, rather than a mere gap or coverage concern. The rest of the reviewed macOS evidence does not show a comparably strong causal or timestamp contradiction.

## Evidence For Synthetic

- **Endpoint Security action-union mismatch (strong):** On both Macs, all 303 records use notification event types 9/11/15 and `action_type: 1`, while carrying `action: {result: {result_type: 0, result: {auth: 0}}}`. This represents an authorization-result payload alongside notification events. The repeated mismatch affects exec, fork, and exit records alike.
- **Overly uniform result envelope (moderate):** The same `action` result is repeated on every distinct notification type and outcome. It is not event-specific and does not express an observed per-event authorization decision.
- **Dense, deliberately coordinated telemetry (weak by itself):** The reviewed Mac records preserve tight history-to-process timing, flow-to-Zeek tuple identity, and SSH session relationships across hosts. Such coordination is realistic in a synthetic corpus; it is not treated as an indicator on its own.

## Evidence For Real

- **Plausible Endpoint Security process lifecycle:** `NOTIFY_FORK`-style records create children, subsequent exec records retain the process PID while changing the executable, and exit records occur after short-lived commands. Parent PIDs, audit tokens, effective UIDs, shell ancestry, and session IDs are generally coherent.
- **Shell history agrees with execution telemetry:** The 21 commands in `MAC-MROSS-01` history each have a matching eCAR execution with a median timestamp difference of about 1.9 seconds (maximum about 2.2 seconds). The 19 commands on `MAC-MROSS-02` correspond to Endpoint Security execution evidence; the matching command sequence includes SSH, local discovery, and file inspection activity.
- **Endpoint-to-network agreement:** All 469 TCP/UDP FLOW tuples on `MAC-MROSS-01` and all 349 on `MAC-MROSS-02` have exact source/destination address and port matches in the Zeek connection logs. eCAR FLOW timestamps consistently follow Zeek connection-start timestamps: median delays are about 1.47 seconds and 0.65 seconds, respectively.
- **Proxy-path agreement:** Many flows to `10.10.3.20:8080` have source ports repeated in proxy access records. Exact source-port matches exist for 271/353 flows from `10.10.1.41` and 159/260 from `10.10.1.42`; their associated proxy records are within a few seconds. The remaining rows do not carry enough matching fields to call a contradiction.
- **SSH semantics and order:** The inbound SSH login on `MAC-MROSS-02` from `10.10.1.41:50952` agrees with an outbound SSH command on `MAC-MROSS-01`; the reverse session from `10.10.1.42:57317` agrees with an SSH command from `MAC-MROSS-02`. Endpoint process creation precedes session login, and logout follows the session's command activity. The `MAC-MROSS-01` Unified Log also records successful public-key authentication for that source and port.
- **Unified Log shape and timing:** The available Unified Log rows have native-looking timestamp, Mach timestamp, boot UUID, process/sender image, subsystem/category, message type, and trace/activity fields. The login-window event is within roughly 0.11 seconds of the corresponding local eCAR session start; the SSH authentication message falls within the matching session's interval.
- **Network behavior has plausible bursts:** The many connections to the same proxy endpoint occur in irregular clusters, including short bursts consistent with loading web content, rather than at one fixed interval. Non-proxy service traffic also appears on DNS, Kerberos, LDAP, SMB, and syslog destinations.

## Detailed Analysis

### Endpoint Security schema and source semantics

The two Endpoint Security streams contain 136 and 167 valid NDJSON objects. Their observed event types are only 9, 11, and 15, corresponding to exec, fork, and exit notifications. Each record identifies a process and includes an event-specific payload: exec has a target process, fork has a child, and exit has an exit status. Across those records, however, `action_type` is uniformly 1 and the nested action is uniformly shaped as an authorization result with `auth: 0`. That action shape conflicts with the notification event family and is the primary reason for the synthetic verdict.

Within the event payloads themselves, process identity is mostly well maintained. Fork children inherit a plausible parent PID; exec keeps the PID while the image and execution identity change; and exit events follow command execution. The host and process timestamps are increasing. The global sequence values have a small number of gaps (7 on the first host and 6 on the second), which can arise from missed or filtered notifications and are not independently suspicious.

### Unified Log

The first Mac has three Unified Log entries and the second has two. The records contain a mix of a login-window message, an Apple System Policy denial, and an sshd public-key acceptance. Sender/process metadata and timestamps are internally plausible. In particular, the public-key acceptance identifies `10.10.1.42` and source port `57317`, matching the eCAR SSH session. The small sample limits what can be concluded about broader Unified Log coverage; thin coverage alone is not counted against realism.

### Process and shell history

The shell-history timestamps use second precision, while eCAR process records use millisecond timestamps and Endpoint Security uses sub-millisecond timestamps. On `MAC-MROSS-01`, all 21 history commands correspond to eCAR exec events within about 2.2 seconds. On `MAC-MROSS-02`, the history sequence corresponds to Endpoint Security exec events, and most commands also appear in eCAR. This supports credible process ancestry and timing; the few source-level omissions do not create a visible contradiction.

### Network and session relationships

The eCAR flow records carry usable tuple fields and exact tuple matches in Zeek. Their eCAR timestamps trail the Zeek start times by a consistent sub-second-to-few-second interval, which is a plausible endpoint observation delay. Proxy access lines also reproduce many of the source ports for client connections to the proxy. This is more than broad cross-source alignment: the tuple, direction, service port, and timing agree in the source-specific record forms.

SSH lifecycle relationships are also credible. Each remote session has a corresponding source-side SSH invocation, a target-side login and process chain, and a later logout. Source addresses and ephemeral ports agree in both directions. No reversed transport/authentication ordering or impossible process ownership was observed in these Mac sessions.

## Synthetic Indicator Summary

| Category | Finding | Weight |
|---|---|---|
| Source schema / action semantics | Notification event types paired with an authorization-result action payload throughout both Endpoint Security streams | High |
| Timestamp precision and ordering | Event times are monotonic and source delays are plausible | None observed |
| Causal process relationships | Fork, exec, and exit relationships are mostly coherent | Low concern |
| Network tuple consistency | Exact eCAR-to-Zeek tuple matches and many proxy source-port matches | Positive realism evidence |
| Behavioral distribution | Proxy bursts are irregular and consistent with browsing activity | Low concern |
| Coverage | Unified Log sample is small, but no coverage penalty applied | None |

## Realism Score by Category

Scores are 0-10, where 10 is most production-like.

| Category | Score | Notes |
|---|---:|---|
| Endpoint Security schema and action semantics | 4 | Event payloads are plausible, but the action union conflicts with notification event types. |
| Endpoint Security process identity and lifecycle | 9 | PID, parent, exec-image, UID, and exit relationships are generally coherent. |
| Unified Log structure and timestamp behavior | 8 | Fields and message timing look credible; sample is small. |
| Timestamp precision and event ordering | 9 | Source-native precision differs appropriately and dependencies are ordered. |
| Shell history and process evidence | 9 | Histories align closely with process execution records. |
| Network tuples and proxy semantics | 9 | Flow tuples and proxy-port evidence agree across sources. |
| SSH authentication/session lifecycle | 9 | Source, port, process chain, login, and logout agree. |
| Overall | 8 | Strong operational realism offset by one repeated schema-semantic defect. |

## Recommendations

- Correct the Endpoint Security action representation so notification events carry the notification action shape, not an authorization result. Keep authorization results only on authorization events.
- Add representative Endpoint Security authorization events only when the modeled activity actually includes an authorization decision; do not attach a generic action envelope to every event.
- Preserve the existing source-specific timestamps and tuple evidence. The process, flow, proxy, and SSH records provide useful detection-training relationships without showing a concrete causal contradiction.
- If broader macOS Unified Log realism is required, include more event families in that source; the current sample is too small to assess coverage, but its size is not itself a synthetic finding.
