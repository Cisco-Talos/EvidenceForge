# Detection Engineer Blind Authenticity Review — Loop 8

## Verdict

Likely synthetic or substantially constructed from synthetic records.

## Verdict Confidence (0–100)

87

## Synthetic-Confidence Score (0–100; lower is more production-like)

84

## Executive Summary

The reviewed macOS evidence is well-formed and internally rich: Endpoint Security fork, exec, and exit records carry coherent audit-token identities; process identifiers and parent relationships mostly line up; mach timestamps advance at a consistent 24 MHz rate; and SSH session tuples are corroborated across Endpoint Security, Unified Log, and eCAR.

The strongest concern is causal ordering in both modeled SSH logins. In each case, Endpoint Security records execution of the user's `/bin/zsh` before Unified Log records the successful SSH authentication that should enable the shell. The first inversion is 778 ms and the second is 32 ms. The successful sessions otherwise correlate unusually neatly across sources. A second synthetic signal is the tightly sequenced termination of all long-lived user processes immediately before local-session logout on both Macs. General JSON/XML validity and coherent identifiers are positive, but do not outweigh these repeated temporal patterns.

## Evidence For Synthetic

- **SSH authentication follows its dependent shell in both observed sessions.** On `MAC-MROSS-01`, Endpoint Security records `/bin/zsh` exec at `2026-11-02T16:02:02.857615Z`; Unified Log records `Accepted publickey for maya.ross from 10.10.1.42 port 57317` at `16:02:03.635545Z` (778 ms later). On `MAC-MROSS-02`, the `/bin/zsh` exec is at `14:24:42.242937Z`; Unified Log records `Accepted keyboard-interactive/pam for maya.ross from 10.10.1.41 port 50952` at `14:24:42.275062Z` (32 ms later). The session shell is a dependent of successful SSH authentication. The same inversion on both hosts is a causal defect, especially the larger first gap.
- **Process teardown is unusually compressed and orderly.** On `MAC-MROSS-01`, 8 user process-termination records span about 0.69 seconds, followed 51 ms later by local-session logout. On `MAC-MROSS-02`, 14 terminations span about 1.50 seconds, followed 258 ms later by logout. Chrome helpers, shells, login, terminals, and separate GUI applications all exit in a tight staggered run. A forced logout can terminate processes quickly, but this repeated sub-second, highly ordered closure across unrelated applications looks more like a generated lifecycle finalizer than ordinary endpoint shutdown telemetry.
- **Source timing is conspicuously regular.** The matching eCAR process events are consistently shifted later than Endpoint Security events: the matched process-event offsets center near 1.1 seconds on host 01 and 0.3 seconds on host 02. A stable per-host collector delay is plausible, but the narrow, host-wide offsets add to the constructed appearance when combined with the repeated lifecycle sequencing.
- **Unified Log coverage is extremely sparse relative to the detailed endpoint activity** (three records on host 01 and two on host 02), and the few rows are highly salient login, policy, and SSH messages. Sparsity by itself is not treated as proof; it limits corroboration and makes the repeated auth-order inversion more consequential.

## Evidence For Real

- All reviewed JSON/NDJSON records parse. Both macOS Unified Log files use consistent UTC timestamps, stable boot UUIDs per host, and plausible Apple Unified Logging fields (`messageType`, `machTimestamp`, process/sender image paths and UUIDs, activity/trace identifiers, and formatted messages).
- Endpoint Security records use consistent version/schema fields and event-specific payloads for the observed event types: fork (11), exec (9), and exit (15). Fork child audit tokens, exec targets, parent PIDs, executable paths, and process PID versions are internally coherent. The global sequence is monotonic, with a small number of gaps consistent with missed/filtered observations.
- Mach-time deltas track wall-clock deltas at approximately 24,000,000 ticks/second across the observed records, a coherent clock relationship. Timestamp precision is also consistent within each source (nanoseconds in Endpoint Security; milliseconds in eCAR).
- Both successful SSH sessions are corroborated. Unified Log, eCAR session records, network flow tuples, and Endpoint Security process trees agree on user `maya.ross`, source IP, and source port: `10.10.1.42:57317` to host 01 and `10.10.1.41:50952` to host 02. The flow precedes the target-side sshd process tree, and the eCAR login follows the Unified Log authentication message.
- eCAR process create/modify/terminate rows retain PID, parent PID, image path, process UUID/execution identity, and principal fields that broadly agree with Endpoint Security. The shell history timestamps also fall within the observed activity window.

## Detailed Analysis

**Source structure and semantics.** The macOS Endpoint Security data contains 136 records on host 01 and 167 on host 02. Event types are limited to fork, exec, and exit, with valid corresponding payload shapes. This review does not treat the absence of other Endpoint Security event types as evidence. Fork records identify the child in `event.fork.child`; exec records carry the target identity and image; exit records describe the terminating process. Process identity is strengthened by audit tokens and PID-version changes across exec transitions. The records are chronologically ordered and have no duplicate global sequence values; small sequence gaps are not independently suspicious.

Unified Log rows are structurally plausible and their mach timestamps agree with wall time. The loginwindow entry on each host aligns with the eCAR local-session start to within tens of milliseconds. The SSH authentication rows also agree with the eCAR source address and port. The key defect is their ordering relative to the Endpoint Security shell exec: an accepted-authentication log message is timestamped after the authenticated shell already exists on both hosts. Because these are event timestamps rather than stated ingestion timestamps, ordinary collection delay is not established by the logs.

**Cross-source process and session relationships.** The SSH network flows begin before target-side sshd activity, and the subsequent Endpoint Security ancestry proceeds through `launchd`, `xpcproxy`, sshd/session/auth helpers, and a user shell. eCAR reports the matching successful session after the authentication message and closes it later. This is a strong correlation chain, but the authentication message should precede the shell execution within that chain.

**Distribution and lifecycle.** Process activity includes interactive commands, application launches, SSH clients, short-lived utility processes, and exits. The most conspicuous distribution feature is the pair of nearly complete user-process shutdown sequences compressed into under two seconds, immediately preceding session logout. This could represent forced session termination, but the near-contiguous, similarly staged closure on two hosts has low production plausibility without an accompanying shutdown or session-management record. The sparse Unified Log stream does not provide that corroboration.

## Synthetic Indicator Summary

- **Causal ordering:** Strong indicator. Successful SSH authentication is logged after the resulting user shell exec on both Macs (778 ms and 32 ms).
- **Lifecycle/timing distribution:** Moderate-to-strong indicator. Long-lived and unrelated processes terminate in tightly staged bursts immediately before logout on both Macs.
- **Cross-source consistency:** Mixed. Strong identity and tuple alignment supports deliberate construction; the auth-to-shell inversion contradicts expected causal order.
- **Schema and identifier quality:** Evidence for realism. The observed Unified Log and Endpoint Security records are parseable and their core fields, audit tokens, PID relationships, and clock conversion are coherent.
- **Coverage:** Sparse Unified Log rows limit corroboration, but thin coverage alone is not scored as a synthetic indicator.

## Realism Score by Category

| Category | Score (0–100) | Assessment |
|---|---:|---|
| Source schema and field semantics | 86 | Native-looking Unified Log and Endpoint Security structures; observed event payloads are coherent. |
| Timestamp precision and clock consistency | 89 | Stable ordering within files and coherent ~24 MHz mach-time conversion. |
| Process identity and parent/child correlation | 87 | PIDs, audit tokens, PID versions, paths, and parentage broadly align. |
| Cross-source SSH/network correlation | 88 | User, source IP, source port, flow, auth, and session records align closely. |
| Causal event ordering | 43 | Both successful SSH auth messages follow the user's shell exec. |
| Lifecycle and activity distribution | 54 | User-process shutdown bursts are too compressed and similarly staged. |
| Overall production realism | 62 | Good record mechanics and correlation, undermined by repeated temporal contradictions. |

## Recommendations

1. Timestamp successful SSH authentication before the user-session shell exec in both Unified Log and Endpoint Security evidence. Preserve source-native event time semantics; if delayed collection is intended, represent it as collection/ingest time separately.
2. Review the two session-close sequences. If the endpoint is being forcibly logged out or shut down, include a plausible initiating/session-management event and vary process termination timing according to process behavior instead of using a near-contiguous exit run.
3. Retain the strong audit-token, PID-version, SSH-tuple, and per-source timestamp relationships; they make the records substantially more credible.
4. Increase Unified Log breadth only where the modeled host behavior warrants it, so it can independently corroborate endpoint and session activity. Do not add unrelated volume solely to meet a count target.
