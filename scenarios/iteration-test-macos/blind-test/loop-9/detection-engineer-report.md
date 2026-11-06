# Blind Authenticity Review — Detection Engineer

## Verdict

Synthetic-leaning; the bundle is internally plausible and no decisive schema or causal contradiction was found in the reviewed macOS evidence.

## Verdict Confidence (0-100)

63

## Synthetic-Confidence Score (0-100, lower is more production-like)

67

## Executive Summary

The macOS records show unusually good structural discipline: Endpoint Security payload shapes consistently match the represented operation, process ancestry and exec transitions are coherent, and the Unified Log SSH messages line up with endpoint SSH activity. Timestamps use source-appropriate precision and are ordered consistently. These are strong production-like properties.

The synthetic lean comes from the highly curated, low-entropy behavior visible across the two Mac endpoints: compact command sequences recur in similar forms, with repeated inventory and inspection activity, while the Unified Log contributes only a few precisely relevant messages across multi-hour endpoint timelines. Those observations are suggestive, not conclusive; limited log coverage by itself is not treated as a failure. I found no single log-visible contradiction strong enough to establish synthetic origin.

## Evidence For Synthetic

- On both Mac endpoints, the visible user activity centers on a narrow set of command and file-inspection patterns (`sw_vers`, `uname`, `pwd`, `ls`, `du`, `find`, `ps`, `df`, `id`, and `cat`), repeated in similar short bursts. This looks more curated than a broad workstation command distribution, though a focused administrative or investigation session could produce it.
- Endpoint inventory execution recurs at regular-looking intervals in the eCAR timelines, including repeated `com.meridianhcs.endpoint-inventory` / `sw_vers` activity. Periodic inventory is normal; the concern is the combination with the otherwise narrow, repeated activity palette.
- The Unified Log files contain only two or three records per host despite endpoint records spanning several hours. This is weak evidence only: the files may represent selective collection, and sparsity alone is not a concrete contradiction.
- Both hosts use a similarly staged local session bootstrap (launchd → xpcproxy → Terminal → login → zsh), followed by a compact collection of user and application activity. This is plausible operationally, but the repeated construction contributes to the curated feel.

## Evidence For Real

- Endpoint Security records have consistent top-level schemas. In the sampled files, event type 9 carries an `exec` payload, 11 carries `fork`, and 15 carries `exit`; the nested payloads contain operation-appropriate target/child/exit data.
- Process identity transitions are coherent. For example, on `MAC-MROSS-01`, PID 42171 progresses through launchd, xpcproxy, and Terminal exec targets; subsequent fork/exec records use the corresponding parent and child PIDs. Similar chains appear on `MAC-MROSS-02` around PIDs 18381–18383.
- Endpoint Security `time` uses nanosecond-formatted timestamps, Unified Log uses six fractional digits with an explicit UTC offset, and eCAR uses epoch milliseconds. The streams are ordered and their precisions are plausible for their respective formats.
- SSH evidence has plausible cross-source timing and tuple details. On `MAC-MROSS-01`, the Unified Log records an accepted SSH login from `10.10.1.42` on source port `57317`; the endpoint stream shows the corresponding sshd/session process activity in the same time window. On `MAC-MROSS-02`, an accepted SSH message from `10.10.1.41:50952` likewise fits the endpoint activity window.
- Endpoint Security global sequence numbers are increasing and unique within each file. A few gaps are present; gaps are compatible with collection loss or filtering and are not independently suspicious.
- The eCAR rows use stable UUID-shaped event and object IDs, and process, file, and session records have coherent host, PID, parent, principal, and operation fields in the reviewed examples.

## Detailed Analysis

### macOS Endpoint Security

The two files contain 136 and 167 records. In each, the observed event-type/payload mapping is stable: type 9 records contain `event.exec`, type 11 contain `event.fork`, and type 15 contain `event.exit`. The event payloads include process audit tokens and executable metadata; exec records carry target image, arguments, working directory, and environment, while fork records carry child identity. These are internally consistent shapes rather than generic records with an operation label substituted.

The launch chains demonstrate sensible PID and parent relationships. On `MAC-MROSS-01`, launchd PID 1 forks PID 42171; PID 42171 successively execs xpcproxy and Terminal, then forks PID 42172, which execs login and then zsh as PID 42173. On `MAC-MROSS-02`, the equivalent visible chain is PIDs 18381–18383. The associated eCAR process modifications agree on these PIDs and parent relationships.

Within each Endpoint Security file, timestamps are sorted, global sequence values do not repeat, and the values advance with event time. The observed gaps in global sequence values could reflect incomplete collection; they do not create a visible ordering or lifecycle contradiction.

### macOS Unified Log and SSH

The Unified Log records retain source-specific fields such as `eventType`, `messageType`, `machTimestamp`, `bootUUID`, process and sender image paths, subsystem/category, format string, and rendered message. The few entries are sparse but structurally credible. SSH acceptance messages agree with sshd process activity visible in the endpoint stream, including the remote address and source port in the messages.

### eCAR and activity distribution

The eCAR files contain hundreds of rows per Mac, with process, flow, session, and file objects. The reviewed process records use MODIFY for exec/service-drop transitions and connect those transitions to process IDs, parent IDs, principal changes, image paths, and execution IDs. File operations reference plausible command lines and user principals. Session records distinguish local and remote activity.

The main realism concern is the narrow and repeated user-command mix and regular-looking inventory cadence. These may be valid for a deliberately bounded work period, so they carry moderate rather than decisive weight. No visible timestamp inversion, impossible parent relation, or malformed cross-stream timestamp was established in this review.

## Synthetic Indicator Summary with categories

| Category | Indicator | Strength |
|---|---|---|
| Activity distribution | Similar short command/inspection sequences recur on both Mac endpoints, with a relatively narrow command palette | Moderate |
| Scheduling | Endpoint inventory and `sw_vers` activity recur at regular-looking intervals | Weak to moderate |
| Source coverage | Only a few Unified Log messages accompany multi-hour endpoint timelines | Weak; coverage may be selective |
| Schema and fields | No clear malformed or operation-incompatible payload found in reviewed macOS records | None observed |
| Timestamp/order | No material ordering or precision contradiction found | None observed |
| Cross-source correlation | SSH message and endpoint process activity agree on time and connection details | Evidence against synthetic |

## Realism Score by Category

Scores are 1–10, with 10 representing highly production-like evidence.

| Category | Score | Notes |
|---|---:|---|
| Actual source schemas | 8 | Endpoint Security and Unified Log records retain detailed, source-shaped fields. |
| Timestamp precision and ordering | 8 | Precision is source-appropriate; reviewed streams are ordered. |
| Process ancestry and lifecycle | 8 | Fork/exec identities and parentage are coherent in reviewed chains. |
| IDs and field consistency | 8 | Audit tokens, PIDs, execution IDs, UUIDs, and eCAR process fields align in examples. |
| macOS source semantics | 7 | SSH and process evidence are plausible; Unified Log coverage is very sparse. |
| Activity distribution | 5 | Repeated, narrow command activity and regular inventory cadence feel curated. |
| Overall | 7 | Credible records with moderate distribution and collection-shape concerns. |

## Recommendations

- Broaden the background macOS command and application activity around the focused inspection sequences, while retaining realistic user and host-specific differences.
- Add ordinary Unified Log activity from the same collection period, or make the selective collection boundary evident in the records themselves.
- Vary endpoint inventory timing modestly across hosts and cycles so it does not read as a rigid cadence.
- Preserve the strong operation-specific Endpoint Security payloads, process ancestry, and SSH address/port/timing agreement; these are the most production-like aspects of the reviewed data.
