# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 72
**Synthetic-Confidence Score:** 62

## Executive Summary

The sampled Windows Security/Sysmon, eCAR, Zeek, and macOS Endpoint Security records are generally well-shaped and retain credible identifiers and cross-source relationships. The strongest synthetic indicators are a highly concentrated internal port sweep and sustained random-label DNS activity from one address, plus similar Mac inventory checklists on both hosts. One SMB eCAR login and inbound FLOW share a millisecond timestamp, but matching Windows Security records show the WFP connection before the 4624, so I treat the eCAR equality as a weak precision/timing concern rather than a demonstrated cross-source contradiction.

## Evidence For Synthetic

- [distribution_texture] `zeek-core/conn.json:2765–4033` contains 760 TCP attempts from `10.10.3.10` to `10.10.2.0/24` on ports 22, 445, and 3306 in about 6.2 seconds. The port counts are nearly equal (253, 253, 254); 740 connections are `S0`, and 749 show zero application bytes. The sequence is possible for a rapid discovery sweep, but the near-equal per-port totals and tightly packed target population create a strong generated-distribution signal.
- [distribution_texture] `zeek-dmz/dns.json:689–920` contains 91 random-looking `.top` queries from `10.10.3.10` between 18:00:34 and 18:45:19 UTC, mostly `NXDOMAIN`, with recurring gaps around 20–45 seconds. `snort-perimeter/snort_alert.log:54–66` repeatedly flags `.top` queries from the same source during that interval. The source activity can be malicious, but the long, regular cadence and concentrated participation are conspicuous.
- [distribution_texture] The two Maya Ross histories repeat similar ordered inventory commands. `MAC-MROSS-01.../zsh_history/maya.ross.zsh_history:1–6` records `id`, `sw_vers`, `uname`, `pwd`, `ls` and `du`; `MAC-MROSS-02.../zsh_history/maya.ross.zsh_history:1–5` repeats `sw_vers`, `uname`, `pwd`, `ls` and `du`. Endpoint Security shows the commands actually executed on both systems. This is plausible troubleshooting behavior, but the same narrowly scoped checklist across two machines has templated texture.
- [weak_signal] `DC-02.../ecar.json:1035–1036` gives the matching type-3 SMB USER_SESSION/LOGIN and inbound FLOW exactly the same `timestamp_ms` (`1793629313776`). The rows have the same tuple and the LOGIN is serialized first. eCAR timestamps only resolve to milliseconds; this is not independently enough to establish impossible order, especially because the Windows Security evidence below shows the matching native sequence correctly.
- [weak_signal] In `MAC-MROSS-02.../zsh_history/maya.ross.zsh_history:7–8`, `ps aux` and a PDF `find` command share one second. The Endpoint Security observations for the two commands are only about 22 ms apart (`macos_endpoint_security.ndjson:80,83`), which is consistent with second-resolution history output and is a weak signal only.

## Evidence For Real

- Windows Security, Sysmon, and eCAR retain source-appropriate identities and service fields. On DC-02, Security Event 5156 at `windows_event_security.xml:51455–51490` allows the matching `10.10.1.34:55083 -> 10.10.2.11:445` flow at 14:21:53.121Z; the corresponding 4624 type-3 logon is at `51580–51620`, 14:21:53.215Z, with `WS-DRAMIREZ-01$`, Kerberos, and logon ID `0xcbf622a`. The paired 4634 at `51755–51785` closes that same logon ID at 14:22:05.312Z. These native records support correct authentication ordering and lifecycle.
- The corresponding SMB tuple appears in Zeek at `zeek-core/conn.json:2056` with UID `CAvJYmKBK1q2l1vi84`, `SF`, varied bytes and packets, and a plausible 0.67264-second duration. The workstation eCAR row at `WS-DRAMIREZ-01.../ecar.json:227` is the outbound view of the same tuple; the DC eCAR file contains its inbound view. Exact cross-source matching is positive evidence here, not a synthetic clue.
- macOS process records preserve executable and actor identity across successive execs. The initial local Terminal/login/zsh chain on `MAC-MROSS-01` proceeds at 13:08:00.998–13:08:01.086Z; Endpoint Security rows retain PID, parent, audit-token and PID-version fields through the image transitions. `macos_endpoint_security.ndjson:59` records PID 55151 switching from `/bin/zsh` to `/bin/cat`, and the eCAR file-read record carries the same process identity.
- macOS SSH evidence is temporally and structurally plausible. `MAC-MROSS-01.../macos_unified_log.ndjson:3` records sshd accepting Maya Ross's public key from `10.10.1.42:62470` at 16:02:17.562108Z. The Endpoint Security stream records the corresponding session process chain and the `/bin/zsh` exec at 16:02:17.723014Z; the eCAR session records retain the user and source tuple.
- The Unified Log export uses distinct wall timestamps, boot UUIDs, Mach timestamps, sender paths, process identifiers, and message types. Its AppleSystemPolicy message on `MAC-MROSS-01.../macos_unified_log.ndjson:2` says policy would not allow MeetingAssist; I found no successful child launch in the sampled Endpoint Security sequence and did not infer execution or effects from that message.
- Sampled Windows Event XML and Sysmon rows have expected event-specific fields. Security 4624 includes LogonType, SID, logon ID, source IP/port, and authentication package; Sysmon Event 1 includes process GUID, PID, image, command line, hashes and parent identity, while Event 3 includes typed tuple and `Initiated` fields. Zeek uses numeric timestamps, UIDs, connection state, service, packet and byte counters, and DNS response codes in their normal source-specific shapes.

## Detailed Analysis

### Windows event schemas and session lifecycle

The Windows Security XML contains familiar event families including 4624/4634, 4672, 4688/4689, 4697, 5156, 4768/4769 and 4776. The DC-02 export contains 238 Event 4624 rows, 128 Event 4634 rows, 109 Event 4688 rows, 108 Event 4689 rows and 3,771 Event 5156 rows. These records have monotonic event record IDs in the inspected ranges and ordinary Windows field forms. The sample SMB login's source IP and ephemeral port agree across Security 5156, Security 4624, eCAR and Zeek. Its eCAR login/inbound-flow timestamps tie at millisecond precision, but the native Security evidence places WFP before authentication by roughly 94 ms; the tie does not establish an impossible system chronology.

The DC-02 Sysmon stream has Events 1, 3, 5, 7, 8, 10, 11, 13 and 22. A sampled Event 3 has a complete process GUID, PID, protocol, initiated flag, source/destination IPs and ports. The sampled process-create records retain parent GUID/PID and command-line fields. I did not identify a demonstrated event-ID/field-shape contradiction in these samples.

### macOS Endpoint Security and Unified Log

Both Endpoint Security exports declare schema version 1 and message version 11, with the observed fork, exec and exit event types. Exec targets use separate target audit tokens and updated PID versions while preserving the process PID where appropriate. The Mac histories align with Endpoint Security execution observations. Their two-command same-second history entry is explained by the history's second-level timestamp and the native events' subsecond spacing; I do not count it as an impossible ordering.

Unified Log records distinguish the writer/sender image from the message text and retain the same boot UUID per host in the inspected records. The accepted SSH authentication and subsequent shell exec appear in that order. The policy message is not treated as proof that a program ran or that an effect occurred.

### Network records and distribution

Zeek's core, DB and DMZ connection records show completed, failed, reset and rejected states; incomplete sessions commonly have `S0`, SYN-only history and zero payload bytes, while established sessions carry byte/packet counts and duration. The notable distribution feature is not an invalid Zeek field: it is the short, near-equal three-port scan from `10.10.3.10`, plus the long stream of random-label `.top` queries from that same source and repeated Snort alerts. Those records could describe compromised-host activity, but their regular timing/count shape is the main reason I did not call the dataset fully production-like.

### Mac user activity

Maya Ross's two zsh histories show similar system-inventory commands and SSH pivots. The files are user histories with second-resolution timestamps, and the observed Endpoint Security records support that the commands ran. The repetition is the concern; I found no evidence that the history rows are fabricated independently of host execution or that their timestamps invert a visible process lifecycle.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected the score |
|---|---|---|---|
| `distribution_texture` | Zeek conn.log | One source, 10.10.3.10; ~760 attempts across 22/445/3306 in ~6.2 seconds | Near-equal target-port counts and mostly S0/zero-byte rows are unusually concentrated. |
| `distribution_texture` | Zeek DNS and Snort | One source, 10.10.3.10; 91 `.top` queries over ~45 minutes | Random-looking labels recur on a narrow cadence and draw repeated IDS alerts. |
| `distribution_texture` | macOS shell history and Endpoint Security | Two Maya Ross Macs | Similar ordered inventory checklists recur across hosts and are confirmed in process telemetry. |
| `weak_signal` | eCAR session/flow and zsh history | One SMB tuple; one same-second command pair | Same-ms eCAR timestamps and second-resolution history output leave a small timing ambiguity; other native evidence is coherent. |

## Realism Score by Category

- **Field format accuracy:** 8 — Sampled Windows XML, Sysmon, eCAR, Zeek, Unified Log and Endpoint Security fields are well-formed and source-appropriate.
- **Temporal patterns:** 7 — Most sampled process, auth and network lifecycles are plausible; one eCAR tuple is equal at millisecond resolution and the suspicious network cadences are repetitive.
- **Cross-source correlation:** 9 — SMB, Windows Security, eCAR, Zeek and macOS process/session pivots align on concrete identities and tuples.
- **Behavioral realism:** 6 — Both routine host activity and suspicious traffic exist, but the two-host Mac checklist and concentrated scan/DNS patterns are conspicuous.
- **Environmental consistency:** 7 — The visible Windows, Linux, macOS, proxy, DMZ and database roles mostly fit; the suspicious activity is unusually concentrated on one address.

## Recommendations

- If this were synthetic, vary scan target/port selection and pacing enough to avoid almost equal port counts in a six-second burst; retain the realistic TCP states and packet accounting.
- If this were synthetic, vary endpoint participation and cadence for the random-label DNS family, while preserving the valid DNS and alert tuples.
- If this were synthetic, vary the routine Mac inventory checklist between sessions and hosts while retaining the process/history identity links.
- If source-native eCAR ordering is expected to distinguish transport from authentication at millisecond precision, preserve a visible positive interval when that can be supported by the underlying event timing. The matching Windows Security 5156/4624 order is already correct, so the observed eCAR tie alone is not a proven contradiction.
