# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive  
**Verdict Confidence:** 72  
**Synthetic-Confidence Score:** 56

## Executive Summary

The dataset is SIEM-usable and shows strong, specific cross-source correlations across Windows process telemetry, eCAR, macOS endpoint records, and Zeek. I found no demonstrated source-native contradiction; the main synthetic tell is a highly regular macOS process-exit cadence on two hosts immediately before each user-session logout, though orderly logout and collector serialization are plausible alternatives. That evidence supports a mixed assessment rather than a confident synthetic verdict.

## Evidence For Synthetic

- [distribution_texture] In `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson`, ten exit events occur during 18:54–18:55 UTC. The final ten are spaced roughly 0.06–0.13 seconds apart, from `/bin/zsh` at 18:54:58.884 to Terminal at 18:54:59.800. On `MAC-MROSS-02`, fifteen app/session exits from 18:56:58.318 to 18:56:59.782 are mostly spaced about 0.08–0.12 seconds apart. The corresponding eCAR process terminations form similar tight sequences immediately before the 18:55:01.020 and 18:57:03.134 session logouts. Repetition on two Macs suggests serialized lifecycle generation or collection. This is a weak indicator because orderly logout can close many applications together, and the eCAR records corroborate the same process lifecycles.
- I found no hard contradiction or impossible visible event ordering in the samples reviewed. The synthetic-confidence score is therefore not driven by the coherent attack narrative, complete matching, file timestamps, or absent out-of-window initiators/terminators.

## Evidence For Real

- Windows Security and Sysmon process records use plausible source-native layouts, including hexadecimal Security process IDs versus decimal Sysmon PIDs, well-formed SIDs/GUIDs, and system paths appropriate to Windows Server 2022 and Windows 11 records. Across the paired Windows hosts, 867 Sysmon Event ID 1 records and 867 Security Event ID 4688 records were present; nearly all process creations matched by PID and image. A few unmatched records are compatible with ordinary collection differences and are not treated as authenticity defects.
- The DC-01 account-change sequence is represented with consistent identities and timing in Security, Sysmon, and eCAR. At 17:14:32–17:14:40 UTC, the command creates `svc_dirsync`, adds it to Domain Admins, and emits matching account/group change records. PIDs 4936/4952 and 4956/4964 align across eCAR, Sysmon, and Security. eCAR records the WmiPrvSE parent as `NETWORK SERVICE` and the child command as `SYSTEM`; this agrees with the process-parent evidence and does not by itself imply an identity contradiction. The account is deleted at 18:50:02–18:50:06 UTC, with matching process and account-deletion records.
- The macOS SSH sessions show strong event-level correlation without relying on completeness as an authenticity test. For the 14:24 session, eCAR records the outbound flow from `10.10.1.41:53075` to `10.10.1.42:22` at 14:24:37 and the inbound flow on MAC-MROSS-02 at 14:24:36; the remote login follows at 14:24:42. Unified Log records acceptance from the same source address and port at 14:24:42. Zeek records the same tuple starting at 14:24:35 with an `SF` state and 623-second duration. The reverse-direction session at 16:02 also aligns across the Mac eCAR records, Unified Log, and Zeek.
- Zeek source records have useful join integrity: all 3,082 core DNS, 2,138 HTTP, 312 SSL, 720 files, 207 SMB-files, and 123 SMB-mapping UID references resolve to a `zeek-core/conn.json` UID; the DNS, HTTP, SSL, and files UIDs in the DMZ and DB partitions also resolve to their respective connection records. This improves detection pivots; complete matching alone is not scored as synthetic.
- Visible activity is not just a compact storyline. The directory contains 114 files across endpoint, network, firewall, proxy, IDS, web, history, and syslog sources. The three Zeek connection partitions contain 11,972 core, 9,220 DMZ, and 420 DB records. Core connection states include 9,711 `SF`, 1,893 `S0`, and smaller counts of resets/rejections; core DNS includes 229 `NXDOMAIN` and 11 `SERVFAIL` answers among 3,082 records. These distributions provide background volume and negative outcomes useful for alert tuning.
- The two Macs’ histories and endpoint records contain ordinary interactive commands, app launches, process exits, and file activity alongside SSH sessions. Unified Log has only 2–3 records per Mac, but the visible inbound SSH sessions have corresponding SSH acceptance messages; sparse coverage alone is not evidence against authenticity.

## Detailed Analysis

### Windows event and process fields

I parsed the Windows XML event records rather than relying on filenames or line counts. DC-01 contains 121 Sysmon Event ID 1 and 121 Security Event ID 4688 records; DC-02 contains 133 of each; Windows member systems contain comparable per-host process-event volumes. Event IDs and the sampled field shapes are internally coherent. For example, DC-01 Security 4688 at 17:14:32.3059896Z reports `cmd.exe` PID `0x1348` (4936), and the child `net.exe` PID `0x1358` (4952) at 17:14:32.4669345Z. Sysmon Event ID 1 at 17:14:32.3834400Z reports that same `net.exe` PID and command. eCAR reports the corresponding process creation at 17:14:32.271Z. Subsequent `net group` process creation and the 4728 membership record follow in causal order.

Security 4720, 4724, 4738, and 4728 records for `svc_dirsync` occur from 17:14:36.236Z through 17:14:40.683Z. Security 4728 identifies `Domain Admins` with the expected built-in group SID suffix `-512`, and the member SID matches the account’s 4720 SID ending `-5861`. At 18:50:02.765Z, the delete command is represented in Security 4688 and Sysmon Event ID 1; Security 4726 follows at 18:50:06.781Z. The password-bearing command line is a high-value detection signal, not a synthetic indicator by itself.

Some Windows PID/image pairs do not have a same-PID partner in the paired file, such as Sysmon Event ID 1 for `svchost.exe` PID 6844 on WS-PPATEL-01 at 18:14:48.197Z. There are only a few such unmatched samples among more than a thousand process events. Given the selected collection scope and possible event loss, I do not classify these as contradictions.

### macOS Endpoint Security, Unified Log, and eCAR

The Endpoint Security NDJSON files contain 140 records on MAC-MROSS-01 and 164 on MAC-MROSS-02. Observed event types are 9, 11, and 15, with process actor/target data, audit tokens, PID versions, executable paths, and timestamps. I did not verify these fields against an external OS-version schema; no schema error is asserted. Unified Log records use separate writer/process and message fields, and the SSH messages agree with eCAR and Zeek session evidence.

The two final process-exit series are the only notable timing texture I found. On MAC-MROSS-01, Endpoint Security exits precede matching eCAR process-termination records by fractions of a second; the local session logout is at 18:55:01.020Z. MAC-MROSS-02 shows the same pattern before its 18:57:03.134Z logout. The orderly lifecycle is plausible, but the near-regular spacing across two independent hosts mildly reduces confidence in production provenance. The visible logs do not prove whether this spacing comes from the application shutdown sequence or from the event generator/collector.

### Network and SIEM pivots

The `zeek-core`, `zeek-dmz`, and `zeek-db` connection files show mostly successful `SF` records, a substantial `S0` population, and smaller reset/rejection states. Duration tails include multi-hour SSH sessions; those flows begin inside the visible period and can validly continue beyond it. DNS records include positive, negative, and failed resolutions; measured core DNS RTT has a sub-millisecond median and a 3.3-millisecond 90th percentile. I did not treat domain naming or external resolution as authenticity evidence.

UID joins between connection, DNS, HTTP, SSL, and file records support practical SIEM pivots. The macOS SSH tuple example above also shows that endpoint flow, authentication, and network timing agree within seconds. This demonstrates detection usefulness, but complete reference integrity is not a synthetic clue under the study rules.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected the score |
|---|---|---|---|
| `distribution_texture` | macOS Endpoint Security and eCAR | MAC-MROSS-01 and MAC-MROSS-02, at session end | Both hosts show near-regular, sub-second termination series immediately before session logout. The repetition is mildly generator-like, but orderly logout and collector serialization remain plausible explanations. |

## Realism Score by Category

- **Field format accuracy:** 8 — Sampled Windows XML, Zeek JSON, eCAR JSON, macOS NDJSON, and shell-history records have coherent source-specific field shapes and types.
- **Temporal patterns:** 7 — Most sampled process, SSH, account-change, and network sequences are causally ordered; the repeated macOS end-of-session cadence is a mild distribution concern.
- **Cross-source correlation:** 9 — PID, process, SSH tuple, authentication, account/SID, Zeek UID, and eCAR relationships support useful pivots. Matching is treated as positive usability evidence, not as a synthetic tell.
- **Behavioral realism:** 7 — The visible endpoint and infrastructure activity has varied background behavior and actionable signals; the synchronized macOS sign-outs are plausible but unusually regular.
- **Environmental consistency:** 8 — Windows, Linux, and macOS records match their visible host roles, and network views cover core, DMZ, and DB segments. No missing source is penalized without a required companion or demonstrated volume contradiction.

## Recommendations

- If this were synthetic, vary the process-exit timing around the two macOS logouts or model the actual application shutdown sequence. The current roughly 0.06–0.22-second spacing repeats on both hosts and is the clearest visible distribution artifact.
- If the shutdown cadence reflects collector serialization rather than host behavior, preserve that provenance in the export/collection model so downstream detections do not interpret it as a host-native event-timing pattern.
