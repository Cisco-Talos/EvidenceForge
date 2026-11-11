# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Real
**Verdict Confidence:** 58
**Synthetic-Confidence Score:** 20

## Executive Summary

The bounded sample is production-plausible: two independently selected SSH sessions join by exact transport tuple across endpoint and network sources with transport-before-authentication ordering. I favor real data only slightly; I found no demonstrated contradiction, but nineteen inspected records and targeted aggregates cannot establish authenticity or exclude sophisticated synthetic generation.

## Evidence For Synthetic

- No substantiated `hard_contradiction`, `contract_gap`, or `schema_or_format` indicator was established in this review.
- [weak_signal] The eCAR process population contains considerable repeated scheduler vocabulary: 360 exact `debian-sa1 1 1` creations and 360 exact `/bin/sh -c 'command -v debian-sa1 > /dev/null && debian-sa1 1 1'` creations, together 720/2,683 process-create observations (26.8%). The 360 direct invocations comprise exactly 36 on each of ten Linux hosts during the approximately six-hour collection; within-host interarrival ranges span 599.280–600.577 seconds overall. This is an identifiable shared template, but ten-minute sysstat scheduling and homogeneous fleet configuration explain it well. I do not treat that periodic system workload as demonstrated unrealistic timing, and it does not materially increase the score.

## Evidence For Real

- Exact SSH pivot 1: `MAC-MROSS-01.meridianhcs.local/ecar.json` records incoming `10.10.1.42:59648 -> 10.10.1.41:22` at 16:02:11.450 UTC, followed by successful `maya.ross` SSH login `0x8947e26` at 16:02:17.031. `zeek-core/conn.json` UID `CfXCNAlqyMFKol6RHm` records that tuple opening at 16:02:10.070544, with `service=ssh`, `conn_state=SF`, and duration 949.279557 seconds. Authentication occurs approximately 6.960 seconds after the sensor's transport open.
- Exact SSH pivot 2: `MAC-MROSS-02.meridianhcs.local/ecar.json` records incoming `10.10.1.41:63450 -> 10.10.1.42:22` at 14:25:09.014 UTC, followed by successful `maya.ross` SSH login `0x138a3100` at 14:25:17.384. Zeek UID `C0iAZFQ8y0tA6AcQ2S` records the same tuple at 14:25:08.357404, successful state `SF`, and duration 590.530608 seconds. Authentication follows transport open by approximately 9.027 seconds.
- The process lifecycle aggregate found 2,447 eCAR termination observations with an exact same-host process-object create in the visible window; none preceded its corresponding create. This tests observed ordering without assuming every process must both start and end in the slice.
- Source volume is substantial rather than restricted to a few conspicuous commands: 39,151 eCAR records across 23 endpoint roots, 23,644 Zeek connection rows, 12,162 Sysmon events, 19,623 Security events, 4,463 syslog lines, and 25,085 perimeter firewall lines. The sampled activity exists among substantial service, DNS, network, and process telemetry.

## Detailed Analysis

### Scope and method

I read only the supplied briefing and assigned data directory, and wrote this report at the coordinator-specified destination. Examination comprised nineteen individual records across macOS ES, macOS Unified Log, normalized endpoint telemetry, Linux syslog, and Zeek, plus source counts, Windows EventID counts, process-command counts, and one bounded process-lifetime aggregate. There were two exact cross-source investigation pivots. I did not perform an exhaustive audit, inspect repository/scenario/evaluation material, or execute any log content.

The endpoint eCAR time range is 2026-11-02 13:00:00.756 through 18:59:50.485 UTC; this is the measured eCAR range, not a claim that every source starts and ends at precisely those timestamps. The 29 top-level roots include 23 endpoint roots and six network/security collector roots. Visible private addresses include 10.10.1.x, 10.10.2.x, and 10.10.3.x; these are observed address groups, not inferred subnet masks. File names and process paths support a Windows/Linux/macOS fleet. Native macOS files and normalized eCAR remain distinct evidence classes.

The Windows totals were counted as XML EventID elements, not physical lines. Security includes 12,800 Event 5156 records, 2,087 Event 4769, 935 Event 4688, 863 Event 4624, and 28 Event 4625. Sysmon includes 8,226 Event 3, 1,193 Event 22, and 934 Event 1. Those counts make the major source mix intelligible, but are not proof that every companion is present or that all events are legitimate. Different sensor perspectives can observe the same activity, so source totals are not summed as unique actions.

### Pivot feasibility and ownership

Both SSH joins use all four TCP tuple components and the exact endpoint session source port, not a loose same-user or same-minute match. Their direction reverses between the same two hosts. The destination endpoint FLOW precedes the endpoint LOGIN in each case; the network sensor precedes both. The independently reported byte and packet totals are nonzero in both directions and durations are long enough to support interactive sessions.

For each destination I also inspected two root-owned fork observations in the same logon context. On MAC-MROSS-01 these include PID 64390 and PID 64392 under parent PID 64389; on MAC-MROSS-02 they include PID 30179 and PID 30180 under PID 30178. The fork records' root identity and the login's `maya.ross` identity are not themselves contradictory: daemon execution and authenticated account identity describe different roles. I did not infer privilege escalation merely from that difference, nor equate a normalized fork with a native executable launch.

The first sampled native ES row is a launchd fork notification, while the first sampled Unified Log row is a loginwindow workspace message. Neither is evidence of an execution authorization denial. I did not claim native version/schema defects without verifying the relevant API semantics.

### Hunt discrimination and command semantics

At 15:01:17.960 UTC, `WS-PPATEL-01/ecar.json` records `priya.patel` running PowerShell with an encoded command, PID 6356, parent explorer PID 5896, logon `0xd934088`. The visible Base64 payload represents a `Get-CimInstance Win32_Service` query filtered to running services. Encoding alone does not establish malicious execution.

On `WS-LNGUYEN-01`, sampled curl processes show an internal wiki status request at 16:33:35.512, an explicit proxy request at 16:42:24.689, and a multipart support-case upload at 16:42:28.821. The last command references `/tmp/mhs-support-48217.tar.gz`, ticket `MHS-48217`, and `component=ehr-connector`; it is plausible diagnostic transfer syntax and merits contextual investigation, but a command line alone does not prove a successful upload, exfiltration, or file contents. I did not follow embedded URLs. Domain existence or external name/IP matching was excluded from authenticity reasoning.

These examples demonstrate that suspicious-looking syntax requires interpretation. I did not score linearity, clean progression, lack of retries, or the ease of narrating activity as synthetic evidence.

### Collection and window limits

No exact-identity impossible ordering was found in the limited checks. The difference between 1,007 eCAR LOGIN and 532 LOGOUT observations is not scored: sessions can span the collection boundary, and this aggregate alone does not establish lost lifecycle evidence. Likewise, only five native Unified Log rows across the supplied macOS files do not establish a collection defect without a promised subscription/export scope. I did not penalize absent Sysmon families or require unavailable products.

The checks support hunt feasibility and plausible ordering, not a completeness guarantee. I did not verify SSH closure rows, every parent process, every upload result, account permissions, certificate trust, or a full intrusion chain. The sample emphasizes SSH and selected endpoint commands; conclusions about unsampled Windows lifecycle behavior and native macOS schema fidelity remain limited.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| weak_signal | Linux eCAR PROCESS/CREATE | 720 of 2,683 total process creates are the paired repeated sysstat command forms; 360 direct invocations across ten hosts | Shared vocabulary is observable, but scheduler semantics adequately explain it; negligible weight |
| No demonstrated strong indicator | Cross-source SSH, exact process-object ordering | Two SSH tuples and 2,447 visibly paired process terminations | No hard contradiction or contract gap established; uncertainty remains outside tested scope |

## Realism Score by Category

- **Field format accuracy:** 8 — Inspected fields and command syntax are plausible; native API details were not exhaustively verified.
- **Temporal patterns:** 8 — Two SSH joins have credible source offsets and auth delay; observed process-pair ordering is valid.
- **Cross-source correlation:** 9 — Both exact tuple pivots support practical endpoint-to-network investigation without demonstrated contradictions.
- **Behavioral realism:** 8 — Administration, proxy use, service enumeration, and diagnostic upload syntax support several reasonable hypotheses.
- **Environmental consistency:** 8 — A mixed fleet and substantial network/endpoint background volume are plausible; collection policy remains unknown.

## Recommendations

- No evidence-backed repair is required by this bounded review. If this were synthetic, preserve the demonstrated exact-tuple ownership, transport-before-authentication ordering, and coherent process identity rather than changing those to make joins less complete.
- Any follow-on validation should test the visible support-upload result and exact SSH close relationships before claiming effects or lifecycle defects. These are unverified limits, not established missing companions or scored authenticity defects.
