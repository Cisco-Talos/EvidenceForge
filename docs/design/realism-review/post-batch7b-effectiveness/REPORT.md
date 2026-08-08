# Post-Batch-7b effectiveness assessment

## Outcome

The completed architecture and remediation work made real mechanical improvements, but this
one-pass assessment does **not** demonstrate a material improvement in aggregate blind realism.
The latest panel's average synthetic-confidence score is **90.0** (lower is better), compared with
**91.75** before remediation and **90.75** at the final post-fix gate. The differences are too small
and the panels too independent to support a causal claim of improvement.

The branch is **not ready for its PR to `dev`**. A controlled Batch 7a versus Batch 7b run found a
new deterministic SSH source-order regression, and the fresh panel identified four additional
release-blocking shared-contract defects. Per the approved assessment scope, this report records
those results without starting another fix/regenerate/review loop.

## Frozen measurement

- Commit: `53934a16778c5eea22e389c0d7d80061103e730e` on
  `codex/batch7-compatibility-docs`.
- Benchmark: the frozen six-hour `branch-enterprise` review scenario, SHA-256
  `bf7eef77f0cb121bb0838cc4252ae19347e1a8c8304079c11426163806cc07ff`, using
  `enterprise_standard` observation.
- Output: 53,548 records in 38 data files. The primary and repeat data trees have the same digest,
  `911decaca74f1b2663d6508d2e99eed861a247ffbdd76c34ed6f9cbcb803e67f`.
- Isolation: each reviewer received only a neutral data directory, not the scenario, ground truth,
  source code, prior results, or another reviewer's report.
- Scope: effectiveness measurement only. No generator change or blind-review repair loop was made.

The archived `iteration-test-expanded` scenario offered by the user no longer validates unchanged
under the current capability rules. The exact integrated review benchmark was therefore used; this
preserves the most useful pre-fix comparison and avoids editing the scenario to make it pass.

## Scores

Blind synthetic-confidence is the primary comparison metric; lower means the reviewer found the
data more realistic.

| Checkpoint | Threat | Detection | Network | Host/EDR | Panel average |
| --- | ---: | ---: | ---: | ---: | ---: |
| Original pre-fix | 88 | 96 | 86 | 97 | **91.75** |
| Post-Batch-2 | 98 | 95 | 94 | 99 | **96.50** |
| Post-gate loop 3 | 72 | 74 | 84 | 85 | **78.75** |
| Final post-fix gate | 96 | 85 | 96 | 86 | **90.75** |
| Post-Batch-7b | 72 | 96 | 96 | 96 | **90.00** |

The latest score is 1.75 points better than the original pre-fix score and 0.75 better than the
final post-fix gate, but 11.25 worse than the best recorded intermediate checkpoint. These are
directional observations, not controlled effect sizes: each panel was independent, generated
content and record counts changed, and evaluator behavior also changed during the campaign.

The latest deterministic evaluator scored **95.0256** over 53,548 records. Its only failed
acceptance criterion was `causality.pivot_linkability` at 40 against an 80 threshold. Because the
hard gate and evaluator implementation changed during remediation, this automated score should not
be read as a direct before/after comparison.

The assessment-style comparison image is preserved as
[`effectiveness-dashboard.png`](effectiveness-dashboard.png), with an editable
[`SVG`](effectiveness-dashboard.svg). Its numbered checkpoints map to the five rows above; the
source values are in [`comparison.json`](comparison.json).

## Blind panel

All four reviewers independently returned **Synthetic**. Average verdict confidence was 94.25 and
the synthetic-score spread was 24, so the established deliberation conditions were not met.

| Reviewer | Verdict confidence | Synthetic confidence | Main decisive evidence |
| --- | ---: | ---: | --- |
| Threat Hunter | 84 | 72 | SMB byte conservation, bounded Type 3 durations, unclosed compromised SSH lifecycle |
| Detection Engineer | 98 | 96 | inbound WFP remote-PID leakage, clock-derived Linux PIDs, formulaic Windows LogonIDs |
| Network Forensics | 97 | 96 | SMB/HTTP framing and loss contradictions, missing Zeek gap history, quantized TLS durations |
| Host/EDR | 98 | 96 | inbound WFP remote-PID leakage, clock-derived Linux PIDs, accumulating singleton services |

The individual evidence and counterevidence are preserved in the four reviewer reports in this
directory. Strong areas remain: source-native envelopes, Windows process joins, identity and hash
stability, connection state/packet minima, DNS/TLS/certificate semantics, firewall/NAT topology,
and many SSH/RDP transport-to-session relationships.

## Controlled Batch 7b effect

Running the same scenario through archived Batch 7a code under the current dependency environment
separated a Batch 7b regression from general benchmark variation:

- Batch 7a produced one Linux PID reversal finding and no SSH syslog/process ordering finding.
- Batch 7b removes that PID reversal.
- Batch 7b produces 37 same-PID SSH syslog rows before the corresponding eCAR process creation on
  `PROXY-BO-01` and `WEB-BO-01`. The primary and repeat runs reproduce the same two host families.

This establishes that Batch 7b was not behavior-neutral: one contract defect was repaired, but the
semantic-identity/source-timing migration introduced an observable lifecycle-order regression.

## Validated release blockers

### P7B-REG-001 — SSH source-order regression (P1)

- **Invariant:** a source-native SSH message cannot reference an sshd child PID before that
  provider's process-create observation for the same PID.
- **Evidence:** 9 proxy and 28 web syslog records fail; repeat generation is identical, while the
  controlled Batch 7a output has none.
- **Owner:** SSH action-bundle constraints and source-timing planning, not a syslog text renderer.
- **Required proof:** targeted source-order tests across both observation profiles and controlled
  Batch 7a/B7b-equivalent probes.

### P7B-REAL-001 — inbound WFP process ownership (P1)

- **Invariant:** Windows Event 5156 on a receiver must identify the local receiving process, never
  combine the local image with a remote host's PID.
- **Evidence:** detection and host reviewers independently found thousands of inbound records where
  the PID equals the remote initiator. Some `Application=System` records use Linux-sized PIDs.
- **Owner:** `WindowsEventEmitter._render_wfp_connection()` uses
  `network.initiating_pid` even for inbound projection, despite the canonical occurrence carrying
  the local process image.
- **Required proof:** inbound/outbound 5156 matrix tests for Windows-to-Windows and Linux-to-Windows
  traffic, including PID 4/System and DNS service ownership.

### P7B-REAL-002 — file/transport/capture-loss conservation (P1)

- **Invariant:** application framing plus observed file bytes must fit within directional transport
  payload, and capture loss must propagate coherently into file/application completeness and Zeek
  history.
- **Evidence:** 22 SMB files exceed directional payload; 172 more exactly equal it with no SMB
  framing. A fully observed 93.6 MB HTTP body coexists with connection loss and zero header room.
- **Owner:** file-transfer and network transaction plans independently assign file size, transport
  payload, and `missed_bytes`.
- **Required proof:** byte-conservation property tests for SMB/HTTP in both directions, with loss,
  truncation, framing, sensor projection, and files/HTTP/conn fan-out.

### P7B-REAL-003 — clock-derived Linux PIDs (P1)

- **Invariant:** PID progression must reflect host process-allocation state, not reveal a direct
  wall-clock formula.
- **Evidence:** both Linux hosts advance at essentially two PIDs per second for six hours, with
  regression R-squared above 0.99999999.
- **Owner:** `StateManager._allocate_linux_pid()` explicitly derives `time_offset` from elapsed
  seconds despite its contrary docstring.
- **Required proof:** deterministic host-scoped allocation tests with workload-sensitive gaps,
  non-regression under out-of-order event planning, reuse/wrap behavior, and duration-stable state.

### P7B-REAL-004 — SSH closure ownership (P1)

- **Invariant:** a normally closed modeled SSH transport must have lifecycle-compatible endpoint,
  PAM, logind, shell, and session closure unless one coherent observation decision drops the group.
- **Evidence:** the compromised `www-data` transport closes normally in Zeek and ASA, but its
  endpoint session and processes remain open despite more than four hours of later logging.
- **Owner:** the world-planner SSH path delegates to a bundle whose close emission defaults false;
  a session-end plan schedules state but does not itself dispatch the close lifecycle.
- **Required proof:** explicit, baseline, compatibility, and SCP SSH matrices covering normal FIN,
  reset, boundary-open, planned logoff, and coherent observation drop.

## Secondary validated risks

- Type 3 Windows sessions show strong 30- and 60-second population ceilings. Replace per-call
  uniform duration sampling with service/channel reuse and a heavy-tailed lifecycle model.
- Singleton Windows services and GUI clients can accumulate parallel live instances. Durable
  application/service state should decide reuse, restart, or termination before a new start.
- Linux service chatter and administrator SSH cadence remain template-shaped and too frequent.
- Repeated TLS durations and near-identical Windows LogonID slopes expose additional quantization
  and formula texture.

These are legitimate follow-up work, but they do not become a separate blind-review-driven loop.
The reviewed remediation roadmap remains the governing plan; this gate adds verified regression
and release-blocker evidence to it.

## Decision and next action

The evidence supports neither “the changes had no effect” nor “the changes improved aggregate
realism.” The accurate conclusion is:

1. The architecture work improved ownership, immutability, deterministic identity, and bounded
   lookup behavior, and specific previous contradictions were repaired.
2. Those gains did not translate into a measurable aggregate blind-authenticity improvement in
   this benchmark.
3. Batch 7b introduced one controlled source-order regression, while several high-impact existing
   owner defects remain visible.

Before opening the cumulative PR to `dev`, address the five P1 release blockers in dependency
order: identity/state allocation, network/file accounting, inbound Windows projection, SSH source
ordering, then SSH closure. Validate them with deterministic invariant tests and one integrated
regression generation. A second blind panel is optional future assessment, not a condition of this
one-pass effectiveness measurement.

Machine-readable scores, comparison inputs, reproduction details, and exact artifact paths are in
[`scores.json`](scores.json), [`comparison.json`](comparison.json), and
[`results.json`](results.json).
