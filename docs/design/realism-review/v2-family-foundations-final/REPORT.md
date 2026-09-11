# V2 family foundations final assessment

## Outcome

The bounded V2 family-foundations implementation closure is complete. Automated evaluation passed at
**96.89649234949579** over 88,187 records, with no failed hard criteria. The four frozen blind
synthetic-confidence scores were **66, 94, 47, and 96**, averaging **75.75**. Lower is more
production-like. This is 6.25 points worse than this effort's immediate Loop 30 baseline of 69.5,
but 17.5 points better than the later post-P1-blockers checkpoint at 93.25. It is therefore not a
clean blind-improvement result.

The reviewers did not find the dataset indistinguishable from production. Three initially returned
Synthetic and the network reviewer returned Inconclusive. Because the verdicts differed and the
score spread was 49, the protocol required deliberation. After the endpoint findings were shared,
all four converged on Synthetic, with final scores of 85, 95, 78, and 97. Trend comparison uses the
independent initial scores; deliberation records how evidence changed the panel's interpretation and
is not substituted into that measurement.

The definitive output is `/private/tmp/eforge-v2-final-a12.HrzaXo`; the independent
`PYTHONHASHSEED=99991` repeat is `/private/tmp/eforge-v2-final-b1.Lxe3fn`. Their complete data and
artifact trees are byte-identical. Only the generation manifest's expected `created_at` value
differs. Generated datasets remain untracked; durable normalized manifest and data-tree digests are
preserved in [`generation-evidence.json`](generation-evidence.json).

The user-approved bounded closure supersedes the older worklog contract that would have added an
A/B panel, effectiveness dashboard, dev sync, push, and draft PR. This closure intentionally uses
two final generations, one evaluation, one isolated blind panel with required deliberation, durable
reports, and one local commit. It closes the implementation effort as a documented roadmap pivot;
it does not claim blind improvement against Loop 30 or authorize external delivery.

## Individual expert summaries

- **Threat Hunter — Synthetic, 82% verdict confidence, 66 synthetic confidence.** The hunter found
  strong hunt pivots, realistic network accounting, and meaningful baseline noise. The deciding
  defects were a collapsed reverse-shell pipeline, module loads after process termination, dense
  repeated command texture, and missing NTP despite visible chrony activity.
- **Detection Engineer — Synthetic, 98% verdict confidence, 94 synthetic confidence.** The
  detection review found the logs parseable and generally source-accurate, with excellent Zeek UID
  integrity and useful Windows correlations. Widespread future-valued Sysmon `UtcTime`, empty
  successful-logon fields, incorrect FILE-SRV workstation semantics, RDP lineage gaps, and the
  post-termination module sequence were decisive.
- **Network Forensics — Inconclusive, 82% verdict confidence, 47 synthetic confidence.** Network
  behavior was the strongest family: TCP state/history, DNS texture, TLS/certificate semantics,
  DHCP renewal jitter, OS-aware source ports, proxy byte accounting, and sensor-specific views were
  convincing. Repeated proxy-origin TLS before the only visible DNS answer and total NTP absence
  kept it from a Real verdict.
- **Host/EDR Forensics — Synthetic, 99% verdict confidence, 96 synthetic confidence.** The endpoint
  review independently confirmed widespread impossible Sysmon timestamps, then added cross-build
  `winlogon.exe`/`userinit.exe` hash reuse, RDP bootstrap ancestry through PID 4, blank Windows
  identity fields, child-before-parent Security records, and post-termination eCAR module loads.

## Deliberation findings

The facilitator reconciled the disagreement without erasing the network review's positive result.
The network reviewer revised to Synthetic because the independently corroborated endpoint
timestamp and lifecycle contradictions cannot be explained by DNS cache state, filtering, or
sensor placement. The panel retained proxy DNS ordering, NTP coverage, and command texture as
lower-confidence realism findings. The final consensus was driven by source-native impossibilities,
not by complete correlation or an easy-to-follow narrative.

## Prioritized improvements

- **P0 — Canonical Windows occurrence and lifecycle ordering.** Derive Sysmon payload time,
  provider time, Security time, and dependent events from one canonical occurrence. Reject rows
  published before their claimed occurrence, child-before-parent events, dependents before process
  creation, and process-owned events after termination.
- **P1 — Complete Windows session and authentication identity.** Route RDP bootstrap through
  `smss.exe -> winlogon.exe -> userinit.exe -> explorer.exe`; preserve parent and subject identity
  across Security, Sysmon, and eCAR; populate Type 3/10 logon fields with native values or
  sentinels; and derive remote `WorkstationName` from the initiator.
- **P1 — Build-aware binary and execution/effect identity.** Bind Windows system-binary metadata
  and hashes to the OS build. Model shell pipelines as actual process trees and attach sockets and
  file effects to the descendant that performs them.
- **P2 — Explicit proxy DNS cache causality.** Require a still-valid cached answer or a completed
  lookup before proxy-origin connection open, including explicit expiry and stale-refresh state.
- **P3 — Infrastructure and human texture.** Add low-volume role-appropriate NTP when it is within
  collection scope, and diversify administrator command habits, pacing, task focus, and mistakes.
- **P4 — Preserve proven strengths.** Keep sensor-specific observations, protocol-child ownership,
  OS-aware source ports, varied TCP outcomes, TLS certificate behavior, DHCP jitter, cross-source
  tuples, SSH/SCP, proxy accounting, service installation, and audit-clear semantics under
  regression coverage.

## Priority rationale

The ordering follows expected synthetic-score leverage. The widespread Sysmon contradiction is
both independently reproduced and impossible, so it outranks narrower schema and ownership gaps.
Windows identity and build-aware execution paths come next because they affect high-value endpoint
pivots across several hosts. Proxy cache ordering is important but partially explainable by unseen
cache state. NTP and command texture remain useful realism work, but neither drove consensus.

## Comparison with quantitative evaluation

The evaluator correctly confirmed high parseability, cross-source causal support, IDS integrity,
and intent reconciliation. The panel likewise praised tuple integrity, source-native protocol
structure, and operational huntability.

The main disagreement is coverage, not arithmetic. Automated causality scored 95.2022 and its
causal-ordering check passed 11,295/11,295, yet reviewers found future-valued Sysmon occurrence
times, child-before-parent Security events, and module loads after termination. The evaluator also
did not surface cross-build bootstrap hashes, blank Windows authentication fields, proxy DNS cache
ordering, or human-command texture. These become focused follow-on invariants and realism work; the
passed foundation gate does not claim that the dataset is already indistinguishable from real
production telemetry.
