# Loop 2 — Iterative assessment

## Results

| Measure | Result |
|---|---:|
| Automated eval | 96.29796 / PASS |
| Records | 138,383 |
| Threat Hunter synthetic-confidence score | 73 |
| Detection Engineer synthetic-confidence score | 88 |
| Network Forensics synthetic-confidence score | 64 |
| Host/EDR synthetic-confidence score | 93 |
| Average blind synthetic-confidence score | 79.5 — likely synthetic |
| Prior loop average | 79.25 (partial-policy diagnostic) |
| Change | +0.25; no meaningful movement |

All four reviewers found the bundle synthetic. The standalone score range is 64–93; deliberation was not triggered because there was no verdict disagreement, average verdict confidence was 85.5, and score spread was 29 points. Automated quality remains above its guardrail. Pivot linkability scored 87, above its acceptance minimum of 80 but below its aspiration of 95.

## Loop 2 fixes and verification

### Empty-file content identity

- **Classification:** `family_level`; initial exact finding and sibling risk across file-producing paths.
- **Owner:** canonical `FileContentIdentity` digest semantics.
- **Invariant:** a zero-byte canonical file exposes the standard empty-payload MD5, SHA-1, and SHA-256; object/version identity remains distinct.
- **Entry paths:** SMB/file activity, transfers, and other producers that share the content identity.
- **Consumers:** Zeek file/SMB rows and endpoint/file correlation.
- **Verification:** focused tests assert the three standard empty hashes and distinct file identities; loop output contains the standard empty-file digest values.
- **Residual risk:** this corrects the hash for a known zero-byte object. It does not resolve whether a visible non-empty source artifact was incorrectly reduced to zero bytes.

### Mounted macOS SMB process starts

- **Classification:** `adapter_to_family_model` plus family config/identity completion. The adapter routes SMB-created helpers into the existing `ProcessExecutionService`; the profile and installed-command catalog supply exact executable facts.
- **Owner:** shared `ProcessExecutionService` for fork/exec publication; mounted SMB profile and macOS executable catalog for command identity and validation facts.
- **Invariant:** modeled mounted Mac helper starts use one exact executable path, canonical argv display, known executable identity, and the existing native fork/exec lifecycle.
- **Entry paths:** mounted SMB browse/read/create/update and sibling copy/move/delete profile operations; process reuse continues through the existing reuse contract.
- **Consumers:** StateManager process census, ES ingress, eCAR, and SMB projections.
- **Verification:** focused Mac SMB/profile/argument tests, `eforge validate-config`, behavior-manifest check, Ruff checks, and complete generation. The prior census showed 7 unresolved aggregate starts; the successful full run reports no aggregate starts and passed the complete Mac process gate.
- **Residual risk:** other SMB helpers or installed tools outside this catalog still require exact executable and validation facts before they can claim complete native ES evidence.

The generation behavior manifest had a duplicated revision 23 before this work. Its adjacent DNS and Windows WFP notes were merged to restore the required contiguous history; the manifest now validates at revision 400. This was required to keep the generation behavior contract usable.

## Prioritized findings

| Priority | Finding and reviewer ratings | Category | Scope and likely leverage | Owner / next action |
|---|---|---|---|---|
| P0 | Mac process exits spaced exactly 100 ms apart near the end of the window (reviewer ratings: not labeled; Detection and Host both observed it; also present in loop 1) | `distribution_texture` | Repeated across unrelated long-lived processes; high | Source timing / process lifecycle finalization. Replace deterministic staircase timing with bounded per-process close timing that preserves session and process ordering. Verify siblings from baseline, storyline and app/session termination. |
| P1 | SMB transfer of `rpt_0318.sql.gz` appears as a successful host-side write but Zeek reports 0 bytes and standard empty-file hashes (reviewer rating: not labeled; Threat Hunter) | `contract_gap` | One visible transfer, likely high because the source file was just created by gzip and scp; verify before changing | Canonical file-content identity and SMB transfer lifecycle. Reconcile source artifact size/content, transferred bytes and destination write metadata. The hash fix is correct for a truly empty file but does not explain this zero-byte transfer. |
| P2 | Repeated check-ins from `10.10.2.10` to `api.westbridge-services.net` at a regular cadence (reviewer rating: not labeled; Threat Hunter) | `distribution_texture` | Recurring in a single behavior family; medium | Periodic activity timing/config. Confirm per-host/per-campaign jitter and cadence variation without breaking causal beacon ownership. |
| P3 | Concentrated Zeek bursts and four-port activity attributed to `10.10.3.10` (reviewer rating: not labeled; Network) | `environment_or_collection_plausibility` | Network-only context does not establish the host role; low pending role correlation | Defer pending a data-based host-role/flow check; no change justified from the blind records alone. |
| P4 | Repeated Mac shell inventory commands and high Security 5156 volume (reviewer ratings: not labeled; Detection/Network) | `weak_signal` | These may fit the threat exercise and selected collection; low | No immediate change. Revisit only if other source evidence supports a concrete distribution or collection inconsistency. |

## Findings classification and score movement

- The repeated exit staircase is a `sibling_defect` and recurrence from the prior blind panel, not a regression introduced by this loop's Mac SMB fixes. It is the next root-cause target because two independent specialists identified it and a prior loop noted the same timing family.
- The zero-byte SMB finding is a `sibling_defect` adjacent to the corrected empty-file digest family. The digest repair made zero-byte hashes internally correct; the remaining issue is whether a successful transfer of a known gzip artifact was modeled with a zero size. Verify the source and destination canonical identities before altering output behavior.
- Network concerns about multi-port traffic and failed random-looking DNS labels are `false_positive_or_unproven` from network-only evidence; the reviewer explicitly noted that the host role and threat interpretation are not established by those records.
- The average score moved only +0.25 from 79.25 to 79.5. That is effectively flat; two reviewers surfaced a concrete, recurring Mac timing defect, so the next loop should address that family rather than infer a score change from reviewer variance.

## Automated evaluation

The complete scenario validated with zero errors, one retained low-intensity warning, and 27 informational notes. Generation completed with the main scenario's complete Mac process policy. JSON evaluation passed all hard requirements at 96.29796 across 138,383 records. Parseability, plausibility, causality and timing pillar scores were 100.0, 94.6091, 96.8384 and 92.1804. Evaluation findings include pivot linkability below aspiration and source-trace gaps; no acceptance failure occurred.

## Artifacts

- `validation.txt`
- `eval.txt`
- `eval_results.json`
- `scores.json`
- Four independent reviewer reports in this directory.
- Generated bundle: `/private/tmp/eforge-iteration-test-macos-loop-2`.
- Reviewer data: `/private/tmp/eforge-blind-loop2/data` (118 data files; hashes verified against the authoritative generation manifest; no scenario, ground truth, manifest, report, or evaluation files included).
