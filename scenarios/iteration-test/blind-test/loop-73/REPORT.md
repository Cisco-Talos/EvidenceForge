# Loop 73 — Linux logind session identity allocation

## Outcome

Fixed the confirmed clock-derived systemd-logind session identity pattern at the canonical
`StateManager` allocator. Before the fix, eight Linux hosts showed almost exact 8–9 IDs/minute
fits (loop72 output; e.g., MAIL-CLIN R² 0.9999992). Afterward, per-host fits have substantially
lower slopes and less clock correlation; the minimum observed `New session` ID step is 1 and the
maximum 56. IDs remain host-unique and consistent with event-time allocation. See
[logind ID probe](logind-id-probe.json) and [family contract](family-contract.md).

This is a `family_level` fix: SSH, local interactive logon, and baseline session entry paths all
use the shared allocator. Added focused allocator tests, including caller-RNG non-perturbation;
targeted baseline admission and checkpoint restore tests cover sibling paths. The first generated
attempt exposed an unrelated seeded RNG shift; that output was discarded, the allocation now uses
a separately scoped deterministic RNG, and the clean generation completed successfully.

## Evaluation and review

Scenario validation passed with only existing low-baseline and storyline-pivot notices. The fixed
seed output contains 141,745 records across 25 sources. Automated evaluation is 96.1181/100,
hard acceptance PASS: parseability 100, plausibility 96.868, causality 95.719, timing 89.857. This
matches the recent evaluation range and requires no guardrail investigation.

Standalone synthetic-confidence scores: Threat Hunter 63, Detection Engineer 34, Network Forensics
36, Host/EDR Forensics 34; mean 41.75 (mixed/inconclusive), verdict-confidence mean 78.25, score
spread 29. The verdicts differed, triggering deliberation. It retained the disagreement and did
not create revised votes. Its recurring agreement was that no hard contradiction or material
schema defect was established. Sparse macOS Unified Log files were noticed by three reviewers, but
collection scope is unknown, so this remains unproven. Network Forensics noted a narrow and partly
old browser UA mix; it is weak and has plausible managed/stale-client explanations. Threat Hunter's
concentrated IDS/DNS behavior is consistent with the authored suspicious activity and does not by
itself establish a synthetic-only defect.

## Prioritized findings

| Priority | Finding | Category and scope | Owner / disposition |
|---|---|---|---|
| P2 | Browser UA versions concentrated in a small set; some Windows versions look old for the observed date (Network) | `distribution_texture`, repeated in browser traffic; low to medium leverage | Verify which source paths and software identities own these UAs. Current managed/stale-client explanations remain plausible; candidate for next loop qualification, not yet a confirmed defect. |
| P3 | Two or three macOS Unified Log entries per host across the window (Threat, Detection, Host) | `environment_or_collection_plausibility`, two hosts; leverage depends on collection scope | No owner defect established from output alone. Check configured collection scope and required companions before changing generation. |
| P3 | Several IDS-significant behaviors on a few internal addresses (Threat) | `distribution_texture`, localized; low leverage | Activity can reflect a compromised or misused host; suspicious traffic is not itself synthetic. No change. |
| — | Linux logind IDs tracked elapsed wall-clock minutes (loop64/72 host evidence) | `distribution_texture`, eight Linux hosts; medium leverage | Fixed at shared `StateManager` identity allocator and verified across rendered sessions. |

No P0/P1 defect was established by this panel. Full routine pytest was not run. Focused evidence and
lint/format/behavior checks are in [test evidence](test-evidence.json); output-copy checks are in
[data hash audit](data-hash-audit.json). The 115-file neutral review copy is byte-identical to the
authoritative bundle's data directory. Scenario inputs and seed were unchanged.

## Individual reviewer summaries

- **Threat Hunter:** Synthetic, verdict confidence 72, synthetic-confidence 63. Found a cluster of unusual DNS and IDS-significant behavior on several internal addresses, but no hard contradiction; acknowledged compromised or misused hosts as an alternative.
- **Detection Engineer:** Real, verdict confidence 86, synthetic-confidence 34. Found coherent Windows/Linux source semantics and a useful root SSH/database export/archive/transfer sequence; macOS collection sparsity is limited evidence without scope.
- **Network Forensics:** Inconclusive, verdict confidence 79, synthetic-confidence 36. Found Zeek UIDs, tuples, TLS states, proxy paths, and firewall semantics coherent; flagged a narrow/partly old browser UA mix as weak texture.
- **Host/EDR Forensics:** Inconclusive, verdict confidence 76, synthetic-confidence 34. Found Windows and Linux lifecycle agreement and plausible process trees; macOS Unified Log sparsity and flow attribution depend on unknown collection scope.

## Next loop candidate

Qualify browser UA versions against the specific generated traffic paths and the canonical software identity before editing. If records are external clients or intentionally stale managed versions, classify the finding as false positive; otherwise fix the shared version/profile owner and test sibling paths.
