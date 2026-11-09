# Loop 80 Blind Assessment Deliberation

## Scope and method

This deliberation uses only the four loop-80 assessments in this directory. It adds no dataset inspection or new evidence. Final positions are calibrated judgments about the same reported observations; numeric scores are not measurements from a new analysis.

## Initial and final positions

| Reviewer | Initial verdict | Initial verdict confidence | Initial synthetic-confidence | Final verdict | Final verdict confidence | Final synthetic-confidence |
|---|---|---:|---:|---|---:|---:|
| Threat hunter | Synthetic | 78/100 | 78/100 | Synthetic | 70/100 | 70/100 |
| Detection engineer | Synthetic | 68/100 | 68/100 | Synthetic | 62/100 | 62/100 |
| Network forensics | Inconclusive, moderate synthetic lean | 69/100 | 54/100 | Inconclusive, slight synthetic lean | 60/100 | 53/100 |
| Host/EDR forensics | Inconclusive | 65/100 (moderate) | 48/100 | Inconclusive | 65/100 (moderate) | 48/100 |

**Mean final synthetic-confidence:** 58.25/100 across the four reviewers (70, 62, 53, and 48).

The detection engineer remains Synthetic because the reported sysstat pattern is a specific, repeated fleet-wide regularity, while reducing confidence because it is plausible under a standardized package schedule. The threat hunter also remains Synthetic, but lowers confidence to reflect the absence of decisive contradictions and the possibility that tidy profiles arise from deliberately coordinated collection. Network forensics remains Inconclusive: the scan burst adds some synthetic weight, but it is coherent and plausibly operational. Host/EDR forensics remains Inconclusive because process and session evidence is coherent, and the sparse macOS Unified Log has an unverified but plausible narrow-filter explanation.

## Evidence considered

### Strongest evidence for synthetic construction

- **Uniform Linux scheduled task (detection engineer):** All ten Linux hosts reportedly contain exactly 36 `sysstat` CRON entries, spaced exactly 600 seconds apart, running the same command. Start phase differs by only one minute across hosts and the series has no missed slot. This is the clearest positive texture signal because it is precise, replicated, and fleet-wide. A standardized package or centrally managed configuration could explain it, so it is not proof.
- **Concentrated scan-shaped burst (network forensics):** Core and DMZ sensors each report roughly 1,300 connections around 14:40 UTC, dominated by a sweep from `10.10.3.10` into `10.10.2.0/24`, including ICMP probes. The cross-sensor visibility is coherent, and a real scan or diagnostic job could produce it. Its unusual concentration contributes modestly to synthetic suspicion.
- **macOS collection sparsity (host/EDR forensics):** The two macOS hosts have hundreds of eCAR events and 128/182 Endpoint Security records, but only two/three Unified Log lines in the six-hour window. This raises a collection-plausibility question, though narrow filters could account for it and no collection contract is supplied.
- **Curated completeness and tidy profiles (threat hunter):** Broad, role-appropriate source coverage, compact repeated endpoint inventories, and unusually convenient cross-source pivots contribute to a synthetic impression. The assessment explicitly treats these as cumulative distribution/packaging clues, not contradictions.

### Strongest evidence against a confident synthetic finding

- All four reports identify **no verified hard contradiction**. None reports impossible event ordering, malformed data, broken core Zeek UID joins, or a clear identity/tuple mismatch.
- Host, network, and detection reviews describe plausible temporal alignment, source-native formats, lifecycle ordering, and varied activity. Cross-source agreement is useful evidence of internal consistency, but the reviewers appropriately do not treat it alone as proof of either authenticity or synthesis.
- The largest anomalies each have plausible operational or collection explanations: standard sysstat deployment, a real scan/diagnostic burst, and narrow macOS Unified Log selection. The reports do not contain metadata that resolves those explanations.
- The network report notes one unmatched proxy CONNECT among 2,290 (`10.10.3.10` to `data.mixpanel.app`), but considers proxy-local activity or sensor coverage plausible. It is too isolated to drive the overall classification.

## Agreements and disagreements

**Agreements:** The bundle is internally coherent; no reviewer found a decisive impossibility. Temporal boundaries can explain many unmatched lifecycle records. Cross-source correlation is strong and useful for investigation. Any synthetic assessment rests mainly on texture or collection completeness, rather than broken record contracts.

**Disagreements:** Threat hunter and detection engineer classify the bundle Synthetic, with the detection engineer identifying a particularly specific sysstat cadence. Network and host/EDR reviewers remain Inconclusive because their primary concerns are plausible events or undocumented collection scope, not demonstrated defects. The disagreement is therefore about evidentiary weight and threshold, not whether the observed patterns exist.

## Calibrated assessment

The evidence supports **a moderate synthetic lean, but not a high-confidence or contradiction-based finding**. The fleet-wide, perfectly complete sysstat series is the strongest reason to retain Synthetic votes. The synchronized scan-shaped burst adds limited support, while macOS Unified Log sparsity is unresolved and should be treated as a coverage question rather than affirmative proof. Internal consistency is strong, but does not settle provenance.

Final positions intentionally remain split: two Synthetic and two Inconclusive. The Synthetic reviewers reduce their confidence; the network reviewer keeps a slight synthetic lean; the host reviewer remains near-neutral at 65/100 verdict confidence and 48/100 synthetic-confidence. No reviewer is asked to adopt a verdict unsupported by their evidence.

## Recommendations

1. Preserve source-native formatting, lifecycle coherence, Zeek UID integrity, and the useful cross-source pivots; no repair is indicated by the reviewed hard-contract evidence.
2. Document the macOS Unified Log predicate, subsystem/category filters, and expected collection volume so sparse coverage can be interpreted against an explicit scope.
3. Review whether the ten-host sysstat cadence represents a deliberate fleet standard. If it does, document that rationale; if not, introduce believable per-host schedule or observation variation without undermining ordinary task semantics.
4. Keep the 14:40 scan as a coherent observable traffic family if intentional. Its cross-sensor alignment makes it investigable; the reports do not establish it as an error.
5. Label the bundle's provenance for training use. The reviewed evidence supports a coherent exercise dataset, while the distribution and collection signals warrant caution about presenting it as an unmodified production capture.
