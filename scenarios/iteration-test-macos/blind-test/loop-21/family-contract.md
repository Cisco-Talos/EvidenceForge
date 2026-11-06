# Loop 21 family contract: millisecond-resolution causal evaluation

- **Owning layer:** eCAR causality scoring in `CausalityScorer`, which interprets serialized source timestamps.
- **Invariant:** An exact-tuple inbound FLOW timestamp strictly later than a successful type-3/type-10 LOGIN is a causal-order failure; an equal eCAR millisecond is ambiguous and must not be asserted as reversed.
- **Entry paths:** Every parsed eCAR inbound FLOW and matching remote USER_SESSION/LOGIN pair considered by `_score_ecar_remote_auth_ordering`.
- **Consumers:** Quantitative causality pillar, JSON/text evaluation reports, and loop acceptance summaries.
- **Sibling risks:** Keep tuple and five-second proximity matching unchanged; keep clear inversions failing; do not infer success from a missing/wrong tuple or a distant reused port.
- **Why this layer owns the truth:** eCAR serializes timestamps at millisecond precision. The loop 20 DC-02 LOGIN and exact inbound FLOW share the same serialized millisecond, while Windows Security 5156 is earlier than 4624. The records do not establish a reversed order, so a strict `<` test overstates the evidence.

## Verification

Add a scorer regression for an equal-millisecond exact tuple and retain the existing strict-inversion regression at +25 ms. Run the focused evaluation tests, one fresh scenario generation, one human-readable and one JSON evaluation, copy the generated `data/` tree byte-identically, then run a fresh blind panel.
