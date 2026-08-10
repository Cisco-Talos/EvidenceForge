# Loop 51 Assessment Report

## Outcome

Loop 51 generated 83,559 records and scored 96.29. Fresh synthetic-confidence scores were
76 (Threat Hunter), 68 (Detection), 74 (Network), and 78 (Host/EDR), averaging 74.0. All four
reviewers returned Synthetic verdicts, confidence was adequate, and the score spread was 10,
so deliberation was not triggered.

## Fresh Expert Findings

- Threat Hunter found exact cross-host eCAR FLOW timestamp reuse and serialized module loads.
- Detection independently reproduced the duplicate RDP shell bootstrap and strained service
  parentage for interactive PowerShell.
- Network identified bounded 41–66 ms cross-sensor timing and categorical TLS artifact regimes.
- Host identified arbitrary process-to-registry ownership, repeated Defender exclusion churn,
  and multi-hour lifetimes for one-shot processes.

## Prioritized Improvements

1. **P0 — Historical-time process state (`hard_contradiction`).** The duplicate RDP bootstrap
   remains in two sessions. The lazy Explorer owner must recognize retained ended identities
   whose scheduled end is later than the canonical activity time.
2. **P1 — Registry effect ownership (`hard_contradiction`).** Bind registry keys to
   executable-specific contracts rather than arbitrary live actors.
3. **P2 — Source timing texture (`distribution_texture`).** Replace exact cross-host endpoint
   timestamps and bounded sensor timing with source-specific clock/collection models.
4. **P3 — Executable lifetime profiles (`contract_gap`).** Distinguish one-shot commands,
   installers, scheduled scripts, agents, and daemons.

## Implemented Fix

StateManager now answers whether a live or retained process identity spans an arbitrary
canonical timestamp. Session state retains the initial Explorer PID after live pointers clear.
Lazy Explorer repair reuses or suppresses that historical shell when its scheduled lifetime
contains the requested time, while still permitting a genuine post-termination restart. The
focused activity/state/spawn/RDP/world suite passes (541 tests).

## Quantitative Comparison

Parseability was 100.0, plausibility 97.35, causality 90.39, and timing 96.76. The deterministic
score remained stable while the blind panel identified source-native ownership and distribution
defects beyond its current checks.
