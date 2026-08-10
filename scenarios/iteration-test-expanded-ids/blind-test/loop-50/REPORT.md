# Loop 50 Assessment Report

## Outcome

Loop 50 generated 83,559 records and scored 96.29. Fresh initial synthetic-confidence
scores were 91 (Threat Hunter), 39 (Detection), 56 (Network), and 76 (Host/EDR), averaging
65.5. The 52-point spread and verdict disagreement triggered deliberation; final scores were
88, 68, 65, and 80 (average 75.25), with a Synthetic consensus and one reasoned dissent.

## Fresh Evidence

- Threat Hunter emphasized role-insensitive Linux/Windows behavior libraries.
- Detection found strong schemas and lifecycle semantics but bounded command/web templates.
- Network found strong sensor drift and protocol contracts but finite actor/protocol pools.
- Host found the exact same 38 Event 5156 execution-thread IDs on all nine Windows hosts,
  plus non-stateful `irqbalance` and `multipathd` message sequences.
- The required Loop 50 verification probe independently showed that both known RDP cases still
  contained two shell chains for one login. Full generation schedules future teardown eagerly,
  clearing live PID pointers before the duplicate semantic path executes.

## Prioritized Improvements

1. **P0 — Durable session bootstrap ownership (`hard_contradiction`).** A live-PID check was
   insufficient. Store completion of initial Windows shell bootstrap as durable session state,
   independent of whether eager future teardown has removed processes from the live map.
2. **P1 — Event 5156 provider thread state (`distribution_texture`).** Replace the fleet-global
   38-value set with evolving host/provider-specific execution contexts.
3. **P2 — Stateful Linux daemon narratives (`contract_gap`).** Model IRQ affinity and multipath
   path transitions instead of independently sampling messages.
4. **P3 — Role-specific activity libraries (`distribution_texture`).** Narrow command, health
   check, updater, and public actor pools by host/user/workload state.

## Implemented Fix

`ActiveSession` now stores `windows_shell_bootstrapped`, a durable semantic ownership flag.
The canonical logon path sets it after the initial chain and will not create a second chain even
if future teardown has already cleared live process pointers. The regression explicitly removes
Explorer from live state before replaying the same Logon ID. Focused activity, state, spawn,
RDP, and world-model verification passes (541 tests).

## Quantitative Comparison

Parseability remained 100.0, plausibility 97.35, causality 90.39, and timing 96.76. The
deterministic evaluator did not detect either the RDP ownership defect or fleet-global 5156
thread-ID universe, demonstrating the continued value of blind source-native review.
