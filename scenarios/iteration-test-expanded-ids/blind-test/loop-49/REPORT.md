# Loop 49 Assessment Report

## Outcome

Loop 49 generated 83,559 records and scored 96.29 in the deterministic evaluation. The
fresh blind panel's initial synthetic-confidence scores were 66 (Threat Hunter), 66
(Detection Engineer), 68 (Network Forensics), and 56 (Host/EDR), averaging 64.0. Verdict
disagreement triggered deliberation; the reconciled panel classified the data as likely
synthetic, with final scores of 70, 70, 70, and 64 (average 68.5).

## Individual Expert Summaries

- **Threat Hunter — Synthetic, verdict confidence 72, synthetic confidence 66.** The
  strongest defect was two `userinit.exe → explorer.exe` chains for one RDP Logon ID;
  repeated Linux health checks and broad administrative access added distribution texture.
- **Detection Engineer — Synthetic, verdict confidence 74, synthetic confidence 66.** Two
  separate Type 10 sessions each reproduced the duplicate shell bootstrap, while Windows,
  Zeek, firewall, SMTP, and IDS contracts were otherwise strong.
- **Network Forensics — Synthetic, verdict confidence 72, synthetic confidence 68.** The
  network sources were internally coherent, but DHCP cadence, inter-sensor timestamp offsets,
  public HTTP vocabulary, and external DNS latency showed bounded generator-like regimes.
- **Host/EDR — Inconclusive, verdict confidence 62, synthetic confidence 56.** Host lifecycle
  and schema fidelity were strong; narrow call-trace pools, shared Windows process palettes,
  and discretized UFW scanner fingerprints drove the residual score.

## Deliberation Findings

The panel agreed that duplicate RDP shell initialization is a localized but decisive
session-ownership contract defect. Host/EDR revised to Synthetic after reviewing the
cross-host reproduction. The panel retained strong realism credit for source-native schema,
network accounting, sensor-local identity, and lifecycle correlation.

## Prioritized Improvements

1. **P0 — Duplicate RDP shell bootstrap (`hard_contradiction`).** One visible Type 10 login
   owned two `userinit.exe` and two `explorer.exe` creates on each of two hosts. Make the
   canonical logon lifecycle idempotent when the session already owns a live Explorer shell.
2. **P1 — Timing regimes (`distribution_texture`).** Replace narrowly bounded sensor offsets,
   DHCP renewal jitter, and discrete external DNS latency with stateful clock/client/resolver
   models.
3. **P2 — Host activity pools (`distribution_texture`).** Expand process-access call traces,
   role-specific software, Linux maintenance behavior, and scanner TCP fingerprints.
4. **P3 — Administrative topology (`environment_or_collection_plausibility`).** Narrow user
   affinities and interactive service-account use by host role and policy.
5. **P4 — Preserve strong contracts.** Keep certificate/FUID integrity, proxy byte scopes,
   firewall lifecycles, mail queue propagation, and source-specific observation gaps.

## Implemented Fix

The shared Windows logon lifecycle now treats an existing live session Explorer as proof that
the bootstrap chain already exists, preventing a second semantic owner from creating another
`userinit.exe → explorer.exe` pair. A regression test renders the same active Logon ID twice
and asserts that only one three-process shell chain exists. The focused activity, spawn-rule,
RDP baseline, and world-model suite passes (439 tests).

## Quantitative Comparison

Parseability remained 100.0. Plausibility was 97.35, causality 90.39, and timing 96.76. The
automated evaluator did not detect the duplicate per-session shell ownership; the blind panel
identified it by grouping source-native process evidence by Logon ID.
