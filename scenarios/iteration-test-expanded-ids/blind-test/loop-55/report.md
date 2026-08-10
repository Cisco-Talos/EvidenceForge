# Loop 55 Assessment Report

## Outcome

Loop 55 generated 82,076 records and scored 95.64. Fresh initial synthetic-confidence scores
were 48 (Threat Hunter), 68 (Detection), 32 (Network), and 74 (Host/EDR), averaging 55.5. The
Inconclusive/Synthetic/Real split triggered deliberation. Revised scores were 60/76/49/78,
averaging 65.75, with the panel collectively assessing the corpus as likely synthetic.

## Fresh Expert Findings

- Host found a bare `runas.exe` process that produced successful Event 4648 evidence and stayed
  alive for 2,605.686 seconds, plus six of six Office registry effects owned by the wrong Office
  application.
- Detection found identical low-order microsecond residues in all 34 DHCP REQUEST/ACK/bound
  syslog triplets across three hosts.
- Threat Hunter found overlapping duplicate RDP sessions, 136 successful SSH authentications
  concentrated in three users, and generic health checks aimed at role-incompatible domains.
- Network found excellent dual-sensor identities, clock drift, and loss texture, but no UDP/123
  traffic and unusually tidy external scanner cohorts.

## Prioritized Improvements

1. **P0 — Explicit-credential process semantics (`hard_contradiction`).** Successful generated
   `runas.exe` activity needs a valid `/user:` operand, target command, and one-shot lifetime.
2. **P1 — Office registry ownership (`contract_gap`).** Application-specific state must be owned
   by the corresponding Office executable.
3. **P1 — DHCP source timing (`distribution_texture`).** Lifecycle messages need separate
   source-native low-order timestamp observations.
4. **P1 — SSH process lifecycle (`contract_gap`).** The inherited Loop 54 probe still found 35
   visibly closed `sshd` processes without matching eCAR termination.

## Implemented Fix

`ExplicitCredentialUseActionBundle` now constructs action-native command lines when it must
materialize a caller. A generated `runas.exe` exposes `/netonly`, the requested `/user:` value,
and a target-server command. The bundle terminates only callers it created itself after a
deterministic 1.8–7.0 second lifetime; caller processes supplied by another action retain their
existing lifecycle owner. Focused explicit-credential tests pass (16 tests).

## Quantitative Comparison

Parseability was 100.00, plausibility 97.24, causality 88.84, and timing 95.60. The Loop 54 file
probe found 11 Sysmon Event 11 records and zero generic five-digit Windows Temp artifacts.
