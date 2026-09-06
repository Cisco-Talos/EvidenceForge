# Iteration Test Blind Assessment — Loop 55

## Outcome

The chained SCP-to-SMB transfer contract now passes its hard probe: byte accounting covers the
823,965-byte artifact on both transports, the upstream transfer completes before SMB starts, and
the APP receiver keeps one object identity from create through read. Automated evaluation passed
at 96.1262 across 114,250 records.

## Expert summaries

- **Threat Hunter:** Synthetic, 72 verdict confidence, 65 synthetic-confidence. Strong attack and
  baseline realism, offset by remote-admin source-port gaps and missing command-required children.
- **Detection Engineer:** Synthetic, 88 verdict confidence, 72 synthetic-confidence. Found the
  highest-leverage defect: every Type-10 RDP logon has wrong winlogon ownership, with three visible
  ordering inversions; also found Windows LUID semantics on Linux eCAR.
- **Network Forensics:** Real, 74 verdict confidence, 30 synthetic-confidence. Network evidence is
  production-like; uniform omitted REJ durations are the strongest network-specific weakness.
- **Host/EDR Forensics:** Synthetic, 84 verdict confidence, 74 synthetic-confidence. Found
  long-lived userinit processes, formulaic SSH launch trees, and fleet-wide Snap package texture.

Required deliberation retained a 3-1 Synthetic majority and revised synthetic-confidence to 76,
82, 44, and 82 (mean 71). The network dissent is source-scoped; all reviewers accepted that the
combined endpoint corpus contains repeated Type-10 RDP contradictions.

## Prioritized improvements

1. **P0 — RDP bootstrap identity/lifecycle:** create one unique smss-parented winlogon per session
   before 4624, put its exact PID in the logon, and terminate userinit shortly after explorer.
2. **P0 — remote-admin tuple inheritance:** preserve the authentication/service-control source
   tuple through transport, FLOW, logon, and session evidence.
3. **P1 — Linux eCAR session identity:** prevent Windows `0x3e7` LUID semantics from appearing on
   Linux processes.
4. **P1 — command-required children:** materialize external children for shell and cmd chains.
5. **P1 — role-aware Snap activity:** scope packages and refresh volume to plausible host roles.
6. **P2 — source-native network edges:** model positive REJ durations and redirect-body MIME.

## Quantitative comparison

The deterministic evaluator passed all hard gates and remained above 90 in every pillar, but it
does not currently test RDP caller-process identity, per-session bootstrap ordering, userinit
lifetime, cross-OS LUID semantics, or command-required subprocesses. Its high score therefore acts
as a regression guardrail rather than contradicting the blind findings.
