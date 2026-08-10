# Loop 58 Assessment Report

## Outcome

Loop 58 generated 78,878 records and scored 95.77, but failed the automated acceptance gate
because pivot linkability scored 50.0 against an 80.0 threshold. Fresh blind scores were
58/25/69/76 (mean 57.0); deliberation revised them to 68/51/73/82 (mean 68.5).

## Previous-Fix Verification

Routine SSH consolidation passed. Successful core SSH sessions fell from 133 to 48 (63.9%),
top-three client session-hours fell from 46.2 to 27.57, and peak concurrency changed from
7/7/5 to 6/4/2. Typed/storyline SSH and shared evidence contracts remained present.

## Fresh Expert Findings

- Threat Hunter found strong huntability but exact command repetition and a two-millisecond
  collision between encoded PowerShell and Security-log clearing.
- Detection assessed the source-native schemas and cross-source identities as strong; its
  findings were low-weight 4648 invariants and a few unmatched session edges.
- Network found workstation-like proxy activity on the apparent domain controller, low TLS
  history diversity, absent observed NTP, and millisecond-quantized DHCP child timing.
- Host found the hard lifecycle gap selected by deliberation: visible successful SSH closes whose
  exact receiver `sshd` process had created but never terminated.

## Implemented Fix

Tuple-scoped SSH responders are now late-bound from the system service identity used during
pre-auth creation to the final canonical receiver session. `StateManager` refreshes the process
session index after that ownership change, allowing compatibility-path generic logoff to find
and terminate the exact responder. Existing action-owned immediate and deferred close paths keep
their behavior. The focused state/SSH suite passes (92 tests). Classification: `family_level`.
