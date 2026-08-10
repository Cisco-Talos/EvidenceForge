# Loop 56 Assessment Report

## Outcome

Loop 56 generated 84,790 records and scored 95.99. Fresh initial synthetic-confidence scores
were 36 (Threat Hunter), 24 (Detection), 66 (Network), and 67 (Host/EDR), averaging 48.25. The
Real/Synthetic split triggered deliberation; revised scores were 45/34/58/64, averaging 50.25,
with the panel retaining an informed Real/Inconclusive/Synthetic disagreement.

## Fresh Expert Findings

- Threat Hunter found an operationally coherent attack chain but roughly 120 successful SSH
  authentications concentrated in a few administrators across unrelated Linux roles.
- Detection found strong schema and correlation integrity; its main concern was that all 695
  Sysmon Event 3 records were outbound despite thousands of inbound Security 5156 records.
- Network found persistent service-specialized scanner identities, nearly fixed per-client DHCP
  renewal periods, and a short internal protocol tail.
- Host found five exact 1 ms Windows network-logon lifetimes and one SCP transfer that split
  authentication/file ownership across two sibling `sshd` processes, only one of which closed.

## Prioritized Improvements

1. **P0 — SSH receiver lifecycle (`contract_gap`).** One tuple must retain one responder process
   through auth, dependent SCP file creation, and termination.
2. **P1 — SSH role/frequency model (`distribution_texture`).** Reduce the shared persona/host
   matrix and bind remote administration to role, bastion, automation, and session reuse state.
3. **P1 — DHCP/logon timing (`distribution_texture`).** Remove exact lifecycle floors and
   near-invariant recurrence.
4. **P2 — Collection and network tail (`environment_or_collection_plausibility`).** Align
   inbound Sysmon and low-frequency protocols with an explicit observation profile.

## Implemented Fix

Storyline SCP now defers SSH closure until dependent receiver artifacts have consumed the live
tuple-owned responder. The SSH action bundle captures and schedules responder termination before
dispatching the logoff state transition that retires that process. This prevents both the
duplicate receiver PID and the recurring missing-termination sibling defect while leaving
ordinary immediate-close SSH sessions on the same shared lifecycle path. The focused SCP/SSH
suite passes (6 tests). Classification: `family_level` plus one `adapter_to_family_model` flag on
the storyline SCP caller.

## Quantitative Comparison

Parseability was 100.00, plausibility 97.20, causality 90.21, and timing 95.70. The Loop 55
explicit-credential probe found one valid generated `runas.exe`, zero bare invocations, and one
matching termination after 6.304 seconds.
