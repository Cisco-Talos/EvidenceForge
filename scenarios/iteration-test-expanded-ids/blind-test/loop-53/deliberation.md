# Loop 53 Expert Deliberation

## Trigger

The initial panel disagreed on the verdict and had a 56-point synthetic-confidence spread:
Threat Hunter Inconclusive/46, Detection Synthetic/84, Network Real/30, and Host Synthetic/86.

## Evidence Reconciliation

The panel agreed that network construction, packet arithmetic, protocol fan-out, source-native
formats, and investigative pivots are unusually strong. Those strengths did not rebut the fresh
cross-source proof that 138 completed SMB/445 sessions on six Linux hosts were attributed to
native `rsyncd`, which cannot speak SMB. Zeek success state and bidirectional bytes ruled out a
failed-probe explanation. The Windows file/registry ownership findings and repeated RDP endpoint
ordering inversions provided independent corroboration.

The panel downgraded the narrow core-to-DMZ timestamp band to supporting evidence because stable
clock or collection offset is plausible. The one-SYN scan population, repeated SSH launches,
cloned sysstat activity, and missing custom-binary provenance remained secondary texture targets.

## Revised Verdicts

| Reviewer | Assessment | Verdict confidence | Synthetic confidence |
|---|---|---:|---:|
| Threat Hunter | Synthetic | 91 | 82 |
| Detection Engineer | Synthetic | 96 | 89 |
| Network Forensics | Synthetic | 94 | 88 |
| Host/EDR Forensics | Synthetic | 97 | 93 |

Average revised synthetic confidence: **88.0** (highly likely synthetic).

## Consensus Improvement Order

1. Fix canonical process/protocol ownership, beginning with `rsyncd`-owned SMB.
2. Bind Windows file and registry effects to executable-native behavior.
3. Replace fleet-wide artifact pools with durable entity-specific state.
4. Correct eCAR RDP session-before-process observation timing.
5. Diversify role-specific scheduled/admin behavior and scan failure ecology.
