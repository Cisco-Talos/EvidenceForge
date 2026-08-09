# Loop 39 Deliberation Summary

## Evidence Boundary

The four reviewers reconsidered only the four Loop 39 blind reports under the
expert-deliberation protocol. No scenario, ground truth, evaluator result,
implementation context, repository history, prior-loop report, or new dataset
inspection entered the round.

## Score Revision

| Expert | Initial | Initial score | Final | Final confidence | Final score |
|---|---:|---:|---:|---:|---:|
| Threat Hunter | Real | 35 | Synthetic | 88 | 72 |
| Detection Engineer | Inconclusive | 42 | Synthetic | 86 | 66 |
| Network Forensics | Inconclusive | 43 | Synthetic | 84 | 69 |
| Host/EDR Forensics | Synthetic | 67 | Synthetic | 95 | 86 |

The initial average was **46.75**. The final average is **73.25**, and the
post-deliberation verdict is unanimously **Synthetic**.

## Reconciliation

All reviewers retained the strong evidence for realistic source schemas,
lifecycle ordering, UID/tuple fan-out, certificate-loss handling, process
correlation, and varied background traffic. The change in consensus came from
four independent repeated patterns that were not available to every specialist
in the initial round:

1. All 31 Event 4648 records used destination-like addresses and independently
   sampled ports in source-native Network Information fields.
2. Twelve ordinary `ssh.exe` launches used unrelated Firefox, Edge, or Outlook
   parents, with the same ancestry projected through Security, Sysmon, and eCAR.
3. All 1,490 SMB and LDAP sessions remained below a sharp 45-second ceiling.
4. Periodic Linux jobs, stale-account failures, and some scanner populations
   retained visible generator-like distribution boundaries.

The panel downweighted the missing PsExec client, one delayed SMB copy,
outbound-only Sysmon Event 3, smooth sensor drift, and sparse process volume
because collection or operational explanations remain plausible. The canonical
Event 4648 semantics and repeated SSH ancestry were regarded as the strongest
actionable contract failures.
