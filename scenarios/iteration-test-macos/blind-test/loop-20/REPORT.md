# Iterative assessment loop 20

## Individual Expert Summaries

- **Threat Hunter:** Inconclusive (verdict confidence 72; synthetic-confidence score 57). The Windows foothold, account/service lifecycles, and primary pivots aligned; concentrated DNS and scan behavior was technically plausible under compromise, while the Mac checklist repeated across hosts.
- **Detection Engineer:** Inconclusive (72; 62). Sampled source formats and correlations were credible. The short port sweep and `.top` DNS cadence were the clearest distribution tells; the DC-02 SMB FLOW/LOGIN tie was weak because matching Windows 5156 preceded 4624.
- **Network Forensics:** Synthetic (76; 73). Zeek/proxy/TLS/IDS records and UID references were coherent, but one source produced about 760 attempts across TCP 22/445/3306 in about 6.2 seconds and 91 `.top` queries over 45 minutes.
- **Host/EDR Forensics:** Inconclusive (76; 56). macOS process and SSH lifecycles were coherent; repeated shell inventory and launchd plist file activity were texture concerns. The same-millisecond SMB pair and second-resolution history ties were ambiguous, not hard contradictions.

## Deliberation Findings

Deliberation remained split: Network Forensics stayed Synthetic while the other three reviewers stayed Inconclusive. Revised synthetic-confidence scores were 59 / 63 / 68 / 55 (mean 61.25). The group agreed that the equal-millisecond SMB FLOW/LOGIN pair is ambiguous at eCAR precision, with Windows WFP preceding the logon; the scan/DNS pattern and repeated Mac shell inventories remain the strongest distribution concerns.

## Prioritized Improvements

1. **P1 — Concentrated network behavior (`distribution_texture`, Network; other reviewers noted related concentration):** One source produced a near-balanced sweep across three internal ports in roughly six seconds and sustained random-label `.top` DNS. These are concrete distribution patterns, but the scenario authors these behaviors; no network generator patch is justified without evidence of a rendering defect.
2. **P2 — Repeated Mac shell inventory (`distribution_texture`, Detection/Host/Threat):** Similar discovery commands occur on both Macs and in endpoint events. The commands are explicitly represented in the scenario, so this remains scenario-specific and does not justify changing shared shell generation.
3. **P3 — eCAR SMB FLOW/LOGIN millisecond tie (`weak_signal`, Detection/Host/evaluation):** DC-02 lines 1035–1036 give an exact tuple and equal `timestamp_ms`; the related Windows 5156 is earlier than 4624. At eCAR's millisecond precision, equality cannot establish a reversed order. Loop 21 corrects the quantitative scorer to treat this tie as ambiguous while retaining failures for visibly later flows.
4. **P4 — Same-second shell-history commands (`weak_signal`, Threat):** zsh history uses second-level timestamps; the reviewers found no source-native contradiction from the tie.

## Priority Rationale

The concentrated scan/DNS activity received the largest score leverage from Network Forensics, but it is authored behavior rather than a generator defect. The equal-time causal finding was not independently treated as a hard contradiction; because the format cannot order events within one millisecond, the loop 21 evaluator change is more accurate than shifting canonical logon timing.

## Comparison with Quantitative Eval

The JSON eval passed at 96.349141 with 132,196 records. It reported one eCAR causal-ordering failure for DC-02's same-millisecond SMB FLOW/LOGIN pair. The loop 21 fix treats the precision tie as ambiguous; the existing +25 ms visible inversion test remains failing as intended.
