# Deliberation Summary

## Panel Composition

| Expert | Initial Verdict | Initial Verdict Confidence | Initial Synthetic-Confidence | Final Verdict | Final Verdict Confidence | Final Synthetic-Confidence |
|---|---:|---:|---:|---:|---:|---:|
| Threat Hunter | Inconclusive | 78 | 43 | Synthetic | 95 | 87 |
| Detection Engineer | Synthetic | 91 | 78 | Synthetic | 97 | 88 |
| Network Forensics | Synthetic | 86 | 72 | Synthetic | 95 | 85 |
| Host/EDR Forensics | Synthetic | 94 | 84 | Synthetic | 97 | 89 |

## Key Agreements

The panel agreed that attack-path correlation, identifiers, lifecycle joins, and network pivots are
unusually strong and operationally useful. After cross-review, all four also agreed that multiple
independent source-native contradictions outweigh that strength as authenticity evidence.

## Key Disagreements

The initial disagreement concerned whether broad correlation and plausible operational behavior
were stronger evidence than fleet homogeneity and endpoint defects. The threat hunter initially
treated the data as inconclusive, while the three source specialists gave more weight to repeated
field ownership, process ancestry, lifecycle, and packet-accounting contradictions.

## Most Convincing Evidence

1. Positive durations on 245 unanswered one-packet ICMP scan flows at two Zeek sensors.
2. A Java process identity owning an eCAR flow after its recorded termination.
3. Systematic destination-as-`WorkstationName` values on 158 successful Type 3 logons.
4. Invalid RDP ancestry and repeated competing interactive shell roots.
5. Highly reusable cross-source pivots and plausible source-specific timing, which tempered but did
   not reverse the synthetic judgment.

## Most Debated Points

The panel debated whether homogeneous Linux packages could reflect a golden image, whether
outbound-only Sysmon Event 3 represented collection policy, and whether broad collection coverage
was merely a benchmark design. None was considered decisive after the harder contradictions were
shared.

## Improvement Recommendations (Consensus)

- Derive Zeek ICMP duration only from observed packets and keep analyzer service semantics uniform.
- Correct Windows Type 3 source/destination ownership and render native placeholders or populated
  authentication values instead of blanks.
- Build Windows interactive and RDP shells from one valid parent graph shared by Sysmon, Security,
  and eCAR.
- Prevent endpoint FLOW publication after the exact owning process has terminated.
- Diversify Linux server software and maintenance baselines by role while preserving the current
  high-quality correlation contracts.
