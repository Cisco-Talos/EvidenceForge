# Deliberation Summary

## Panel Composition

| Expert | Initial Verdict | Initial Verdict Confidence | Initial Synthetic-Confidence | Final Verdict | Final Verdict Confidence | Final Synthetic-Confidence |
|---|---:|---:|---:|---:|---:|---:|
| Threat Hunter | Inconclusive | 79 | 52 | Synthetic | 91 | 73 |
| Detection Engineer | Synthetic | 92 | 75 | Synthetic | 96 | 84 |
| Network Forensics | Synthetic | 70 | 62 | Synthetic | 88 | 77 |
| Host/EDR Forensics | Synthetic | 86 | 74 | Synthetic | 94 | 80 |

## Key Agreements

The panel agreed that the dataset is broadly parseable, diverse, and highly correlated, but that
multiple visible source-native contradictions outweigh those strengths. The strongest shared
conclusion was that these are contract failures rather than ordinary collection gaps.

## Key Disagreements

The Threat Hunter initially remained inconclusive because most of the operational attack chain was
convincing. The other reviewers initially treated the repeated Windows identity gaps, TCP DNS
packet semantics, and endpoint lifecycle defects as stronger synthetic indicators. After reviewing
the same-channel Windows parent inversion, the Threat Hunter revised to Synthetic.

## Most Convincing Evidence

1. FILE-SRV-01 Security 4688 visibly creates `userinit.exe` 223 ms before its exact `winlogon.exe`
   parent, while Sysmon shows the correct order.
2. A successful 44 MB proxy upload loses roughly 25.2 MB between the client/proxy and origin legs.
3. Two TCP/53 Zeek rows claim `SF` despite one packet per direction and `Dd`/`DdG` histories.
4. Two SSH sessions execute session-tagged commands before their own shells exist and reuse an
   unrelated shell identity.
5. 151 Type-3 Windows logons repeat the same empty subject/logon-process fields and destination-as-
   workstation value.

## Most Debated Points

The panel debated whether the otherwise strong cross-source correlation and realistic baseline
could outweigh a small number of hard defects. It also treated the end-of-window network drain and
domain-controller probing as weaker signals because plausible operational explanations remain.

## Improvement Recommendations (Consensus)

- Enforce source-local parent-before-child ordering after Windows source timing is applied.
- Derive both proxy legs and proxy-access accounting from one canonical upload payload.
- Make TCP state, history, and packet counts one coherent packet-lifecycle result.
- Ensure SSH session commands are owned by that session's shell and occur after shell readiness.
- Populate Windows network-logon subject, workstation, authentication-process, and GUID fields from
  canonical authentication/session truth rather than emitting empty values.
