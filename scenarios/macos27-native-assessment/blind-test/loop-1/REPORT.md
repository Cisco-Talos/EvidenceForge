# Current-profile standalone review, loop 1

Source commit `0b7930c0`, generation behavior revision 343, authored seed 327.
This replaces the partial, pre-fix `round-1` diagnostic. No captured records or private
system information were used. Reviewers received only an isolated generated-data copy.

All five nested command steps execute. Native coverage is eight fork, four exec and
two known-exit notifications; selected Unified Log coverage is three records. These are
bounded source subsets. Native fields, audit/session linkage and sequence chronology
survived the specialist review; missing GUI app-launch relationships remain unqualified.

Automated evaluation: **90.0882**, 9,494 records, all hard gates pass. Parseability 100,
plausibility 91.2833, causality 97.3995, timing 64.5876. The timing/volume warnings describe
the small mixed benchmark; they do not override the concrete native-source findings.

| Reviewer | Verdict | Verdict confidence | Synthetic confidence |
|---|---|---:|---:|
| Threat hunter | Synthetic | 78 | 64 |
| Detection engineer | Synthetic | 96 | 92 |
| Network forensics | Synthetic | 95 | 90 |
| Host/EDR forensics | Inconclusive | 82 | 56 |

Standalone average: **75.5** (lower is better). Deliberation preserves the independent
positions and confirms the two shared Zeek defects; no revised expert votes were invented.

## Findings and next fix selection

| Priority | Finding and classification | Scope/reviewers | Owner | Leverage/risk |
|---|---|---|---|---|
| P0 | Repeated once-only TCP history markers; `sibling_defect` | 352/873 TCP rows; network, detection | Canonical transport planning/config | High / low |
| P0 | TLS ServerHello direction wrong, encrypted messages inferred; `sibling_defect` | 686/689 rows; network, detection | Canonical TLS context/config | High / low |
| P1 | Trivial Mac queries consistently take seconds; `sibling_defect` | 13 paired diagnostics; host, threat | Command timing config/canonical process close | High / moderate |
| P2 | Stratum-2 NTP reference identifier is a display token; `sibling_defect` | 12 responses; network, detection | Protocol identity facts/config | Medium / low after qualification |
| P2 | UserAssist count regresses for same value; `new_family` | Three writes; host | Windows registry state | Medium / requires bounded state investigation |
| P2 | Repeated Chrome roots share one profile command; `false_positive_or_unproven` | One Mac; threat | Application/session ownership | Medium / qualify singleton semantics first |
| P3 | Browser-shaped HTTP owner and periodic SMB vocabulary; `false_positive_or_unproven` | Small cohorts; threat | Process/network attribution, activity catalog | Low / retain alternative explanations |

Selected families are shared protocol-history semantics and bounded Mac query timing. Their
pre-implementation contracts, entry paths, consumers and sibling risks are recorded in
`docs/worklog/2026-10-27-macos-native-coverage.md`. The fixes belong upstream of emitters.
They do not close native reference gates or resolve the separate capture-loss/packet-count
backlog. No scenario change is needed. The remaining unrelated findings are retained for
verification rather than being silently declared solved.

Primary source qualification: [Zeek conn history](https://docs.zeek.org/en/current/scripts/base/protocols/conn/main.zeek.html#type-Conn::Info),
[SSL direction and event handlers](https://github.com/zeek/zeek/blob/v8.0.0/scripts/base/protocols/ssl/main.zeek),
and [NTP reference field](https://docs.zeek.org/en/current/scripts/base/protocols/ntp/main.zeek.html#type-NTP::Info).
