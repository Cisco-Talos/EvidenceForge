# Mixed-fleet macOS assessment, loop 2

Revision 328 (`638ba6a4`) passes quantitative acceptance: **89.7644**, 10,823
records, 100% parseability and causality. The hard family probe has **zero
failures**, including three nonempty native v10 fork rows. The separately
generated supported-source revision has identical shared-source bytes and no
native ES file. Source, bundle and file hashes are retained in `provenance.json`.

Four fresh reviewers received only the neutral data tree and current briefing
plus their own persona. The source scenario, code, ground truth, prior findings
and quantitative results were withheld. Reports are preserved unchanged.

| Reviewer | Verdict | Verdict confidence | Synthetic-confidence |
| --- | --- | ---: | ---: |
| Threat Hunter | Synthetic | 82 | 67 |
| Detection Engineer | Inconclusive | 80 | 57 |
| Network Forensics | Synthetic | 74 | 64 |
| Host/EDR | Synthetic | 91 | 78 |

Average synthetic-confidence **66.5**, down from **83**; lower means more
production-like. Verdict disagreement triggered report-only deliberation. No
reviewer scores were replaced. The main change is removal of the previous hard
lifecycle and TLS contradictions; reviewers now expose deeper distribution and
identity issues. This is improvement, not a native-fidelity or realism pass.

## Finding classification and next priorities

| Priority | Finding / classification | Reviewers and scope | Owner / leverage / risk |
| --- | --- | --- | --- |
| P1 | Main GUI processes accumulate / new_family | All three endpoint-aware reviewers; both Macs | Platform catalog and existing session-instance policy; high leverage, low risk |
| P1 | Journal directories change machine identity / sibling_defect | Host, Hunter; repeated Linux writes | Canonical engine machine ID into shared file-effect templates; high leverage, low risk |
| P1 | History time differs from matching process / sibling_defect | Host; one exact command | Shared session source timing must preserve embedded command start; medium leverage, low risk |
| P1 | SMB auth/close precede likely transport / sibling_defect | Hunter; one outlier; native tuple association qualified | Explicit-credential bundle uses requested rather than committed interval; medium leverage, low risk |
| P2 | Curl creates its installed executable / sibling_defect | Host; curl and custom image | Process preflight's generic file guarantee lacks write intent on Mac; medium leverage, low risk |
| P2 | Chrome image version differs from request / sibling_defect | Detection; linked Windows PID | Loaded executable release into shared browser identity; medium leverage, low risk |
| P2 | OCSP durations occupy a narrow band / exact_regression | Network; all 23 flows | Shared HTTP transport-floor slack; medium leverage, moderate reuse/headroom risk |
| P3 | Independent launches share fractional phases / sibling_defect | Hunter; several apps | Baseline integer-second jitter; medium leverage, low risk |
| P3 | TLS companions partition by closure state / new_family | Network; sensor population | Requires handshake/collection semantics investigation; medium leverage, moderate risk |
| P4 | Valid IPv6 spelling differs from expected exporter / false_positive_or_unproven | Network; padded valid groups | Undeclared exporter version; low leverage; do not change valid addresses solely for appearance |

The selected family contracts and entry/consumer inventories are in the focused
assessment worklog. The next checkpoint addresses process population and shared
identity/timing owners, retaining the original probe as a regression guard.
Native exec/exit (ES-R1) and Gatekeeper denial (GK-R1) remain gated by the user's
explicit decision. No native capture or existing local-log inspection occurred.

The sub-90 automated score was investigated: distribution, volume and timing
diagnostics explain it; all acceptance criteria pass. One OCSP analyzer row is
absent on a flow reporting missed bytes, with no decoded identity mismatch.
The evaluator and source-selection policy remain unchanged.
