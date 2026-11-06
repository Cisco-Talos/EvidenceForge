# Iterative assessment loop 14

## Outcome

Loop 14 replaced evenly spaced macOS authoritative process-termination slots with deterministic,
process- and session-scoped timing gaps at the canonical generic-logoff planner. Parent/child
lifecycle constraints, exact session end plans, and downstream source observations continue to use
the resulting canonical timestamps. Behavior revision 413 records the change.

Focused timing and generic-logoff tests passed (2 selected), including deterministic repeatability,
session-scoped variation, and bounded gap samples. `eforge validate-config` reported 0 errors and
the same existing Chrome Helper catalog warning. Ruff, formatting, and behavior-manifest checks
passed. Fresh generation produced 133,413 records and passed one JSON evaluation at 96.697351
(parseability 100.0, plausibility 96.7994, causality 95.9151, timing 92.5936). All 114 blind-copy
data files matched the generated output byte-for-byte.

## Family probes

| Host | Exit count | Exit range UTC | Inter-exit gap CV | Logout UTC |
|---|---:|---|---:|---|
| MAC-MROSS-01 | 10 | 18:54:58.555–18:54:59.800 | 0.29 | 18:55:01.020 |
| MAC-MROSS-02 | 16 | 18:56:57.390–18:56:59.806 | 0.33 | 18:57:03.134 |

The observed gaps vary from 76–204 ms on MAC-MROSS-01 and 91–293 ms on MAC-MROSS-02. Both
process cohorts remain before their owning local logout. This removes the prior equal-slot pattern,
but the cohorts are still clustered near logout; reviewers continued to identify that timing as a
weak signal, so the family is improved but not closed.

## Independent expert panel

| Expert | Initial verdict | Verdict confidence | Synthetic-confidence score |
|---|---|---:|---:|
| Threat Hunter | Inconclusive | 66 | 53 |
| Detection Engineer | Inconclusive | 72 | 39 |
| Network Forensics | Inconclusive | 62 | 46 |
| Host/EDR Forensics | Synthetic | 87 | 66 |
| **Mean** | **mixed/inconclusive** | **71.75** | **51.0** |

The disagreement triggered deliberation. Three reviewers remained inconclusive and Host/EDR retained
a synthetic verdict. The final deliberation mean synthetic-confidence was 55.0. The panel's strongest
shared concern is repetitive shell-history texture across Linux and both Macs. It also identified the
same temporary endpoint-inventory LaunchDaemon workflow on the two Macs and a concentrated,
encoded-looking DNS TXT burst. Those behaviors may be legitimate or intentionally malicious, but
their repeated shape is a concrete next realism target. The Mac exit bursts remain a weak concern,
not a demonstrated lifecycle contradiction.

## Prioritized findings

| Priority | Finding | Category | Reviewer original rating | Status |
|---|---|---|---|---|
| P1 | Authoritative Mac shutdown assigned near-equal process-close intervals across two hosts. | `distribution_texture` | not labeled | Improved; variable gaps now preserve session deadlines, but near-logout bursts remain |
| P2 | Linux and Mac shell histories reuse narrow generic inspection commands across different users and hosts; Mac histories also repeatedly use `cat` on PDFs/XLSX files. | `distribution_texture` | not labeled | Highest consensus candidate for loop 15 |
| P2 | Both Macs show a temporary root-owned endpoint-inventory plist, repeated xpcproxy/`sw_vers` activity, and similar removal timing. | `distribution_texture` | not labeled | New candidate; verify the modeled management owner before changing event details |
| P3 | DB-PROD-01 produces 237 encoded-looking TXT requests in 15 minutes. | `distribution_texture` | not labeled | Plausible DNS-tunnel behavior; avoid treating attack behavior itself as a synthetic defect |
| P4 | A quiet Lina local Mac session and some unmatched eCAR/Zeek tuples lack full context. | `environment_or_collection_plausibility` / `weak_signal` | not labeled | Unproven without collection-scope evidence |

## Comparison with quantitative evaluation

The evaluator passed all hard acceptance criteria and returned the same score and record count as
loop 13 (96.697351; 133,413 records). Its high score is a guardrail and does not capture the
behavioral distribution concerns raised by reviewers. The standalone mean rose 3.25 points from
loop 13 (47.75 to 51.0), while the panel continued to disagree about the dataset's overall origin.

## Next target

Target repeated shell-history behavior next. Trace the owning generators and data pools for Linux
and macOS command histories, then vary task selection and command vocabulary by host role, user,
and session without erasing the useful logged activity. Keep the Mac close-gap improvement and
verify its remaining logout clustering in later loops. Treat the inventory plist and DNS tunnel as
separate follow-up families until their canonical owners and expected scenario semantics are
confirmed.

Loop 14 is **complete**. The one evaluation, family contract and probes, four independent reports,
deliberation, and machine-readable scores are saved in this directory.
