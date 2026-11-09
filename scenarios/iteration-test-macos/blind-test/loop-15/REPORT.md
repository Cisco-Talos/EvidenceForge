# Iterative assessment loop 15

## Outcome

Loop 15 targeted generic Linux shell-history texture at the command-pool owner. Help desk sessions on Linux servers previously fell through to the sysadmin pool; the role selector now routes them to a separate, YAML-backed `help_desk_server` pool while preserving workstation-specific help desk activity. Behavior revision 414 records the change.

The focused 15-test suite passed. `eforge validate-config` reported 0 errors, one pre-existing Chrome Helper catalog warning, and an informational message because the validator does not yet understand the derived server-pool key. Ruff, formatting, and behavior-manifest validation passed. Fresh generation produced 132,201 records and passed its one JSON evaluation at 96.349234 (parseability 100.0, plausibility 96.8412, causality 95.3255, timing 91.5378). All 117 data files in the blind copy match the generated bundle byte-for-byte.

## Family probes

| Probe | Loop 14 | Loop 15 | Result |
|---|---:|---:|---|
| Aisha Johnson server history files | 5 | 7 | More Linux server sessions exercised the route in this generated bundle |
| Aisha Johnson server commands | 56 | 68 | Increased session coverage; each of the seven hosts has a distinct operational context |
| DB-PROD-01 help desk examples | generic diagnostics | loginctl, getent, resolver, sshd and mysql service checks | New pool is visible in generated history |
| Host/EDR verdict | Synthetic (66) | Synthetic (68) | Broad repetitive shell vocabulary remains a concern across Linux users and both Macs |

The fix corrects one exercised help desk routing case. It does not close the broader shell-history distribution family: sysadmin, security, DBA and macOS histories still contain recurring inspection vocabulary, and reviewers continue to flag cross-user repetition.

## Independent expert panel

| Expert | Initial verdict | Verdict confidence | Synthetic-confidence score |
|---|---|---:|---:|
| Threat Hunter | Inconclusive | 65 | 37 |
| Detection Engineer | Inconclusive | 65 | 43 |
| Network Forensics | Inconclusive | 65 | 30 |
| Host/EDR Forensics | Synthetic | 76 | 68 |
| **Mean** | **mixed/inconclusive** | **67.75** | **44.5** |

Verdicts disagreed and synthetic-confidence scores spanned 38 points, so deliberation was required. The facilitator modeled revised positions using only the saved reports: three experts remained inconclusive and Host/EDR remained synthetic. Revised mean verdict confidence was 66.75 and mean synthetic-confidence was 45.75. The panel's clearest shared concern is repetitive command vocabulary across unrelated Linux users and both Mac histories. It also debated repeated Mac directory metadata and the mirrored temporary endpoint-inventory plist; none of these reports demonstrated an impossible ordering or source-native contradiction. SSH and DNS/proxy/TLS correlations were judged coherent but are not authenticity evidence by themselves.

## Prioritized findings

| Priority | Finding | Category | Status |
|---|---|---|---|
| P1 | Generic Linux inspection command vocabulary recurs across users and server roles. | `distribution_texture` | Help desk server routing now has a distinct support pool; broader role and host variation remains open. |
| P2 | Both Macs reuse a narrow discovery-command set and the same temporary endpoint-inventory plist workflow. | `distribution_texture` | Separate families; do not alter without verifying their canonical management/task owners. |
| P3 | Mac Endpoint Security directory records reuse inode values and exact 2025 timestamps. | `weak_signal` | No contradiction demonstrated; investigate filesystem-image metadata ownership before repair. |
| P4 | Four failed local Mac logins are close-spaced; HTTP user agents and DNS/Kerberos traffic are concentrated. | `weak_signal` | Plausible retries, limited clients, and directory infrastructure remain alternatives. |

## Comparison with quantitative evaluation

The evaluator passed hard acceptance criteria, with a 96.349234 quality score across 132,201 records. This is 0.348117 points below loops 13–14 and 1,212 fewer records. Parseability remained 100.0; the modest change is primarily in causality and timing sub-scores. Quantitative acceptance does not assess whether command pools vary enough across roles and hosts. The blind panel mean synthetic-confidence score was 44.5, with a 38-point spread and split verdicts; deliberation's modeled mean was 45.75.

## Next target

Continue with the broad shell-history distribution family, but trace the next fix to the owner of the repeated commands and workflows across active Linux personas. Prioritize differences by server role and user task, then verify both exact-command recurrence and semantic task variation in fresh `bash_history`. Keep the macOS plist and filesystem metadata concerns separate until their canonical owners are confirmed.

Loop 15 is **complete**. The family contract, root-cause probe, single automated evaluation, four independent reports, deliberation, and canonical score JSON are saved in this directory.
