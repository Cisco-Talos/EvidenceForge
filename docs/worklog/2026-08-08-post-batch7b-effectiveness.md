# Post-Batch-7b effectiveness gate

## Purpose

Measure whether the cumulative architecture/remediation work improved rendered realism. This is a
single assessment pass, not an iterative blind-review fix loop.

## Frozen inputs

- Branch/commit: `codex/batch7-compatibility-docs` at `53934a16`.
- Scenario: `/private/tmp/eforge-realism-review/branch-enterprise.yaml`, SHA-256
  `bf7eef77f0cb121bb0838cc4252ae19347e1a8c8304079c11426163806cc07ff`.
- Duration/profile: six hours, `enterprise_standard`.
- Primary output: `/private/tmp/eforge-post-batch7b-effectiveness/branch-enterprise`.
- Repeat output: `/private/tmp/eforge-post-batch7b-effectiveness/branch-enterprise-repeat`.
- Neutral reviewer copy: `/private/tmp/case-omega.SimlDV/data`.

The user-supplied `iteration-test-expanded` scenario was considered but no longer validates
unchanged under the current capability contract. The exact frozen integrated review benchmark was
used instead.

## Execution result

- Validation passed with the existing undeclared network-identity warning for
  `portal.northstarclaims.net`.
- Primary/repeat outputs are byte-identical across 38 data files, digest
  `911decaca74f1b2663d6508d2e99eed861a247ffbdd76c34ed6f9cbcb803e67f`.
- Evaluation parsed 53,548 records across 16 sources and scored 95.025576. Acceptance failed only
  at `causality.pivot_linkability=40`, below the current threshold of 80.
- The current realism probe reports two deterministic SSH ordering families: 9 records on PROXY
  and 28 on WEB have syslog for an sshd PID before eCAR observes that PID's process creation.
- A controlled run from Batch 7a commit `868eb35d` has one Linux PID-reversal finding and no SSH
  ordering failure. Batch 7b therefore repaired the reversal but introduced the SSH regression.

## Blind panel

Four isolated reviewers saw only the neutral data directory. All returned Synthetic:

| Specialty | Verdict confidence | Synthetic confidence |
| --- | ---: | ---: |
| Threat Hunter | 84 | 72 |
| Detection Engineer | 98 | 96 |
| Network Forensics | 97 | 96 |
| Host/EDR | 98 | 96 |

The panel average is 90.0 and the spread is 24. No deliberation was triggered. The result is 1.75
points lower than the original pre-fix 91.75 and 0.75 lower than the final gate 90.75; those small
differences do not demonstrate material aggregate improvement across independent panels.

## Validated dispositions

Five P1 families block PR readiness: the Batch 7b SSH source-order regression, inbound WFP remote
PID leakage, file/application/transport loss-accounting contradictions, clock-derived Linux PID
allocation, and missing SSH close ownership. Secondary findings include bounded Type 3 durations,
singleton service accumulation, template-shaped Linux chatter/SSH cadence, and timing/ID
quantization.

No generator fix was made and no follow-up blind assessment was started. The complete evidence,
static ownership traces, score comparison, and next dependency order are in
`docs/design/realism-review/post-batch7b-effectiveness/REPORT.md`.
