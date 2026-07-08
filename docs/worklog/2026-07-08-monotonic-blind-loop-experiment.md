# Monotonic Blind Loop Experiment

## Purpose

This branch tests a stricter assessment-loop policy on
`scenarios/iteration-test-expanded/` before changing the `eforge-assess` skill.
The goal is to keep accepted EvidenceForge realism-loop checkpoints
monotonically improving with respect to standalone blind-review
synthetic-confidence scores. Lower synthetic-confidence scores are better.

## Branch Policy

- Run the experiment on `codex/monotonic-blind-loop-experiment`, branched from
  `dev`.
- Do not push unless the experiment is worth preserving.
- Keep all protocol notes, loop artifacts, rejected-attempt artifacts, and any
  candidate fixes on this branch so the entire experiment can be discarded by
  deleting or abandoning the branch.
- Do not update `/Users/dabianco/.codex/skills/eforge-assess/SKILL.md` during
  the experiment.

## Scoring Policy

- Use only standalone blind reviewer `synthetic-confidence score` values.
- Do not run deliberation for this experiment, even when reviewers disagree or
  the reviewer score spread is large.
- Compute the decision score as the average of available standalone reviewer
  synthetic-confidence scores.
- If any reviewer omits a synthetic-confidence score, treat the attempt as
  invalid and rerun or replace that reviewer. Do not substitute verdict
  confidence.
- Automated eval remains a guardrail only. Do not accept or reject a candidate
  because the automated score improved or declined unless it fails the normal
  parser/acceptance guardrails.

## Acceptance Rule

Each candidate loop starts from the latest accepted checkpoint and must satisfy:

```text
candidate_average_synthetic_confidence < accepted_average_synthetic_confidence
```

If the candidate average is equal to or higher than the accepted average, reject
the candidate fix and revert it. A stricter margin can be added later if reviewer
variance makes the strict comparison too noisy, but the initial experiment uses
the simple strict-decrease rule.

Do not promote a candidate that introduces a new candidate-caused hard
contradiction, even if the average score technically decreases.

## Artifact Layout

Accepted loops stay in the normal canonical loop series:

```text
scenarios/iteration-test-expanded/blind-test/loop-N/
```

Rejected attempts stay outside the dashboard trend:

```text
scenarios/iteration-test-expanded/blind-test/rejected/attempt-N-a/
scenarios/iteration-test-expanded/blind-test/rejected/attempt-N-b/
```

Dashboards and rolling score tables should use accepted `loop-N/scores.json`
artifacts only. Rejected attempts are preserved for diagnosis but are not part
of the monotonic accepted-loop trend.

## Loop Procedure

For each candidate attempt:

1. Confirm the current branch and accepted baseline commit.
2. Read the latest accepted loop report and recent recurrence context.
3. Select one or two highest-leverage family-level targets.
4. Write the family contract before coding.
5. Implement the fix at the owning layer, with focused tests and probes.
6. Run relevant focused tests, `uv run ruff check .`, and
   `uv run ruff format --check .`.
7. Commit the candidate fix before regenerating and reviewing the output.
8. Regenerate, evaluate, and run the standalone blind panel.
9. Save candidate results in a rejected-attempt directory until accepted.
10. Compare the candidate standalone blind average to the latest accepted
    average.
11. If accepted, promote artifacts to the next `loop-N/`, update dashboard and
    worklog notes, and keep the candidate commit.
12. If rejected, preserve the rejected reports, revert the candidate commit, and
    select a new target from the latest accepted state plus rejected-review
    evidence.

## Attempt Log

Starting accepted baseline: `scenarios/iteration-test-expanded/blind-test/loop-59`.

- Baseline standalone blind average: 38.25
- Baseline reviewer scores: Threat Hunter 36, Detection Engineer 62, Network
  Forensics 28, Host/EDR 27
- Automated eval is ignored for acceptance, but loop 59 passed at 95.90845223387653
  over 96,389 records.

### Attempt 60-a — Rejected

- Candidate target: loop-59 Detection Engineer P1 ASA connection-ID hidden-volume
  model. The prior report found 6,048 built TCP/UDP connection IDs with adjacent
  visible gaps always in the 1-5 range.
- Candidate commit: `3b43c998 fix: add ASA hidden connection-id volume`
- Owning layer: Cisco ASA source-native emitter
- Family contract: visible ASA Built/Teardown IDs remain monotonic and paired,
  but adjacent visible IDs include deterministic hidden-volume gaps instead of
  exposing a tiny bounded synthetic increment range.
- Verification before review:
  - `uv run pytest --no-cov tests/unit/test_cisco_asa_emitter.py`
  - `uv run ruff check src/evidenceforge/generation/emitters/cisco_asa.py tests/unit/test_cisco_asa_emitter.py`
  - `uv run ruff format --check src/evidenceforge/generation/emitters/cisco_asa.py tests/unit/test_cisco_asa_emitter.py`
  - `uv run pytest --no-cov` before the same-second ordering correction: 4,875
    passed, 19 skipped
  - Regenerated and evaluated `scenarios/iteration-test-expanded/`: PASS,
    95.90845223387653, 96,389 records
  - Hard probe: 6,048 Built IDs, 0 nonpositive adjacent Built gaps, 194 distinct
    adjacent gaps, max gap 231, 6 expected dangling Built IDs at collection edge
- Standalone blind scores:
  - Threat Hunter: 45
  - Detection Engineer: 43
  - Network Forensics: 56
  - Host/EDR: 32
  - Average: 44.0
- Decision: rejected because 44.0 is not lower than the accepted baseline 38.25.
- Revert commit: `512a8304 Revert "fix: add ASA hidden connection-id volume"`
- Artifacts: `scenarios/iteration-test-expanded/blind-test/rejected/attempt-60-a/`

Carry-forward findings from the rejected blind reviews:

- Detection Engineer: eCAR FLOW timing repeatedly lags Zeek/syslog transport
  evidence, including SSH sessions and short DNS flows.
- Network Forensics: repeated `mail-fin.meridianhcs.com` proxy-origin path
  mismatch; DNS answers internal `10.10.2.27`, but proxy-origin TLS/ASA goes to
  `54.230.228.12`.
- Threat Hunter: one SSH tuple has endpoint session close roughly 15 minutes
  before Zeek TCP close, plus repeated rsyslog reload and Sysmon static registry
  texture.
- Host/EDR: endpoint telemetry remains mostly realistic; minor bash-history
  timestamp backstep and filtered Windows Security EventRecordID gaps.
