# Monotonic Blind Loop Experiment

## Purpose

This branch tests a stricter assessment-loop policy before changing the
`eforge-assess` skill. The goal is to keep accepted EvidenceForge realism-loop
checkpoints monotonically improving with respect to standalone blind-review
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
scenarios/iteration-test/blind-test/loop-N/
```

Rejected attempts stay outside the dashboard trend:

```text
scenarios/iteration-test/blind-test/rejected/attempt-N-a/
scenarios/iteration-test/blind-test/rejected/attempt-N-b/
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

Starting accepted baseline: current `dev` state at branch creation. Establish
the precise loop number, commit, and standalone blind average before the first
candidate fix.
