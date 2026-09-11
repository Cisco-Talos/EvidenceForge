# Experimental clean-room scenario-agent acceptance

This directory is a repository-local experiment. It is not imported by `evidenceforge`, installed
in the EvidenceForge wheel, exposed by the public `eforge` CLI, run by GitHub Actions, or required
for a release. A maintainer may discard the entire directory without changing shipped behavior.

The harness asks whether deterministic observation of live Codex and Claude authoring sessions
produces trustworthy regression signals. It does **not** evaluate generated-log realism, use an LLM
judge, produce a composite quality score, or establish statistically confident model quality.

## Isolation claim

Each session gets a disposable workspace containing a prompt, controlled starting files, freshly
installed packaged skills and references, and access to the branch's freshly built wheel through an
instrumented `eforge` shim. The source checkout, existing scenarios, worklogs, public reference
manual, personal skills, and generated data are not copied into the workspace.

Provider authentication is reused. Provider CLIs still own credential access and some built-in
behavior, so the report deliberately says `session-isolated`, not credential-isolated. Codex runs
ephemerally with user configuration and rules disabled. Claude runs nonpersistently with only
project settings, no Chrome, an empty strict MCP configuration, and a restricted tool list. The
harness treats detected access outside the workspace as a strict isolation violation.

The shim permits only:

- `eforge schema <selector> --json`
- read-only `eforge info`
- `eforge validate <workspace-path> --json`
- non-writing `eforge resolve <workspace-path> --explain-composition --json`
- `eforge pack list|show|validate`

Generation, OOB flags, project-root overrides, configuration writes, pack mutation/release, and
writing resolve are rejected and recorded. Unsupported provider versions or transcript events are
reported as `INFRASTRUCTURE_ERROR`, never as agent-quality failures.

## Maintainer workflow

From the repository root:

```bash
uv sync --all-extras

uv run python -m experiments.scenario_agent_acceptance run \
  --suite smoke \
  --agents codex,claude \
  --report .eforge/agent-acceptance/smoke.json

uv run python -m experiments.scenario_agent_acceptance verify \
  --report .eforge/agent-acceptance/smoke.json
```

The full experiment executes eight cases once with each provider:

```bash
uv run python -m experiments.scenario_agent_acceptance run \
  --suite full \
  --agents codex,claude \
  --report .eforge/agent-acceptance/full.json

uv run python -m experiments.scenario_agent_acceptance verify \
  --report .eforge/agent-acceptance/full.json
```

The default per-session timeout is 45 minutes. It is a hung-process cleanup bound, not an expected
authoring duration. Maintainers may change it for an individual run with
`--timeout-seconds <seconds>`; timeout is always classified as infrastructure failure, never agent
failure.

Reports, normalized transcripts, stderr captures, command traces, and scenario snapshots live
beneath ignored `.eforge/agent-acceptance/`. They can contain authored exercise content and should
not be committed.

After reviewing a satisfactory full report, preview the compact baseline and then explicitly apply
it:

```bash
uv run python -m experiments.scenario_agent_acceptance baseline \
  --from-report .eforge/agent-acceptance/full.json

uv run python -m experiments.scenario_agent_acceptance baseline \
  --from-report .eforge/agent-acceptance/full.json \
  --apply
```

`--apply` refuses reports containing infrastructure errors or strict violations. The resulting
tracked `baseline.json` contains only aggregate behavior and input digests—not YAML or transcripts.
An initial baseline describes observed behavior without inventing numeric quality thresholds.
Later verification ratchets first-draft successes, passes to zero errors, warning churn, and repair
regressions.

## Status and metrics

Each session is `PASS`, `FAIL`, or `INFRASTRUCTURE_ERROR` and retains its metric scorecard. Strict
invariants always apply: terminal validity, valid pack composition when selected, no unchanged
validation loop, all required references and schema selectors observed, no repair drift, no
forbidden command, and no ambient-context access.

Non-strict reported signals include first-complete-draft validity, validation passes to zero,
introduced/removed/retained/unexpected warnings, newly introduced errors, interview turns and
question discipline, duration, tool calls, and provider-reported usage. They remain separate; the
harness never hides tradeoffs inside one score.

## Deterministic tests

Live model calls are never made by pytest:

```bash
uv run pytest experiments/scenario_agent_acceptance/tests --no-cov
```

The tests cover transcript adapters, schema-oracle behavior, warning and repair metrics, negative
controls, redaction and bounds, atomic report writes, integrity verification, timeout process-group
cleanup, the policy shim, and fake-provider session behavior. Known-good case scenarios are also
validated with the packaged wheel as runtime preflight whenever a live suite starts.

## Effectiveness decision

After the first full 16-session run, review aggregate results, representative pass/fail traces,
false-positive and false-negative risks, runtime, and provider usage. Record a recommendation to
merge, revise, or discard in the worklog. Do not merge this experiment, alter release processes, or
close the existing TODO P1 without explicit maintainer approval.
