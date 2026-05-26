# EvidenceForge Worklogs

Use this directory for tracked, shared memory that is too detailed or volatile
for `TODO.md`.

## When to Create or Update a Worklog

- Multi-session implementation efforts
- Assessment or realism loop batches
- PR review/rework batches
- Long investigations with decisions, probes, or follow-up targets
- Branch-local handoff notes that future agents should read

Do not create a worklog for small one-shot fixes where the commit, PR, or final
assistant response is enough.

## Naming

Use one file per effort:

```text
YYYY-MM-DD-<effort-slug>.md
```

Examples:

```text
2026-05-current-dev-assessment-continuation.md
2026-05-proxy-realism-follow-up.md
```

## Suggested Format

```markdown
# Effort Title

## Status

Short current state and whether the work is active, paused, or complete.

## Current Handoff

The next useful action, latest verified findings, and any constraints.

## Decisions

Durable decisions that future agents should not rediscover.

## Validation

Important test/eval commands and latest known results.

## References

PRs, commits, scenario artifacts, scratch outputs, or related docs.
```

Keep worklogs concise. They are for continuity, not for mirroring every command
or replacing the changelog.
