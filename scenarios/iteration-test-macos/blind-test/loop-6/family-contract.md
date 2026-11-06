# Loop 6 family contract — macOS process identity chronology

## Target

Canonical process identity allocation in `StateManager` and its action-cohort builder.
Fork births, exec image replacements, baseline processes, and storyline processes must
share one per-host native PID-version timeline.

## Entry paths and consumers

Entry paths include direct `plan_process_materialization`, materialization-batch process
planning, action-cohort process starts, action-cohort `execute_process`, and compatibility
adapters that delegate into those owners. Baseline and storyline activity both reach these
canonical paths. Endpoint Security, eCAR/EDR, lifecycle identity references, and checkpoint
recovery consume the resulting immutable process identities.

## Required invariant

For any two distinct macOS process identity transitions on one host, if transition A's
canonical event time is earlier than transition B's, A's `audit_pid_version` must be
smaller than B's. This must hold in returned canonical identities before rendering; sorting
ES records or rewriting emitted tokens is not a repair. Versions remain unique, positive,
within the unsigned 32-bit namespace, host-scoped, and stable across checkpoint/resume.

## Evidence motivating the loop

Loop 5's independent Host review identified visible version regressions. A direct read-only
scan of the loop 5 blind data confirmed 15 reversals on MAC-MROSS-01 and 39 on
MAC-MROSS-02. The current allocator increments a host counter in planning/commit order,
while some canonical process and exec transitions are planned out of event-time order.

## Acceptance evidence

- A focused regression reproduces out-of-time-order process/exec planning and proves the
  canonical versions preserve chronological ordering.
- Existing host scoping, fork/exec, retry/abort, PID reuse, and checkpoint contracts continue
  to hold.
- The full loop-6 generation passes exact native fork/exec coverage and evaluation.
- An independent scan of every generated macOS fork/exec audit token finds zero version
  regressions by event time on both modeled hosts.
- Reviewers assess the complete sanitized bundle; score spread/verdict disagreement triggers
  the required deliberation.

## Scope guard

Do not change the authored scenario, weaken coverage, sort source output to conceal the issue,
or independently invent token facts in an emitter. If the allocation owner cannot preserve
this invariant without changing identity references, report the exact blocker before modifying
identity semantics.

The sibling risk is an execution transition that is sequenced locally but backdated relative to
another process birth. It must reserve through the same temporal index; source-local or event-type-
specific counters would leave that path inconsistent.
