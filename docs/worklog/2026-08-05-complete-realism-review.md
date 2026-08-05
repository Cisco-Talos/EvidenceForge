# Complete EvidenceForge Code and Realism Review Worklog

## Status

Review campaign complete on 2026-08-05. The architecture gate was accepted, the exhaustive path
census and empirical campaign completed, four isolated blind reviews completed, the security scan
was sealed, and the final synthesis and remediation roadmap were published.

No generator behavior has been changed.

The canonical contract proposals were approved with six amendments on 2026-08-05. Implementation
is authorized as bounded feature-branch batches, beginning with
`codex/canonical-contract-foundation`.

## Frozen baseline

- Requested branch: `dev`
- Commit: `0a035e97d94cd2a35ebd1498cc4e133336fe14a4`
- Initial tracked worktree state: clean
- Worktree mode: detached HEAD at the requested `dev` commit
- Review package: `docs/design/realism-review/`
- Generated-output policy: review datasets and transient probes remain untracked

## Scope decisions

- Included: the complete deterministic pipeline from scenario validation through evaluation,
  plus build and security surfaces.
- Excluded: Phase 1 authoring skills except where they define or consume the scenario-schema
  contract.
- Review-only constraint: do not fix generator behavior, change public APIs, migrate schemas, or
  bump the version during the campaign.
- Gate: stop after the architecture/object-model assessment and continue only after acceptance.
- Contract implementation gate: contract proposals are review deliverables and require separate
  user review and approval before any implementation.

## Architecture gate acceptance

- Accepted by the user on 2026-08-05.
- Authorized: path census, cross-cutting audits, empirical campaign, blind expert reviews,
  security review, and final synthesis.
- Additional constraint: present contract proposals for user review before implementing them.
- This does not alter the existing review-only rule; no fixes or migrations occur in this campaign.

## Architecture-gate work completed

- Read `TODO.md`, repository instructions, the accepted architecture-reset requirements,
  requirements review, recommendation, implementation plan, current architecture reference, and
  event-model PRD.
- Traced the implemented control flow through `GenerationEngine`, baseline/storyline scheduling,
  `WorldModel`/`WorldPlanner`, action bundles, `ActivityGenerator`, causal expansion,
  `SecurityEvent`, identity/lifecycle planning, `StateManager`, visibility/NAT, observation,
  source timing, dispatcher routing, emitters, ground truth, and the evaluation boundary.
- Inventoried the object-model families at the architectural level: 31 authored event specs,
  55 `SecurityEvent` fields, 38 mutable context dataclasses, immutable identity/lifecycle/network/
  cryptography/proxy/authentication plans, 51 concrete action-bundle classes, and 23 concrete
  format definitions.
- Measured the largest ownership surfaces at this baseline:
  - `ActivityGenerator`: 22,407 lines
  - `BaselineMixin`: 8,409 lines
  - `StorylineMixin`: 5,456 lines
  - `_execute_typed_event`: 2,846 lines
  - `NetworkTransactionPlanner.execute`: 2,463 lines
  - `StateManager`: 2,385 lines
  - `SourceTimingPlanner`: 1,558 lines
- Compared the accepted reset's intended ownership with the actual call and mutation boundaries.
- Produced the gate report at `docs/design/realism-review/architecture-object-model.md`.

## Reproducible architecture probes

Run from the repository root at the frozen commit. The local `.venv/bin/python` commands require
the project environment to exist; an equivalent `uv run python` invocation is acceptable with a
writable uv cache.

### Missing canonical event contract

This demonstrates that a known internal kind with a missing required context reaches dispatch,
receives an event ID, and completes without an error:

```bash
.venv/bin/python -c 'from datetime import datetime, timezone; from evidenceforge.events.base import SecurityEvent; from evidenceforge.events.dispatcher import EventDispatcher; from evidenceforge.generation.state_manager import StateManager; sm=StateManager(); now=datetime(2026, 1, 1, tzinfo=timezone.utc); sm.set_current_time(now); event=SecurityEvent(timestamp=now, event_type="connection"); print(EventDispatcher(sm, {}).dispatch(event)); print(bool(event.event_id), event.identity_plan, event.lifecycle)'
```

Observed shape: `{}` followed by `True None None`.

### Sequence-sensitive event identity

This demonstrates that inserting an unrelated earlier event changes the target event's ID even
when the target type and canonical timestamp are unchanged:

```bash
.venv/bin/python -c 'from datetime import datetime,timezone,timedelta; from evidenceforge.events.base import SecurityEvent; from evidenceforge.events.dispatcher import EventDispatcher; from evidenceforge.generation.state_manager import StateManager; t=datetime(2026,1,1,tzinfo=timezone.utc)
def run(types):
 sm=StateManager(); sm.set_current_time(t); dispatcher=EventDispatcher(sm,{}); result={}
 for kind in types:
  event=SecurityEvent(timestamp=t+timedelta(seconds=10),event_type=kind); dispatcher.dispatch(event); result[kind]=event.event_id
 return result
print(run(["target"])["target"]); print(run(["prefix","target"])["target"])'
```

Observed target IDs differ (`505bf5f2-f7c6-40ed-8f8e-66ab49643e14` versus
`4f29a607-69ff-4472-929b-3bd5585df7c2`).

### Fail-open causal expansion

Injecting a rule whose expansion raises logs a traceback but returns an empty list, allowing the
triggering generation path to continue without its required evidence:

```bash
.venv/bin/python -c 'from datetime import datetime,timezone; from evidenceforge.generation.causal.engine import CausalExpansionEngine,ExpansionContext; from evidenceforge.generation.causal.rules import ExpansionRule
class Broken(ExpansionRule):
 def matches(self,event_type,ctx): return True
 def expand(self,event_type,ctx): raise RuntimeError("probe")
engine=CausalExpansionEngine([Broken()]); print(engine.expand("connection",ExpansionContext(event_type="connection",timestamp=datetime(2026,1,1,tzinfo=timezone.utc))))'
```

Observed: a logged `RuntimeError: probe`, then `[]`.

### Observation time feeding canonical lifecycle state

The behavior is already encoded by
`tests/unit/test_dispatcher.py::TestObservationProfiles::test_delayed_process_source_observation_extends_process_activity`.
It configures a 900,000 ms Sysmon observation delay and asserts that
`RunningProcess.last_activity_time` becomes the delayed source timestamp. Static control flow is
`EventDispatcher.dispatch()` -> per-emitter delayed `event_to_emit` ->
`StateManager.update_process_activity_time()`.

## Command and failure notes

- `git rev-parse HEAD`, branch containment, and status confirmed the requested clean baseline.
- `uv run python` initially created the local project environment and reported CPython 3.12.12.
- A later `uv run python --version` attempt failed because the sandbox could not initialize the
  default cache under `/Users/dabianco/.cache/uv`. Subsequent read-only probes used
  `.venv/bin/python`.
- `.venv/bin/pytest` was unavailable because the created environment did not include the test
  executable. No suite run was required for this gate; full and targeted validation remains in
  the post-gate empirical campaign.
- No generated dataset was produced during the architecture gate.

## Gate findings

The architecture report records ten root-cause findings:

- `ARCH-001`: canonical event contracts are not centrally defined or enforced.
- `ARCH-002`: canonical state is mutated from source-observation time.
- `ARCH-003`: canonical and compatibility truth coexist in a mutable event graph.
- `ARCH-004`: action-bundle ownership is structurally inconsistent and often remains in the
  generator.
- `ARCH-005`: timing and observation constraints are spread across order-sensitive registries and
  special cases.
- `ARCH-006`: causal expansion is stringly typed and fail-open.
- `ARCH-007`: source projection can recompute shared destination identity.
- `ARCH-008`: event identity is sequence-sensitive rather than action-relative.
- `ARCH-009`: ground truth is maintained as a parallel imperative model.
- `ARCH-010`: architecture documentation overstates completed boundaries and contains stale
  object/extension claims.

## Authorized post-gate work

1. Build the reproducible `scripts/` review utility and static event/context path matrix.
2. Complete path classification for every authored and internal event kind, context/plan, bundle,
   constructor, state transition, emitter, evaluator, and raw escape hatch.
3. Run the cross-cutting consistency, lifecycle, timing, world/config, source-native, evaluation,
   general-quality, and scoped security audits.
4. Execute the bounded scenario/seed/profile/stress/repeat/filter/parallel empirical matrix.
5. Run four isolated blind expert reviews and validate every accepted observation against code or
   rendered evidence.
6. Publish the machine-readable finding register, coverage and reference ledgers, final report,
   and dependency-ordered remediation batches without implementing fixes.

## Static path census

- Expanded the AST inventory to include emitter contracts and finite dynamic event-name domains.
- Final static scope: 31 authored specs, 66 event names, 68 constructors, 38 contexts, 27
  plans/identities, 51 bundles, and 23 formats.
- Completed grouped manual classifications for every row; coverage reports no missing or unknown
  classifications.
- Recorded path-level risks in `docs/design/realism-review/event-context-path-census.md`.
- No generator behavior was changed.

## Cross-cutting and empirical campaign

- Added `scripts/realism_review_inventory.py` for reproducible static census generation and
  `scripts/realism_review_probe.py` for rendered invariant checks. Neither changes generation.
- Reviewed all 23 concrete formats against official documentation or license-compatible public
  exemplars and recorded the ledger in `source-references.json`.
- Ran minimal, repeat, baseline-only, adapted full-coverage APT, branch-office enterprise,
  ten 24-hour profile variants, three seven-day baseline variants, and one 30-day stress workload.
- Generated-data root: `/private/tmp/eforge-realism-review`. Generated data is untracked; SHA-256
  manifests and parameters are in `empirical-results.json`.
- Confirmed byte-identical repeat generation for the minimal scenario.
- Confirmed that full-output and Zeek-only generation are not projection-equivalent: all nine
  common Zeek files differ, including `conn.log` counts of 20,591 versus 12,885.
- The branch-enterprise expanded probe recorded 44 errors and two warnings, covering process and
  session lifecycle, failed-attempt identity, RDP ordering, SSH process reuse, IDS attachment,
  LogonGuid immutability, Windows 4648 fields, and Zeek distribution/interval contracts.
- The 30-day minimal workload reproduced 1,442 DHCP role-separation errors and 1,442 related
  self-flow observations.
- The public API exposes no coherent seed. The ten requested seed runs were therefore documented
  scenario-name variants; `GenerationEngine` resets a thread-local RNG to 42.

### Test and tool results

- `uv run ruff check .`: passed.
- `uv run ruff format --check .`: passed; 447 files already formatted.
- `uv run pytest --no-cov`: 5,075 passed, 41 skipped in 215.04 seconds.
- `uv run pytest --no-cov --include-slow -m slow`: 13 passed, one skipped, 5,102 deselected in
  58.57 seconds; the memory test was skipped.
- `uv run pytest --no-cov --include-external-parsers -m external_parser -q -rs`: four skipped.
  Docker/Podman Compose was unavailable; Splunk also requires explicit local license acceptance.
- `eforge eval --real-parsers` is a reserved option and does not currently run real parsers.
- The shipped `tests/fixtures/scenarios/full-coverage-apt.yaml` failed validation because three
  network segments lack required `exposure`; a temporary copy adding only those values was used.
  Static review also found a silently accepted duplicate YAML key.

## Blind expert reviews

- Four isolated reviewers received only
  `/private/tmp/eforge-realism-review/branch-enterprise/data`.
- They did not receive scenario YAML, ground truth, source, review artifacts, prior reports, or one
  another's output.
- Threat Hunter: synthetic, confidence 90, score 88.
- Detection Engineer: synthetic, confidence 97, score 96.
- Network Forensics: synthetic, confidence 93, score 86.
- Host/EDR Forensics: synthetic, confidence 98, score 97.
- Panel result: unanimous synthetic, 94.5 average confidence, 91.75 average score, 11-point spread.
  No deliberation threshold was triggered.
- Every observation admitted to the finding register was verified against code or rendered data.
- The user-provided historical archive under
  `/Users/dabianco/projects/SURGe/EvidenceForge/scenarios/iteration-test-expanded/blind-test` was
  consulted only after current blind work completed. It was used for recurrence and sibling-risk
  evidence, never as the current verdict.

## Security scan

- Codex Security scan ID: `8b382b68-e6ad-4638-8725-d5800897d49f`.
- Snapshot:
  `codex-security-snapshot/v1:sha256:42528a309387007d2298edd853bcbcea8c9159cb2aa90175bf4eecc014bdf612`.
- Status: completed, sealed, and indexed at 2026-08-05T18:15:39.286020Z.
- Accounting: 1,127 repository files, 664 authoritative worklist receipts, 14 candidate
  validations, and 12 eligible attack-path decisions.
- Final findings: eight medium and two low; no critical or high finding survived calibration to
  the current local CLI boundary.
- One evaluator full-corpus RSS concern is deferred pending a calibrated capacity benchmark.
- Strong controls include safe YAML loading, sandboxed Jinja, DTD/entity rejection, pinned
  workflows, and hardened SOF-ELK® staging.
- Docker and licensed Splunk runtime dependencies were unavailable, so three optional Splunk
  findings have complete static traces but no runtime reproduction.

## Final finding and deliverable state

- Normalized register: 34 root-collapsed findings — 15 P1, 16 P2, and three P3.
- Finding types: seven architectural risks, 14 current defects, one documentation-drift item, one
  evaluator gap, ten completed security findings, and one deferred security capacity item.
- Complete package index: `docs/design/realism-review/README.md`.
- Final synthesis and dependency-ordered roadmap:
  `docs/design/realism-review/final-report.md`.
- Contract decision package: `docs/design/realism-review/contract-proposals.md`.

## Contract approval follow-up

- Approved by the user on 2026-08-05 after an explicit downside review.
- Binding amendments preserve independent authored intent, use semantic occurrence keys, reject
  missing infrastructure by default, define ownership per shared fact/lifecycle rather than per
  monolithic class, model partial visibility explicitly, and move path/resource safety earlier.
- The user requires every code update to occur on a feature branch.
- First branch: `codex/canonical-contract-foundation`.
- Review-only artifacts remain a separate commit from implementation code.

No fix, public API change, schema migration, version bump, staging action, or commit was made.

## Final artifact validation

- All 12 tracked review JSON artifacts pass `jq empty`.
- Both review utilities pass targeted Ruff check and format validation.
- Re-running the static inventory to a temporary directory produced a byte-identical
  `event-context-paths.json` with SHA-256
  `cd78a2470870bea9b461c8700128be0d6b67922f6655b0b107280e8c73f9b1fb`.
- The only coverage-summary differences from a fresh static extraction are the deliberately
  post-campaign status fields: dynamic probes and 23-of-23 source references are complete with
  documented limitations rather than pending.
- Re-running the expanded probe against the minimal dataset produced a byte-identical report with
  SHA-256 `37a795c08776a43013f02bb80c17a717c382fd289ff298bc6addbdb8ac5e6112`.
- A trailing-whitespace scan of the complete review package and utilities found no matches.
- Final Git status contains only the new review package, focused worklog, and two review utilities;
  all generator, evaluator, configuration, test, and build files remain untouched.
