# Architecture Reset Recommendation

Status: planning recommendation, pending user decision

This document evaluates architecture options against the reviewed requirements in
`architecture-reset-requirements.md` and the interactive review decisions in
`architecture-reset-requirements-review.md`. It recommends a direction, but it does
not create the implementation plan or start implementation.

## Executive Recommendation

Use an evolutionary architecture reset with partial rewrites behind stable
interfaces.

Do not start over from a greenfield codebase. Also do not continue with only local
incremental hardening. EvidenceForge already has the correct major architectural
idea: deterministic generation, canonical events, durable state, source renderers,
data-driven config, validation, evaluation, and a large regression history. The
quality problems are mostly caused by responsibility boundaries that have grown too
broad or too event-local, not by a fundamentally wrong product architecture.

The best path is to preserve the current CLI, scenario schema, generated bundle
shape, canonical event model, config assets, and test history while replacing the
most overloaded internals in slices. The reset should introduce clearer domains for
action planning, lifecycle ownership, temporal constraints, observation, and source
rendering.

## Current Architecture Pressure Points

- `ActivityGenerator` is doing too much. At roughly 17k lines, it owns unrelated
  concerns across auth, process, network, DNS, endpoint, web, proxy, file, registry,
  account, DHCP, and sensor startup behavior. That makes root-cause realism fixes
  hard to place cleanly.
- Baseline and storyline generation are large orchestration surfaces. The baseline
  and storyline modules are valuable, but they mix scenario intent, scheduling,
  lifecycle decisions, canonical event construction, and source-specific edge cases.
- Timing is better than the original PRD described, but still too event-local for
  the reviewed requirements. The current source timing planner can add
  source-native offsets and relationship bounds, but multi-event actions, lifecycle
  intervals, observation windows, and durable training anchors need a larger model.
- Lifecycle ownership exists in pieces, but not as a first-class domain. Sessions,
  processes, connections, leases, file transfers, and proxy transactions need
  explicit owners and bounded dependent evidence.
- Some source-family terminology and contracts lag behind the product direction,
  especially endpoint telemetry. The source family should be `edr`; eCAR should be
  treated as the concrete record format where that name is useful.
- Ground truth and observation manifests are already product deliverables, but they
  need a stronger contract for consistent reader structure and observation-aware
  truth.
- The tests, config library, generated-output probes, and TODO/CHANGELOG history
  are major assets. A greenfield rewrite would risk losing many accumulated realism
  lessons unless they were carefully migrated first.

## Optimization Opportunities

### 1. Introduce Action And Evidence Bundles

Many realistic behaviors are not single events. They are actions that produce a
bundle of evidence across state, time, visibility, and sources.

Examples:

- An SSH login may create syslog auth lines, session state, shell process state,
  endpoint session telemetry, bash history, network flows, and later process/file
  activity.
- A proxy web request may create client-to-proxy evidence, proxy application logs,
  proxy-to-origin network evidence, TLS/certificate artifacts, and firewall/NAT
  rows.
- A process execution may create process start, module/file/registry/network side
  effects, process termination, and ground-truth references.

An action/evidence bundle layer would let baseline and storyline planners express
intent once, then expand it into canonical events with shared identities, lifecycle
constraints, observation status, and source timing.

### 2. Add A Temporal Constraint Model

The reset should promote timing from "event timestamp plus source jitter" to a
temporal evidence model. The model should represent:

- Occurrence time: when the modeled action actually happened.
- Lifecycle interval: when the session, process, connection, lease, or transfer was
  alive.
- Causal constraints: prerequisites and dependents that cannot invert.
- Source observation time: when each source would record or expose the evidence.
- Source clock behavior: precision, skew, latency, batching, and sensor viewpoint.
- Stable anchors: durable evidence identities that survive unrelated scenario
  evolution better than timestamp-only references.

A temporal constraint graph is the strongest candidate because it can reason across
more than one `SecurityEvent`. The implementation plan should still validate this
choice with a focused design spike before committing broad code changes.

### 3. Make Lifecycle Ownership Explicit

Lifecycle owners should become named architecture concepts rather than scattered
state-manager conventions. Candidate lifecycle domains include:

- User sessions and authentication contexts.
- Process trees and process lifetimes.
- Network connections and protocol transactions.
- DHCP leases and renewals.
- File transfers and staged file artifacts.
- Proxy transactions and tunnel legs.
- Endpoint telemetry object identities.

`StateManager` can remain the durable runtime state owner, but it should be fed by
clear lifecycle planning APIs rather than absorbing unrelated allocation patterns.

### 4. Separate Observation From Rendering

Observation should answer: "Which canonical facts are visible to which source, from
which perspective, at what source-native time?"

Rendering should answer: "How does this source represent those already-selected
facts?"

This separation would make source-native gaps, complete observation, imperfect
profiles, sensor viewpoints, NAT/firewall behavior, and ground-truth observation
status easier to reason about without pushing shared facts into emitters.

### 5. Clarify EDR As A Source Family

Endpoint telemetry should be modeled as the `edr` source family with a stable core
schema plus event-type-specific fields. The eCAR name should be used only where the
concrete emitted record format matters.

The renderer should stay close to the adopted eCAR format where useful, but the
canonical model should be allowed to deviate when strict format adherence would
harm realism, consistency, or source-native endpoint behavior.

### 6. Strengthen Ground Truth And Manifest Contracts

Ground truth should be generated from the same action, lifecycle, and observation
model as the logs. The implementation plan should include a stable
`GROUND_TRUTH.md` structure and a clear convention for observed, partially
observed, and unobserved scenario facts.

This is also where known ground-truth issues, such as truncated File IOC
representation, should be handled.

### 7. Decompose Large Generation Modules By Ownership

The reset should reduce large module responsibility by moving toward domain modules
with clear ownership. Candidate boundaries:

- `planning/`: scenario intent, world decisions, action selection.
- `actions/`: action bundle construction and canonical expansion.
- `lifecycle/`: session, process, connection, lease, transfer, and proxy lifecycles.
- `timing/`: temporal constraints, source clocks, and timestamp resolution.
- `observation/`: visibility, sensors, collection profiles, and source eligibility.
- `sources/`: source-family renderers and source-native formatting.
- `ground_truth/`: reader-facing truth, manifests, and durable anchors.

These names are not final API commitments. They describe the ownership split the
implementation plan should pursue.

## Option Scorecard

Scores are relative fit scores from 1 to 5, where 5 is strongest. They are not
performance gates or hard product metrics.

| Option | Realism impact | Cross-source consistency | Migration risk | Architecture clarity | Verification strength | Time-to-value | Total | Fit |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| A. Continue incremental hardening only | 2 | 2 | 5 | 2 | 4 | 4 | 19 | Not enough |
| B. Evolutionary reset with partial rewrites behind stable interfaces | 5 | 5 | 4 | 4 | 5 | 4 | 27 | Recommended |
| C. Greenfield reimplementation | 5 | 5 | 1 | 5 | 2 | 1 | 19 | Too risky |
| D. Full in-place rewrite in one broad pass | 4 | 4 | 2 | 3 | 2 | 2 | 17 | Too disruptive |

## Option Analysis

### A. Continue Incremental Hardening Only

This is the safest short-term path and has worked well for focused realism fixes.
It preserves tests and avoids schema churn.

It is not sufficient for the reset goals. The reviewed requirements call for a
better timing model, first-class lifecycle ownership, durable evidence anchors, and
clearer observation semantics. Those changes are hard to achieve through local
fixes inside the current large generation modules.

### B. Evolutionary Reset With Partial Rewrites Behind Stable Interfaces

This is the recommended path.

It preserves the current product surface while replacing internal ownership
boundaries in controlled slices. Existing tests, scenario fixtures, skills, config
data, and generated-output probes remain useful. New architecture can be proven by
running old and new paths side-by-side for selected event/action families before
expanding coverage.

This path also matches the reviewed defaults:

- Preserve public scenario schema and CLI behavior unless a reviewed requirement
  justifies a break.
- Keep deterministic generation and bit-perfect same-input output as a core goal.
- Treat existing tests and loop-derived lessons as migration assets.
- Bias toward evolving the existing codebase unless greenfield clearly wins.

### C. Greenfield Reimplementation

Greenfield offers the cleanest blank-page architecture, but it performs poorly
against migration risk and time-to-value.

The current repo contains years of encoded lessons: source-native quirks, config
assets, scenario examples, validation rules, evaluation rules, and regression tests.
A greenfield rewrite would have to re-import that knowledge before it could be
trusted. The highest-risk part is not typing new code; it is preserving the many
small cross-source realism constraints that are already embedded in behavior and
tests.

Greenfield should be reconsidered only if a design spike proves that the current
canonical event, state, config, and emitter surfaces prevent the required temporal
or lifecycle model. Current evidence does not show that.

### D. Full In-Place Rewrite In One Broad Pass

This would avoid a second repository but carries many of the same risks as
greenfield. It would touch too many behavioral contracts at once, weaken
verification, and make regressions hard to attribute.

The implementation should instead use replacement slices with narrow adapters and
clear acceptance gates.

## Recommended Architecture Direction

The next implementation plan should aim for this flow:

```text
Scenario YAML + config overlays
  -> world model and scenario intent planning
  -> action/evidence bundles
  -> lifecycle owners
  -> temporal constraint resolution
  -> canonical SecurityEvents with durable anchors
  -> observation and visibility routing
  -> source-family renderers
  -> generated data, observation manifest, and ground truth
```

The existing `SecurityEvent`, context objects, `StateManager`, `EventDispatcher`,
emitters, validators, and config loaders should remain in service during the reset.
The reset should add clearer upstream ownership and gradually move event families
onto that path.

## Suggested First Slice For The Future Implementation Plan

The implementation plan should not start by rewriting every event type. A good
first slice would be one behavior family that stresses the new architecture but is
small enough to verify.

Strong candidates:

- SSH session action bundle: exercises auth, process, session lifecycle, syslog,
  EDR, bash history, Zeek, source timing, and ground truth.
- Explicit proxy transaction: exercises multi-leg timing, observation viewpoint,
  proxy access, Zeek, firewall, TLS, and source-family rendering.
- Windows interactive/RDP session: exercises logon lifecycle, process ownership,
  Windows Security, Sysmon, EDR, and training-reference anchors.

SSH session is the best first candidate because recent history shows recurring
timing, lifecycle, and process-ownership defects, and it crosses multiple source
families without requiring the full proxy stack.

## Acceptance Gates For The Future Implementation Plan

The plan should include gates like these before broad migration:

- Same scenario, config, options, and code version produce bit-perfect output.
- Existing scenario schema and CLI behavior remain compatible unless explicitly
  approved.
- The selected first slice produces no lifecycle inversions, orphaned dependent
  evidence, or source timing inversions in generated-output probes.
- Unit and integration tests cover old behavior preservation plus new ownership
  contracts.
- `GROUND_TRUTH.md` and `OBSERVATION_MANIFEST.json` reflect the same action and
  observation model as the logs.
- Source renderers do not allocate or invent shared facts that belong to action,
  lifecycle, timing, observation, or canonical context layers.

## Recommendation Gate

Before writing `architecture-reset-implementation-plan.md`, decide whether to
accept the recommended path:

1. Adopt Option B: evolutionary reset with partial rewrites behind stable
   interfaces.
2. Use action/evidence bundles plus a temporal constraint model as the target
   architecture direction.
3. Preserve current CLI, scenario schema, generated bundle layout, config assets,
   and tests by default.
4. Use SSH session behavior as the likely first implementation slice, unless the
   implementation-planning discussion selects another slice.

