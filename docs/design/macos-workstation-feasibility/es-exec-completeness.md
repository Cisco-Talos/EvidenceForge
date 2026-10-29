# Complete modeled macOS ES exec coverage

## Accepted outcome

On October 28, 2026, the user accepted this contract as the highest development priority:

> Every modeled successful exec within supported Mac profiles and active, lossless collection
> produces a corresponding native exec record, or generation fails with the missing requirements.

The current supported generation target is macOS 27 arm64. This contract concerns accepted
modeled behavior; it does not assert qualification of every possible macOS application or launch
mechanism. An unsupported mechanism must be rejected explicitly rather than accepted with
missing ES output. Qualification and coverage remain separate: complete but fabricated fields
cannot satisfy the contract.

The practical goal also requires useful successful workloads. A strict check that merely rejects
all ordinary Mac activity is an intermediate guard, not completion of this effort.

The user further clarified that the goal covers every modeled process starting during the
simulation window, including background services and helpers. Complete ES collection must be
active throughout that window. A fork-only child needs fork evidence; each image activation
needs exec evidence, including a replacement within an existing PID. These are different
occurrences, not an assumption of one exec per PID. Apple's [fork](https://developer.apple.com/documentation/endpointsecurity/es_event_fork_t)
and [exec](https://developer.apple.com/documentation/endpointsecurity/es_event_exec_t) event
contracts describe those separate observations.

## What counts

Count actual image activations, including multiple execs in one process lifetime. Use canonical
host/boot, process lifetime and execution identity, not PID, display command, eCAR row count or
path alone. A process born with a new image must have an explicit birth-to-image-activation
contract. Existing aggregate process births are unresolved coverage requirements, not evidence
that no exec was needed. A fork retaining the parent's image is not itself a new exec.

Shell builtins, activation of an already-running app, failed execs that preserve the old image,
and policy-refused attempts that never activate an image must retain those distinct semantics.
Processes already running when collection starts do not acquire retrospective exec records.
Collector bootstrap, shutdown and subscription boundaries need explicit ordering; a collector
cannot observe its own pre-subscription launch by assertion.

The guarantee applies only to exec occurrences eligible for the requested ES source instance,
subscription, collection interval and output interval. A complete-coverage request must reject
incompatible source loss, exclusion or format settings. Deliberately lossy/partial collection
remains separately available, with an explicit narrower scope and no complete-coverage claim.
Observation delay must not silently move an otherwise required record beyond exported output.
The public setting and default enforcement policy remain implementation decisions; enforcement
must run through CLI and Studio's shared engine, not depend on an author remembering a check.

Exec completeness is the first acceptance condition. Fork and exit evidence retain independent
obligations when modeled and observable. Do not fabricate a fork, terminal status or an exit
after the collection window to make a lifecycle look complete.

## Implementation order and acceptance

### 1. Measure and repair a small real generation workload

Start with ordinary local commands, SSH commands, a service start and a GUI app launch. List
the intended successful process starts/executions independently of native publication and
compare them with actual generated ES records. Repair the concrete missing producers or
metadata, retaining the comparison as a regression test. Then expand the same test to baseline
activity. Add infrastructure only when a specific omission requires it.

An 11-command local/SSH workload is the first implemented slice. This is not acceptance of
all process starts: the terminal/bootstrap processes, services, GUI applications and helpers
must receive their own entries rather than being hidden by the command-only denominator.

### 2. Complete shared metadata and ordinary launch producers

Use the workload failures to prioritize defects by accepted workload coverage. Extend canonical
executable, file, signing, image-security, audit, parent/responsible, thread, environment, cwd
and descriptor owners. Unknown values must remain distinct from empty/absent values. Enumerable
application and launch policies belong in versioned configuration. Native emitters render
these shared facts.

Convert shell commands, service/launchd activity, SSH client/receiver/command processes and
background helpers to explicit birth/exec contracts. Finish ordinary supported workloads before
expanding unusual applications. Each producer must work for both storyline and baseline through
the same action owner. Do not preserve a silent aggregate fallback in the covered scope.

Literal commands already have a bounded path. Pipelines, redirections, substitutions, scripts,
PTY commands and helper trees require explicit subprocess, argv and descriptor ownership. A
display command string cannot substitute for that execution plan. Reject constructs without a
supported plan until implemented.

### 3. Connect GUI launch activity

Finish the Finder launchd/xpcproxy birth-to-exec producer using the existing authenticated GUI
exec transition. The same PID/lifetime survives image replacement; do not model the app as an
invented child of xpcproxy or assert a native fork from missing evidence. Supply every modeled
launcher/app execution's own metadata and connect authored and baseline activity explicitly.

The human's version-4 offline report resolves the preimage audit/session/group and token
relationships. The source observation keeps the old audit pair/PID/PID version but has four
zero POSIX credential words. Canonical launcher credentials stay those of the account; target
responsibility equals the complete target token. That distinction is implemented in revision 348.
Broader Dock/Spotlight, application/helper and signing/entitlement classes require bounded
qualification where current evidence and primary format contracts do not establish needed facts.
Reuse shared contracts when justified; do not extrapolate the Finder test automatically.

Expose launch intent where the authored model needs it. CLI, Studio, validation, authoring
references and effective application policies must agree on supported choices and failures.

### 4. Establish complete accounting and enforcement

Inventory every Mac-reachable process allocation, registration, birth, execution and lifecycle
path, including initialization, baseline, storyline, causal effects, SSH, services and helpers.
Classify imported/pre-existing state separately. The current report counts exact source cohorts
and authored aggregate births; it is not the required census.

Create an execution obligation at the canonical state/action commit boundary before native
qualification, routing or rendering. An expectation derived only from ES ingress cannot detect
a producer that never enters ingress. Bind obligations to the existing atomic publication and
rollback/retry boundaries; account for legacy mutation paths until they are migrated or rejected.

Reconcile those obligations with independently retained native publication receipts. At bundle
completion require an exact match for each eligible execution, with no missing, duplicate or
unexplained extra records. Check native before/after execution identity and source ownership,
not just total counts. Unknown metadata and aggregate births are failures in the covered scope,
not source filtering. Diagnose the owning launch/action, executable and missing fact class.

Reject statically known incompatibilities during validation/preflight. Reject contingent failures
at runtime before accepting the bundle as complete. Retain the existing recoverable failure and
output-replacement behavior. Make accounting streaming/disk-backed or bounded by existing
checkpoint journals, not an in-memory list growing with scenario duration. Prove rollback,
restart and exact recovery before relying on totals.

### 5. Prove the guarantee on useful workloads

Build a finite acceptance matrix covering every inventoried producer and supported launch
family, across authored and baseline activity. Include shell/local/SSH, services, helpers, GUI,
same-PID re-exec, runtime artifacts/scripts, PID reuse and pre-existing processes. Include
negative controls for builtins, reuse, failed exec and refusals.

Verify native shapes and shared identity/timing against canonical truth and existing qualified
references. Exercise output selection, collection boundaries, explicit loss, delayed delivery,
threaded rendering and interrupted checkpoint/resume. Fault injection must detect a bypassed
producer, omitted/duplicated native write and missing metadata. Compare exact uninterrupted and
resumed output where deterministic behavior is promised.

Completion requires: no unclassified Mac producer paths; no unexplained aggregate fallback;
zero uncovered eligible execs in supported acceptance workloads; actionable rejection of
unsupported cases; and passing regression/recovery gates. Fixes must broaden successful realistic
coverage rather than silently exclude ordinary workloads. A new blind assessment loop is not a
prerequisite for every implementation increment.

## Evidence and privacy boundaries

Accounting, enforcement, shared producer wiring and invented-input verification can proceed
without new collection. Human help is limited to the prepared offline classification and any
subsequently identified native qualification gaps. Request specific bounded evidence only when
needed to implement a concrete missing contract. Existing standing restrictions continue:
agents do not inspect private kits/local logs or run native collectors/apps; raw captures stay
outside Git; the human shares fixed schema/relationship labels only.

See the [Finder relationship reference](gui-launch-reference/finder-relationship-contract.md)
and [native coverage worklog](../../worklog/2026-10-27-macos-native-coverage.md) for current
capabilities and reference limits.
