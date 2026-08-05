# Complete EvidenceForge Code and Realism Review

Baseline: `dev` commit `0a035e97d94cd2a35ebd1498cc4e133336fe14a4`

Review date: 2026-08-05

Disposition: **review complete; contracts approved with amendments; implementation proceeds in
bounded feature-branch batches**

## Executive conclusion

EvidenceForge has unusually strong source breadth and several deep, durable correlation contracts,
especially across Zeek, firewall/NAT, explicit proxy, TLS/X.509/OCSP, SSH server evidence, and most
Windows process identity. It is capable of producing useful training datasets.

It is not yet consistently realistic under adversarial or expert scrutiny. All four independent
reviewers classified the integrated dataset as synthetic with 94.5% average confidence. The
decisive defects are not primarily missing vocabulary or cosmetic formatting. They come from
shared ownership boundaries: one activity can still be constructed through parallel paths,
canonical identity and lifecycle state can be changed by source observation, emitters or
compatibility fields can recompute shared truth, and evaluation can accept datasets with material
scenario, temporal, and correlation failures.

The canonical contracts were approved with six amendments after this review. The first
implementation work should make ownership, identity, lifecycle, time, observation, projection,
and workload budgets enforceable. Family-specific fixes should then migrate vertically through
those contracts on separately reviewed feature branches.

## Scope and evidence

The review covered the complete deterministic Phase 2 pipeline and its supporting surfaces:

- scenario models, YAML loading, validation, configuration, and world planning;
- baseline, storyline, red-herring, startup, causal-expansion, and internal entry paths;
- action bundles, canonical events and contexts, identity, state, lifecycle, time, observation,
  visibility, routing/NAT, and network accounting;
- all source emitters and output targets, CLI, ground truth, evaluation, and tests;
- dependencies, build/workflow configuration, templates, paths, artifacts, resource exhaustion,
  and optional external-parser integrations.

Phase 1 authoring skills were excluded except for the scenario-schema boundary. Generated datasets
remain untracked beneath `/private/tmp/eforge-realism-review`; this package records commands,
parameters, hashes, findings, and limitations.

## Architecture and object model

The implemented dependency flow is:

`YAML intent -> Pydantic scenario -> WorldModel/WorldPlanner -> baseline or storyline scheduling ->
action bundle and ActivityGenerator construction -> mutable SecurityEvent/context graph -> causal
expansion -> dispatcher/observation/source timing -> emitter projection -> output -> evaluator`

`StateManager` participates across planning, construction, dispatch, observation, and projection.
This makes it a shared mutable integration surface rather than a purely canonical state owner.

The architecture assessment identified eight root-cause findings in the normalized register:

- no closed, centrally enforced canonical event-kind contract;
- source-observation time can mutate canonical process lifecycle state;
- mutable compatibility truth coexists with immutable plans;
- many action bundles route calls but leave lifecycle ownership in legacy generator methods;
- temporal rules remain distributed and order-sensitive;
- causal expansion is stringly typed and fails open;
- occurrence identity is dispatch-sequence-sensitive and ground truth is a parallel model;
- documentation and registered surfaces overstate actual ownership or reachability.

The target architecture is not a wholesale rewrite. It is an incremental extraction around a
typed action request, immutable sealed occurrences, explicit action-relative identity, separated
canonical/observed/rendered time, coherent observation groups, projection-only emitters, a
ground-truth projection, and bounded input/workload contracts. See
`architecture-object-model.md` and `contract-proposals.md`.

## Event and context path census

The census is complete with no silently unreviewed row and no unresolved dynamic constructor:

| Surface | Reviewed count |
| --- | ---: |
| Authored event specifications | 31 |
| Discovered internal event names | 66 |
| `SecurityEvent` constructors | 68 |
| Mutable context dataclasses | 38 |
| Immutable plans and identities | 27 |
| Concrete action bundles | 51 |
| Concrete output formats | 23 |
| Public generator methods with call sites | 57 |
| `StateManager` methods with call sites | 53 |

Every event, context/plan, bundle, and format has a manual path classification. Parallel paths are
classified as intentional adapters, equivalent alternate entries, incompatible bypasses,
duplicate owners, or unsupported escape hatches. The most important structural results are:

- 33 thin bundles still delegate lifecycle construction to legacy generator methods;
- `module_load` and `special_privileges` have registered emitter contracts but no canonical
  producer at this baseline;
- `WeirdContext` has no production constructor;
- email bundles have weaker anchor/test integration, and `EmailContext` has no emitter/evaluator
  consumer because email evidence uses a separate artifact pipeline;
- `raw` remains intentionally outside cross-source consistency guarantees;
- projection purity is not guaranteed: Sysmon can recompute shared hostname or process identity,
  and output-format selection changes upstream generation.

The machine-readable inventory is in `event-context-paths.json`; reviewed classifications and
closure accounting are in `path-classifications.json` and `coverage-summary.json`.

## Validated finding register

The root-collapsed register contains 34 findings:

| Priority | Count | Meaning in this review |
| --- | ---: | --- |
| P0 | 0 | Immediate correctness emergency |
| P1 | 15 | Architectural or realism blocker that invalidates important evidence |
| P2 | 16 | Material defect, fidelity gap, evaluator weakness, or medium security issue |
| P3 | 3 | Lower-risk security/capacity follow-up |
| P4 | 0 | Future enhancement only |

By type, the register contains seven architectural risks, 14 current defects, one documentation
drift finding, one evaluator gap, ten completed security findings, and one deferred security
capacity finding. Every entry records exact code/output evidence, confidence, affected paths and
families, the violated invariant, owning layer, recurrence, reproduction, sibling risk,
remediation, and required tests. See `findings.json`.

### Highest-impact current defects

1. **Process/session ownership is not durable.** A connection-owner process can be reused across
   ended or different logon sessions; dependents can occur after termination or logoff; Explorer
   and Linux login ancestry can be impossible.
2. **Authentication identity is mutable or insufficiently scoped.** One LogonID can change from
   zero to nonzero LogonGuid, and distinct failed attempts can share one eCAR object ID.
3. **Network semantic children can contradict their owner.** An IDS response signature attached to
   a SYN-only, zero-response connection; RDP endpoint flow can render after successful target
   authentication; Zeek file intervals can extend beyond their parent connection.
4. **World capability fallback can produce impossible infrastructure.** The minimal world uses the
   same endpoint as DHCP client, server, and assigned IP, creating a self-flow on every renewal.
5. **Format selection affects canonical generation.** All nine common Zeek files differed between
   full and Zeek-only generation, including large record-count changes.
6. **Automated acceptance is too permissive.** Large datasets passed at 93.45 and 96.19 while
   retaining indicator mismatches, missing pivots/traces, temporal failures, and unanimous expert
   rejection.
7. **Source-native and distribution fingerprints remain.** Windows 4648 uses non-native field
   names, OCSP durations are fixed, AAAA answers are unrealistically successful, and several
   schedules/state selections are independently resampled instead of lifecycle-shaped.
8. **Authoring and determinism contracts have gaps.** Duplicate YAML keys are silently accepted,
   the flagship full-coverage fixture is invalid, and there is no coherent public seed contract.

## Empirical campaign

### Quality gates

- Ruff check passed; Ruff reported all 447 files formatted.
- The complete non-slow suite passed: 5,075 passed, 41 skipped.
- Targeted slow/scale tests passed: 13 passed, one memory test skipped.
- Four external-parser tests were skipped because Docker/Podman Compose was unavailable; Splunk
  additionally requires explicit license acceptance.
- `eforge eval --real-parsers` is currently reserved rather than implemented.

### Scenario and stress results

- Minimal one-hour generation was byte-identical on repeat, but contained two DHCP-role errors and
  two related self-connection observations. The evaluator still scored it 96.85 and accepted it.
- Baseline-only generation passed the original invariant probe, but warned that four of five users
  had no primary-system assignment.
- The shipped full-coverage APT fixture did not validate because all three segments omitted the
  now-required `exposure` field; it also contains a duplicate YAML key. An exposure-only temporary
  adaptation scored 93.45 and passed despite 20 indicator mismatches and incomplete pivot,
  temporal, and trace coverage.
- The branch-office enterprise dataset scored 96.19 and passed, but the expanded probe found 44
  errors and two warnings across lifecycle, timing, IDS, field, and distribution contracts.
- Ten 24-hour profile variants reproduced failed-attempt identity collisions in nine runs and one
  post-termination process action. They are scenario-name variants, not true seeds, because the
  public contract exposes no generation seed and part of the engine resets its RNG to 42.
- Three seven-day baseline variants passed the original probe. This is useful counterevidence but
  not proof of semantic realism because that probe did not yet contain the expanded host and
  cross-source checks.
- The 30-day minimal stress run reproduced 1,442 DHCP-role errors and 1,442 self-flow observations,
  demonstrating deterministic linear recurrence.
- Full-output versus Zeek-only generation was not projection-equivalent. Every common Zeek file
  differed; for example, `conn.log` fell from 20,591 to 12,885 records.

The reproducible commands, hashes, profiles, outputs, scores, and limitations are in
`empirical-results.json`. The invariant implementation is `scripts/realism_review_probe.py`.

## Blind expert assessment

Four specialists independently reviewed only the integrated rendered data. They did not receive
the scenario, ground truth, code, review package, prior reports, or one another's conclusions.

| Reviewer | Verdict | Confidence | Synthetic score |
| --- | --- | ---: | ---: |
| Threat Hunter | Synthetic | 90 | 88 |
| Detection Engineer | Synthetic | 97 | 96 |
| Network Forensics | Synthetic | 93 | 86 |
| Host/EDR Forensics | Synthetic | 98 | 97 |
| **Panel** | **Unanimous synthetic** | **94.5 average** | **91.75 average** |

No deliberation threshold was met because the panel agreed and the score spread was only 11.
Each accepted blind observation was independently verified against code or rendered evidence.

The user-provided historical archive was consulted only after the current blind reports were
complete. It provided recurrence and sibling-risk evidence for failed-auth identity, lifecycle,
timing, file-envelope, and accounting families, plus counterevidence that many prior network and
cryptographic repairs remain durable. Historical impressions were never accepted without a
current reproduction. See `blind-summary.md` and `historical-blind-evidence.json`.

## Source-native assessment

All 23 concrete formats received both a code-path review and an official or license-compatible
public reference assessment. The review covered field names and nullability, timestamp morphology,
ordering, protocol semantics, and target transformations. The reference ledger is
`source-references.json`.

The clearest source-native defect is Windows Security Event 4648: generated records use
`NetworkAddress` and `NetworkPort` where the native event schema uses `IpAddress` and `IpPort`.
Zeek file intervals and OCSP duration texture also fail current source-semantic checks even though
the corresponding records parse.

## Security assessment

The sealed standard scan accounts for 1,127 files and reports eight medium and two low findings.
The medium findings cover output-path traversal, unrestricted corpus reads, unbounded scenario,
attachment, CIDR, and include amplification, adversarial Snare parser complexity, and Splunk log
staging symlinks. The low findings cover Splunk archive quotas and application-tree symlinks. No
critical or high finding survived calibration to the local CLI boundary.

One evaluator full-corpus memory concern remains explicitly deferred pending a supported RSS and
corpus-size contract. See `security-review.md` for threat model, dispositions, controls, scan
identity, and limitations.

## Dependency-ordered remediation roadmap

The contract proposals were approved with amendments on 2026-08-05. Implementation proceeds as
bounded feature-branch batches; approval does not authorize a single campaign-long rewrite.

### Batch 0 — Approve contracts and freeze executable invariants

- Decide the nine contract questions in `contract-proposals.md`.
- Convert the census and empirical probes into non-mutating CI closure and regression checks.
- Define compatibility, migration, and deprecation boundaries before changing public schemas.

### Batch 1 — Canonical occurrence, identity, and time boundaries

- Add the closed event-kind registry and seal validation in shadow/assert-only mode.
- Separate canonical, observed, and rendered time; stop observation-to-state feedback.
- Introduce stable `ActionId` plus role-relative occurrence identity.
- Make published occurrences immutable and prevent emitter-owned shared truth.

This batch addresses ARCH-001 through ARCH-007 and is a prerequisite for safe family fixes.

### Batch 2 — Session/process/authentication vertical slice

- Establish one owner for interactive, network, SSH, RDP, and failed-auth lifecycles.
- Enforce session-bound process reuse, immutable LogonGuid, unique failed-attempt identity,
  lifecycle containment, and role-valid parent chains.
- Migrate baseline, storyline, startup, and compatibility callers through the same bundles.

This resolves REAL-001 through REAL-004, REAL-006, and REAL-015 as one ownership family.

### Batch 3 — Network/protocol/IDS vertical slice

- Make the network plan authoritative for tuple, interval, accounting, protocol children, file
  analyzers, visibility, and IDS eligibility.
- Evaluate structured IDS predicates after transport/protocol outcome planning.
- Bind endpoint flow, auth, file, and analyzer observations to the final source-visible interval.
- Add full/filter/parallel projection-equivalence tests.

This resolves REAL-005, REAL-007, and REAL-009 while preserving already-strong tuple/accounting
behavior.

### Batch 4 — World capabilities and distribution texture

- Require typed DHCP, DNS, DC, proxy, SSH, RDP, and service capabilities with distinct-host rules.
- Replace fallback role collapse with validated or explicitly synthesized infrastructure policy.
- Move fixed and independently sampled source fingerprints into lifecycle-aware, scoped,
  data-driven models.

This addresses REAL-008 and REAL-012 without broad unstructured noise expansion.

### Batch 5 — Projection fidelity and evaluation validity

- Correct Windows 4648 and remaining source-native morphology only at projection boundaries.
- Project ground truth from the action/occurrence and observation ledgers.
- Separate parsing, invariant, scenario-completeness, distribution, and expert-comparison scores.
- Make missing denominators non-vacuous and promote high-impact mismatches to hard gates.

This resolves REAL-010 and REAL-011 and makes later realism scores trustworthy.

### Batch 6 — Input safety, budgets, authoring, and reproducibility

- Enforce safe asset/output paths and no-symlink external-parser staging.
- Add aggregate scenario, duration, event, CIDR, attachment, include, archive, parser-record, and
  evaluation-corpus budgets with explicit trusted overrides.
- Reject duplicate YAML keys, repair the flagship fixture, and add an explicit scoped seed.
- Measure and close the deferred evaluator memory capacity item.

This addresses REAL-013, REAL-014, SEC-001 through SEC-010, and SEC-DEFER-001.

### Batch 7 — Compatibility removal and documentation reconciliation

- Remove legacy mutable/duplicate fields only after all consumers migrate.
- Reconcile architecture, scenario, source, and evaluation documentation with enforced behavior.
- Treat any public API or schema change as its own approved migration and release decision.

## Completion and limitations

The approved review completion criteria are met with the following explicit proof gaps:

- no current production telemetry was available; official references and public exemplars were
  used instead;
- optional external parsers could not run without Docker and licensed Splunk dependencies;
- the project lacks a true public seed, so the requested seed campaign used documented
  scenario-name variants;
- the evaluator capacity security candidate needs a calibrated runtime benchmark;
- generated outputs are intentionally untracked and reproducible through recorded hashes and
  commands rather than retained in Git.

No generator fix, public API change, scenario-schema migration, or version bump was made during the
review. The approved implementation starts with the behavior-preserving contract foundation on
`codex/canonical-contract-foundation`; enforcement and behavioral migrations remain separate
review gates.
