# Architecture Reset Requirements Review

Status: completed interactive review gate

This document records the interactive review of reconstructed requirements for
missing, unclear, conflicting, stale, or duplicated requirements. Architecture
recommendations and rewrite-vs-greenfield scoring should use these decisions as
their requirements baseline.

## Review Goal

Before choosing an architecture path, lock a requirements baseline that is:

- Complete enough to design against.
- Current with the implementation, not just the original PRD.
- Clear about which constraints are hard requirements versus future options.
- Honest about conflicts between docs, skills, tests, and implementation history.

## Review Matrix

| ID | Area | Finding | Type | Proposed interpretation | Decision |
| --- | --- | --- | --- | --- | --- |
| RR-001 | Evaluation model | Older PRD text describes 5 dimensions and 23 sub-scores, while the active eval skill and `thresholds.yaml` use 4 pillars and current hard gates. `data-quality-prd.md` now marks the 5-dimension model as superseded. | Stale/duplicate | Treat the 4-pillar implementation and threshold config as authoritative. Keep the 5-dimension text only as historical context. | Accepted: 4-pillar model is authoritative. |
| RR-002 | Supported formats | Different docs count formats as 7 MVP formats, 9 skill-level formats, 20+ sources, or Zeek subformats. `ecar` is also overloaded as both a source-family idea and a concrete record format. | Unclear | Define support at two levels: user-facing format groups/source families and concrete emitted formats/files. Use `edr` as the simulated endpoint detection source-family name; reserve `eCAR` for the adopted concrete EDR record format. | Accepted with terminology revision. |
| RR-003 | Determinism | PRD says bit-perfect seed reproducibility is a non-goal, while architecture and README emphasize deterministic/reproducible generation. Training exercises may need stable references to specific evidence across regeneration. | Conflict | Require bit-perfect output for identical scenario/config/options/runtime inputs within the same code version. For scenario evolution, preserve stable evidence identities and minimize unrelated output churn so training materials can use durable anchors instead of fragile timestamps alone. Do not promise byte-identical output across arbitrary EvidenceForge versions. | Accepted with stronger same-input and evidence-anchor requirement. |
| RR-004 | RNG guidance | `docs/ARCHITECTURE.md` still says thread RNG uses `hash((thread_id, 42))`, but `AGENTS.md` forbids Python `hash()` for deterministic derivation and code contains `_stable_seed()` utilities. | Stale/conflict | Stable seeded derivation is authoritative. Python's process-local `hash()` behavior is not acceptable for deterministic generation. Update stale architecture text later. | Accepted; architecture docs are stale on RNG specifics. |
| RR-005 | LLM use | Generation must never call LLMs. Skills may use agent reasoning for scenario authoring and troubleshooting. | Unclear | Generation, validation, and evaluation scoring are deterministic CLI workflows and do not require or invoke LLMs. Agent skills may assist with scenario authoring and troubleshooting outside the deterministic CLI path. | Accepted; do not mention external blind/LLM assessment loops as repo requirements. |
| RR-006 | Raw events | Scenario docs allow `raw`, while event-model docs position raw as rare escape hatch and realism docs discourage it because it bypasses correlation. | Unclear | Keep raw supported for compatibility, but treat raw as non-correlated and discouraged for anything representable as typed events. Architecture only needs to route/render raw safely, not make raw cross-source consistent. | Accepted. |
| RR-007 | Proxy semantics | Current behavior assumes TLS interception, but TODO tracks non-intercepting proxy mode and standard Squid/Blue Coat compatibility as future work. | Missing/unclear | Current requirement is explicit/transparent proxy with TLS-intercept semantics. Architecture should leave room for tunnel-only proxy mode and vendor-specific proxy formats, but not require them for the first reset implementation. | Accepted: future/extensible, not first-pass scope. |
| RR-008 | Observation profile default | Scenario docs default to `complete`, but realism work increasingly values imperfect collection and source-native gaps. | Tradeoff | Default remains `complete` for training and regression stability. Non-default profiles model gaps without contradictions, and observation status remains first-class in manifests/eval. | Accepted: `complete` remains default. |
| RR-009 | Cloud/SaaS | PRD lists cloud logs as future, TODO says hybrid SOCs need them, scenario skill warns not to invent third-party OS logs. | Missing/future | Treat cloud/SaaS as future log-source families. Current architecture should not block them, but implementation need not include them yet. Future cloud/SaaS support must preserve the defender-visibility boundary by modeling tenant/application audit evidence, not impossible third-party OS telemetry. | Accepted: future/extensible, not first-pass scope. |
| RR-010 | Performance targets | Original PRD scale targets include 100M events and fixed generation times, but those numbers were illustrative and became over-hardened. Current realism, source count, and memory TODOs also make fixed old gates unreliable. | Stale/unclear | Performance requirements are qualitative unless a specific workflow proves it needs a measured gate. Keep generation time, memory use, and output I/O reasonable through streaming/spooling, format filtering, and scalable architecture. Numeric benchmarks are diagnostic/calibration tools, not default product requirements. | Accepted: no arbitrary hard numbers. |
| RR-011 | Scenario compatibility | Event-model PRD says no scenario schema changes, but Phase 8.4 already made typed `events` mandatory and removed older fields. | Stale/conflict | Current typed event schema is the compatibility baseline. Future breaking changes require explicit migration review and user-facing migration assistance, potentially via a dedicated migration skill or scenario-skill guidance. | Accepted. |
| RR-012 | Temporal evidence model | Older PRD talks generally about timestamp consistency; later TODO and architecture require source-specific timing profiles and relationship bounds. The current planner is useful but event-local and ad hoc in places. | Missing from older docs | Promote temporal evidence modeling to a top-level requirement: occurrence, lifecycle, causal, source-observation, and source-clock constraints must produce deterministic source-native timestamps with no dependent-evidence inversions. Do not require the current planner shape; evaluate a temporal constraint graph or action/evidence bundle model in the architecture phase. | Accepted with broader model wording. |
| RR-013 | State lifecycle | Lifecycle completeness appears in AGENTS and loop history but is scattered across many event families. | Missing structure | Treat lifecycle ownership as a first-class architectural domain, not per-emitter cleanup. Stateful activities need explicit owners, start/update/end semantics, and dependent evidence bounded by those lifecycles. | Accepted. |
| RR-014 | EDR/eCAR fidelity | eCAR has canonical correlation value, but endpoint telemetry needs a clearer source-family contract and consistent schema. | Unclear | Simulated EDR is a first-class endpoint telemetry source. Use `edr` for the source-family/group concept and reserve eCAR for the concrete adopted record format. Prioritize canonical correlation, use a stable core schema with event-type-specific fields, stay close to eCAR where useful, and allow justified deviations when realism or consistency requires them. Do not emulate a specific commercial EDR unless a future renderer/source profile says so. | Accepted with schema/core-plus-extension wording. |
| RR-015 | Ground truth | TODO includes a remaining File IOCs truncation issue; ground truth also needs consistent structure and observation-aware truth/visibility semantics. | Missing/open | Ground truth and observation manifest are product deliverables, not best-effort sidecars. `GROUND_TRUTH.md` should keep a consistent reader-facing structure across datasets. It may include things that happened but did not appear in generated logs; when feasible, mark observation status, and otherwise clearly distinguish scenario truth from observed evidence. Include known File IOC truncation fix in future implementation planning. | Accepted with consistent-format and observation-status wording. |
| RR-016 | Source ownership boundary | Scenario skill strongly says not to model third-party systems as owned hosts, but this is not prominent in architecture docs. | Missing | Add defender visibility boundary to core product requirements. External services can appear as network destinations or modeled tenant/application audit sources, but not as impossible owned OS-level telemetry. | Accepted. |
| RR-017 | Config overlay semantics | Overlay `_replace` is shallow and `_delete` is future. Architecture should know whether config composition is a core requirement. | Unclear/future | Keep current overlay behavior as baseline; recursive replace/delete remain future unless a later implementation plan explicitly targets config composition. | Accepted: future, not reset scope. |
| RR-018 | Evaluation as oracle | Automated eval can pass while source-native realism issues remain visible in generated data. | Conflict of practice | Treat automated eval as a deterministic regression and quality guardrail, not the complete definition of realism. For realism-sensitive code changes, developer-side verification may need focused generated-output probes or manual sample inspection when the evaluator does not yet model the relevant source-native behavior. | Accepted. |
| RR-019 | Test suite value | Greenfield reimplementation could discard many regression lessons embedded in tests and TODO history. | Risk | Treat tests, generated probes, known issues, TODO/CHANGELOG history, and loop-derived lessons as requirements evidence and migration assets. Individual tests may be replaced, but the behavioral protections they encode must carry forward. | Accepted. |
| RR-020 | Module boundaries | Large generator modules have accumulated many responsibilities, but docs also define canonical layers. | Architectural gap | Architecture review should evaluate whether to evolve the current code by extracting clearer planner/state/timing/source modules, partially rewrite behind stable interfaces, or reimplement. Requirements review should not choose the module-boundary solution. | Accepted; defer solution to architecture recommendation phase. |

## Requirements That Appear Stable

- Generation remains deterministic and LLM-free.
- Scenario authoring remains skill-assisted but scenario YAML remains reviewable and
  hand-editable.
- Canonical event/context/state ownership is the central cross-source consistency
  mechanism.
- Emitters should render source-native views rather than inventing shared facts.
- Data-driven config and overlay-aware loaders are required for enumerable realism.
- Validation, tests, generated-output probes, and eval reports are all part of the
  acceptance strategy.
- Public scenario schema and CLI behavior should be preserved by default.

## Review Outcome

All RR-001 through RR-020 decisions are resolved. The requirements baseline has
been updated with the accepted decisions. The next phase can evaluate architecture
options, optimization opportunities, and rewrite-vs-greenfield tradeoffs against
this baseline.

## Architecture-Phase Inputs

- Evaluate a temporal constraint graph, action/evidence bundle model, evolved
  timing planner, or hybrid lifecycle/source-clock model for temporal evidence.
- Compare evolving the current code, partial rewrite behind stable interfaces, and
  greenfield reimplementation.
- Keep non-intercepting proxy, cloud/SaaS sources, recursive overlay
  replace/delete, and arbitrary numeric performance gates out of first-pass scope
  unless the later architecture recommendation explicitly reopens them.
