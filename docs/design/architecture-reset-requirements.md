# Architecture Reset Requirements Baseline

Status: reviewed baseline after interactive requirements review

This document reconstructs EvidenceForge requirements from the repository as if the
simulator were being specified from scratch today. It intentionally stops before
recommending an implementation strategy. The companion review decisions are recorded
in `architecture-reset-requirements-review.md`.

## Sources Reviewed

- Project instructions and implementation rules: `AGENTS.md`.
- Active plan and project memory: `TODO.md`, `CHANGELOG.md`.
- Product and user-facing documentation: `README.md`, `CONTRIBUTING.md`.
- Design documents: `docs/design/PRD.md`, `docs/design/event-model-prd.md`,
  `docs/design/data-quality-prd.md`, `docs/design/traffic-profiles-design.md`.
- Architecture and references: `docs/ARCHITECTURE.md`,
  `docs/reference/scenario-reference.md`,
  `docs/reference/EVIDENCE_FORMATS.md`,
  `docs/reference/CUSTOMIZING_CONFIG.md`.
- Skill prompts and bundled skill references under `commands/eforge/`.
- Configuration readmes under `src/evidenceforge/config/`.
- Test inventory under `tests/unit/` and `tests/integration/`.

No repo-local memory files were discovered during the scan.

## Product Requirements

- EvidenceForge generates realistic synthetic security logs for cybersecurity threat
  hunting training, research, SOC exercises, and detection validation.
- The product serves educators, threat hunters, detection engineers, SOC trainers,
  and researchers. It must support both guided authoring and hand-authored YAML.
- The system is two-phase:
  - Scenario authoring is agent/skill-assisted and may involve research,
    interviewing, and creative expansion.
  - Log generation is deterministic and must not call LLMs.
- Identical inputs under the same EvidenceForge code version must produce
  bit-perfect generated output. Inputs include scenario YAML, config overlays,
  output target, CLI options, and runtime-relevant environment.
- Deterministic derivation must use stable seeded hashes, not Python's process-local
  `hash()` behavior.
- Scenario evolution should preserve stable evidence identities and minimize
  unrelated output churn, so training material can refer to durable anchors instead
  of fragile timestamps alone.
- Generated datasets must include realistic baseline activity, injected attack
  storylines, optional red herrings, and instructor ground truth.
- Output must be useful for hunting, not merely syntactically valid. Analysts should
  have to work through plausible noise and source-specific evidence.
- The defender visibility boundary is a first-class requirement. The scenario should
  model logs the victim organization would realistically collect, not omniscient
  attacker or third-party infrastructure logs.
- Future cloud/SaaS support must preserve that boundary by modeling tenant or
  application audit evidence the organization can access, not impossible OS-level
  telemetry from third-party infrastructure.

## Functional Requirements

- Provide CLI workflows for validation, generation, evaluation, configuration
  validation/introspection, skill installation, and version reporting.
- Support agent skills for scenario creation, generation, validation, evaluation,
  and configuration editing. Scenario creation should produce both `scenario.yaml`
  and student-facing `ENVIRONMENT.md` under `scenarios/<slug>/`.
- Validate scenario YAML before generation using Pydantic schema validation plus
  cross-reference checks for users, systems, personas, groups, segments, sensors,
  storyline actors, and event timing.
- Generate logs into a scenario bundle containing generated `GROUND_TRUTH.md`,
  `OBSERVATION_MANIFEST.json`, `OUTPUT_TARGET.txt`, and `data/`.
- Preserve canonical output formats in scenario YAML and select parser-specific
  file shapes through `eforge generate --target default|sof-elk`.
- Use format terminology at two levels:
  - User-facing format groups/source families such as `windows`, `zeek`, `edr`,
    `syslog`, `proxy_access`, and `cisco_asa`.
  - Concrete emitted formats/files such as Windows Security XML, Zeek `conn.json`,
    and eCAR records. Use the name `eCAR` sparingly for the adopted EDR record
    format, not as the general product/source-family name.
- Support runtime format filtering with `--formats`, intersected with scenario
  `output.logs`.
- Support typed storyline and red-herring event declarations. Current typed events
  include authentication, process, network, SSH/RDP, account/group/service/task,
  log clearing, remote thread, DHCP, scans, beacons, DNS, web scan, credential
  spray, DGA, DNS tunnel, explicit credentials, workstation lock/unlock, and raw.
- Prefer typed events over raw events. Raw events are allowed only as an escape hatch
  for single-format evidence that cannot be expressed canonically.
- Raw events are explicitly non-correlated. They must be routed and rendered safely,
  but they are outside cross-source consistency guarantees and should not be used
  when a typed event can express the evidence.
- Generate source-specific output for Windows Security, Sysmon, Zeek families,
  simulated EDR telemetry using the eCAR record format, Linux syslog, bash history,
  Snort/Suricata-style alerts, web access, proxy access, and Cisco ASA firewall
  logs according to current supported formats.
- Simulated EDR is a first-class endpoint telemetry source. It should prioritize
  canonical correlation for process, session, file, flow, registry, module, thread,
  and object identities; use a stable core schema with event-type-specific fields;
  and stay close to eCAR where useful without treating strict eCAR adherence as more
  important than realism or consistency.
- Provide deterministic 4-pillar data-quality evaluation with hard gates,
  aspirational targets, source-observation awareness, and actionable diagnostics.
- Preserve or improve ground truth accuracy. Ground truth should distinguish the
  scenario truth of what happened from the source-observation status of what made
  it into the dataset.
- `GROUND_TRUTH.md` should use a consistent reader-facing structure across
  datasets. Contents may vary by scenario, but headings, tables, lists, and major
  sections should remain stable enough that instructors and analysts can move from
  dataset to dataset without relearning the document shape.
- With observation profiles, ground truth may include actions or evidence that
  happened but did not appear in generated logs. When feasible, mark observation
  status; if precise marking would be misleading or brittle, prefer clear narrative
  separation from observed evidence rather than overclaiming.

## Realism Requirements

- Cross-source consistency is a primary realism requirement. Shared truth such as
  users, hostnames, source/destination tuples, LogonIDs, PIDs, UIDs, hashes, domain
  names, ports, bytes, status codes, and session IDs must be computed once and
  reused across all consumers.
- Source-native realism matters. Each log source should render the specialized view
  that source would actually expose, including timestamp precision, field naming,
  ID morphology, process ownership, sensor perspective, and protocol semantics.
- The generator must fix realism defects at the owning layer:
  - Shared event truth belongs in canonical contexts, state, world planning, timing,
    visibility/routing, or data config.
  - Emitters render source-native views of already-correct canonical truth.
  - Emitter-only fixes are appropriate only for source-local rendering details.
- Baseline activity must be realistic enough to hide the signal:
  - Human activity should be bursty and persona-aware.
  - System traffic should be periodic with jitter.
  - Day-of-week and work-hour patterns should affect user behavior.
  - Baseline should include legitimate lateral movement, stale-account noise,
    red-herring network activity, process-to-network correlation, and Linux syslog
    depth.
- Lifecycle completeness is required. Sessions, processes, DHCP leases, connections,
  file transfers, and other stateful activities need realistic creation, update,
  and termination semantics when the source would expose them.
- OS-aware generation is required. Windows defaults must not leak into Linux output,
  Linux shell/process assumptions must not leak into Windows output, and all
  fallback paths must check platform context.
- No uniform synthetic tells. Generation loops should avoid fixed counts, fixed
  intervals, cloned sensor rows, static command pools, cookie-cutter users, and
  repeated source-native artifacts.
- External infrastructure should look mundane and plausible. Reserved documentation
  domains/ranges, obvious malicious names, and narratively tidy artifact names are
  realism defects unless the scenario explicitly intends them.
- Observation profiles may introduce source-level missingness, delay, filtering, or
  out-of-window evidence, but they must not create contradictory canonical facts.
- `observation_profile: complete` is the default. Imperfect collection is an
  explicit scenario choice, not a silent engine behavior.
- Automated evaluation is a regression guardrail and calibration aid, not the sole
  definition of realism.

## Architecture Requirements

- Use a canonical `SecurityEvent` model with composable context objects as the
  shared truth carrier for correlated evidence.
- Preserve dual `src_host` and `dst_host` semantics. Source host is the actor or
  emitting origin; destination host is the target or receiver.
- Keep `StateManager` as the durable runtime state owner for sessions, processes,
  connections, DNS cache, boot times, and lifecycle metadata.
- Use a two-phase build pattern:
  - World planning or activity generation allocates durable IDs and ownership.
  - A complete `SecurityEvent` is built with those IDs.
  - Dispatch records state and routes to matching emitters.
- `StateManager.apply()` records already-built event state and handles teardown or
  updates. It must not allocate IDs.
- Put user placement, host capabilities, infrastructure roles, service inference,
  and session bootstrap decisions in a compiled world model/planner layer shared by
  baseline and storyline generation.
- Centralize causal expansion in composable rules. DNS before TCP, Kerberos before
  domain logons, remote-thread dependent process access, and supplementary audit
  evidence should be generated from rules rather than manually duplicated.
- Model evidence timing from explicit occurrence, lifecycle, causal,
  source-observation, and source-clock constraints. Rendered timestamps should be
  deterministic, source-native, and impossible to invert across dependent evidence.
  The implementation may use a temporal constraint graph, event/action bundles, a
  planner, or another mechanism; emitters should not invent independent jitter when
  shared temporal relationships own the timing.
- Route network evidence through visibility, NAT, firewall policy, and sensor
  observation logic before rendering.
- Keep proxy behavior modular enough to support additional proxy modes and
  vendor-specific renderers later. The current baseline remains explicit or
  transparent proxy behavior with existing TLS-intercept semantics.
- Emitters self-select with `can_handle()` and render only from canonical contexts,
  state lookups, and source-local format rules.
- Format definitions remain declarative YAML where practical. Templates are allowed
  for final string rendering, with constrained and validated inputs.
- Data pools and enumerable realism inputs belong in YAML config under
  `src/evidenceforge/config/` with overlay-aware cached loaders.
- Architecture must allow partial observation, target-specific output layouts, and
  additional log sources without duplicating source-of-truth logic.
- Lifecycle ownership is a first-class architectural domain. Stateful activities
  such as sessions, processes, connections, leases, file transfers, and proxy
  transactions need explicit owners, start/update/end semantics, and dependent
  evidence bounded by those lifecycles.

## Implementation Requirements

- Python 3.11+ is required.
- Use `uv` for dependency and command execution.
- Use Pydantic v2 for structured validation models.
- Use Typer for CLI, Rich for progress/reporting, Jinja2 for templates, PyYAML for
  config/scenario parsing, and pathlib for paths.
- Use type hints throughout, modern Python collection syntax, explicit return types,
  and Google-style docstrings for public APIs.
- Keep structured data in Pydantic models or dataclasses, not loose dictionaries,
  except at rendering boundaries and explicit raw escape hatches.
- Validate early and fail with actionable field paths and suggestions.
- Use custom exceptions rooted in `EvidenceForgeError`.
- Logging must avoid secrets, use module loggers, use lazy `%s` formatting, and
  separate user-facing console levels from file logging.
- All new YAML lookup data must live in the appropriate `config/` subdirectory and
  use cached loader patterns.
- Current config overlay behavior is the baseline: project-local overlays can add
  or merge entries and use the existing shallow `_replace` behavior. Recursive
  replace/delete semantics are future work unless a later implementation plan
  explicitly targets config composition.
- Scenario schema, docs, skills, validation, evaluation rules, causal expansion, and
  coverage prompts must be updated together when event types or schemas change.
- Version bumps are release-only on `dev` before `dev` to `main` PRs, not feature
  branch work.

## Performance And Scale Requirements

- Keep generation time, memory use, and output I/O reasonable for classroom,
  training, and research workflows.
- Preserve bounded memory through streaming writes, emitter buffering, and spooling
  where final ordering requires deferred fixups.
- Emitter-level parallelism is part of the architecture. Time-slice parallelism is a
  future option and must not corrupt shared state.
- Long scenarios need format filtering and source-specific memory controls.
- Numeric benchmarks are diagnostic and calibration tools, not product requirements
  by default. Add measured gates only when a concrete workflow needs them.

## Verification Requirements

- Normal development validation uses `uv run pytest --no-cov`.
- Release readiness uses explicit coverage gates only when preparing `dev` to
  `main`.
- Run `uv run ruff check .` and `uv run ruff format --check .` before committing.
- Add focused regression tests for every root-cause realism fix, especially when a
  blind-review finding is accepted.
- Use rendered-output probes for source-native realism issues that unit tests cannot
  fully cover.
- For realism-sensitive code changes, verification may need focused generated-output
  probes or manual sample inspection when the deterministic evaluator does not yet
  model the relevant source-native behavior.
- Treat automated eval scores as necessary but insufficient. A high score can still
  hide source-native artifacts that expert reviewers reject.
- Keep source-observation-aware evaluation honest: expected dropped/filtered evidence
  can be excluded from coverage denominators, but visible contradictions and field
  mismatches remain failures.

## Compatibility Requirements

- Default to preserving the current scenario schema, CLI behavior, generated bundle
  layout, and canonical output format names.
- Breaking schema changes require explicit review and updates across docs, skills,
  validators, tests, migration guidance, and examples.
- Future breaking schema changes should include user-facing migration assistance,
  potentially through a dedicated migration skill or migration guidance in the
  existing scenario skill.
- Current Phase 8.4 typed `events` lists are the compatibility baseline. Older
  `details` and `event_sequence` formats are not part of the current baseline.
- Target-specific rendering is not encoded in scenario YAML.
- Skill-created scenarios should remain under `scenarios/<slug>/`.
- Existing tests, loop artifacts, TODO history, and changelog entries are assets for
  migration planning and should not be discarded in a greenfield approach.
- A greenfield or major rewrite path may replace individual tests, but it must carry
  forward the behavioral protections and lessons those tests/history encode.

## Future And Deferred Requirements

These items are important but not necessarily in scope for the first architecture
reset implementation:

- Non-intercepting proxy mode and vendor-specific proxy formats.
- Cloud/SaaS log formats such as Azure AD, AWS CloudTrail, GCP audit logs, and M365.
  First-reset architecture should leave room for these source families, but they
  are not required in the first implementation pass.
- Per-host or named-group log deployment coverage beyond event-level observation
  profiles.
- Configurable work-week schedules and shift-worker calendars.
- Storyline cadence fields for human, automated, and periodic actions.
- Defense-response modeling where controls block, quarantine, or partially disrupt
  attack steps.
- ML-informed baseline profile learning from sanitized real logs.
- High-performance generation modes for larger enterprises and CI-scale workloads.
- Example scenario libraries and richer persona/host story packs.

## Implicit Lessons From Iteration History

- Family-level fixes work better than path-shaped patches. Each fix should identify
  the owner, invariant, entry paths, consumers, sibling risk, and proof strategy.
- Many recurring defects are ownership defects: session kind reuse, process lineage,
  endpoint occurrence time, source port binding, proxy leg ownership, certificate
  identity, DNS answer shape, and sensor observation semantics.
- Realism regressions often appear as deeper findings after obvious tells are fixed.
  A worse blind score does not automatically mean the last fix was wrong.
- Automated eval has become saturated for current realism work. Developer-side
  generated-output probes and sample review can catch source-native defects the
  scorer may not yet model.
- Cross-source timing should be modeled as relationship-bounded source latency, not
  a single global event timestamp or arbitrary emitter jitter.
- Data-driven pools are not optional. Repeated hardcoded values, recognizable public
  IPs, placeholder domains, and uniform templates become durable synthetic tells.
- The architecture should make it easier to prove negative assertions, such as "no
  flow before owning process", "no upstream proxy leg before CONNECT", or "no source
  sees link-local DHCP outside its segment".
