# Skill Schema Reference Redesign

## Scope

Make authored EvidenceForge schema discoverable through focused skill references instead of
routine `eforge info` calls. Preserve `eforge info` for installation- and project-dependent
inventories, retain the consolidated public scenario manual for humans, and remove the redundant
exhaustive scenario-reference copy from installed skill resources.

## Decisions

- Focused references own exact YAML fields, defaults, constraints, examples, and semantic guidance.
- Pydantic models remain the implementation authority; contract tests compare runtime event and
  environment surfaces with the focused-reference coverage map.
- `eforge info` no longer advertises or returns storyline event types or JSON Schemas.
- The public `docs/reference/scenario-reference.md` remains a consolidated human manual and is not
  installed as an agent reference.
- Industry and organization pack skills load the focused scenario references required by their
  consumer harnesses instead of the exhaustive manual.
- A possible future `eforge schema` command is backlog-only and should be implemented only for a
  demonstrated editor or external-integration need.

## Verification

- Focused schema, skill installation, CLI-info, IDS, spillage, and validation contracts:
  370 passed, 22 deselected.
- Temporary ChatGPT/Codex installation: 63 files installed; all eight generated skills passed the
  skill-creator validator.
- Ruff check, Ruff format check, and `git diff --check`: clean.
- Complete routine non-slow suite: 8,119 passed, 5 skipped, 2,052 deselected in 188.22 seconds.

The first complete run exposed an unrelated obsolete test that concurrently drove the whole logon
publication pipeline while claiming to test thread-local RNG. Transactional dispatch correctly
rejected one stale prepared state, making the test nondeterministic. The test did not observe RNG
selection and duplicated dedicated StateManager concurrency coverage, so it was removed. Seven
direct thread-local RNG tests and the dedicated StateManager/dispatcher concurrency suites remain.

## 2026-08-26 project and authoring reconciliation

A parent-branch audit found that lifecycle reconciliation had preserved the new focused schema
design but missed several independent authoring contracts. The restoration kept schema ownership in
the focused references and did not recreate `commands/eforge/references/scenario-reference.md` or
the removed schema fields in `eforge info`.

The reconciled skill behavior now uses one shared `project-context.md`: authored compilation,
pack/config management, and project-dependent inventory default to the current working directory;
`--project-root` is an explicit override only; ancestor, home, installed-package, and source-tree
searches are forbidden. New-scenario authoring now establishes explicit industry and organization
decisions before writing, including compatible organization-pack inspection after an industry-only
choice and a confirmation step after explicit delegation such as “you decide.” Authored schema
continues to come from focused references, and skills explicitly reject invalid-scenario probing as
a discovery mechanism.

Focused references and public manuals regained exact deployment/release/module/software identity,
exact source-deployment and collection diagnosis, organization/scenario override boundaries,
current V2 owner guidance, proxy compatibility warnings, and exact compiled SMB references. The
installer bundles the shared project context into all seven project-aware skills. A fresh temporary
ChatGPT/Codex installation produced 70 files, and all eight generated skills passed the
skill-creator validator. Focused compiler/CLI/pack/config/validation/skill/installer coverage is
green.

Final verification completed with Ruff lint and formatting checks, the complete routine gate
(8,139 passed, 5 skipped, and 2,052 deselected in 193.58 seconds), and the complete extended
release gate (1,823 passed and 8,373 deselected in 735.23 seconds). The first slow-gate pass exposed
two stale composition fixtures that still inferred a temporary project from the scenario file's
parent. Those fixtures now pass their intended temporary root explicitly, and the complete slow
gate is clean. Soak was not run because the reconciliation changes neither scale nor retention
behavior.

## 2026-08-26 scenario-authoring validation-loop remediation

Repeated first-draft failures demonstrated a concrete need for the previously deferred focused
schema interface. `eforge schema <selector> --json` now exposes installed-version field types,
requirements, defaults, enums, constraints, units where the model declares them, full JSON Schema,
and one model-validated minimal example for focused environment paths and every typed event.
Legacy network identities remain compatible with either hosts or IPs, while new guidance and the
minimal example consistently show the exact plural `hosts` and `ips` fields.

Authoring guidance now validates broad scenarios in coherent stages and clears blockers before
warning review. References add targeted examples only at demonstrated ambiguity points: scalar
service accounts, network identity shape, numeric-second email reads, RDP receiver capability,
sensor/output compatibility, and generated-storage overrides. Validation collapses sibling
missing/unsupported-field failures into one object-shape issue, links it to the focused selector,
and never promotes a warning over an available error in the JSON headline.

Focused schema, validation, scenario/validation skill, storage, installer, and slow installed-CLI
contract suites passed. Temporary installed scenario and validation skills passed the
skill-creator validator. The complete routine gate passed with 8,163 tests, 5 skips, and 2,058
deselections; Ruff lint/format plus `git diff --check` were clean. Clean-room agent acceptance
measurement remains deliberately deferred as a P1 roadmap item in `TODO.md`.
