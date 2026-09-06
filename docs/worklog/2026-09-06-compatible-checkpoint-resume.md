# Compatible Checkpoint Resume and Exact-Behavior Recovery

## Objective

Recover an interrupted long generation whose recovery 23 was produced by source commit
`af8c01f3`, while making future checkpoint compatibility diagnostics precise enough to permit
EvidenceForge build-only migrations without weakening hard runtime or input checks.

## Diagnosis

- The copied bundle is `/Users/dabianco/TEMP/lab-3.1_v4`; recovery 23 is authoritative at
  simulated hour 557, with recovery 22 retained as fallback.
- Both retained lifecycle heads contain valid child processes whose bootstrap parents had aged out
  before checkpoint publication. Recovery 23 has 47 such processes and recovery 22 has 50. They
  are closed Explorer-family processes, not cyclic process graphs.
- The old restoration loop treated every unresolved parent as a cycle and repeatedly scanned and
  removed from pending lists. At this checkpoint's approximately 37,000 process records and 95,000
  session records, that path was both semantically wrong and quadratic.
- The checkpoint build digest resolves to commit `af8c01f3`. The immutable `v2.0.0rc2` tag is a
  sibling version-bump commit and remains unchanged.

## Implementation decisions

- Resume compatibility has three levels: `exact`, `load-compatible`, and `incompatible`.
  `load-compatible` permits only EvidenceForge version/build identity differences. All resolved
  input, options, schema, dependency, Python ABI, OS, architecture, and byte-order differences are
  hard failures. `--resume-policy compatible` is the default; `exact` remains available.
- `eforge checkpoint verify BUNDLE [--json]` authenticates the recovery and fully hydrates every
  participant in isolated scratch storage without modifying the source bundle.
- A load-compatible resume publishes an atomic same-cursor migration checkpoint only after full
  hydration and before generation advances. The selected pre-migration recovery remains fallback.
- Checkpoints and the final generation manifest retain bounded provenance with originating and
  resuming build identity, compatibility classification, cursor, and migration lineage.
- Lifecycle restoration uses indexed topological ordering. A retained process with an absent
  parent is registered without fabricating that parent, then retains its exact original
  `parent_object_id`; actual self-parenting and multi-node cycles still fail.
- The general implementation lives on updated `dev`. The same checkpoint-control and restoration
  commit is backported onto `af8c01f3` for an exact-behavior recovery build; version declarations
  are not changed.

## Validation record

- Lifecycle and incremental-checkpoint unit coverage includes aged-out parents, exact parent-ID
  preservation, valid ancestry, self-parenting, multi-node cycles, participant schema rejection,
  same-cursor migration/fallback retention, and a 5,000-process restoration scale contract.
- Focused checkpoint suites: 132 passed, with the representative slow test deselected for the
  focused run.
- Default suite: 8,252 passed, 5 skipped, and 2,005 deselected.
- Checkpoint slow tier: all 14 cases passed. The representative uninterrupted-versus-resumed
  bundle comparison passed after adding the two iteration-test runtime fields to the explicit
  checkpoint inventory and reconstructing Cisco ASA connection-ID uniqueness state from its
  authenticated sorted runs.
- Repository Ruff checks and format checks passed for all 755 Python files.
- Recovery 23 from `/Users/dabianco/TEMP/lab-3.1_v4` passed authenticated, read-only full hydration
  with 21 participants under Python 3.12.9 and the stored compiler identity. It reported 47
  dangling process parents, all retained Explorer application processes, and no lifecycle cycle.
  The dependency versions exactly match the checkpoint. The locally available Python 3.12.9
  builds use different compiler identities, so this acceptance check simulated only the stored
  compiler string; the product correctly retains compiler identity as a hard compatibility field.
- A disposable APFS clone of the real bundle exercised migration publication and was intentionally
  stopped immediately afterward. Recovery 24 was published at the unchanged hour-557 cursor with
  complete build transition provenance, and `CURRENT.json` retained recovery 23 as fallback:
  `[24, 23]`. The source copy remained `[23, 22]` and was never modified.
- The exact-behavior backport is branch `codex/checkpoint-recovery-af8c01f3`, based directly on
  `af8c01f3`, at commit `3942c478d67d061615ccee4fdaacdc3e2db77223`. Its installed build
  digest is `ed1961d641440bf7d3fd60d3451ca0aa9678a5286c5573228e8b4f9c67f2d47f`.
  The transfer wheel is `dist/recovery-af8c01f3/evidence_forge-2.0.0rc1-py3-none-any.whl`
  (SHA-256 `9ede93903d0570e5a5c1fe539cf6fa006132aaaa73492e02c37fb074ab5ea557`).
  A clean wheel installation reproduced the same installed build digest.

## Attemptable drift policy pivot

The follow-on implementation is isolated on `codex/checkpoint-permissive-resume` from integrated
local `dev`; the exact-behavior `af8c01f3` recovery branch, commit, and wheel above remain unchanged.
The compatibility contract now asks three independent questions: immutable run identity,
serialized-state loadability, and expected EvidenceForge behavior drift.

- Python version/compiler/implementation, dependencies, OS, architecture, interpreter cache tag,
  and byte order are attemptable. They no longer fail static compatibility, but successful restore
  cannot promise equivalent remaining bytes.
- Explicit scenario/seed/formats/target conflicts, integrity and ownership failures, missing
  participants, and unsupported checkpoint or participant schemas remain hard failures. Omitted
  ordinary inputs adopt checkpoint authority. Stored OOB hosts never confer authorization and must
  be supplied again exactly.
- `compatible` remains the default. Declared non-material behavior continues after hydration;
  material or unknown behavior prompts with default refusal, and noninteractive use receives
  verify-plus-`attempt` guidance. `attempt` is explicit output-risk consent, never a state or safety
  bypass. `exact` still requires the complete original fingerprint.
- `config/generation_behavior.yaml` starts revision 1 at the integrated `dev` baseline. Its
  gap-free history declares stable IDs, impact, domains, and formats. CI checks a behavior-surface
  digest that excludes checkpoint-control code but covers generation, canonical events/formats,
  composition/config/model inputs, output targets, and deterministic RNG/time utilities.
- Status and verify report schema 1.1 retain `compatibility_level` while adding run identity,
  loadability, behavior change, confirmation, and categorized differences. Non-exact migration
  provenance adds runtime drift, behavior IDs/risk, accepted policy, and confirmation status.
- Verification now reports integrity, initialization, participant `N/M` hydration, cleanup, and
  completion. Its scratch-disposal path stops workers and closes SQLite handles without ordinary
  terminal source finalization. Detailed aged-out-parent examples are verbose-only.
- Before a non-exact actual restore, staged evidence is atomically retained. Failed pre-migration
  restore reinstates it; successful same-cursor migration releases that temporary fallback while
  the normal two-recovery index continues to retain the prior recovery point.

## Attemptable drift validation and integration

Final validation covered the behavior-manifest validator/digest and retained-history lineage,
runtime drift matrix, hard run-identity fields, severity aggregation, legacy/downgrade handling,
policy consent paths, fresh OOB authorization, progress ordering, scratch SQLite disposal,
migration provenance, installed skill references, and package contents.

- Focused checkpoint, behavior, CLI, and skill-contract runs passed, including the final 104-test
  combined gate and the 46-test lineage/checkpoint gate.
- The default suite passed with 8,284 tests and five optional external-parser tests skipped.
- The full checkpoint slow gate passed 57 tests in 9m32s, including exact resumed-versus-control
  evidence comparisons for every output target and the checkpoint-publication crash matrix.
- The Python 3.12 to 3.13 portability fixture fully hydrated, published migration lineage,
  completed generation, and passed authoritative bundle verification.
- Ruff check, Ruff format check, `git diff --check`, and the generation-behavior surface checker
  passed. A temporary wheel confirmed that the behavior manifest, behavior classifier, and
  checkpoint-recovery skill reference are packaged.
- `pyproject.toml`, `src/evidenceforge/__init__.py`, and `uv.lock` remain unchanged. The
  `codex/checkpoint-recovery-af8c01f3` branch still resolves to `3942c478d`, and its recovery wheel
  remains untouched. No remote branch was pushed.
