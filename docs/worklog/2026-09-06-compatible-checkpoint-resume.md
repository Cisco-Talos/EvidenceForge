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
