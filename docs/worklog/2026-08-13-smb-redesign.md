# Canonical SMB2/3 Storage Redesign

## Objective

Replace inferred TCP/445 file behavior with canonical Windows SMB2/3 disk-share
activity. Generic SMB connections remain transport-only; semantic storage activity
owns share mappings, file operations, mutable storage state, and correlated Zeek,
Windows, and eCAR evidence.

## Approved contracts

- Compile deterministic storage topology and a bounded metadata catalog from
  `environment.storage`; never allocate file payloads.
- Add typed `smb_activity` events with mechanical operations, orthogonal purpose,
  typed locations, bounded batch selection, and explicit outcomes.
- Compose existing network and Windows remote-authentication contracts. SMB owns
  only session attachment, tree/handle/operation semantics, and storage mutations.
- Use durable file identity plus content version and path history. Runtime SMB state
  is owned by `StateManager` and remains bounded.
- Add Zeek `smb_mapping`, `smb_files`, and directional `files` projection. Native
  Zeek Kerberos/NTLM output is deferred.
- Replace whole-file Zeek final sorting with bounded external merge sorting.
- Remove implicit 32 KiB SMB file inference and ad hoc port-445 logon/file side
  effects after semantic callers migrate.
- Treat the output change as breaking. Feature work does not bump the package;
  the first release containing it must be 2.0.0.

## Implementation record

- 2026-08-13: Design approved and implementation started on
  `codex/smb-redesign` from package version 1.17.0.
- 2026-08-13: Added bounded, fan-in-limited external merge sorting for Zeek
  output, including byte/count caps, atomic publication, cleanup, disk forecasts,
  and failure-path coverage. Windows retains its existing SQLite spool.
- 2026-08-13: Added `environment.storage`, deterministic generated file-server
  and domain-controller topology, drive-root and folder-mounted volumes, shares,
  mappings, effective access, bounded catalogs, manifest diagnostics, and
  duration-independent selection.
- 2026-08-13: Added `smb_activity`, canonical SMB lifecycle occurrences, mutable
  `StateManager` storage/session/tree/handle state, batch and outcome validation,
  external-client mode, and correlated Zeek, Windows Security, and eCAR
  projection. SMB phases reuse the owning network transport plan rather than
  allocating a second tuple, UID, timing interval, or byte ledger.
- 2026-08-13: Performed the direct cutover. Generic TCP/445 connections are now
  transport-only, semantic baseline and storyline callers use canonical SMB,
  the byte-volume-to-file heuristic and ad hoc SMB companions were removed, and
  retired overlay and likely-legacy scenario diagnostics were added.
- 2026-08-13: Advanced machine-readable ground truth to schema v3 for typed SMB
  activity and added storage manifest output and workload/resource forecasting.
- 2026-08-13: Updated architecture, scenario, evidence-format, generation, and
  validation documentation together with the canonical `commands/eforge` skill
  sources and their installed-skill reference inventory.
- 2026-08-26: Extended the storage world with bounded persistent host file sets. Ordinary Windows
  and Linux hosts can now own files without becoming SMB servers; optional same-host/same-root
  share bindings alias the exact canonical file objects rather than compiling or forecasting a
  second population. The storage manifest advances to schema v3 for file sets and share bindings.
- 2026-08-26: Client-file-set uploads now preserve relative paths beneath an explicit destination
  directory, reuse an immediately preceding authored transfer process, and flow through the
  existing authenticated SMB transport/session/tree/mutation/recovery owner. Copies use distinct
  destination objects with shared content lineage; moves commit destinations before retiring
  sources. Schema diagnostics distinguish exact files from directories and reject unbounded or
  incompatible batch forms before generation.
- 2026-08-13: Expanded `validate --show-storage` from a compact share/mapping
  summary into explicit volume, share-root, resolved scale/policy, effective-access,
  bounded catalog-sample, and mapping-audience diagnostics, including unused volumes.
- 2026-08-13: Recalibrated validation/generation resource forecasting as model v3.
  Final output and peak working disk are now separate, SMB catalog/batch/mutation and
  source fan-out affect estimates, and the calibration harness measures transient allocated
  spool space as well as final logical bytes. Matched source-isolated runs reproduced the
  146-operation SMB output delta within 0.01 MiB for Zeek, Windows Security, and eCAR; 7-day
  and 31-day holdouts kept every measured resource inside its forecast interval.
- 2026-08-13: Restored the expanded `validate --show-storage` preview to wrapping
  Rich tables, splitting share locations from policy/catalog fields and rendering
  bounded samples per share so exact paths and access details remain readable on
  ordinary terminal widths.
- 2026-08-13: Refined mapped-drive policy: authored SMB mappings may use `D:`
  through `Z:`, while `A:`/`B:` remain reserved, `C:` remains the local system
  drive, and automatic mapping allocation remains constrained to `H:` through
  `Z:`. The iteration scenario now exercises an explicit `F:` mapping.
- 2026-08-13: Expanded the canonical iteration-test scenario with explicit NTFS
  drive-root and ReFS folder-mount storage, mapped and UNC access, effective ACLs,
  encrypted and unencrypted shares, deterministic seed files, benign browse/read/
  create/update/move activity, a denied access attempt, and bounded attacker copies
  followed by local archive staging.
- 2026-08-13: The iteration generation check caught and fixed a hardcoded Zeek
  `native_file_system: NTFS` projection. Canonical SMB phases now carry the
  compiled volume filesystem, so ReFS-backed mappings render as `ReFS`; the
  attacker collection step also establishes a user-owned PowerShell process
  before the correlated SMB copies instead of falling back to PID 4.
- 2026-08-13: Focused `--formats zeek,windows,ecar` generation exposed a raw
  Syslog dispatch into an intentionally filtered emitter. Raw escape-hatch events
  now skip valid disabled formats while the dispatcher retains its fail-fast
  behavior for genuinely unknown direct requests.
- 2026-08-13: An initial blind assessment found server audit ordering, SID,
  native event-shape, share-root, transport-byte, and sensor-timing defects. The
  owning lifecycle, identity, transport-plan, source-timing, and emitter-schema
  layers were corrected and the assessment dataset was regenerated before the
  final panel.

## Verification record

- `uv run ruff check .`: passed.
- `uv run ruff format --check .`: passed (483 files already formatted).
- Focused SMB, storage, sorted-writer, configuration, and skill-install tests:
  120 passed.
- Expanded storage-preview CLI and regenerated-skill regression tests: 95 passed.
- Focused SMB generation and evaluator tests: 62 passed.
- `uv run eforge validate-config`: 91 files validated with no errors, warnings,
  or informational findings.
- `uv run pytest --no-cov --include-slow tests/integration/test_smb_long_run.py -q`:
  1 passed; the 31-day bounded-state/external-sort workload completed in 2.12s.
- `uv run pytest --no-cov`: 5,527 passed, 21 skipped in 382.53s.
- Final deterministic assessment: 14,543 records across 13 sources, 97/100;
  14,543/14,543 strict schema and constraint checks passed, all declared SMB
  storyline traces reconciled, and every hard acceptance gate passed. The sole
  evaluator flag was the existing general baseline service-interval regularity
  diagnostic, not an SMB contradiction.
- Independent blind reviews initially found and drove fixes for application
  phases outside transport intervals, server audit records before logon, reused
  placeholder SIDs, write operations through read-only handles, incomplete
  access-right translations, cross-host eCAR process identities, PID 4 client
  copies, mirrored client/server timestamps, fixed tree-connect delays, and
  affine byte accounting.
- The final regenerated output was re-audited without scenario, ground-truth,
  source, documentation, or history access. Host and network reviewers found no
  remaining SMB P0/P1 contradiction: 429/429 successful endpoint FLOW views are
  inside their 215 matching SMB connection intervals; 210/210 rendered network
  LOGIN events follow FLOW and precede close; 29/29 logon-linked FILE events
  follow LOGIN and precede close; client-copy actors and object identities are
  host-local; and write handle rights contain every realized access bit. Two
  standard-audit 4663 rows without visible handle companions remain acceptable
  P2 collection texture.
- Post-review focused source-timing/eCAR/SMB tests: 160 passed, followed by 55
  passed after exact sensor-close deadline propagation.
- SMB-aware resource-forecast recalibration: matched source-isolated output deltas agreed within
  0.01 MiB, all short/7-day/31-day holdouts landed inside their v3 memory/final-output/working-disk
  intervals, 69 focused tests passed, and the full non-slow suite passed 5,530 tests with 21 skips.
- Iteration scenario follow-up: `validate --show-storage` passed with only the
  scenario's pre-existing topology/pivot warnings; 62 focused SMB/storage/CLI
  tests passed; full and `--formats zeek,windows,ecar` generations completed.
  Output inspection confirmed mapped Finance reads/writes/rename, a denied read,
  bounded collection FUIDs, ReFS mapping projection, encrypted-share operation
  opacity, server-local paths, and non-System client file actors.
- Mapped-drive policy follow-up: 18 storage tests and 95 CLI/skill-install tests
  passed; repository-wide Ruff checks and formatting passed; iteration-test
  validation resolved the explicit Finance mapping to `F:` while automatic-drive
  coverage remained constrained to `H:` through `Z:`.
- Final `git diff --check`, repository-wide Ruff lint, and Ruff formatting checks
  passed. Version and changelog artifacts remain untouched.

Package version files intentionally remain unchanged on this feature branch. The
first release containing the transport-only cutover must be 2.0.0.

### 2026-08-26 reusable host-file verification

- Focused SMB, storage, validator, forecast, documentation, and installer coverage:
  284 passed.
- The bounded three-workstation upload fixture passed in 56.68 seconds and verified
  `robocopy.exe` attribution, relative-path preservation, source/destination content
  correlation, originator-heavy TCP/445 accounting, Zeek SMB/files rows, endpoint
  reads/writes, durable fileserver state, and drained lifecycle owners.
- Multi-file move ordering and lost-return mutation recovery passed without duplicate
  objects, operations, transports, or terminal evidence.
- All eight freshly installed canonical skills passed the skill validator.
- `uv run ruff check .` and `uv run ruff format --check .` passed repository-wide.
- `uv run pytest`: 8,147 passed, 5 skipped, and 2,056 deselected in 179.86 seconds.
- `uv run pytest -m slow --no-cov`: 1,827 passed and 8,381 deselected in 840.43
  seconds. The first slow run identified one archived batch destination still using
  exact-file `path`; both sides of that migration fixture now use `directory`, and
  the complete slow rerun is green.
