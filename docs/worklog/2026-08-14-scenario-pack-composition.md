# Scenario Pack Composition

## Status

Implementation complete on `codex/scenario-pack-composition`, branched from `dev`
at `ef99f23897cd0092800136846a2405f6f4f935eb`. The branch is ready for review
and merge into `dev`; package versions remain unchanged for the feature PR.

## Durable decisions

- Scenario 1.0 remains a warning-free compatibility contract and never discovers packs.
- Scenario 2.0 may be monolithic or select whole industry packs or one organization pack.
- Packs live in package data, project-local `.eforge/packs`, or an explicit path; there is no
  user-global pack registry.
- Public packs use fixed typed catalogs and exact source/name/version references.
- Organization packs pin their industry dependencies exactly.
- Generated bundles gain an authoritative resolved scenario and run manifest; resolved input
  cannot grant live OOB authorization.
- Dedicated pack-authoring skills are a separate immediate follow-on after this feature is tested.

## Compatibility baseline

- `uv run eforge validate tests/fixtures/scenarios/minimal.yaml`: valid with no warnings.
- Include behavior is covered by `tests/unit/test_utils.py` and CLI include fixtures.
- Fixed seed `424242`, `zeek_conn` output:
  - `data/core-zeek/conn.json`: `5463c06bc5a1c3a882c7d9319025b197517f3030eacd05e12aa33aefe4abefe5`
  - `GROUND_TRUTH.json`: `5b2edf29801ddc61d7c1437db6ad2744d40c4ed3c3a6660371c30c9460831c7a`
  - `GROUND_TRUTH.md`: `274c7d30391bf509302dd8c305216e5813c5f80465c3a9394a690595f45d7958`
  - `OBSERVATION_MANIFEST.json`: `bfc7d7c1d99b9be95cb7a0017255d42fce471532c342331d647f73e71659ca8a`
  - `OUTPUT_TARGET.txt`: `01666ec060466c14b9fa06c613fbac449163f2a2017558fe16526209ab78c6b0`
  - `STORAGE_MANIFEST.json`: `d223ba777909e0737b1903e2fe60f1764ffe6234d4a689d29f17333ca3cfdddd`

## Validation results

- Focused Scenario 2.0/compiler/provider suite passes, including no-pack silence, exact org
  dependency resolution, qualified catalogs, fixed empty catalogs, declaring-include-relative path
  packs, contained pack includes, sequential/concurrent config isolation, and resolved round trips.
- Existing include, CLI, info, DNS-registry, SMB-storage, and email-evidence regression suites pass.
- `northstar-health` validates and fixed-seed `zeek_conn` generation succeeds. Evaluation discovers
  and verifies the authoritative bundle without `--scenario` and scores it successfully.
- Regeneration from the emitted resolved scenario produced byte-identical `conn.json`,
  `GROUND_TRUTH.json`, and `RESOLVED_SCENARIO.yaml` in the representative run.
- `finance` validates and generates a fixed-seed authoritative Windows bundle as a direct-industry
  sample. `northstar-health` validates and generates as an organization-backed sample with its
  pinned healthcare dependency, email topology, and SMB storage.
- Scenario 1.0 fixed-seed regeneration retained every captured pre-refactor hash for logs and
  legacy sidecars. Determinism tests exclude only the intentionally timestamped run manifest.
- `uv run ruff check .` and `uv run ruff format --check .` pass.
- The complete default suite passes: 5,563 passed and 21 expected skips.
- The relevant 31-day SMB slow regression passes separately with `--no-cov --include-slow`.
- The release coverage gate passes at 85.22% (5,563 passed, 21 skipped); its XML report was written
  under `/private/tmp` to preserve the unrelated untracked `coverage.xml`.
- Wheel and source-distribution builds contain every sample manifest, catalog, model file, and the
  packaged digest index.

## Implementation notes

- Pack public catalogs are qualified as `<pack-name>:<local-name>` and use typed, extra-forbidden
  schemas. Explicit adapters currently feed destination/DNS, persona traffic, and SMB storage
  profiles into the immutable effective configuration.
- Effective configuration snapshots packaged YAML, project overlays, selected catalogs, and
  scenario-relative email corpora. A compatibility scope clears/restores raw and derived caches;
  direct `Scenario` engine callers retain legacy CWD-overlay discovery.
- Generated sidecar ownership is centralized in a registry; the resolved scenario and generation
  manifest participate in overwrite protection, staging, rollback, hashing, and discovery. Only
  registered engine-owned paths are hashed, so unrelated author collateral is not silently folded
  into the bundle identity.
- `TODO.md` records composition as complete, removes the overlapping older pack backlog item, and
  makes dedicated industry/organization pack-authoring skills the next active P1.
