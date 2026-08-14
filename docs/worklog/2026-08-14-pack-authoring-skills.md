# Pack Authoring Skills and Runtime-Effective Catalogs

## Status

Implementation and validation complete on `codex/pack-authoring-skills`, created directly from
`dev` at `5c079f5f6ed03d7cad89222ebd0ccb453b75968b`. Package versions remain unchanged; the branch is
ready for a PR to `dev`.

## Durable decisions

- Canonical skill sources live under `commands/eforge/`; tracked `.agents/skills` content is
  regenerated from the installer rather than edited directly.
- Add separate pack-management, industry-pack, and organization-pack skills, then integrate pack
  discovery and consumption into the scenario/config/validation workflows.
- Finalize the unreleased pack schema `1.0` before EvidenceForge 2.0.0. Every semantic catalog
  field must affect effective configuration or generation; obsolete prototype shapes fail with
  migration guidance.
- Application entries own persona allowlists, matching the existing non-pack application runtime.
- Traffic cadence is structured and generation-effective. Pack traffic keeps its qualified group
  identity so scheduling and provenance are not lost during adaptation.
- Pack lifecycle commands must provide safe contained writes, reference-aware renamed copies, and
  stable JSON suitable for chat skills.
- Draft pack versions may be edited in place only while explicitly unshared and incomplete. Shared
  or complete packs are forked according to SemVer compatibility impact.
- The public process/application/destination/traffic catalogs form one validated reference graph.
  Application-bound traffic selects exact eligible processes and destinations; structured weighted,
  periodic, and burst cadence is generation-effective. Low-level outbound traffic stays
  intentionally processless.
- Pack validation is recursively strict and checks packaged executable/domain collisions, qualified
  cross-references, OS-native commands, supported placeholders, storage path/MIME safety, and
  realizable storage populations.
- Pack loading and copying use bounded, no-follow traversal and immutable validated byte snapshots.
  Digests, assets, runtime data, copies, and copy provenance therefore describe the same exact input.
- Composition explanations retain portable authored, catalog-include, and organization-model field
  origins plus concrete scenario/project replacement decisions.
- The ignored project-local `.agents/skills/` tree is generated from `commands/eforge/`. All formerly
  tracked `.agents` files are removed from the Git index; no unique development content was found in
  them.

## Compatibility baseline

- `uv run eforge validate tests/fixtures/scenarios/minimal.yaml`: valid without warnings.
- Fixed seed `424242`, `zeek_conn` output:
  - `data/core-zeek/conn.json`: `5463c06bc5a1c3a882c7d9319025b197517f3030eacd05e12aa33aefe4abefe5`
  - `GROUND_TRUTH.json`: `5b2edf29801ddc61d7c1437db6ad2744d40c4ed3c3a6660371c30c9460831c7a`
  - `GROUND_TRUTH.md`: `274c7d30391bf509302dd8c305216e5813c5f80465c3a9394a690595f45d7958`
  - `OBSERVATION_MANIFEST.json`: `bfc7d7c1d99b9be95cb7a0017255d42fce471532c342331d647f73e71659ca8a`
  - `OUTPUT_TARGET.txt`: `01666ec060466c14b9fa06c613fbac449163f2a2017558fe16526209ab78c6b0`

## Validation results

- Six independent clean-room chat-authoring trials passed: three industry workflows, two
  organization workflows (including a renamed Northstar fork with SMB storage), and one scenario
  routing/non-mutation trial. Runtime evidence proved qualified destinations, exact processes,
  cadence, dependencies, and SMB-backed storage.
- All packaged samples validate: finance, healthcare, technology, and Northstar Health with its
  exact healthcare dependency.
- Focused integrated gates passed: 383 pack/CLI/runtime/installer tests before final review, then
  205 pack/compiler and 96 runtime/SMB tests after the final immutable-byte and singleton-history
  fixes.
- Full default suite: `5696 passed, 21 skipped` in 478.89 seconds.
- Relevant slow gate: the 31-day SMB state/sorting test passed with `--include-slow --no-cov`.
- `uv run ruff check .` and `uv run ruff format --check .` pass.
- Scenario 1 fixed-seed hashes remain byte-identical to the compatibility baseline above.
- Authored finance-pack generation and generation from its authoritative resolved document are
  byte-identical apart from intentionally timestamped generation-manifest data.
- Fresh wheel and source distribution contain all 21 canonical skill files and 31 pack files
  byte-for-byte, contain no `.agents` content, and retain version `1.17.0` on this feature branch.
- The release coverage gate remains a `dev` to `main` release responsibility and was not rerun on
  this feature branch.

## Handoff

- Open the feature PR into `dev`; do not bump the package version on this branch.
- Preserve the unrelated untracked `coverage.xml` and
  `docs/worklog/2026-08-04-iteration-test-expanded-ids-assessment.md`.
- After merge, `.agents/` remains an ignored local install target. Continue all skill development
  under `commands/eforge/` and regenerate installed copies through `eforge install-skills`.
