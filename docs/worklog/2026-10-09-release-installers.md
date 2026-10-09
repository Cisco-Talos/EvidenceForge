# Automatic release installers

## Scope and entry points

User authorized implementing automatic installer builds/publication on October 9, 2026.
The implementation request did not authorize a version bump or publication, and the initial
packaging rehearsal used 2.1.2. A subsequent request authorized preparing version `2.2.0a1`,
with `2.2.0` as the planned stable release. The initial preparation did not authorize tag pushes
or publication. On October 9, after testing the regenerated DMG and app, the user authorized
final checks, committing, pushing dev and the annotated alpha tag, and monitoring automatic
publication. The user retains the final smoke test of the GitHub-built installer. Main merges
remain outside this alpha release.

- Stable: the prepared release merge to main starts validation, required checks, installer
  builds and publication. The publisher creates the annotated tag on that exact commit.
- Preview: an annotated version-matching alpha/beta/RC tag on a commit reachable from remote
  dev starts the same pipeline without changing main. Normal dev pushes do not publish.
- macOS Apple Silicon is the sole installer target. Signing/notarization remain deferred.
  Linux/Windows can later add native build-matrix entries and explicit required-asset contracts.

## Implementation

- Release jobs call the existing routine and slow/portability workflows through workflow_call.
  CI supports optional 70% Linux routine coverage for releases. Concurrency groups distinguish
  regular CI from release callers so regular main CI cannot cancel the release's checks.
- The macOS-26 build job requires arm64, checks out the validated SHA, assembles the existing
  private runtime/app, creates release filenames without the developer-test suffix, verifies
  the isolated packaged CLI/resources, checks DMG integrity and validates its checksum.
- Publication downloads installer artifacts from the same Actions run, creates/resumes a draft
  bound to the source commit and channel, uploads missing files, downloads them to verify the
  bytes, and only then publishes. Only the publication job has repository write access.
- Rerun failed jobs to retain original build artifacts. Matching draft assets are reused;
  differing bytes are rejected. Published releases are verified and remain unchanged. API/auth
  errors do not imply absent objects. Tags are never forced or recreated.
- AGENTS.md and docs/releases.md document tag examples, preparation, release gates and recovery.

## Validation

- 50 focused release/version/workflow tests passed. Real temporary Git repositories exercise
  annotated/lightweight tags, dev ancestry, stable reruns, wrong versions, reused tags and drift.
  Simulated GitHub publication covers incomplete/corrupt assets, upload/auth failure, exact
  partial-draft retries, existing complete releases and protection of foreign/differing drafts.
- Official actionlint 1.7.12, downloaded to a temporary directory and checked against upstream
  SHA256, passed on all three changed workflows. Repository-wide Ruff lint/format passed.
- A complete local Apple Silicon private-runtime/app/release-DMG build succeeded at product
  version 2.1.2. Generated build output is ignored by Git. Native DMG integrity,
  release filename/checksum and isolated packaged CLI/resource verification all passed, including
  pack inspection, artifact naming/properties, validation and checkpoint-enabled generation.

## Remaining release execution

The actual GitHub-hosted runner build and release API write sequence have not been dispatched.
They require the upcoming authorized release snapshot/tag. The native local build and mocked
failure/recovery checks do not claim that remote publication has occurred. Prepare the chosen
alpha snapshot before pushing its release tag. Existing outstanding platform,
cross-account and public Studio acceptance items in TODO.md remain independent release decisions.

## Alpha version preparation

- Set Python declarations and the uv lock to `2.2.0a1`; regenerate derived Studio npm/Tauri/Cargo
  metadata and lockfiles as `2.2.0-alpha.1` using the version synchronizer.
- Consolidate the unreleased changelog into `v2.2.0a1 (2026-10-09)`, summarizing non-merge product
  commits since `v2.1.2` with short SHA references and retaining alpha platform/acceptance limits.
- Reconcile TODO.md's stale release target with the planned `2.2.0a1` preview and `2.2.0` stable
  release. This prepares source metadata; the earlier local 2.1.2 DMG is not an alpha installer.
- Verification after the bump: version synchronization check passed, all 50 focused
  release/version/workflow tests passed, repository-wide Ruff lint/format and diff whitespace
  checks passed, and every non-dependency/non-merge commit since `v2.1.2` has a changelog SHA
  reference. Dependency package versions remain unchanged; uv regenerated the lock format
  revision along with the product version.

## Studio documentation consolidation

- User authorized replacing the source-run and macOS-specific guides with one `docs/studio.md`
  user guide. It states current macOS/Apple Silicon availability, updates the alpha installer
  filenames, and covers Codex setup, workspace/import/authoring/release workflows, runs and updates.
- Move source launch, isolated development, native packaging and verification instructions to
  CONTRIBUTING.md. Remove both superseded guides and update navigation and publication-note links.
- Replace outdated recoverable-pack-deletion instructions with current permanent-deletion and
  dependency-warning behavior. No recovery copies are promised.
- Add routine workspace/private-state backup and same-account restore instructions, including
  custom outputs, hidden files, SQLite companions, stopped writers and path/permission constraints.
  Explain automatic upgrade-recovery scope and pre-use restoration limits separately. Codex
  histories/credentials remain managed separately. No alpha troubleshooting guide was added.
- Validation: 113 local Markdown links/anchors checked across the affected guides/navigation,
  all 28 release-pipeline tests passed after updating its generated guide reference, and
  repository-wide Ruff lint/format and diff whitespace checks passed. No real user state was
  backed up/restored and no application, installer build, or release publication was run.
- Following user review, shorten CONTRIBUTING.md's Studio section to prerequisites, locked
  dependency setup, source launch, app/DMG build and verification, and frontend checks. Remove
  architecture, helper lifecycle, profile internals and packaging implementation explanations
  from the build instructions; user workflows and detailed recovery remain in their linked guides.

## Local alpha DMG build

- User requested the DMG on October 9. Built the current working tree with
  `uv run --no-sync python scripts/package_studio_macos.py --build-app --release`.
  No source commit, tag push or GitHub publication was performed.
- Apple Silicon installer: `dist/macos/EvidenceForge-Studio-2.2.0a1-aarch64.dmg`
  (36,084,438 bytes), with its `.dmg.sha256` companion. SHA256:
  `5261899a031092c42292f3a9397b9fe1faf976d71454c0c8d13e5f5f9c65dc14`.
- Native app metadata is `2.2.0-alpha.1`; the bundled engine and runtime manifest are
  `2.2.0a1`. Version synchronization, `hdiutil verify` and checksum verification passed.
- `scripts/verify_studio_macos.py` passed all isolated packaged-runtime checks: runtime checksum,
  CLI, bundled skills/references, pack inspection, artifact naming/properties, bundle data
  properties, validation and checkpoint-enabled generation. This does not replace the pending
  clean-machine GUI acceptance or full GitHub release gates.

## Installer icon branding

- Add a native Swift icon setter and build the installer as a writable image first. Mount it,
  apply Studio's artwork to the volume, detach it, then convert to the compressed release DMG.
  The `.VolumeIcon.icns` and volume custom-icon flag are inside the disk image, so ordinary
  downloads retain the mounted disk's branding. Also apply a local DMG file icon; this external
  Finder metadata is not preserved by direct GitHub downloads.
- Rebuilt the `2.2.0a1` Apple Silicon DMG (37,669,774 bytes). That build's SHA256:
  `0c14928d403334ca6415ce3f5996c30a04e73047f9bbbd29aa5de0c6333064d2`.
  Disk-image integrity, companion checksum, packaging Ruff lint/format and whitespace checks pass.
- Verified a byte-only copy with external icon metadata cleared: read-only mounting retained
  the 1,747,929-byte `.VolumeIcon.icns`, the volume's custom-icon flag and alpha app metadata.
  The verification mount was ejected. The app/helper was not launched.
- User clarified interest in icons surviving distribution. A standalone downloaded DMG's file
  icon before mounting remains distinct from the embedded mounted-volume icon. A metadata-aware
  ZIP can transport the file icon with an extraction step; no ZIP release asset or publication
  workflow change was made.

## Requested regeneration

- After accepting the native icon implementation, the user requested another DMG regeneration.
  Rebuilt the app and installer from the current working tree using the same release command.
- Latest `dist/macos/EvidenceForge-Studio-2.2.0a1-aarch64.dmg`: 37,669,777 bytes; SHA256
  `7e44867271cc47865e6b86541cf386fc669291d3d6b65bf8b62f11e2bb8fa93b`.
- Image integrity and companion checksum pass. A read-only copy with external metadata cleared
  retained its embedded volume icon/custom-icon flag, alpha app/engine versions and verified
  bundled runtime checksum. The verification image was ejected. No commit or publication occurred.

## Authorized alpha publication

- User reports that the regenerated DMG and app work. This records the local smoke-test result;
  it does not claim separate-account or clean-machine acceptance.
- Final pre-commit Ruff lint/format and version synchronization checks pass. All 47 focused
  release-pipeline/version tests pass; workflow contracts are checked separately. Full routine,
  coverage, slow, checkpoint portability and native macOS gates run on the tagged snapshot
  before automatic publication. The final downloaded-installer smoke test belongs to the user.
